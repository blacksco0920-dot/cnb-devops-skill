"""Installer checks use real local artifacts; privileged host activation is not a cloud test."""
import hashlib
import contextlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from test_bundle_host_policy import HOST_PATH, load_host, sample_policy


INSTALLER_PATH = HOST_PATH.with_name("install-project.py")


def load_installer():
    spec = importlib.util.spec_from_file_location("bundle_installer", INSTALLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostInstallerTests(unittest.TestCase):
    def setUp(self):
        self.installer = load_installer()

    def bundle(self, root):
        host = load_host()
        policy = sample_policy()
        compose = b"name: sample-test\nservices: {}\n"
        policy["compose_sha256"] = hashlib.sha256(compose).hexdigest()
        policy_bytes = (json.dumps(policy, sort_keys=True) + "\n").encode()
        files = {
            "host/tat-deploy-test.py": HOST_PATH.read_bytes(), "host-policy.json": policy_bytes,
            "docker-compose.yml": compose,
            "tat-command.sh": host.render_tat_template(policy, hashlib.sha256(HOST_PATH.read_bytes()).hexdigest(), hashlib.sha256(policy_bytes).hexdigest()),
            "bundle.json": b'{"version":"0.1.0"}\n',
        }
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        lock = {"schema": "cnb-devops-artifacts/v1", "version": "0.1.0",
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        raw = (json.dumps(lock, sort_keys=True) + "\n").encode()
        (root / "artifact-lock.json").write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_bundle_hash_policy_compose_and_fixed_shim_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest = self.bundle(root)
            plan = self.installer.verify_bundle(root, digest)
            self.assertEqual(plan["policy"]["project"], "sample")
            self.assertEqual(plan["lock_sha256"], digest)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root, "f" * 64)
            (root / "docker-compose.yml").write_bytes(b"tampered")
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root, digest)

    def test_artifact_lock_path_escape_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root)
            lock = json.loads((root / "artifact-lock.json").read_bytes())
            lock["files"]["../outside"] = "a" * 64
            (root / "artifact-lock.json").write_text(json.dumps(lock))
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root)
            self.bundle(root)
            (root / "docker-compose.yml").unlink()
            (root / "docker-compose.yml").symlink_to(root / "host-policy.json")
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root)

    def test_immutable_file_repeat_keeps_inode_and_drift_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "controller"
            self.assertTrue(self.installer.install_file(path, b"reviewed", 0o444, os.getuid(), os.getgid()))
            inode = path.stat().st_ino
            self.assertFalse(self.installer.install_file(path, b"reviewed", 0o444, os.getuid(), os.getgid()))
            self.assertEqual(path.stat().st_ino, inode)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_file(path, b"new-unreviewed", 0o444, os.getuid(), os.getgid())
            self.assertEqual(path.read_bytes(), b"reviewed")

    def test_runtime_environment_derives_only_uninitialized_image_slots(self):
        host = load_host()
        host.configure_policy(sample_policy(), policy_sha256="b" * 64)
        raw = b"DATABASE_URL=postgresql://sample_test_user:private@project-postgres:5432/sample_test\n"
        result = self.installer.prepare_runtime_env(host, raw)
        self.assertIn(b"SAMPLE_API_IMAGE=uninitialized\n", result)
        self.assertIn(b"SAMPLE_WEB_IMAGE=uninitialized\n", result)
        self.assertTrue(result.startswith(raw))
        with self.assertRaises(self.installer.InstallError):
            self.installer.prepare_runtime_env(host, raw + b"SAMPLE_API_IMAGE=repo:latest\n")

    def test_empty_database_requires_zero_objects_and_uses_fixed_argv(self):
        host = load_host()
        host.configure_policy(sample_policy(), policy_sha256="b" * 64)
        with mock.patch.object(host, "_run", return_value=b"0\n") as run:
            host._assert_database_empty()
        command = run.call_args.args[0]
        self.assertIn("sample_test", command)
        self.assertIn("project-postgres", command)
        self.assertNotIn("sh", command)
        for output in (b"1\n", b"", b"false", b"0\n1"):
            with mock.patch.object(host, "_run", return_value=output), self.assertRaises(host.DeploymentError):
                host._assert_database_empty()

    @contextlib.contextmanager
    def simulated_root_install(self, temporary):
        """Real files/state machine, with root ownership and external dependencies simulated."""
        base = Path(temporary).resolve()
        bundle = base / "bundle"
        bundle.mkdir()
        lock_sha = self.bundle(bundle)
        plan = self.installer.verify_bundle(bundle, lock_sha)
        host = plan["host"]
        machine = base / "machine"
        machine.mkdir()
        install = machine / "opt/cnb-devops/sample/test/v1"
        app = machine / "opt/apps/sample-test"
        plan["policy"]["install_dir"] = str(install)
        host.APP_DIR = app
        host.ENV_PATH, host.COMPOSE_PATH = app / ".env", app / "docker-compose.yml"
        host.RELEASE_PATH, host.TRANSACTION_PATH = app / ".release.json", app / ".release.transaction.json"
        host.LOCK_PATH = app.parent / ".sample-test.deploy.lock"
        host.CONTROLLER_COMPOSE_PATH = install / "docker-compose.yml"
        runtime = base / "protected.env"
        runtime.write_bytes(b"DATABASE_URL=postgresql://sample_test_user:private@project-postgres:5432/sample_test\n")
        runtime.chmod(0o600)
        actual_file, actual_dir = self.installer.install_file, self.installer.ensure_directory
        actual_verify = self.installer.verify_file

        def simulated_file(path, raw, mode, uid, gid):
            self.assertTrue(path.is_relative_to(machine))
            return actual_file(path, raw, mode, os.getuid(), os.getgid())

        def simulated_dir(path, mode, uid, gid):
            if path == machine or not path.is_relative_to(machine):
                return
            return actual_dir(path, mode, os.getuid(), os.getgid())

        def simulated_verify(path, raw, mode, uid, gid):
            return actual_verify(path, raw, mode, os.getuid(), os.getgid())

        def administrator_json(path):
            raw = path.read_bytes()
            return json.loads(raw), hashlib.sha256(raw).hexdigest()

        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir="/home/ubuntu")
        with mock.patch.object(self.installer.os, "geteuid", return_value=0), \
             mock.patch.object(self.installer.pwd, "getpwnam", return_value=account), \
             mock.patch.object(self.installer, "ensure_directory", side_effect=simulated_dir), \
             mock.patch.object(self.installer, "install_file", side_effect=simulated_file), \
             mock.patch.object(self.installer, "verify_file", side_effect=simulated_verify), \
             mock.patch.object(host, "read_root_owned_json", side_effect=administrator_json), \
             mock.patch.object(host, "_run", return_value=b""), \
             mock.patch.object(self.installer, "check_dependencies") as dependencies, \
             mock.patch.object(host, "_assert_database_empty") as empty:
            yield plan, runtime, install, app, simulated_file, dependencies, empty

    def test_unknown_existing_application_directory_is_preserved_without_installing_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, install, app, _file, _dependencies, _empty):
                app.mkdir(parents=True, mode=0o750)
                unknown = app / "existing-project-data.txt"
                unknown.write_bytes(b"existing application data must survive")
                with self.assertRaises(self.installer.InstallError):
                    self.installer.apply_install(plan, runtime)
                self.assertEqual(unknown.read_bytes(), b"existing application data must survive")
                self.assertEqual(set(app.iterdir()), {unknown})
                self.assertFalse(install.exists())
                self.assertFalse(plan["host"].LOCK_PATH.exists())

    def test_exact_existing_application_container_blocks_first_install_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, install, app, _file, _dependencies, _empty):
                with mock.patch.object(plan["host"], "_run", return_value=b"other-project\nsample-test-api\n") as run:
                    with self.assertRaises(self.installer.InstallError):
                        self.installer.apply_install(plan, runtime)
                self.assertFalse(app.exists())
                self.assertFalse(install.exists())
                self.assertEqual(run.call_args.args[0][-4:], ["ps", "--all", "--format", "{{.Names}}"])

    def test_other_container_names_do_not_expand_the_project_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, _install, _app, _file, _dependencies, _empty):
                with mock.patch.object(plan["host"], "_run", return_value=b"sample-test-api-old\nsample-test-api2\n"):
                    self.assertEqual(self.installer.apply_install(plan, runtime), "installed")

    def test_completed_install_repeat_preserves_deployed_environment_without_empty_database_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, install, app, _file, dependencies, empty):
                self.assertEqual(self.installer.apply_install(plan, runtime), "installed")
                self.assertEqual(json.loads((app / ".release.json").read_bytes())["images"], {})
                current = (app / ".env").read_bytes().replace(b"uninitialized", b"registry.example.invalid/demo/image@sha256:" + b"1" * 64)
                (app / ".env").write_bytes(current)
                host = plan["host"]
                passed = {
                    "schema": host.RELEASE_SCHEMA_V2, "status": "passed", "controller": host.CONTROLLER_ID,
                    "controller_compose_sha256": host.CONTROLLER_COMPOSE_SHA256,
                    "controller_program_sha256": "c" * 64, "git_sha": "a" * 40, "build_id": "cnb-build-123",
                    "images": {name: spec["image_repository"] + "@sha256:" + "1" * 64
                               for name, spec in host.POLICY["services"].items()},
                    "snapshot": "20260906T010203Z-0123456789abcdef", "snapshot_manifest_sha256": "d" * 64,
                    "deployed_at": "2026-09-06T01:02:03Z", "probes": list(host.PUBLIC_PROBES),
                }
                host._validate_release_record_model(passed)
                passed_raw = self.installer.canonical(passed)
                (app / ".release.json").write_bytes(passed_raw)
                inode = (app / ".env").stat().st_ino
                runtime.unlink()  # The administrator may erase the transferred private input.
                dependencies.reset_mock()
                empty.reset_mock()
                self.assertEqual(self.installer.apply_install(plan, runtime), "unchanged")
                self.assertEqual((app / ".env").read_bytes(), current)
                self.assertEqual((app / ".env").stat().st_ino, inode)
                self.assertEqual((app / ".release.json").read_bytes(), passed_raw)
                dependencies.assert_not_called()
                empty.assert_not_called()

    def test_interrupted_install_resumes_matching_files_and_rejects_core_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, install, app, file, _dependencies, _empty):
                def interrupted(path, raw, mode, uid, gid):
                    if path == app / ".release.json":
                        raise OSError("simulated interruption")
                    return file(path, raw, mode, uid, gid)
                with mock.patch.object(self.installer, "install_file", side_effect=interrupted):
                    with self.assertRaises(OSError):
                        self.installer.apply_install(plan, runtime)
                self.assertFalse((install / "installation.json").exists())
                inode = (install / "tat-deploy-test.py").stat().st_ino
                self.assertEqual(self.installer.apply_install(plan, runtime), "installed")
                self.assertEqual((install / "tat-deploy-test.py").stat().st_ino, inode)
                (install / "tat-deploy-test.py").chmod(0o644)
                (install / "tat-deploy-test.py").write_bytes(b"drift")
                with self.assertRaises(self.installer.InstallError):
                    self.installer.apply_install(plan, runtime)
                self.assertEqual((install / "tat-deploy-test.py").read_bytes(), b"drift")

    def test_root_attested_partial_install_still_rejects_unknown_application_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary) as (plan, runtime, install, app, file, _dependencies, _empty):
                def interrupted(path, raw, mode, uid, gid):
                    if path == app / ".release.json":
                        raise OSError("simulated interruption")
                    return file(path, raw, mode, uid, gid)
                with mock.patch.object(self.installer, "install_file", side_effect=interrupted), self.assertRaises(OSError):
                    self.installer.apply_install(plan, runtime)
                unknown = app / "existing-project-data.txt"
                unknown.write_bytes(b"unknown data")
                with self.assertRaises(self.installer.InstallError):
                    self.installer.apply_install(plan, runtime)
                self.assertEqual(unknown.read_bytes(), b"unknown data")
                self.assertFalse((app / ".release.json").exists())
                self.assertFalse((install / "installation.json").exists())


if __name__ == "__main__":
    unittest.main()
