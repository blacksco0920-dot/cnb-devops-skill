"""Installer checks use real local artifacts; privileged host activation is not a cloud test."""
import hashlib
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from types import ModuleType
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

    def test_production_preview_reports_policy_environment_without_installing(self):
        plan = {"policy": {"project": "sample", "environment": "production", "install_dir": "/opt/cnb-devops/sample/production/v1"},
                "version": "0.1.0", "lock_sha256": "a" * 64, "host": SimpleNamespace(APP_DIR=Path("/opt/apps/sample-production"))}
        output = io.StringIO()
        with mock.patch.object(self.installer, "verify_bundle", return_value=plan), \
             mock.patch.object(self.installer, "apply_install", side_effect=AssertionError("preview mutated host")), \
             contextlib.redirect_stdout(output):
            self.installer.main(["--bundle-dir", "/reviewed", "--runtime-env", "/protected.env"])
        result = json.loads(output.getvalue())
        self.assertEqual(result["environment"], "production")
        self.assertEqual(result["status"], "preview")

    def bundle(self, root, environment="test", recovery=False):
        host = load_host()
        policy = sample_policy()
        if environment == "production":
            policy = json.loads(json.dumps(policy).replace("sample-test", "sample-production")
                                .replace("/sample/test/", "/sample/production/"))
            policy["environment"] = environment
        compose = f"name: sample-{environment}\nservices: {{}}\n".encode()
        policy["compose_sha256"] = hashlib.sha256(compose).hexdigest()
        policy_bytes = (json.dumps(policy, sort_keys=True) + "\n").encode()
        files = {
            "host/tat-deploy-test.py": HOST_PATH.read_bytes(), "host-policy.json": policy_bytes,
            "docker-compose.yml": compose,
            "tat-command.sh": host.render_tat_template(policy, hashlib.sha256(HOST_PATH.read_bytes()).hexdigest(), hashlib.sha256(policy_bytes).hexdigest()),
            "bundle.json": b'{"version":"0.1.0"}\n',
        }
        if recovery:
            files["host/recover-project.py"] = HOST_PATH.with_name("recover-project.py").read_bytes()
            files["recovery-policy.json"] = self.installer.canonical({"schema": "cnb-recovery-policy/v1", "project": "sample",
                "environment": environment, "host_policy_sha256": hashlib.sha256(policy_bytes).hexdigest(), "mounts": {},
                "required_nonempty_tables": [{"schema": "public", "name": "Orders", "minimum_rows": 1}]})
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        lock = {"schema": "cnb-devops-artifacts/v1", "version": "0.1.0",
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        raw = (json.dumps(lock, sort_keys=True) + "\n").encode()
        (root / "artifact-lock.json").write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_production_bundle_without_fixed_approval_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_sha = self.bundle(root, environment="production")
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root, lock_sha)

    def test_recovery_policy_drift_is_rejected_even_when_artifact_hashes_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.bundle(root, recovery=True)
            policy = json.loads((root / "recovery-policy.json").read_bytes())
            policy["host_policy_sha256"] = "f" * 64
            raw = self.installer.canonical(policy)
            (root / "recovery-policy.json").write_bytes(raw)
            lock = json.loads((root / "artifact-lock.json").read_bytes())
            lock["files"]["recovery-policy.json"] = hashlib.sha256(raw).hexdigest()
            lock_raw = self.installer.canonical(lock)
            (root / "artifact-lock.json").write_bytes(lock_raw)
            with self.assertRaises(self.installer.InstallError):
                self.installer.verify_bundle(root, hashlib.sha256(lock_raw).hexdigest())

    def production_bundle(self, root):
        self.bundle(root, environment="production")
        source = HOST_PATH.with_name("production-release.py").read_bytes()
        wrapper = ModuleType("production_installer_fixture")
        exec(compile(source, "production-release.py", "exec"), wrapper.__dict__)
        public = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + bytes(range(32))) + b"\n-----END PUBLIC KEY-----\n"
        (root / "host/production-release.py").write_bytes(source)
        (root / "approval-ed25519.pub").write_bytes(public)
        authority = {"schema": "cnb-production-authority/v1", "project": "sample", "environment": "production",
                     "controller_program_sha256": hashlib.sha256((root / "host/tat-deploy-test.py").read_bytes()).hexdigest(),
                     "host_policy_sha256": hashlib.sha256((root / "host-policy.json").read_bytes()).hexdigest(),
                     "controller_compose_sha256": hashlib.sha256((root / "docker-compose.yml").read_bytes()).hexdigest(),
                     "approval_public_key_sha256": hashlib.sha256(public).hexdigest()}
        (root / "production-authority.json").write_bytes(self.installer.canonical(authority))
        self.production_shim(root, wrapper)
        return self.refresh_lock(root)

    def production_shim(self, root, wrapper=None):
        if wrapper is None:
            wrapper = ModuleType("production_installer_fixture")
            exec(compile((root / "host/production-release.py").read_bytes(), "production-release.py", "exec"), wrapper.__dict__)
        template = wrapper.render_tat_template(json.loads((root / "host-policy.json").read_bytes()),
                    hashlib.sha256((root / "host/production-release.py").read_bytes()).hexdigest(),
                    hashlib.sha256((root / "production-authority.json").read_bytes()).hexdigest())
        (root / "tat-command.sh").write_bytes(template)

    def refresh_lock(self, root):
        lock = json.loads((root / "artifact-lock.json").read_bytes())
        names = set(lock["files"]) | {"host/production-release.py", "production-authority.json", "approval-ed25519.pub"}
        lock["files"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
        raw = self.installer.canonical(lock)
        (root / "artifact-lock.json").write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def test_production_authority_binds_every_reviewed_file_and_fixed_template(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_sha = self.production_bundle(root)
            self.assertEqual(self.installer.verify_bundle(root, lock_sha)["policy"]["environment"], "production")
            for field in ("controller_program_sha256", "host_policy_sha256", "controller_compose_sha256", "approval_public_key_sha256", "unknown"):
                self.production_bundle(root)
                authority = json.loads((root / "production-authority.json").read_bytes())
                authority[field] = "f" * 64
                (root / "production-authority.json").write_bytes(self.installer.canonical(authority))
                self.production_shim(root)
                with self.subTest(field=field), self.assertRaises(self.installer.InstallError):
                    self.installer.verify_bundle(root, self.refresh_lock(root))
            self.production_bundle(root)
            (root / "tat-command.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
            with self.assertRaisesRegex(self.installer.InstallError, "tat_shim_mismatch"):
                self.installer.verify_bundle(root, self.refresh_lock(root))

    def test_production_rejects_multiple_keys_even_when_all_hashes_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.production_bundle(root)
            public = (root / "approval-ed25519.pub").read_bytes() * 2
            (root / "approval-ed25519.pub").write_bytes(public)
            authority = json.loads((root / "production-authority.json").read_bytes())
            authority["approval_public_key_sha256"] = hashlib.sha256(public).hexdigest()
            (root / "production-authority.json").write_bytes(self.installer.canonical(authority))
            self.production_shim(root)
            with self.assertRaisesRegex(self.installer.InstallError, "approval_ed25519_spki_required"):
                self.installer.verify_bundle(root, self.refresh_lock(root))

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
    def simulated_root_install(self, temporary, environment="test", recovery=False):
        """Real files/state machine, with root ownership and external dependencies simulated."""
        base = Path(temporary).resolve()
        bundle = base / "bundle"
        bundle.mkdir()
        lock_sha = self.production_bundle(bundle) if environment == "production" else self.bundle(bundle, recovery=recovery)
        plan = self.installer.verify_bundle(bundle, lock_sha)
        host = plan["host"]
        machine = base / "machine"
        machine.mkdir()
        install = machine / f"opt/cnb-devops/sample/{environment}/v1"
        app = machine / f"opt/apps/sample-{environment}"
        plan["policy"]["install_dir"] = str(install)
        host.APP_DIR = app
        host.ENV_PATH, host.COMPOSE_PATH = app / ".env", app / "docker-compose.yml"
        host.RELEASE_PATH, host.TRANSACTION_PATH = app / ".release.json", app / ".release.transaction.json"
        host.LOCK_PATH = app.parent / f".sample-{environment}.deploy.lock"
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

    def test_optional_recovery_files_are_installed_and_repeat_refuses_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary, recovery=True) as (plan, runtime, install, _app, _file, _dependencies, _empty):
                self.assertEqual(self.installer.apply_install(plan, runtime), "installed")
                for name, mode in (("recovery-policy.json", 0o444), ("recover-project.py", 0o555)):
                    self.assertTrue((install / name).is_file())
                    self.assertEqual((install / name).stat().st_mode & 0o777, mode)
                runtime.unlink()
                self.assertEqual(self.installer.apply_install(plan, runtime), "unchanged")
                helper = install / "recover-project.py"
                helper.chmod(0o644)
                helper.write_bytes(b"drift")
                with self.assertRaises(self.installer.InstallError):
                    self.installer.apply_install(plan, runtime)
                self.assertEqual(helper.read_bytes(), b"drift")

    def test_production_install_preserves_extra_files_and_rejects_repeat_key_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.simulated_root_install(temporary, "production") as (plan, runtime, install, app, _file, dependencies, empty):
                self.assertEqual(self.installer.apply_install(plan, runtime), "installed")
                for name, mode in (("production-release.py", 0o555), ("production-authority.json", 0o444), ("approval-ed25519.pub", 0o444)):
                    self.assertEqual((install / name).stat().st_mode & 0o777, mode)
                baseline = json.loads((app / ".release.json").read_bytes())
                self.assertEqual(baseline["environment"], "production")
                self.assertFalse((app / ".production").exists())
                before = (app / ".env").read_bytes()
                runtime.unlink()
                dependencies.reset_mock()
                empty.reset_mock()
                self.assertEqual(self.installer.apply_install(plan, runtime), "unchanged")
                dependencies.assert_not_called()
                empty.assert_not_called()
                key = install / "approval-ed25519.pub"
                key.chmod(0o644)
                key.write_bytes(b"changed")
                with self.assertRaises(self.installer.InstallError):
                    self.installer.apply_install(plan, runtime)
                self.assertEqual(key.read_bytes(), b"changed")
                self.assertEqual((app / ".env").read_bytes(), before)

    def test_production_requires_openssl_before_dependency_commands(self):
        host = load_host()
        host.configure_policy(sample_policy())
        host.POLICY["environment"] = "production"
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        commands = []
        def regular(path, *_args):
            if str(path) == "/usr/bin/openssl":
                raise FileNotFoundError("openssl missing")
            return SimpleNamespace(st_uid=account.pw_uid, st_gid=account.pw_gid)
        def run(command, **_kwargs):
            commands.append(command)
            if command[-3:] == ["compose", "version", "--short"]:
                return b"2.40.3\n"
            if command[-1] == "SHOW server_version_num":
                return b"160015\n"
            return b"tool (PostgreSQL) 16.15\n"
        with mock.patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"\n'), \
             mock.patch.object(host, "_regular_file", side_effect=regular), \
             mock.patch.object(host, "_run", side_effect=run):
            with self.assertRaises(FileNotFoundError):
                self.installer.check_dependencies(host, account)
        self.assertEqual(commands, [])

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
