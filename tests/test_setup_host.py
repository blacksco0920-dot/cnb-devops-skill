"""Administrator transport tests: synthetic files only; no real SSH or cloud calls."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import test_bundle_host_installer as installer_tests
from test_bundle_host_policy import HOST_PATH, load_host
from test_bundle_host_bootstrap import policy_fixture, spec_fixture

SCRIPT = HOST_PATH.parents[3] / "scripts/setup-host.py"


def load(path):
    spec = importlib.util.spec_from_file_location("admin_setup_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SetupHostTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "Administrator SSH entry is missing")
        self.m = load(SCRIPT)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        helper = installer_tests.HostInstallerTests()
        helper.setUp()
        helper.bundle(self.bundle)
        policy = policy_fixture()
        for index, service in enumerate(policy["services"].values()):
            service["networks"] = ["sample-test"]
            service["loopback_port"] = {"host_ip": "127.0.0.1", "protocol": "tcp", "published": 13000 + index, "target": 8000 + index}
        policy["compose_sha256"] = hashlib.sha256((self.bundle / "docker-compose.yml").read_bytes()).hexdigest()
        policy_raw = (json.dumps(policy, sort_keys=True) + "\n").encode()
        (self.bundle / "host-policy.json").write_bytes(policy_raw)
        core = (self.bundle / "host/tat-deploy-test.py").read_bytes()
        (self.bundle / "tat-command.sh").write_bytes(load_host().render_tat_template(policy, hashlib.sha256(core).hexdigest(), hashlib.sha256(policy_raw).hexdigest()))
        for name in ("install-project.py", "bootstrap-host.py", "configure-native-caddy.py", "setup-project.py"):
            (self.bundle / "host" / name).write_bytes(HOST_PATH.with_name(name).read_bytes())
        files = {p.relative_to(self.bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in self.bundle.rglob("*") if p.is_file() and p.name != "artifact-lock.json"}
        raw_lock = (json.dumps({"schema": "cnb-devops-artifacts/v1", "version": "0.1.0", "files": files}, sort_keys=True) + "\n").encode()
        (self.bundle / "artifact-lock.json").write_bytes(raw_lock)
        self.lock = hashlib.sha256(raw_lock).hexdigest()
        def private(name, raw):
            p = self.root / name
            p.write_bytes(raw)
            p.chmod(0o600)
            return p
        self.identity = private("identity", b"synthetic private key material\n")
        self.known = private("known_hosts", b"demo.example.invalid ssh-ed25519 synthetic\n")
        self.target = private("target.json", json.dumps({"host": "demo.example.invalid", "port": 2222, "user": "ubuntu", "identity_file": str(self.identity), "known_hosts_file": str(self.known)}).encode())
        spec = spec_fixture()
        spec["policy_sha256"] = hashlib.sha256(policy_raw).hexdigest()
        spec["docker_packages"]["caddy"] = "2.6.2-1ubuntu0.24.04.3"
        self.spec = private("spec.json", json.dumps(spec).encode())
        self.secret = "cnb:synthetic-docker-password-only"
        auth = base64.b64encode(self.secret.encode()).decode()
        self.config = private("docker.json", json.dumps({"auths": {registry: {"auth": auth} for registry in ["registry.example.invalid", "ccr.ccs.tencentyun.com"]}}).encode())
        self.args = ["--bundle-dir", str(self.bundle), "--lock-sha256", self.lock, "--target", str(self.target), "--bootstrap-spec", str(self.spec), "--tcr-docker-config", str(self.config), "--caddy-baseline-sha256", "a" * 64]

    def test_preview_is_offline_and_never_prints_credentials(self):
        output = io.StringIO()
        with mock.patch.object(self.m.subprocess, "run", side_effect=AssertionError("preview opened SSH")), contextlib.redirect_stdout(output):
            self.assertEqual(self.m.main(self.args), 0)
        result = json.loads(output.getvalue())
        self.assertEqual((result["status"], result["environment"]), ("preview", "test"))
        self.assertNotIn(self.secret, output.getvalue())
        self.assertNotIn(base64.b64encode(self.secret.encode()).decode(), output.getvalue())

    def test_apply_uses_one_strict_ssh_and_streams_private_input_not_argv(self):
        calls = []
        def execute(argv, **options):
            calls.append(argv)
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("IdentitiesOnly=yes", argv)
            self.assertIn("-F", argv)
            self.assertIn("UserKnownHostsFile=" + str(self.known), argv)
            self.assertIn("ubuntu@demo.example.invalid", argv)
            self.assertNotIn(self.secret, " ".join(argv))
            with tarfile.open(fileobj=io.BytesIO(options["input"]), mode="r:") as archive:
                self.assertEqual(archive.extractfile("docker-config.json").read(), self.config.read_bytes())
                self.assertTrue(all(member.mode == 0o600 and member.isfile() for member in archive))
            return subprocess.CompletedProcess(argv, 0, json.dumps({"schema": "cnb-host-setup/v1", "status": "ready", "project": "sample", "environment": "test", "lock_sha256": self.lock}).encode(), b'')
        with mock.patch.object(self.m.subprocess, "run", side_effect=execute), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.m.main(self.args + ["--apply"]), 0)
        self.assertEqual(len(calls), 1)

    def test_private_modes_symlinks_target_injection_and_bundle_drift_block_ssh(self):
        with mock.patch.object(self.m.subprocess, "run", side_effect=AssertionError("invalid input opened SSH")):
            self.config.chmod(0o644)
            with self.assertRaises(self.m.SetupError):
                self.m.main(self.args + ["--apply"])
            self.config.chmod(0o600)
            original = self.target.read_bytes()
            target = json.loads(original)
            target["host"] = "demo; touch /tmp/unwanted"
            self.target.write_text(json.dumps(target))
            with self.assertRaises(self.m.SetupError):
                self.m.main(self.args + ["--apply"])
            self.target.write_bytes(original)
            self.identity.unlink()
            self.identity.symlink_to(self.known)
            with self.assertRaises(self.m.SetupError):
                self.m.main(self.args + ["--apply"])
            self.identity.unlink()
            self.identity.write_bytes(b"synthetic\n")
            self.identity.chmod(0o600)
            (self.bundle / "host/setup-project.py").write_bytes(b"changed")
            with self.assertRaises(self.m.SetupError):
                self.m.main(self.args + ["--apply"])

    def test_root_gate_rejects_changed_driver_before_executing_it(self):
        _plan, files, expected, _target = self.m.prepare(self.args_namespace())
        driver_sha = hashlib.sha256(files["bundle/host/setup-project.py"]).hexdigest()
        sentinel = self.root / "must-not-exist"
        files["bundle/host/setup-project.py"] = f"open({str(sentinel)!r}, 'w').write('executed')\n".encode()
        result = subprocess.run([sys.executable, "-I", "-c", self.m.ROOT_GATE, driver_sha, json.dumps(expected)],
                                input=self.m.archive_bytes(files), capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sentinel.exists())
        self.assertEqual(json.loads(result.stdout)["status"], "failed")

    def args_namespace(self):
        return SimpleNamespace(bundle_dir=self.bundle, lock_sha256=self.lock, target=self.target,
                               bootstrap_spec=self.spec, tcr_docker_config=self.config, caddy_baseline_sha256="a" * 64)

    def test_real_staged_files_are_private_and_drift_is_not_overwritten(self):
        driver = load(HOST_PATH.with_name("setup-project.py"))
        installer = load(HOST_PATH.with_name("install-project.py"))
        actual_dir, actual_file = installer.ensure_directory, installer.install_file
        with mock.patch.object(installer, "ensure_directory", side_effect=lambda p, mode, _u, _g: actual_dir(p, mode, os.getuid(), os.getgid())), \
             mock.patch.object(installer, "install_file", side_effect=lambda p, raw, mode, _u, _g: actual_file(p, raw, mode, os.getuid(), os.getgid())), \
             mock.patch.object(driver, "existing_private", side_effect=lambda p, _i: installer.read_file(p)):
            task = self.root / "stage"
            payload = {"bundle/controller.py": b"reviewed", "docker-config.json": b"synthetic-private"}
            driver.materialize(task, payload, installer)
            self.assertEqual(task.stat().st_mode & 0o777, 0o700)
            self.assertEqual((task / "bundle").stat().st_mode & 0o777, 0o700)
            secret = task / "docker-config.json"
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            inode = secret.stat().st_ino
            driver.materialize(task, payload, installer)
            self.assertEqual(secret.stat().st_ino, inode)
            secret.write_bytes(b"different")
            with self.assertRaisesRegex(driver.SetupError, "STAGED_INPUT_DRIFT"):
                driver.materialize(task, payload, installer)
            self.assertEqual(secret.read_bytes(), b"different")

    def test_new_pinned_caddy_records_baseline_and_existing_caddy_is_not_upgraded(self):
        driver = load(HOST_PATH.with_name("setup-project.py"))
        binpath, config = self.root / "caddy", self.root / "Caddyfile"
        calls = []
        version = "2.6.2-1ubuntu0.24.04.3"
        default = b":80 {\n file_server\n}\n"
        def run(command, **_kwargs):
            calls.append(command)
            if "caddy=" + version in command:
                binpath.write_bytes(b"synthetic binary")
                config.write_bytes(default)
            return version.encode() if command[0] == "/usr/bin/dpkg-query" else b""
        installer = SimpleNamespace(install_file=lambda path, raw, mode, _u, _g: (path.write_bytes(raw), path.chmod(mode)))
        bootstrap = SimpleNamespace(run=run)
        caddy = SimpleNamespace(check_system=lambda: None, read_safe=lambda path: (path.read_bytes(), None))
        real_path = Path
        def mapped(value):
            return {"/usr/bin/caddy": binpath, "/etc/caddy/Caddyfile": config}.get(value, real_path(value))
        with mock.patch.object(driver, "Path", side_effect=mapped):
            baseline = driver.ensure_caddy({"docker_packages": {"caddy": version}}, None, self.root, installer, bootstrap, caddy)
            self.assertEqual(baseline, hashlib.sha256(default).hexdigest())
            self.assertIn(["/usr/bin/apt-get", "install", "--yes", "--no-install-recommends", "caddy=" + version], calls)
            self.assertEqual((self.root / "caddy-baseline.json").stat().st_mode & 0o777, 0o600)
            (self.root / "caddy-baseline.json").unlink()
            calls.clear()
            with self.assertRaisesRegex(driver.SetupError, "EXISTING_CADDY_BASELINE_REQUIRED"):
                driver.ensure_caddy({"docker_packages": {}}, None, self.root, installer, bootstrap, caddy)
            self.assertEqual(driver.ensure_caddy({"docker_packages": {}}, baseline, self.root, installer, bootstrap, caddy), baseline)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
