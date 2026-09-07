"""Bounded first-host preset; Docker, apt and root effects are simulated explicitly."""
import copy
import hashlib
import importlib.util
import io
import json
import contextlib
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

from test_bundle_host_policy import HOST_PATH, sample_policy


BOOTSTRAP = HOST_PATH.with_name("bootstrap-host.py")


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("host_bootstrap", BOOTSTRAP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy_fixture():
    policy = sample_policy()
    policy["networks"] = ["sample-test"]
    policy["database"].update(host="sample-test-postgres", container="sample-test-postgres")
    policy["required_env"] += ["REDIS_URL", "AUTH_TOKEN_SECRET"]
    policy["redis"] = {"url_env": "REDIS_URL", "host": "sample-test-redis", "port": 6379,
                       "database": 0, "container": "sample-test-redis"}
    return policy


def spec_fixture():
    return {"schema": "cnb-first-host/v1", "policy_sha256": "a" * 64,
            "images": {"postgres": "ccr.ccs.tencentyun.com/example/postgres@sha256:" + "1" * 64,
                       "redis": "ccr.ccs.tencentyun.com/example/redis@sha256:" + "2" * 64},
            "docker_packages": {}, "generate_env": ["AUTH_TOKEN_SECRET"]}


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.b = load_bootstrap()
        self.policy, self.spec = policy_fixture(), spec_fixture()

    def production_policy(self):
        policy = copy.deepcopy(self.policy)
        policy.update(environment="production", networks=["sample-production"])
        policy["database"].update(host="sample-production-postgres", container="sample-production-postgres")
        policy["redis"].update(host="sample-production-redis", container="sample-production-redis")
        return policy

    def test_production_bootstrap_has_separate_resources_and_rejects_test_database(self):
        policy = self.production_policy()
        self.b.validate_spec(self.spec, policy, "a" * 64, apply=True)
        model = self.b.compose_model(policy, self.spec, "b" * 64)
        self.assertEqual(model["name"], "sample-production-data")
        self.assertEqual(model["services"]["postgres"]["container_name"], "sample-production-postgres")
        self.assertEqual(model["volumes"]["redis-data"]["name"], "sample-production-redis-data")
        self.assertEqual(model["services"]["redis"]["labels"]["io.cnb-devops.environment"], "production")
        runtime = self.b.runtime_environment(policy, self.spec, self.b.generate_credentials(self.spec))
        self.assertIn(b"@sample-production-postgres:5432/", runtime)
        policy["database"].update(host="sample-test-postgres", container="sample-test-postgres")
        with self.assertRaises(self.b.BootstrapError):
            self.b.validate_spec(self.spec, policy, "a" * 64, apply=True)

    def test_production_bootstrap_first_write_and_lock_use_production_state(self):
        policy = self.production_policy()
        writes = []
        def first_write(path, *_args):
            writes.append(str(path))
            raise RuntimeError("stop before writing")
        installer = mock.Mock()
        installer.install_file.side_effect = first_write
        bundle = {"policy": policy, "host": mock.Mock(POLICY_SHA256="a" * 64)}
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "os-release"
            release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            actual_path = Path
            def path(value):
                return release if value == "/etc/os-release" else actual_path(value)
            with mock.patch.object(self.b, "Path", side_effect=path), \
                 mock.patch.object(self.b.os, "geteuid", return_value=0), \
                 mock.patch.object(self.b, "ensure_docker"), \
                 mock.patch.object(self.b, "inventory_resources", return_value={"network": {}, "volume": {}, "container": {}}):
                with self.assertRaisesRegex(RuntimeError, "stop before writing"):
                    self.b.apply_bootstrap(installer, bundle, self.spec, "b" * 64)
        self.assertEqual(writes, ["/var/lib/cnb-devops/sample/production/bootstrap/identity.json"])
        with mock.patch.object(self.b.os, "geteuid", return_value=0), \
             mock.patch.object(self.b.os, "open", side_effect=OSError("no write")) as opened:
            with self.assertRaises(OSError), self.b.bootstrap_lock("sample", "production"):
                self.fail("lock must not succeed")
        self.assertEqual(str(opened.call_args.args[0]), "/run/lock/cnb-devops-sample-production-bootstrap.lock")

    def test_production_preview_reports_real_environment(self):
        raw = self.b.canonical(self.spec)
        installer = mock.Mock()
        installer.read_file.return_value = raw
        installer.strict_json.return_value = self.spec
        bundle = {"policy": self.production_policy(), "host": mock.Mock(POLICY_SHA256="a" * 64)}
        output = io.StringIO()
        with mock.patch.object(self.b, "load_bundle", return_value=(installer, bundle)), contextlib.redirect_stdout(output):
            self.b.main(["--bundle-dir", "/reviewed", "--lock-sha256", "c" * 64,
                         "--spec", "/reviewed/spec.json", "--spec-sha256", self.b.sha(raw)])
        result = json.loads(output.getvalue())
        self.assertEqual(result["environment"], "production")
        self.assertEqual(result["status"], "preview")
        self.assertIn("production release verification", result["remaining"])

    def test_only_dedicated_policy_and_digest_images_are_supported(self):
        self.b.validate_spec(self.spec, self.policy, "a" * 64, apply=True)
        for mutate in (
            lambda p, s: s["images"].update(postgres="postgres:16"),
            lambda p, s: p.update(networks=["shared-infra"]),
            lambda p, s: p["database"].update(container="other-project-postgres"),
            lambda p, s: p["database"].update(user="postgres"),
            lambda p, s: s.update(policy_sha256="b" * 64),
            lambda p, s: s["docker_packages"].update(unknown="1.0"),
            lambda p, s: s.update(generate_env=["DATABASE_URL"]),
        ):
            policy, spec = copy.deepcopy(self.policy), copy.deepcopy(self.spec)
            mutate(policy, spec)
            with self.assertRaises(self.b.BootstrapError):
                self.b.validate_spec(spec, policy, "a" * 64, apply=True)

    def test_offline_plan_can_explain_required_image_pins(self):
        self.spec["images"]["postgres"] = None
        self.b.validate_spec(self.spec, self.policy, "a" * 64)
        with self.assertRaises(self.b.BootstrapError):
            self.b.validate_spec(self.spec, self.policy, "a" * 64, apply=True)

    def test_optional_caddy_package_requires_exact_approved_version(self):
        self.spec["docker_packages"]["caddy"] = "2.6.2-1ubuntu0.24.04.3"
        self.b.validate_spec(self.spec, self.policy, "a" * 64, apply=True)
        self.spec["docker_packages"]["caddy"] = "latest"
        with self.assertRaises(self.b.BootstrapError):
            self.b.validate_spec(self.spec, self.policy, "a" * 64, apply=True)

    def test_optimized_python_cannot_disable_spec_security_checks(self):
        self.spec["images"]["postgres"] = "postgres:16"
        code = ("import runpy; m=runpy.run_path(" + repr(str(BOOTSTRAP)) + "); "
                + "m['validate_spec'](" + repr(self.spec) + "," + repr(self.policy) + ",'" + "a" * 64 + "',apply=True)")
        result = subprocess.run([sys.executable, "-O", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)

    def test_generated_secret_values_do_not_enter_compose_or_resource_labels(self):
        credentials = self.b.generate_credentials(self.spec)
        runtime = self.b.runtime_environment(self.policy, self.spec, credentials)
        compose = self.b.compose_model(self.policy, self.spec, "b" * 64)
        serialized = json.dumps(compose)
        for value in credentials.values():
            self.assertNotIn(value, serialized)
        self.assertIn("sample-test-postgres:5432/sample_test", runtime.decode())
        self.assertIn("sample-test-redis:6379/0", runtime.decode())
        self.assertNotIn("REDIS_PREFIX", runtime.decode())
        self.assertNotIn("REDIS_KEY_PREFIX", runtime.decode())
        for service in compose["services"].values():
            self.assertNotIn("ports", service)
            self.assertNotIn("privileged", service)
        self.assertEqual(compose["services"]["postgres"]["environment"]["POSTGRES_USER"], "postgres")

    def test_existing_unowned_resource_is_rejected_without_writes(self):
        existing = {"network": {"sample-test": {"Labels": {}}}, "volume": {}, "container": {}}
        with self.assertRaises(self.b.BootstrapError):
            self.b.validate_resources(self.policy, self.spec, "b" * 64, existing)

    def test_stopped_wrong_image_container_is_not_replaced(self):
        labels = self.b.labels(self.policy, "b" * 64)
        existing = {"network": {}, "volume": {}, "container": {
            "sample-test-postgres": {"Config": {"Labels": labels, "Image": "postgres:16"},
                                     "State": {"Running": False}}}}
        with self.assertRaises(self.b.BootstrapError):
            self.b.validate_resources(self.policy, self.spec, "b" * 64, existing)

    def test_database_provision_uses_restricted_role_and_password_only_on_stdin(self):
        credentials = self.b.generate_credentials(self.spec)
        commands = []
        def run(command, *, input=None, **kwargs):
            commands.append((command, input))
            if "current_user" in " ".join(command):
                return self.policy["database"]["user"].encode() + b"\n"
            if "bootstrap_role_verified" in " ".join(command):
                return b"bootstrap_role_verified\n"
            return b""
        self.b.provision_database(self.policy, credentials, run)
        combined = "\n".join(" ".join(command) for command, _input in commands)
        self.assertNotIn(credentials["BOOTSTRAP_PG_APP_PASSWORD"], combined)
        script = commands[0][1].decode()
        self.assertIn("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION", script)
        self.assertNotIn("ALTER ROLE", script)
        self.assertNotIn("DROP", script)
        self.assertIn("WHERE NOT EXISTS", script)
        self.assertNotIn(credentials["BOOTSTRAP_PG_APP_PASSWORD"], script)
        self.assertEqual(commands[1][0][-2:], ["--command", "\\password " + self.policy["database"]["user"]])

    def test_readonly_authentication_uses_project_network_not_localhost_trust(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if "bootstrap_role_verified" in " ".join(command):
                return b"bootstrap_role_verified\n"
            return self.policy["database"]["user"].encode() + b"\n"
        self.b.provision_database(self.policy, self.b.generate_credentials(self.spec), run, create=False)
        auth = calls[-1]
        self.assertEqual(auth[-3:], [self.policy["database"][k] for k in ("host", "user", "name")])
        self.assertIn('-h "$1" -U "$2" -d "$3"', auth[-5])
        self.assertNotIn("127.0.0.1", " ".join(auth))
        self.assertEqual(len(calls), 2, "只读重复检查不得重设密码或角色")

    def test_existing_compatible_engine_never_installs_or_upgrades_packages(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[-3:] == ["compose", "version", "--short"]:
                return b"2.39.4\n"
            return b"28.3.3\n"
        with mock.patch.object(self.b, "run", side_effect=run), \
             mock.patch.object(self.b, "binary_exists", return_value=True):
            self.b.ensure_docker(self.spec)
        self.assertFalse(any("apt-get" in " ".join(c) for c in calls))

    def test_missing_docker_requires_exact_approved_package_versions(self):
        with mock.patch.object(self.b, "binary_exists", return_value=False), \
             mock.patch.object(self.b, "run") as run:
            with self.assertRaises(self.b.BootstrapError):
                self.b.ensure_docker(self.spec)
        run.assert_not_called()

    def test_apt_install_waits_for_dpkg_lock_and_reports_only_its_fixed_stage(self):
        self.spec['docker_packages'] = {'docker.io': '28.2.2-0ubuntu1',
                                       'docker-compose-v2': '2.37.1+ds1-0ubuntu1', 'curl': '8.5.0-2ubuntu10'}
        calls = []
        def execute(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 100 if 'install' in command else 0,
                                               b'private command output', b'private credential in stderr')
        with mock.patch.object(self.b, 'binary_exists', return_value=False), \
             mock.patch.object(self.b.subprocess, 'run', side_effect=execute):
            with self.assertRaisesRegex(self.b.BootstrapError, '^apt_docker_install_failed$'):
                self.b.ensure_docker(self.spec)
        command, options = calls[-1]
        self.assertEqual(command[:4], ['/usr/bin/apt-get', '-o', 'DPkg::Lock::Timeout=120', 'install'])
        self.assertEqual(options['timeout'], 720)
        self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertEqual(sum('install' in command for command, _ in calls), 1)


if __name__ == "__main__":
    unittest.main()
