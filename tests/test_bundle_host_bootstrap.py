"""Bounded first-host preset; Docker, apt and root effects are simulated explicitly."""
import copy
import hashlib
import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
