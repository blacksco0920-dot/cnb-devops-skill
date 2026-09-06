"""Behavioral tests for the generated, installed host-policy boundary."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


HOST_PATH = Path(__file__).parents[1] / "assets/cnb-tcr-tat/host/tat-deploy-test.py"


def load_host():
    spec = importlib.util.spec_from_file_location("bundle_host", HOST_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_policy(names=("api", "web")):
    services = {
        name: {
            "image_repository": f"registry.example.invalid/demo/sample-{name}",
            "image_env": f"SAMPLE_{name.upper()}_IMAGE",
            "container": f"sample-test-{name}",
            "networks": ["apps"],
            "environment": {},
            "environment_refs": {},
            "runtime_env": False,
            "healthcheck": False,
            "mounts": [],
        }
        for name in names
    }
    return {
        "schema": "cnb-devops-host-policy/v1",
        "project": "sample",
        "environment": "test",
        "controller_id": "sample-test-controller-v1",
        "install_dir": "/opt/cnb-devops/sample/test/v1",
        "release_user": "ubuntu",
        "release_home": "/home/ubuntu",
        "app_dir": "/opt/apps/sample-test",
        "docker_config": "/home/ubuntu/.docker/config.json",
        "recovery_root": "/opt/cnb-devops/sample/recovery",
        "compose_sha256": "a" * 64,
        "services": services,
        "networks": ["apps"],
        "required_env": ["DATABASE_URL"],
        "database": {
            "url_env": "DATABASE_URL",
            "host": "project-postgres",
            "port": 5432,
            "name": "sample_test",
            "user": "sample_test_user",
            "container": "project-postgres",
            "admin_user": "postgres",
        },
        "migration": {"service": names[0], "argv": ["python", "manage.py", "migrate"]},
        "availability_probes": ["https://sample.example.invalid/"],
        "identity_probes": [
            {"url": f"https://{name}.example.invalid/release.json", "service": name, "api_envelope": False}
            for name in names
        ],
    }


class HostPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = load_host()

    def setUp(self):
        self.policy = sample_policy()
        self.host.configure_policy(self.policy, policy_sha256="b" * 64)
        self.images = {
            name: service["image_repository"] + "@sha256:" + "1" * 64
            for name, service in self.policy["services"].items()
        }

    def request(self):
        return {
            "schema": "cnb-release-request/v1",
            "project": "sample",
            "environment": "test",
            "git_sha": "c" * 40,
            "controller": "sample-test-controller-v1",
            "controller_commit": "c" * 40,
            "build_id": "cnb-build-123",
            "images": self.images,
        }

    def script(self, request):
        raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
        prefix = self.host.render_tat_template(self.policy, self.host.controller_program_sha256(), "b" * 64)
        return prefix.replace(b"{{release_request_b64url}}", base64.urlsafe_b64encode(raw).rstrip(b"="))

    def test_two_different_service_sets_use_unchanged_controller(self):
        original = HOST_PATH.read_bytes()
        for names in (("api", "web"), ("gateway", "catalog", "console")):
            policy = sample_policy(names)
            self.host.configure_policy(policy, policy_sha256="b" * 64)
            self.assertEqual(set(self.host.SERVICES), set(names))
            for name in names:
                immutable = policy["services"][name]["image_repository"] + "@sha256:" + "1" * 64
                self.assertEqual(self.host.validate_image(name, immutable), immutable)
                with self.assertRaises(ValueError):
                    self.host.validate_image(name, immutable.replace("@sha256:" + "1" * 64, ":latest"))
            self.assertEqual(len(self.host.PUBLIC_PROBES), len(names) + 1)
        self.assertEqual(HOST_PATH.read_bytes(), original)

    def test_canonical_request_binds_project_environment_and_exact_images(self):
        parsed = self.host.parse_tat_release_script(self.script(self.request()))
        self.assertEqual(parsed["git_sha"], "c" * 40)
        self.assertEqual(parsed["controller_commit"], "c" * 40)
        self.assertEqual(parsed["images"], self.images)
        for field, value in (("project", "other"), ("environment", "production"),
                             ("controller_commit", "d" * 7), ("git_sha", "main")):
            bad = self.request()
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(self.host.DeploymentError):
                self.host.parse_tat_release_script(self.script(bad))
        for extra in ("command", "target", "policy", "path", "application_commit"):
            bad = self.request()
            bad[extra] = "untrusted"
            with self.subTest(extra=extra), self.assertRaises(self.host.DeploymentError):
                self.host.parse_tat_release_script(self.script(bad))
        for replacement in ({"api": self.images["api"]}, {**self.images, "extra": self.images["api"]},
                            {**self.images, "web": self.images["api"]}):
            bad = self.request()
            bad["images"] = replacement
            with self.assertRaises(self.host.DeploymentError):
                self.host.parse_tat_release_script(self.script(bad))

    def test_template_policy_and_controller_tampering_are_rejected(self):
        template = HOST_PATH.with_name("tat-command.sh.tmpl").read_bytes()
        self.assertEqual(template, self.host.TAT_TEMPLATE.encode("ascii"))
        valid = self.script(self.request())
        for old, new in ((b"b" * 64, b"e" * 64),
                         (self.host.controller_program_sha256().encode(), b"f" * 64),
                         (b"--tat-script", b"--policy"),
                         (b"/opt/cnb-devops/sample/test/v1", b"/tmp/alternate")):
            with self.subTest(old=old[:20]), self.assertRaises(self.host.DeploymentError):
                self.host.parse_tat_release_script(valid.replace(old, new))

    def test_request_capacity_supports_sixteen_services_and_stays_bounded(self):
        policy = sample_policy(tuple(f"role{i}" for i in range(16)))
        self.host.configure_policy(policy, policy_sha256="b" * 64)
        request = self.request()
        request["images"] = {name: spec["image_repository"] + "@sha256:" + "1" * 64
                             for name, spec in policy["services"].items()}
        raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        template = self.host.render_tat_template(policy, self.host.controller_program_sha256(), "b" * 64)
        script = template.replace(b"{{release_request_b64url}}", base64.urlsafe_b64encode(raw).rstrip(b"="))
        self.assertEqual(self.host.parse_tat_release_script(script)["images"], request["images"])
        with self.assertRaises(self.host.DeploymentError):
            self.host.parse_tat_release_script(template.replace(b"{{release_request_b64url}}", b"a" * 16385))

    def test_database_binding_is_policy_derived_and_cannot_change_target(self):
        url = "postgresql://sample_test_user:password@project-postgres:5432/sample_test"
        self.assertEqual(self.host.parse_test_database_url(url)["database"], "sample_test")
        for old, new in (("sample_test_user", "postgres"), ("project-postgres", "other"),
                         ("/sample_test", "/other"), ("5432", "5433")):
            with self.assertRaises(ValueError):
                self.host.parse_test_database_url(url.replace(old, new))

    def test_policy_rejects_unsafe_paths_duplicate_roles_and_invalid_migration(self):
        for key, value in (("install_dir", "/opt/x/../escape"), ("app_dir", "/tmp/app"),
                           ("release_user", "ubuntu;id"), ("environment", "production")):
            bad = copy.deepcopy(self.policy)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(self.host.DeploymentError):
                self.host.configure_policy(bad)
        for mutation in (
            lambda p: p["services"]["web"].update(image_env=p["services"]["api"]["image_env"]),
            lambda p: p.update(migration={"service": "unknown", "argv": ["true"]}),
            lambda p: p.update(migration={"service": "api", "argv": []}),
            lambda p: p["database"].update(name="x;id"),
            lambda p: p["identity_probes"].pop(),
        ):
            bad = copy.deepcopy(self.policy)
            mutation(bad)
            with self.assertRaises(self.host.DeploymentError):
                self.host.configure_policy(bad)

    def test_policy_reader_rejects_symlinks_and_writable_or_nonroot_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "host-policy.json"
            target.write_text(json.dumps(self.policy))
            target.chmod(0o444)
            alias = Path(temporary) / "alias.json"
            alias.symlink_to(target)
            for path in (target, alias):
                with self.assertRaises(self.host.DeploymentError):
                    self.host.read_root_owned_policy(path)

    def test_trusted_policy_read_ignores_access_time_but_binds_exact_bytes(self):
        # Only fake root ownership/ancestor permissions; contents and descriptors are real.
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / "host-policy.json"
            raw = json.dumps(self.policy).encode()
            target.write_bytes(raw)
            target.chmod(0o444)
            os.utime(target, (1, 1))
            actual_fstat, actual_stat = os.fstat, os.stat

            def trusted(info):
                fields = list(info)
                fields[0] &= ~0o022
                fields[4] = fields[5] = 0
                return os.stat_result(fields)

            with mock.patch.object(self.host.os, "fstat", side_effect=lambda fd: trusted(actual_fstat(fd))), \
                 mock.patch.object(self.host.os, "stat", side_effect=lambda *a, **k: trusted(actual_stat(*a, **k))):
                policy, digest = self.host.read_root_owned_policy(target)
            self.assertEqual(policy, self.policy)
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_compose_contract_uses_declared_roles_environment_and_mounts(self):
        self.policy["services"]["api"]["runtime_env"] = True
        self.policy["services"]["web"]["environment"] = {"API_HOST": "sample-test-api"}
        self.host.configure_policy(self.policy, policy_sha256="b" * 64)
        runtime = {"DATABASE_URL": "postgresql://sample_test_user:p@project-postgres:5432/sample_test"}
        runtime.update({spec["image_env"]: self.images[name] for name, spec in self.policy["services"].items()})
        model = {"name": "sample-test", "networks": {"apps": {"name": "apps", "external": True}}, "services": {}}
        for name, approved in self.policy["services"].items():
            model["services"][name] = {
                "image": self.images[name], "container_name": approved["container"], "networks": {"apps": None},
                "environment": runtime if approved["runtime_env"] else approved["environment"],
            }
        self.assertEqual(self.host.validate_compose_model(model, self.images, runtime), model)
        for mutation in (
            lambda p: p["services"]["api"].update(privileged=True),
            lambda p: p["services"]["web"].update(ports=[{"published": "80", "target": 80}]),
            lambda p: p["services"]["api"].update(volumes=[{"type": "bind", "source": "/var/run/docker.sock", "target": "/docker.sock"}]),
            lambda p: p["services"]["api"].update(environment={}),
            lambda p: p["services"].pop("web"),
            lambda p: p["networks"]["apps"].update(external=False),
        ):
            bad = copy.deepcopy(model)
            mutation(bad)
            with self.assertRaises(self.host.DeploymentError):
                self.host.validate_compose_model(bad, self.images, runtime)

    def test_identity_mismatch_never_becomes_availability_success(self):
        identity = {"build_id": "cnb-build-123", "git_sha": "c" * 40,
                    "schema": "cnb-release-identity/v1", "service": "api"}
        raw = json.dumps(identity).encode()
        self.assertEqual(self.host.validate_public_release_identity("api", raw, "c" * 40, "cnb-build-123"), identity)
        for mutation in (dict(identity, git_sha="e" * 40), dict(identity, service="web"),
                         dict(identity, extra=True), dict(identity, schema="other/v1")):
            with self.assertRaises(self.host.DeploymentError):
                self.host.validate_public_release_identity("api", json.dumps(mutation).encode(), "c" * 40, "cnb-build-123")
        with mock.patch.object(self.host, "_fetch_public_release_identity", return_value=b"{}") as fetch, \
             mock.patch.object(self.host, "_run", return_value=b""), mock.patch.object(self.host.time, "sleep") as sleep:
            with self.assertRaisesRegex(self.host.DeploymentError, "release_identity_mismatch"):
                self.host._probe_public_urls("c" * 40, "cnb-build-123")
        self.assertEqual(fetch.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
