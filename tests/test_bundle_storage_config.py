"""Project storage declarations reach the existing fixed Compose/host boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

import jsonschema
import yaml

from test_bundle_host_policy import load_host
from test_bundle_host_installer import load_installer

ASSETS = Path(__file__).resolve().parents[1] / "assets/cnb-tcr-tat"


class StorageConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = load_host()
        cls.validator = jsonschema.Draft202012Validator(json.loads((ASSETS / "project.schema.json").read_bytes()))
        spec = importlib.util.spec_from_file_location("storage_render", ASSETS / "templates/render.py")
        cls.render = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.render)

    def config(self, count=1):
        config = yaml.safe_load((ASSETS / "project.example.yml").read_bytes())
        config["project"] = "sample"
        template = next(iter(config["services"].values()))
        config["services"] = {f"app{i}": copy.deepcopy(template) for i in range(count)}
        for name, service in config["services"].items():
            service["image_repository"] = f"ccr.ccs.tencentyun.com/example-team/sample-{name}"
            service["mounts"] = [{"source": f"uploads-{name}", "target": "/app/uploads"}]
        config["host"]["migration"] = None
        config["host"]["identity_probes"] = [
            {"service": name, "url": f"https://{name}.example.test/release.json", "api_envelope": False}
            for name in config["services"]]
        config["host"]["required_env"].append("REDIS_URL")
        config["host"]["redis"] = {"url_env": "REDIS_URL", "host": "sample-test-redis",
            "port": 6379, "database": 0, "container": "sample-test-redis"}
        return config

    def policy(self, config):
        self.validator.validate(config)
        policy, _ci, compose = self.render.model(config, "a" * 64)
        self.host.validate_host_policy(policy)
        return policy, yaml.safe_load(compose)

    def test_one_and_three_service_mounts_and_dedicated_redis_reach_fixed_policy(self):
        for count in (1, 3):
            with self.subTest(count=count):
                config = self.config(count)
                policy, compose = self.policy(config)
                self.assertEqual(policy["redis"], config["host"]["redis"])
                self.assertNotIn("REDIS_PREFIX", policy["required_env"])
                for name in config["services"]:
                    expected = [{"type": "bind", "source": f"/opt/apps/sample-test/uploads-{name}",
                                 "target": "/app/uploads"}]
                    self.assertEqual(expected, policy["services"][name]["mounts"])
                    self.assertEqual(expected, compose["services"][name]["volumes"])

    def test_mount_escape_noncanonical_duplicate_target_and_unknown_fields_are_rejected(self):
        for source in ("../outside", "/tmp/data", ".", "a/../b", "a//b", "a/./b", "a/", "a\\b", "uploads/api"):
            config = self.config()
            config["services"]["app0"]["mounts"][0]["source"] = source
            with self.subTest(source=source), self.assertRaises(jsonschema.ValidationError):
                self.validator.validate(config)
        for key, value in (("target", "/app/../etc"), ("read_only", True)):
            config = self.config()
            config["services"]["app0"]["mounts"][0][key] = value
            with self.subTest(key=key), self.assertRaises(jsonschema.ValidationError):
                self.validator.validate(config)
        config = self.config()
        config["services"]["app0"]["mounts"].append({"source": "models", "target": "/app/uploads"})
        with self.assertRaises(self.host.DeploymentError):
            self.policy(config)

    def test_dedicated_redis_rejects_shared_identity_wrong_db_and_half_prefix_pair(self):
        for field, value in (("host", "shared-redis"), ("container", "shared-redis"),
                             ("database", 1), ("prefix_env", "REDIS_PREFIX"), ("prefix", "sample-test:"),
                             ("command", "redis-server")):
            config = self.config()
            config["host"]["redis"][field] = value
            with self.subTest(field=field), self.assertRaises((self.host.DeploymentError, jsonschema.ValidationError)):
                self.policy(config)

    def test_dedicated_url_and_shared_prefix_runtime_contract(self):
        for shared in (False, True):
            config = self.config()
            if shared:
                config["host"]["required_env"].append("REDIS_PREFIX")
                config["host"]["redis"].update(host="shared-redis", container="shared-redis", database=2,
                                               prefix_env="REDIS_PREFIX", prefix="sample-test:")
            policy, _compose = self.policy(config)
            host = load_host(); host.configure_policy(policy, policy_sha256="b" * 64)
            redis = policy["redis"]
            url = f"redis://:synthetic@{redis['host']}:6379/{redis['database']}"
            self.assertEqual({"database": redis["database"]}, host.parse_test_redis_url(url))
            for bad in (url.replace(redis["host"], "other-redis"), url + "?db=1", url[:-1] + "9"):
                with self.assertRaises(ValueError):
                    host.parse_test_redis_url(bad)
            if shared:
                self.assertEqual("sample-test:", host.validate_test_redis_prefix("sample-test:"))
                with self.assertRaises(ValueError):
                    host.validate_test_redis_prefix("other-test:")
            # The actual installer consumes no invented prefix in the dedicated profile.
            values = {key: "synthetic" for key in policy["required_env"]}
            db = policy["database"]
            values[db["url_env"]] = f"postgresql://{db['user']}:synthetic@{db['host']}:{db['port']}/{db['name']}"
            values[redis["url_env"]] = url
            if shared:
                values[redis["prefix_env"]] = redis["prefix"]
            raw = "".join(f"{key}={value}\n" for key, value in values.items()).encode()
            result = load_installer().prepare_runtime_env(host, raw)
            self.assertEqual("REDIS_PREFIX=" in result.decode(), shared)

    def test_bounded_startup_wait_and_healthcheck_start_period(self):
        config = self.config()
        config["services"]["app0"]["healthcheck"]["start_period"] = "10m"
        config["host"]["startup_timeout_seconds"] = 900
        policy, compose = self.policy(config)
        self.assertEqual(900, policy["startup_timeout_seconds"])
        self.assertEqual("10m", compose["services"]["app0"]["healthcheck"]["start_period"])
        for value in (0, 1201, True, "900"):
            config["host"]["startup_timeout_seconds"] = value
            with self.subTest(timeout=value), self.assertRaises(jsonschema.ValidationError):
                self.validator.validate(config)
            bad_policy = copy.deepcopy(policy)
            bad_policy["startup_timeout_seconds"] = value
            with self.assertRaises(self.host.DeploymentError):
                self.host.validate_host_policy(bad_policy)
        for value in ("10", "10m;true", "-1s"):
            config["host"]["startup_timeout_seconds"] = 900
            config["services"]["app0"]["healthcheck"]["start_period"] = value
            with self.subTest(start_period=value), self.assertRaises(jsonschema.ValidationError):
                self.validator.validate(config)

    def test_runtime_wait_uses_configured_timeout_without_changing_default(self):
        for timeout, succeeds in ((None, False), (900, True)):
            config = self.config()
            if timeout is not None:
                config["host"]["startup_timeout_seconds"] = timeout
            policy, _compose = self.policy(config)
            host = load_host(); host.configure_policy(policy, policy_sha256="b" * 64)
            images = {name: spec["image_repository"] + "@sha256:" + "1" * 64
                      for name, spec in policy["services"].items()}
            clock = [0]
            def sleep(seconds):
                clock[0] += seconds
            def inspect(args, **_kwargs):
                if args[-2] == "{{json .State.Running}}":
                    return b"true" if clock[0] >= 400 else b"false"
                if args[-2] == "{{json .Config.Image}}":
                    return json.dumps(images["app0"]).encode()
                return b'"healthy"'
            with mock.patch.object(host.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(host.time, "sleep", side_effect=sleep), \
                 mock.patch.object(host, "_run", side_effect=inspect):
                if succeeds:
                    host._wait_for_runtime(images)
                    self.assertEqual(400, clock[0])
                else:
                    with self.assertRaises(host.DeploymentError):
                        host._wait_for_runtime(images)
                    self.assertEqual(300, clock[0])


if __name__ == "__main__":
    unittest.main()
