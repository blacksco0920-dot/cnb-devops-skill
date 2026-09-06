"""Fixed loopback publication remains bound through config, Compose and Docker inspect."""
import copy
import json
import unittest
from unittest import mock

import jsonschema

from test_bundle_host_policy import load_host
import test_bundle_storage_config as storage_tests


class LoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage_tests.StorageConfigTests.setUpClass()

    def fixture(self, count=3):
        storage = storage_tests.StorageConfigTests()
        config = storage.config(count)
        for index, service in enumerate(config["services"].values()):
            service.update(loopback_port=(13000, 13080, 18001)[index], expose=[(3000, 80, 8000)[index]],
                           runtime_env=False, environment={}, environment_refs={})
        policy, compose = storage.policy(config)
        host = load_host(); host.configure_policy(policy, policy_sha256="a" * 64)
        images = {name: spec["image_repository"] + "@sha256:" + "1" * 64
                  for name, spec in policy["services"].items()}
        for name in images:
            compose["services"][name]["image"] = images[name]
        return config, policy, compose, host, images

    def test_one_and_three_service_publications_bind_exact_loopback_and_target(self):
        for count in (1, 3):
            config, policy, compose, host, images = self.fixture(count)
            for name, spec in config["services"].items():
                port = {"host_ip": "127.0.0.1", "protocol": "tcp", "published": spec["loopback_port"],
                        "target": spec["expose"][0]}
                self.assertEqual(port, policy["services"][name]["loopback_port"])
                self.assertEqual([dict(port, published=str(port["published"]))], compose["services"][name]["ports"])
            self.assertEqual(compose, host.validate_compose_model(compose, images, {}))
            # Compose's normalized local long form may add this fixed mode.
            compose["services"]["app0"]["ports"][0]["mode"] = "ingress"
            host.validate_compose_model(compose, images, {})

    def test_config_requires_bounded_published_and_one_exposed_target(self):
        storage = storage_tests.StorageConfigTests()
        for value in (1023, 65536, True, "13000"):
            config = storage.config()
            config["services"]["app0"].update(loopback_port=value, expose=[3000])
            with self.subTest(value=value), self.assertRaises(jsonschema.ValidationError):
                storage.validator.validate(config)
        for expose in (None, [], [3000, 3001]):
            config = storage.config()
            config["services"]["app0"]["loopback_port"] = 13000
            if expose is None:
                config["services"]["app0"].pop("expose", None)
            else:
                config["services"]["app0"]["expose"] = expose
            with self.subTest(expose=expose), self.assertRaises(jsonschema.ValidationError):
                storage.validator.validate(config)

    def test_policy_rejects_wildcard_extra_or_duplicate_publication(self):
        _config, policy, _compose, host, _images = self.fixture()
        for field, value in (("host_ip", "0.0.0.0"), ("protocol", "udp"), ("published", 80),
                             ("target", 0), ("command", "ignored")):
            bad = copy.deepcopy(policy)
            bad["services"]["app0"]["loopback_port"][field] = value
            with self.subTest(field=field), self.assertRaises(host.DeploymentError):
                host.validate_host_policy(bad)
        policy["services"]["app1"]["loopback_port"]["published"] = 13000
        with self.assertRaises(host.DeploymentError):
            host.validate_host_policy(policy)

    def test_compose_cannot_add_or_change_port_bindings(self):
        _config, _policy, compose, host, images = self.fixture()
        for field, value in (("host_ip", "0.0.0.0"), ("protocol", "udp"), ("published", "18000"),
                             ("target", 3001), ("mode", "host")):
            bad = copy.deepcopy(compose)
            bad["services"]["app0"]["ports"][0][field] = value
            with self.subTest(field=field), self.assertRaises(host.DeploymentError):
                host.validate_compose_model(bad, images, {})
        for ports in ([], [*compose["services"]["app0"]["ports"]] * 2):
            bad = copy.deepcopy(compose); bad["services"]["app0"]["ports"] = ports
            with self.assertRaises(host.DeploymentError):
                host.validate_compose_model(bad, images, {})

    def test_runtime_inspect_rejects_wrong_extra_and_public_bindings(self):
        _config, _policy, _compose, host, _images = self.fixture(1)
        good = {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13000"}], "1234/tcp": None}
        host.validate_runtime_loopback("app0", good)
        for bad in ({}, {"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "13000"}]},
                    {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13001"}]},
                    {**good, "9999/tcp": [{"HostIp": "127.0.0.1", "HostPort": "19999"}]},
                    {"3000/tcp": good["3000/tcp"] * 2}):
            with self.subTest(bad=bad), self.assertRaises(host.DeploymentError):
                host.validate_runtime_loopback("app0", bad)

    def test_runtime_wait_reads_actual_port_mapping(self):
        _config, _policy, _compose, host, images = self.fixture(1)
        def inspect(args, **_kwargs):
            expression = args[-2]
            if expression == "{{json .State.Running}}": return b"true"
            if expression == "{{json .Config.Image}}": return json.dumps(images["app0"]).encode()
            if expression == "{{json .NetworkSettings.Ports}}":
                return b'{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"13000"}]}'
            return b'"healthy"'
        with mock.patch.object(host, "_run", side_effect=inspect) as run:
            host._wait_for_runtime(images)
        self.assertTrue(any("{{json .NetworkSettings.Ports}}" in call.args[0] for call in run.call_args_list))


if __name__ == "__main__":
    unittest.main()
