#!/usr/bin/env python3
"""Contract tests for the bounded, read-only Docker host inventory."""

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "inspect_docker_host.py"
QUICK_VALIDATE_PATH = Path(__file__).resolve().parent / "quick_validate.py"


def load_module():
    spec = importlib.util.spec_from_file_location("docker_host_inventory", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def load_quick_validate():
    spec = importlib.util.spec_from_file_location("quick_validate", QUICK_VALIDATE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def container(index):
    identifier = f"{index:064x}"
    return {
        "Id": identifier,
        "Image": "sha256:" + f"{index + 1000:064x}",
        "RepoDigests": [f"example.invalid/image{index}@sha256:{index + 2000:064x}"],
        "Config": {
            "Env": ["SECRET=do-not-emit"],
            "Labels": {
                "com.docker.compose.project": "public-project",
                "com.docker.compose.service": "web",
                "deployment.example/id": "release-1",
                "private.label": "never-emit",
            },
        },
        "NetworkSettings": {"Networks": {"public_network": {"NetworkID": "n" * 64}}},
        "Mounts": [],
    }


class FakeRunner:
    def __init__(self, containers, *, containers_after=None, volumes=None, volumes_after=None,
                 networks=None, networks_after=None, diffs=None):
        self.calls = []
        self.containers = containers
        self.containers_after = containers if containers_after is None else containers_after
        self.volumes = volumes or []
        self.volumes_after = self.volumes if volumes_after is None else volumes_after
        self.networks = networks or []
        self.networks_after = self.networks if networks_after is None else networks_after
        self.diffs = diffs or {}
        self._container_ps_calls = 0
        self._volume_ls_calls = 0
        self._network_ls_calls = 0

    @staticmethod
    def _json(value):
        return json.dumps(value, separators=(",", ":"))

    def run(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[-3:] == ("ps", "-aq", "--no-trunc"):
            self._container_ps_calls += 1
            records = self.containers if self._container_ps_calls == 1 else self.containers_after
            return "\n".join(item["Id"] for item in records) + ("\n" if records else "")
        if len(argv) >= 3 and argv[-2:] == ("volume", "ls"):
            raise AssertionError("collector must request untruncated volume IDs")
        if argv[-4:] == ("volume", "ls", "-q", "--no-trunc"):
            self._volume_ls_calls += 1
            records = self.volumes if self._volume_ls_calls == 1 else self.volumes_after
            return "\n".join(item["Name"] for item in records) + ("\n" if records else "")
        if argv[-4:] == ("network", "ls", "-q", "--no-trunc"):
            self._network_ls_calls += 1
            records = self.networks if self._network_ls_calls == 1 else self.networks_after
            return "\n".join(item["Id"] for item in records) + ("\n" if records else "")
        if "inspect" in argv:
            identifiers = argv[argv.index("inspect") + 1:]
            source = self.containers
            if identifiers and identifiers[0] in {item["Name"] for item in self.volumes}:
                source = self.volumes
            elif identifiers and identifiers[0] in {item["Id"] for item in self.networks}:
                source = self.networks
            return self._json([item for item in source if item.get("Id", item.get("Name")) in identifiers or item.get("Name") in identifiers])
        if len(argv) >= 3 and argv[-2] == "diff":
            return self.diffs.get(argv[-1], "")
        raise AssertionError(f"unexpected argv: {argv!r}")


class DockerHostInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = load_module()
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.request = self.inventory.InventoryRequest(
            schema_version="deploydesk-docker-host-inventory-request/v1",
            docker_command=("/usr/bin/docker",),
            docker_config_path="/etc/docker",
            docker_socket_path="/var/run/docker.sock",
            observed_roots=(str(root), str(root / "opt"), str(root / "var-lib")),
            max_containers=80,
            max_volumes=20,
            max_networks=20,
            max_output_bytes=1_000_000,
            expected_caddy_paths=("/etc/caddy/Caddyfile",),
        )
        (root / "opt").mkdir()
        (root / "var-lib").mkdir()
        self.runner = FakeRunner([container(index) for index in range(70)])

    def tearDown(self):
        self.tempdir.cleanup()

    def test_inventory_is_complete_secret_free_and_identity_bound(self):
        value = self.inventory.collect_inventory(self.request, self.runner)
        self.assertTrue(value["complete"])
        self.assertEqual(70, value["container_count"])
        self.assertEqual(
            sorted(item["id"] for item in value["containers"]),
            value["deletion_vector"],
        )
        raw = self.inventory.canonical_bytes(value)
        self.assertNotIn(b"Env", raw)
        self.assertNotIn(b"Secret", raw)
        self.assertEqual(self.inventory.identity_sha256(value), hashlib.sha256(raw).hexdigest())
        self.assertEqual(value, self.inventory.validate_inventory(value))
        self.assertTrue(all(isinstance(argument, tuple) for argument in self.runner.calls))

    def test_rejects_changed_enumerations(self):
        changes = (
            ("container", FakeRunner([container(1)], containers_after=[container(2)])),
            ("volume", FakeRunner([], volumes=[{"Name": "named", "Driver": "local"}], volumes_after=[])),
            ("network", FakeRunner([], networks=[{"Id": "a" * 64, "Name": "bridge"}], networks_after=[])),
        )
        for kind, runner in changes:
            with self.subTest(kind=kind), self.assertRaisesRegex(self.inventory.InventoryError, kind + " inventory changed"):
                self.inventory.collect_inventory(self.request, runner)

    def test_rejects_duplicate_or_short_identifiers_and_missing_repo_digests(self):
        duplicate = container(1)
        with self.assertRaisesRegex(self.inventory.InventoryError, "duplicate"):
            self.inventory.collect_inventory(self.request, FakeRunner([duplicate, copy.deepcopy(duplicate)]))
        with self.assertRaisesRegex(self.inventory.InventoryError, "invalid container id"):
            self.inventory.collect_inventory(self.request, FakeRunner([dict(container(1), Id="short")]))
        missing = container(1)
        del missing["RepoDigests"]
        with self.assertRaisesRegex(self.inventory.InventoryError, "RepoDigests"):
            self.inventory.collect_inventory(self.request, FakeRunner([missing]))

    def test_excludes_arbitrary_labels_and_environment(self):
        value = self.inventory.collect_inventory(self.request, FakeRunner([container(1)]))
        record = value["containers"][0]
        self.assertEqual({"com.docker.compose.project", "com.docker.compose.service", "deployment.example/id"}, set(record["labels"]))
        raw = self.inventory.canonical_bytes(value)
        self.assertNotIn(b"private.label", raw)
        self.assertNotIn(b"never-emit", raw)
        self.assertNotIn(b"SECRET=", raw)

    def test_rejects_output_limit_and_unsafe_request_paths(self):
        limited = self.request.__class__(**{**self.request.__dict__, "max_output_bytes": 64})
        with self.assertRaisesRegex(self.inventory.InventoryError, "output limit"):
            self.inventory.collect_inventory(limited, FakeRunner([container(1)]))
        for field, value in (("docker_command", ("docker",)), ("docker_config_path", "relative"), ("docker_socket_path", "/tmp/docker.sock")):
            raw = {**self.request.__dict__, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(self.inventory.InventoryError, "unsafe"):
                self.inventory.InventoryRequest(**raw)

    def test_request_file_must_be_canonical_regular_and_not_a_symlink(self):
        payload = self.inventory.canonical_bytes(self.request.__dict__)
        request_file = Path(self.tempdir.name) / "request.json"
        request_file.write_bytes(payload)
        self.assertEqual(self.request, self.inventory.read_request_file(request_file, hashlib.sha256(payload).hexdigest(), require_root=False))
        request_file.write_bytes(b'{"schema_version":"deploydesk-docker-host-inventory-request/v1", "docker_command":[]}\n')
        with self.assertRaisesRegex(self.inventory.InventoryError, "canonical"):
            self.inventory.read_request_file(request_file, hashlib.sha256(request_file.read_bytes()).hexdigest(), require_root=False)
        request_file.unlink()
        request_file.symlink_to(Path(self.tempdir.name) / "missing")
        with self.assertRaisesRegex(self.inventory.InventoryError, "symlink"):
            self.inventory.read_request_file(request_file, "0" * 64, require_root=False)

    def test_persistence_and_capacity_evidence(self):
        bind = Path(self.tempdir.name) / "bind"
        bind.mkdir()
        item = container(1)
        item["Mounts"] = [
            {"Type": "volume", "Name": "named-volume", "Destination": "/data", "RW": True, "Driver": "local"},
            {"Type": "volume", "Name": "a" * 64, "Destination": "/cache", "RW": True, "Driver": "local"},
            {"Type": "bind", "Source": str(bind), "Destination": "/host", "RW": False, "Mode": "ro,z,opaque=value"},
            {"Type": "tmpfs", "Destination": "/tmp", "RW": True, "TmpfsOptions": {"SizeBytes": 1234}},
        ]
        value = self.inventory.collect_inventory(self.request, FakeRunner([item], diffs={item["Id"]: "A /changed\nC /another\n"}))
        mounts = value["containers"][0]["mounts"]
        self.assertEqual(["anonymous_volume", "bind", "named_volume", "tmpfs"], sorted(record["kind"] for record in mounts))
        bind_record = next(record for record in mounts if record["kind"] == "bind")
        self.assertEqual({"kind", "destination", "read_only", "device", "inode", "ctime_ns", "mode", "uid", "gid", "options_sha256"}, set(bind_record))
        self.assertRegex(bind_record["options_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual({"count", "sha256"}, set(value["containers"][0]["writable_layer"]))
        self.assertEqual(1, len(value["filesystems"]))

    def test_cli_requires_root_for_host_metadata(self):
        with mock.patch.object(self.inventory.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(self.inventory.InventoryError, "root"):
                self.inventory.require_root()

    def test_rejects_unknown_nested_inventory_field(self):
        value = self.inventory.collect_inventory(self.request, FakeRunner([container(1)]))
        value["containers"][0]["Env"] = ["SECRET=do-not-emit"]
        with self.assertRaisesRegex(self.inventory.InventoryError, "container record"):
            self.inventory.validate_inventory(value)

    def test_quick_validator_compiles_inventory_script(self):
        quick_validate = load_quick_validate()
        self.assertEqual((True, "Docker inventory script is valid!"), quick_validate.validate_docker_inventory_script(MODULE_PATH))


if __name__ == "__main__":
    unittest.main()
