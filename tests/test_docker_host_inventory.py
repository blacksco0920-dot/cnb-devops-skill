#!/usr/bin/env python3
"""Contract tests for the bounded, read-only Docker host inventory."""

import copy
import hashlib
import io
import importlib.util
import json
import os
import stat
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
                 networks=None, networks_after=None, diffs=None, containers_final=None,
                 volumes_final=None, networks_final=None):
        self.calls = []
        self.containers = containers
        self.containers_after = containers if containers_after is None else containers_after
        self.volumes = volumes or []
        self.volumes_after = self.volumes if volumes_after is None else volumes_after
        self.networks = networks or []
        self.networks_after = self.networks if networks_after is None else networks_after
        self.containers_final = self.containers_after if containers_final is None else containers_final
        self.volumes_final = self.volumes_after if volumes_final is None else volumes_final
        self.networks_final = self.networks_after if networks_final is None else networks_final
        self.diffs = diffs or {}
        self._container_ps_calls = 0
        self._volume_ls_calls = 0
        self._network_ls_calls = 0

    @staticmethod
    def _json(value):
        return json.dumps(value, separators=(",", ":"))

    def run(self, argv, *, max_output_bytes):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[-3:] == ("ps", "-aq", "--no-trunc"):
            self._container_ps_calls += 1
            records = (self.containers if self._container_ps_calls == 1 else self.containers_after
                       if self._container_ps_calls == 2 else self.containers_final)
            return "\n".join(item["Id"] for item in records) + ("\n" if records else "")
        if len(argv) >= 3 and argv[-2:] == ("volume", "ls"):
            raise AssertionError("collector must request untruncated volume IDs")
        if argv[-4:] == ("volume", "ls", "-q", "--no-trunc"):
            self._volume_ls_calls += 1
            records = (self.volumes if self._volume_ls_calls == 1 else self.volumes_after
                       if self._volume_ls_calls == 2 else self.volumes_final)
            return "\n".join(item["Name"] for item in records) + ("\n" if records else "")
        if argv[-4:] == ("network", "ls", "-q", "--no-trunc"):
            self._network_ls_calls += 1
            records = (self.networks if self._network_ls_calls == 1 else self.networks_after
                       if self._network_ls_calls == 2 else self.networks_final)
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
        self.request = self.inventory.InventoryRequest(
            schema_version="deploydesk-docker-host-inventory-request/v1",
            docker_command=("/usr/bin/docker",),
            docker_config_path="/etc/docker",
            docker_socket_path="/var/run/docker.sock",
            observed_roots=("/", "/opt", "/var/lib"),
            max_containers=80,
            max_volumes=20,
            max_networks=20,
            max_output_bytes=1_000_000,
            expected_caddy_paths=("/etc/caddy/Caddyfile",),
        )
        self.filesystem_records = mock.patch.object(self.inventory, "_filesystem_records", return_value=[{
            "device": 1, "capacity_bytes": 100, "available_bytes": 50, "apparent_size_bytes": 0,
        }])
        self.filesystem_records.start()
        self.runner = FakeRunner([container(index) for index in range(70)])

    def tearDown(self):
        self.filesystem_records.stop()
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
        self.assertEqual(["com.docker.compose.project", "com.docker.compose.service", "deployment.example/id"], record["labels"])
        raw = self.inventory.canonical_bytes(value)
        self.assertNotIn(b"private.label", raw)
        self.assertNotIn(b"never-emit", raw)
        self.assertNotIn(b"SECRET=", raw)

    def test_rejects_unvetted_or_argument_bearing_docker_commands(self):
        for command in (("/bin/sh", "-c", "echo unsafe"), ("/usr/bin/docker", "container", "rm")):
            with self.subTest(command=command), self.assertRaisesRegex(self.inventory.InventoryError, "unsafe docker command"):
                self.inventory.InventoryRequest(**{**self.request.__dict__, "docker_command": command})

    def test_allowed_label_values_are_not_emitted(self):
        item = container(1)
        item["Config"]["Labels"]["com.docker.compose.project"] = "token=AKIA1234567890;uin=123456789;10.0.0.7"
        value = self.inventory.collect_inventory(self.request, FakeRunner([item]))
        self.assertEqual(["com.docker.compose.project", "com.docker.compose.service", "deployment.example/id"], value["containers"][0]["labels"])
        raw = self.inventory.canonical_bytes(value)
        self.assertNotIn(b"AKIA", raw)
        self.assertNotIn(b"123456789", raw)
        self.assertNotIn(b"10.0.0.7", raw)

    def test_rejects_output_limit_and_unsafe_request_paths(self):
        limited = self.request.__class__(**{**self.request.__dict__, "max_output_bytes": 64})
        with self.assertRaisesRegex(self.inventory.InventoryError, "output limit"):
            self.inventory.collect_inventory(limited, FakeRunner([container(1)]))
        for field, value in (("docker_command", ("docker",)), ("docker_config_path", "relative"), ("docker_socket_path", "/tmp/docker.sock")):
            raw = {**self.request.__dict__, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(self.inventory.InventoryError, "unsafe"):
                self.inventory.InventoryRequest(**raw)

    def test_enforces_exact_ordered_capacity_roots(self):
        for roots in (("/opt", "/", "/var/lib"), ("/", "/opt"), ("/", "/opt", "/var/lib", "/srv")):
            with self.subTest(roots=roots), self.assertRaisesRegex(self.inventory.InventoryError, "observed roots"):
                self.inventory.InventoryRequest(**{**self.request.__dict__, "observed_roots": roots})

    def test_filesystem_evidence_separates_devices_and_does_not_cross_mounts(self):
        self.filesystem_records.stop()
        def facts(device, size=0):
            return mock.Mock(st_dev=device, st_ino=size + 100, st_size=size, st_mode=stat.S_IFDIR,
                             st_ctime_ns=0, st_uid=0, st_gid=0)

        root_facts = {"/": facts(1), "/opt": facts(2), "/var/lib": facts(1),
                      "/root-file": facts(1, 5), "/opt/opt-file": facts(2, 7),
                      "/var/lib/var-file": facts(1, 11)}
        for path in ("/root-file", "/opt/opt-file", "/var/lib/var-file"):
            root_facts[path].st_mode = stat.S_IFREG

        def walk(root, followlinks):
            if root == "/":
                directories = ["opt"]
                yield "/", directories, ["root-file"]
                if "opt" in directories:
                    yield "/opt", [], ["opt-file"]
            elif root == "/opt":
                yield "/opt", [], ["opt-file"]
            else:
                yield "/var/lib", [], ["var-file"]

        usage = mock.Mock(f_blocks=10, f_frsize=10, f_bavail=5)
        with mock.patch.object(self.inventory.os, "stat", side_effect=lambda path, follow_symlinks: root_facts[path]), \
             mock.patch.object(self.inventory.os, "lstat", side_effect=lambda path: root_facts[path]), \
             mock.patch.object(self.inventory.os, "statvfs", return_value=usage), \
             mock.patch.object(self.inventory.os, "walk", side_effect=walk):
            records = self.inventory._filesystem_records(("/", "/opt", "/var/lib"))
        self.filesystem_records.start()
        self.assertEqual([
            {"device": 1, "capacity_bytes": 100, "available_bytes": 50, "apparent_size_bytes": 16},
            {"device": 2, "capacity_bytes": 100, "available_bytes": 50, "apparent_size_bytes": 7},
        ], records)

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

    def test_request_file_rejects_invalid_utf8_and_enforces_root_ownership(self):
        request_file = Path(self.tempdir.name) / "request.json"
        request_file.write_bytes(b"\xff")
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.read_request_file(request_file, hashlib.sha256(b"\xff").hexdigest(), require_root=False)
        payload = self.inventory.canonical_bytes(self.request.__dict__)
        request_file.write_bytes(payload)
        actual_fstat = os.fstat

        def owned_fstat(descriptor, uid):
            facts = actual_fstat(descriptor)
            values = list(facts)
            values[4] = uid
            return os.stat_result(values)

        with mock.patch.object(self.inventory.os, "fstat", side_effect=lambda descriptor: owned_fstat(descriptor, 0)):
            self.assertEqual(self.request, self.inventory.read_request_file(request_file, hashlib.sha256(payload).hexdigest()))
        with mock.patch.object(self.inventory.os, "fstat", side_effect=lambda descriptor: owned_fstat(descriptor, 1)):
            with self.assertRaisesRegex(self.inventory.InventoryError, "root-owned"):
                self.inventory.read_request_file(request_file, hashlib.sha256(payload).hexdigest())

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

    def test_rechecks_all_inventories_after_all_collection(self):
        cases = (
            ("container", FakeRunner([container(1)], containers_final=[container(2)])),
            ("volume", FakeRunner([], volumes=[{"Name": "named", "Driver": "local"}], volumes_final=[])),
            ("network", FakeRunner([], networks=[{"Id": "a" * 64, "Name": "bridge"}], networks_final=[])),
        )
        for kind, runner in cases:
            with self.subTest(kind=kind), self.assertRaisesRegex(self.inventory.InventoryError, kind + " inventory changed"):
                self.inventory.collect_inventory(self.request, runner)

    def test_runner_receives_output_bound_before_parsing(self):
        inventory = self.inventory

        class BoundedFailureRunner:
            def run(self, argv, *, max_output_bytes):
                if max_output_bytes <= 0:
                    raise AssertionError("collector did not provide a positive output bound")
                raise inventory.InventoryError("command output exceeds limit")

        with self.assertRaisesRegex(self.inventory.InventoryError, "command output exceeds limit"):
            self.inventory.collect_inventory(self.request, BoundedFailureRunner())
        process = mock.Mock(stdout=io.BytesIO(b"x" * 9))
        with mock.patch.object(self.inventory.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(self.inventory.InventoryError, "command output exceeds limit"):
                self.inventory.SubprocessRunner().run(("/usr/bin/docker",), max_output_bytes=8)
        process.kill.assert_called_once_with()

    def test_rejects_unknown_nested_inventory_field(self):
        value = self.inventory.collect_inventory(self.request, FakeRunner([container(1)]))
        value["containers"][0]["Env"] = ["SECRET=do-not-emit"]
        with self.assertRaisesRegex(self.inventory.InventoryError, "container record"):
            self.inventory.validate_inventory(value)

    def test_validator_requires_complete_sorted_secret_free_evidence(self):
        value = self.inventory.collect_inventory(self.request, FakeRunner([container(1)]))
        for mutation in (
            lambda item: item["containers"][0].__setitem__("repo_digests_sha256", []),
            lambda item: item.__setitem__("filesystems", []),
            lambda item: item.__setitem__("expected_caddy_paths", ["/etc/caddy/B", "/etc/caddy/A"]),
            lambda item: item.__setitem__("expected_caddy_paths", ["/etc/caddy/A", "/etc/caddy/A"]),
            lambda item: item.__setitem__("expected_caddy_paths", ["/etc/caddy/../private"]),
            lambda item: item.__setitem__("expected_caddy_paths", ["/etc/caddy//Caddyfile"]),
        ):
            invalid = copy.deepcopy(value)
            mutation(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(self.inventory.InventoryError):
                self.inventory.validate_inventory(invalid)

    def test_validator_rejects_noncanonical_record_order(self):
        value = self.inventory.collect_inventory(
            self.request,
            FakeRunner([container(1)], volumes=[
                {"Name": "alpha", "Driver": "local"}, {"Name": "bravo", "Driver": "local"},
            ], networks=[
                {"Id": "a" * 64, "Name": "alpha"}, {"Id": "b" * 64, "Name": "bravo"},
            ]),
        )
        for mutation in (
            lambda item: item["containers"][0].__setitem__("labels", list(reversed(item["containers"][0]["labels"]))),
            lambda item: item.__setitem__("volumes", list(reversed(item["volumes"]))),
            lambda item: item.__setitem__("networks", list(reversed(item["networks"]))),
        ):
            invalid = copy.deepcopy(value)
            mutation(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(self.inventory.InventoryError):
                self.inventory.validate_inventory(invalid)

    def test_rejects_non_string_network_name(self):
        item = container(1)
        item["NetworkSettings"]["Networks"] = {1: {"NetworkID": "a" * 64}}
        with self.assertRaisesRegex(self.inventory.InventoryError, "network memberships"):
            self.inventory._container_record(item, FakeRunner([item]), ("/usr/bin/docker",), self.request.max_output_bytes)

    def test_quick_validator_compiles_inventory_script(self):
        quick_validate = load_quick_validate()
        self.assertEqual((True, "Docker inventory script is valid!"), quick_validate.validate_docker_inventory_script(MODULE_PATH))


if __name__ == "__main__":
    unittest.main()
