#!/usr/bin/env python3
"""Contract tests for Docker host inventory v2.

The expected values in this suite are hand-built fixtures.  The tests do not
derive expected records with collector helpers.
"""

import copy
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "inspect_docker_host_v2.py"
SCHEMA_DIR = ROOT / "references" / "docker-host-inventory-v2"
V1_BLOBS = {
    ROOT / "scripts" / "inspect_docker_host.py": "272fff5357ccddf98e5112ad02ce31a5ea20350b",
    ROOT / "tests" / "test_docker_host_inventory.py": "5d37988d7e9e77050f73ddd4076da42a31fa15f9",
}
SENSITIVE = "do-not-emit-password-redacted-cloud-key-10.23.45.67"


def git_blob_id(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def load_module(testcase: unittest.TestCase):
    testcase.assertTrue(MODULE_PATH.is_file(), "inventory v2 module is missing")
    spec = importlib.util.spec_from_file_location("docker_host_inventory_v2", MODULE_PATH)
    testcase.assertIsNotNone(spec)
    testcase.assertIsNotNone(spec.loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def container(index: int, mounts=None):
    identifier = f"{index + 1:064x}"
    name = f"workload-{index}"
    return {
        "Id": identifier,
        "Name": "/" + name,
        "Image": "sha256:" + f"{index + 1000:064x}",
        "Config": {
            "Env": ["PASSWORD=" + SENSITIVE],
            "Cmd": ["server", "/etc/redis/redis.conf", "--token", SENSITIVE],
            "Entrypoint": ["/entrypoint", SENSITIVE],
            "Labels": {
                "com.docker.compose.project": "accepted-project" if index == 0 else name,
                "com.docker.compose.service": (
                    "cache-primary-neutral" if index == 0
                    else "edge-gateway-neutral" if index == 1
                    else "web-neutral"
                ),
                "io.deploydesk.deployment-id": "accepted-deployment" if index == 0 else name,
                "com.deploydesk.deployment-id": "accepted-deployment" if index == 0 else name,
                "private.secret": SENSITIVE,
            },
        },
        "HostConfig": {
            "LogConfig": {"Type": "json-file", "Config": {"token": SENSITIVE}},
            "Tmpfs": {"/tmp": "rw,size=4096"} if index == 0 else {},
            "Mounts": None,
        },
        "State": {"Running": index % 2 == 0, "Health": {"Status": "healthy"}},
        "NetworkSettings": {
            "IPAddress": "10.23.45.67",
            "Gateway": "10.23.45.1",
            "Networks": {
                "apps": {"NetworkID": "a" * 64, "IPAddress": "10.23.45.67"},
            },
            "Ports": {
                "8080/tcp": [
                    {"HostIp": "0.0.0.0", "HostPort": "18080"},
                    {"HostIp": "127.0.0.1", "HostPort": "28080"},
                    {"HostIp": "10.23.45.67", "HostPort": "38080"},
                ],
            },
        },
        "Mounts": mounts or [],
    }


def docker_image(index: int):
    return {
        "Id": "sha256:" + f"{index + 1000:064x}",
        "RepoDigests": [
            f"registry.example.invalid/team/image{index}@sha256:{index + 2000:064x}"
        ],
    }


class FakeRunner:
    """A complete fixed-output command boundary, not a mock of collector behavior."""

    def __init__(self, containers, volumes, networks, *, images=None, topology_change_at=None):
        self.containers = containers
        self.volumes = volumes
        self.networks = networks
        if images is None:
            images = []
            for item in containers:
                index = int(item["Image"].split(":", 1)[1], 16) - 1000
                images.append(docker_image(index))
        self.images = list({item["Id"]: item for item in images}.values())
        self.calls = []
        self.topology_change_at = topology_change_at
        self.ps_calls = 0

    @staticmethod
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def run(self, argv, *, max_output_bytes, timeout_seconds):
        argv = tuple(argv)
        self.calls.append((argv, max_output_bytes, timeout_seconds))
        if argv[-3:] == ("ps", "-aq", "--no-trunc"):
            self.ps_calls += 1
            values = self.containers
            if self.topology_change_at == self.ps_calls:
                values = self.containers[:-1]
            return "\n".join(item["Id"] for item in values) + ("\n" if values else "")
        if "image" in argv and "inspect" in argv:
            identifiers = set(argv[argv.index("inspect") + 2:])
            return self.encoded([item for item in self.images if item["Id"] in identifiers])
        if "container" in argv and "inspect" in argv:
            identifiers = set(argv[argv.index("inspect") + 1:])
            return self.encoded([item for item in self.containers if item["Id"] in identifiers])
        if argv[-3:] == ("volume", "ls", "-q"):
            return "\n".join(item["Name"] for item in self.volumes) + ("\n" if self.volumes else "")
        if "volume" in argv and "inspect" in argv:
            identifiers = set(argv[argv.index("inspect") + 1:])
            return self.encoded([item for item in self.volumes if item["Name"] in identifiers])
        if argv[-4:] == ("network", "ls", "-q", "--no-trunc"):
            return "\n".join(item["Id"] for item in self.networks) + ("\n" if self.networks else "")
        if "network" in argv and "inspect" in argv:
            identifiers = set(argv[argv.index("inspect") + 1:])
            return self.encoded([item for item in self.networks if item["Id"] in identifiers])
        if len(argv) >= 3 and argv[-3:-1] == ("diff", "--"):
            return "A /created\nC /changed\n"
        fixed = {
            ("/usr/bin/uname", "-r"): "6.8.0-test\n",
            ("/usr/bin/docker", "--config", "/etc/docker", "--host", "unix:///var/run/docker.sock", "version"): (
                "Client:\n Version: 27.5.1\n API version: 1.47\n"
                "Server:\n Version: 27.5.1\n API version: 1.47\n"
            ),
            ("/usr/bin/tar", "--version"): "tar (GNU tar) 1.35\n",
            ("/usr/bin/zstd", "--version"): "*** Zstandard CLI (64-bit) v1.5.6\n",
            ("/usr/bin/psql", "--version"): "psql (PostgreSQL) 16.4\n",
            ("/usr/bin/pg_dump", "--version"): "pg_dump (PostgreSQL) 16.4\n",
            ("/usr/bin/redis-server", "--version"): "Redis server v=7.2.5 sha=00000000:0 malloc=libc bits=64 build=abc\n",
            ("/usr/bin/caddy", "version"): "v2.8.4\n",
            ("/usr/sbin/visudo", "-V"): "Visudo version 1.9.15p5\n",
        }
        if argv in fixed:
            return fixed[argv]
        raise AssertionError(f"unexpected argv: {argv!r}")


class InventoryV1CompatibilityTests(unittest.TestCase):
    def test_v1_script_and_contract_test_remain_byte_identical(self):
        self.assertEqual(
            {str(path.relative_to(ROOT)): expected for path, expected in V1_BLOBS.items()},
            {str(path.relative_to(ROOT)): git_blob_id(path) for path in V1_BLOBS},
        )


class InventoryV2SchemaTests(unittest.TestCase):
    def setUp(self):
        self.inventory = load_module(self)

    def test_every_required_public_api_exists(self):
        for name in (
            "InventoryRequestV2", "collect_topology_v2", "collect_observation_v2",
            "collect_inventory_v2", "validate_topology_v2", "validate_observation_v2",
            "validate_inventory_v2", "canonical_bytes", "identity_sha256",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(self.inventory, name), name)

    def test_all_four_schemas_are_closed_draft_2020_12_documents(self):
        expected = {
            "request.schema.json": "deploydesk-docker-host-inventory-request/v2",
            "topology.schema.json": "deploydesk-docker-host-topology/v2",
            "observation.schema.json": "deploydesk-docker-host-observation/v2",
            "inventory.schema.json": "deploydesk-docker-host-inventory/v2",
        }
        for filename, schema_version in expected.items():
            with self.subTest(filename=filename):
                path = SCHEMA_DIR / filename
                self.assertTrue(path.is_file(), filename)
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual("https://json-schema.org/draft/2020-12/schema", value["$schema"])
                self.assertEqual(False, value["additionalProperties"])
                self.assertEqual(schema_version, value["properties"]["schema_version"]["const"])
                self.assertEqual(set(value["properties"]), set(value["required"]))
                stack = [("$", value)]
                while stack:
                    location, node = stack.pop()
                    if isinstance(node, dict):
                        if node.get("type") == "object":
                            self.assertIs(
                                False,
                                node.get("additionalProperties"),
                                f"open object at {filename}:{location}",
                            )
                            self.assertEqual(
                                set(node.get("properties", {})),
                                set(node.get("required", [])),
                                f"non-exact object at {filename}:{location}",
                            )
                        stack.extend((f"{location}/{key}", item) for key, item in node.items())
                    elif isinstance(node, list):
                        stack.extend((f"{location}/{index}", item) for index, item in enumerate(node))

    def test_combined_schema_has_only_exact_topology_and_observation_children(self):
        value = json.loads((SCHEMA_DIR / "inventory.schema.json").read_text(encoding="utf-8"))
        self.assertEqual({"schema_version", "topology", "observation"}, set(value["properties"]))
        self.assertEqual(
            "topology.schema.json",
            value["properties"]["topology"]["$ref"],
        )
        self.assertEqual(
            "observation.schema.json",
            value["properties"]["observation"]["$ref"],
        )

    def test_request_example_recomputes_projection_without_a_hash_cycle(self):
        example = json.loads((SCHEMA_DIR / "request.example.json").read_text(encoding="utf-8"))
        projection = {
            key: item for key, item in example.items()
            if key not in {"request_identity_projection_sha256", "inventory_target_claim_sha256"}
        }
        self.assertNotIn("request_identity_projection_sha256", projection)
        self.assertNotIn("inventory_target_claim_sha256", projection)
        self.assertEqual(
            example["request_identity_projection_sha256"],
            hashlib.sha256(self.inventory.canonical_bytes(projection)).hexdigest(),
        )
        self.assertNotEqual(
            example["request_identity_projection_sha256"],
            hashlib.sha256(self.inventory.canonical_bytes(example)).hexdigest(),
        )
        mutated = copy.deepcopy(example)
        mutated["max_containers"] -= 1
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_REQUEST_PROJECTION"):
            self.inventory.InventoryRequestV2.from_mapping(mutated)

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (
            '{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}',
            '{"a":1e999}', '{"a":' + "9" * 5000 + '}',
        ):
            with self.subTest(raw=raw), self.assertRaises(self.inventory.InventoryError):
                self.inventory.strict_json(raw)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.strict_json("[" * 2000 + "0" + "]" * 2000)
        nested = 0
        for _ in range(2000):
            nested = [nested]
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.canonical_bytes(nested)
        pretty = json.dumps({"safe": [1, 2]}, indent=2) + "\n"
        self.assertEqual({"safe": [1, 2]}, self.inventory._strict_command_json(pretty))

    def test_schema_lexical_rules_and_hard_array_limits_match_runtime_contract(self):
        request = json.loads((SCHEMA_DIR / "request.schema.json").read_text(encoding="utf-8"))
        topology = json.loads((SCHEMA_DIR / "topology.schema.json").read_text(encoding="utf-8"))
        observation = json.loads((SCHEMA_DIR / "observation.schema.json").read_text(encoding="utf-8"))

        command_contract = request["$comment"]
        for required in (
            "uname -r", "docker version", "docker ps -aq --no-trunc",
            "docker container inspect --", "docker image inspect --", "docker volume inspect --",
            "docker network inspect --", "docker container diff --",
            "tar --version", "zstd --version", "psql --version",
            "pg_dump --version", "redis-server --version", "caddy version", "visudo -V",
        ):
            self.assertIn(required, command_contract)
        for forbidden in ("docker logs", "docker exec", "docker pull", "docker push", "--format"):
            self.assertNotIn(forbidden, command_contract)

        path_pattern = request["$defs"]["path"]["pattern"]
        self.assertEqual(path_pattern, topology["$defs"]["absolute_path"]["pattern"])
        for value in ("/", "/opt/app", "/srv/数据"):
            self.assertIsNotNone(re.fullmatch(path_pattern, value), value)
        for value in ("relative", "/tmp//alias", "/tmp/../escape", "/tmp/./alias", "/tmp/trailing/"):
            self.assertIsNone(re.fullmatch(path_pattern, value), value)

        repo_pattern = topology["$defs"]["raw_repo"]["properties"]["value"]["pattern"]
        self.assertIsNotNone(re.fullmatch(
            repo_pattern,
            "registry.example.invalid/team/app@sha256:" + "a" * 64,
        ))
        for value in (
            "10.23.45.67/team/app@sha256:" + "a" * 64,
            "registry.example.invalid:5000/team/app@sha256:" + "a" * 64,
            "REGISTRY.example.invalid/team/app@sha256:" + "a" * 64,
        ):
            self.assertIsNone(re.fullmatch(repo_pattern, value), value)

        self.assertEqual(4096, request["$defs"]["path_array"]["maxItems"])
        self.assertEqual(70, topology["properties"]["containers"]["maxItems"])
        self.assertTrue(topology["properties"]["containers"]["uniqueItems"])
        self.assertEqual(4096, topology["properties"]["trusted_ancestors"]["maxItems"])
        self.assertEqual(70, topology["properties"]["redis"]["maxItems"])
        self.assertEqual(3, observation["properties"]["observed_sources"]["minItems"])
        self.assertEqual(3, observation["properties"]["observed_sources"]["maxItems"])
        self.assertEqual(250_000, observation["properties"]["persistence"]["maxItems"])
        self.assertEqual(250_000, observation["properties"]["redis_persistence_members"]["maxItems"])
        self.assertEqual(
            8 * 1024 * 1024 * 1024,
            observation["$defs"]["redis_member"]["properties"]["size_bytes"]["maximum"],
        )
        self.assertEqual(
            {
                "os", "docker", "host_tar", "host_zstd", "host_psql",
                "host_pg_dump", "host_redis_server", "host_caddy", "host_visudo",
            },
            set(topology["$defs"]["capabilities"]["required"]),
        )


class DockerHostInventoryV2Tests(unittest.TestCase):
    def setUp(self):
        self.inventory = load_module(self)
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name).resolve()
        self.root = root
        self.opt = root / "opt"
        self.pg = root / "postgres"
        self.redis = root / "redis"
        self.bind = root / "bind"
        self.volume_named = root / "volume-named"
        self.volume_anon = root / "volume-anon"
        for path in (self.opt, self.pg, self.redis, self.bind, self.volume_named, self.volume_anon):
            path.mkdir()
        (self.opt / "app.bin").write_bytes(b"five5")
        (self.pg / "base.dat").write_bytes(b"postgres-data")
        (self.redis / "dump.rdb").write_bytes(b"redis-rdb")
        (self.redis / "appendonly.aof").write_bytes(b"aof")
        self.caddy = root / "Caddyfile"
        self.caddy.write_text(
            "app.example.invalid {\n    encode zstd gzip\n    reverse_proxy upstream-neutral:8080\n}\n",
            encoding="utf-8",
        )
        mounts = [
            {"Type": "volume", "Name": "accepted-volume", "Driver": "local", "Source": str(self.volume_named), "Destination": "/data", "Mode": "z", "RW": True, "Propagation": ""},
            {"Type": "volume", "Name": "a" * 64, "Driver": "local", "Source": str(self.volume_anon), "Destination": "/cache", "Mode": "", "RW": True, "Propagation": ""},
            {"Type": "bind", "Source": str(self.bind), "Destination": "/host", "RW": False, "Mode": "ro,z", "Propagation": "rprivate"},
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "Mode": "", "RW": True, "Propagation": ""},
        ]
        self.containers = [container(0, mounts)] + [container(index) for index in range(1, 70)]
        self.images = [docker_image(index) for index in range(70)]
        self.volumes = [
            {"Name": "accepted-volume", "Driver": "local", "Mountpoint": str(self.volume_named), "Options": {}, "Scope": "local"},
            {"Name": "a" * 64, "Driver": "local", "Mountpoint": str(self.volume_anon), "Options": {}, "Scope": "local"},
        ]
        self.networks = [{
            "Id": "a" * 64, "Name": "apps", "Driver": "bridge", "Scope": "local",
            "Internal": False, "Attachable": True, "Ingress": False,
            "IPAM": {"Driver": "default", "Config": [{"Subnet": "10.23.0.0/16", "Gateway": "10.23.0.1"}]},
        }]
        names = {
            "workload-0", "accepted-project", "cache-primary-neutral", "accepted-deployment",
            "accepted-volume", "apps", "app.example.invalid", "edge-gateway-neutral",
        }
        paths = {
            str(self.opt), str(self.pg), str(self.redis), str(self.bind),
            str(self.volume_named), str(self.volume_anon), str(self.caddy),
        }
        digest0 = self.images[0]["RepoDigests"][0]
        base = {
            "schema_version": "deploydesk-docker-host-inventory-request/v2",
            "inventory_nonce": "1" * 64,
            "request_policy_sha256": "2" * 64,
            "source_lock_sha256": "3" * 64,
            "collector_sha256": "4" * 64,
            "docker_command": ["/usr/bin/docker"],
            "docker_config_path": "/etc/docker",
            "docker_socket_path": "/var/run/docker.sock",
            "observed_sources": [
                {"role": "opt", "path": str(self.opt)},
                {"role": "postgresql", "path": str(self.pg)},
                {"role": "redis", "path": str(self.redis)},
            ],
            "trusted_ancestor_paths": [str(root)],
            "caddy_roots": [str(self.caddy)],
            "allowed_registry_dns_prefixes": ["registry.example.invalid"],
            "expected_name_sha256": sorted(digest_text(value) for value in names),
            "expected_path_sha256": sorted(digest_text(value) for value in paths),
            "approved_repo_digest_sha256": [digest_text(digest0)],
            "service_role_sha256": {
                "caddy": [digest_text("edge-gateway-neutral")],
                "redis": [digest_text("cache-primary-neutral")],
            },
            "max_containers": 70,
            "max_volumes": 20,
            "max_networks": 20,
            "max_mounts_per_container": 32,
            "max_ports_per_container": 64,
            "max_command_output_bytes": 1_000_000,
            "max_command_seconds": 30,
            "max_command_calls": 1024,
            "max_total_command_output_bytes": 33_554_432,
            "max_total_command_seconds": 1800,
            "max_topology_bytes": 1_572_864,
            "max_observation_bytes": 524_288,
            "max_inventory_bytes": 2_097_152,
            "max_recursive_entries": 250_000,
            "max_acl_entries": 256,
            "max_acl_bytes_per_path": 65_536,
            "max_path_bytes": 4096,
            "max_persistence_file_bytes": 1_073_741_824,
        }
        projection_hash = hashlib.sha256(self.inventory.canonical_bytes(base)).hexdigest()
        final = {
            **base,
            "request_identity_projection_sha256": projection_hash,
            "inventory_target_claim_sha256": "5" * 64,
        }
        self.request_dict = final
        self.request = self.inventory.InventoryRequestV2.from_mapping(final)
        self.runner = FakeRunner(self.containers, self.volumes, self.networks, images=self.images)

    def tearDown(self):
        self.tempdir.cleanup()

    def request_variant(self, **changes):
        base = {
            key: copy.deepcopy(value)
            for key, value in self.request_dict.items()
            if key not in {"request_identity_projection_sha256", "inventory_target_claim_sha256"}
        }
        base.update(changes)
        return self.inventory.InventoryRequestV2.from_mapping({
            **base,
            "request_identity_projection_sha256": self.inventory.identity_sha256(base),
            "inventory_target_claim_sha256": "9" * 64,
        })

    def rebind_inventory(self, inventory, request):
        rebound = copy.deepcopy(inventory)
        identity = self.inventory._identity_fields(request)
        rebound["topology"].update(identity)
        rebound["topology"]["privacy_expectations"] = (
            self.inventory._privacy_expectations(request)
        )
        rebound["topology"]["service_role_sha256"] = {
            role: list(request.service_role_sha256[role])
            for role in ("caddy", "redis")
        }
        rebound["observation"].update(identity)
        rebound["observation"]["topology_sha256"] = self.inventory.identity_sha256(
            rebound["topology"],
        )
        return rebound

    def test_request_construction_rejects_unknown_fields_and_derived_hash_cycles(self):
        unknown = {**self.request_dict, "future": True}
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.InventoryRequestV2.from_mapping(unknown)
        invalid = copy.deepcopy(self.request_dict)
        invalid["request_identity_projection_sha256"] = hashlib.sha256(
            self.inventory.canonical_bytes(invalid)
        ).hexdigest()
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.InventoryRequestV2.from_mapping(invalid)

    def test_request_binds_closed_nonliteral_service_role_hashes(self):
        base = {
            key: copy.deepcopy(value)
            for key, value in self.request_dict.items()
            if key not in {"request_identity_projection_sha256", "inventory_target_claim_sha256"}
        }
        roles = {
            "caddy": [digest_text("edge-gateway-neutral")],
            "redis": [digest_text("cache-primary-neutral")],
        }
        base["service_role_sha256"] = roles
        request = self.inventory.InventoryRequestV2.from_mapping({
            **base,
            "request_identity_projection_sha256": self.inventory.identity_sha256(base),
            "inventory_target_claim_sha256": "6" * 64,
        })
        self.assertEqual(tuple(roles["caddy"]), request.service_role_sha256["caddy"])
        with self.assertRaises(TypeError):
            request.service_role_sha256["caddy"] = ("f" * 64,)
        with self.assertRaises(self.inventory.InventoryError):
            dataclasses.replace(
                request,
                service_role_sha256={
                    "caddy": tuple(roles["caddy"]),
                    "redis": tuple(roles["redis"]),
                },
            )
        routed = self.inventory.collect_topology_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks, images=self.images),
        )
        self.assertEqual([self.containers[1]["Id"]], routed["caddy"]["container_ids"])
        self.assertEqual([self.containers[0]["Id"]], [item["container_id"] for item in routed["redis"]])
        tuple_topology = copy.deepcopy(routed)
        tuple_topology["service_role_sha256"]["caddy"] = tuple(
            tuple_topology["service_role_sha256"]["caddy"]
        )
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_topology_v2(tuple_topology)
        tuple_roles = copy.deepcopy(base)
        tuple_roles["service_role_sha256"] = {
            "caddy": tuple(roles["caddy"]), "redis": list(roles["redis"]),
        }
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.InventoryRequestV2.from_mapping({
                **tuple_roles,
                "request_identity_projection_sha256": self.inventory.identity_sha256(tuple_roles),
                "inventory_target_claim_sha256": "6" * 64,
            })
        for invalid_roles in (
            {"caddy": [], "redis": []},
            {"caddy": ["a" * 64], "redis": ["a" * 64]},
            {"caddy": ["b" * 64, "a" * 64], "redis": ["c" * 64]},
            {"caddy": ["a" * 64] * 2, "redis": ["c" * 64]},
            {"caddy": [f"{index:064x}" for index in range(71)], "redis": ["f" * 64]},
            {"caddy": ["a" * 64], "redis": ["b" * 64], "other": []},
        ):
            candidate = {**base, "service_role_sha256": invalid_roles}
            with self.subTest(invalid_roles=invalid_roles), self.assertRaises(self.inventory.InventoryError):
                self.inventory.InventoryRequestV2.from_mapping({
                    **candidate,
                    "request_identity_projection_sha256": self.inventory.identity_sha256(candidate),
                    "inventory_target_claim_sha256": "6" * 64,
                })

    def test_container_repo_digests_are_resolved_by_fixed_image_inspect(self):
        fixtures = copy.deepcopy(self.containers[:2])
        images = []
        for index, item in enumerate(fixtures):
            item.pop("RepoDigests", None)
            images.append({
                "Id": item["Image"],
                "RepoDigests": [
                    f"registry.example.invalid/team/resolved{index}@sha256:{index + 5000:064x}"
                ],
            })

        class ImageRunner(FakeRunner):
            def run(inner_self, argv, *, max_output_bytes, timeout_seconds):
                suffix = tuple(argv)[len(self.inventory._docker_prefix(self.request)):]
                if suffix[:3] == ("image", "inspect", "--"):
                    self.assertEqual(tuple(sorted({item["Image"] for item in fixtures})), suffix[3:])
                    return inner_self.encoded(list(reversed(images)))
                return super(ImageRunner, inner_self).run(
                    argv, max_output_bytes=max_output_bytes, timeout_seconds=timeout_seconds,
                )

        request = self.request_variant(
            max_containers=2,
            approved_repo_digest_sha256=sorted(
                digest_text(value)
                for image in images for value in image["RepoDigests"]
            ),
        )
        topology = self.inventory.collect_topology_v2(
            request,
            ImageRunner(fixtures, self.volumes, self.networks),
        )
        self.assertEqual(
            [digest_text(images[index]["RepoDigests"][0]) for index in range(2)],
            [item["repo_digests"][0]["sha256"] for item in topology["containers"]],
        )

    def test_image_inspect_is_unique_bound_and_fails_closed_on_bad_facts(self):
        fixtures = copy.deepcopy(self.containers[:2])
        fixtures[1]["Image"] = fixtures[0]["Image"]
        image = copy.deepcopy(self.images[0])
        request = self.request_variant(
            max_containers=2,
            approved_repo_digest_sha256=[digest_text(image["RepoDigests"][0])],
        )
        runner = FakeRunner(fixtures, self.volumes, self.networks, images=[image])
        topology = self.inventory.collect_topology_v2(request, runner)
        image_calls = [
            call[0] for call in runner.calls
            if "image" in call[0] and "inspect" in call[0]
        ]
        self.assertEqual(1, len(image_calls))
        self.assertEqual((fixtures[0]["Image"],), image_calls[0][-1:])
        self.assertEqual(
            topology["containers"][0]["repo_digests"],
            topology["containers"][1]["repo_digests"],
        )

        class PayloadRunner(FakeRunner):
            def __init__(inner_self, payload):
                super().__init__(fixtures[:1], self.volumes, self.networks, images=[image])
                inner_self.payload = payload

            def run(inner_self, argv, *, max_output_bytes, timeout_seconds):
                if "image" in argv and "inspect" in argv:
                    return inner_self.encoded(inner_self.payload)
                return super(PayloadRunner, inner_self).run(
                    argv, max_output_bytes=max_output_bytes, timeout_seconds=timeout_seconds,
                )

        invalid_payloads = (
            [],
            [image, copy.deepcopy(image)],
            [{"Id": "sha256:" + "f" * 64, "RepoDigests": image["RepoDigests"]}],
            [{"Id": image["Id"], "RepoDigests": []}],
            [{"Id": image["Id"], "RepoDigests": image["RepoDigests"] * 2}],
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(self.inventory.InventoryError):
                self.inventory.collect_topology_v2(request, PayloadRunner(payload))

        with self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_VECTOR"):
            self.inventory._run(
                request,
                runner,
                self.inventory._docker_prefix(request) + ("image", "ls"),
            )

    def test_image_repo_digest_drift_and_standalone_projection_conflict_are_rejected(self):
        first = copy.deepcopy(self.images[0])
        alternate = (
            "registry.example.invalid/team/alternate@sha256:" + "f" * 64
        )
        request = self.request_variant(
            approved_repo_digest_sha256=sorted({
                digest_text(first["RepoDigests"][0]), digest_text(alternate),
            }),
        )

        class DriftRunner(FakeRunner):
            def __init__(inner_self):
                super().__init__(self.containers, self.volumes, self.networks, images=self.images)
                inner_self.image_calls = 0

            def run(inner_self, argv, *, max_output_bytes, timeout_seconds):
                if "image" in argv and "inspect" in argv:
                    inner_self.image_calls += 1
                    payload = copy.deepcopy(inner_self.images)
                    if inner_self.image_calls == 2:
                        payload[0]["RepoDigests"] = [alternate]
                    return inner_self.encoded(payload)
                return super(DriftRunner, inner_self).run(
                    argv, max_output_bytes=max_output_bytes, timeout_seconds=timeout_seconds,
                )

        with self.assertRaisesRegex(self.inventory.InventoryError, "E_OBSERVATION_CONTAINER_DRIFT"):
            self.inventory.collect_inventory_v2(request, DriftRunner())

        shared = copy.deepcopy(self.containers[:2])
        shared[1]["Image"] = shared[0]["Image"]
        topology = self.inventory.collect_topology_v2(
            request,
            FakeRunner(shared, self.volumes, self.networks, images=[first]),
        )
        topology["containers"][1]["repo_digests"] = [{"kind": "hashed", "sha256": "f" * 64}]
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_IMAGE_BINDING"):
            self.inventory.validate_topology_v2(topology)

        unordered = copy.deepcopy(first)
        second_digest = "registry.example.invalid/team/second@sha256:" + "e" * 64
        unordered["RepoDigests"] = [second_digest, first["RepoDigests"][0]]
        unordered_request = self.request_variant(
            max_containers=2,
            approved_repo_digest_sha256=sorted(map(digest_text, unordered["RepoDigests"])),
        )
        normalized = self.inventory.collect_topology_v2(
            unordered_request,
            FakeRunner(
                self.containers[:2], self.volumes, self.networks,
                images=[unordered, self.images[1]],
            ),
        )
        self.assertEqual(
            sorted(map(digest_text, unordered["RepoDigests"])),
            sorted(item["sha256"] for item in normalized["containers"][0]["repo_digests"]),
        )

    def test_caddy_closed_parser_supports_frozen_directives_and_blocks(self):
        raw = (
            ROOT / "tests" / "fixtures" / "shared-caddy-v1" / "bundle" / "caddy" / "site.caddy"
        ).read_bytes()
        parsed = self.inventory._parse_caddy_file(
            str(self.caddy), raw, self.request, os.lstat(self.caddy),
        )
        self.assertEqual(
            {"docker_proxy", "https_proxy", "redirect"},
            {item["kind"] for item in parsed["behaviors"]},
        )
        serialized = self.inventory.canonical_bytes(parsed)
        for private in (
            b"app.example.test", b"sample-app-staging-web",
        ):
            self.assertNotIn(private, serialized)
        bad_values = (
            b"edge.example.invalid {\n encode gzip\n reverse_proxy app-neutral:8080\n}\n",
            b"edge.example.invalid {\n reverse_proxy app-neutral:8080 extra\n}\n",
            b"edge.example.invalid {\n transport http {\n }\n}\n",
            b"edge.example.invalid {\n reverse_proxy https://origin.example.invalid:443 {\n }\n}\n",
            b"edge.example.invalid {\n unknown value\n}\n",
            b"edge.example.invalid {\n encode zstd gzip\n}\n",
            b"edge.example.invalid {\n redir /relative 302\n}\n",
            b"Upper.example.invalid {\n redir https://canonical.example.invalid{uri} 308\n}\n",
            b"edge.example.invalid. {\n redir https://canonical.example.invalid{uri} 308\n}\n",
            b"edge.example.invalid {\n encode zstd gzip\n reverse_proxy Upper.invalid:8080\n}\n",
            b"edge.example.invalid {\n redir https://Canonical.example.invalid{uri} 308\n}\n",
        )
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(self.inventory.InventoryError):
                self.inventory._parse_caddy_file(
                    str(self.caddy), value, self.request, os.lstat(self.caddy),
                )
        invalid = copy.deepcopy(self.request_dict)
        invalid["inventory_target_claim_sha256"] = invalid["request_identity_projection_sha256"]
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.InventoryRequestV2.from_mapping(invalid)

    def test_request_hard_limits_accept_boundary_and_reject_boundary_plus_one(self):
        limits = {
            "max_containers": 70,
            "max_volumes": 4096,
            "max_networks": 4096,
            "max_mounts_per_container": 256,
            "max_ports_per_container": 1024,
            "max_command_output_bytes": 4_194_304,
            "max_command_seconds": 300,
            "max_topology_bytes": 1_572_864,
            "max_observation_bytes": 524_288,
            "max_inventory_bytes": 2_097_152,
            "max_recursive_entries": 250_000,
            "max_acl_entries": 256,
            "max_acl_bytes_per_path": 65_536,
            "max_path_bytes": 4096,
            "max_command_calls": 1024,
            "max_total_command_output_bytes": 33_554_432,
            "max_total_command_seconds": 1800,
            "max_persistence_file_bytes": 8_589_934_592,
        }
        for field, boundary in limits.items():
            valid = {key: value for key, value in self.request_dict.items() if key not in {
                "request_identity_projection_sha256", "inventory_target_claim_sha256"
            }}
            valid[field] = boundary
            valid["request_identity_projection_sha256"] = self.inventory.identity_sha256(valid)
            valid["inventory_target_claim_sha256"] = "6" * 64
            self.inventory.InventoryRequestV2.from_mapping(valid)
            invalid = {key: value for key, value in valid.items() if key not in {
                "request_identity_projection_sha256", "inventory_target_claim_sha256"
            }}
            invalid[field] = boundary + 1
            invalid["request_identity_projection_sha256"] = self.inventory.identity_sha256(invalid)
            invalid["inventory_target_claim_sha256"] = "6" * 64
            with self.subTest(field=field), self.assertRaises(self.inventory.InventoryError):
                self.inventory.InventoryRequestV2.from_mapping(invalid)

    def test_collects_70_containers_all_persistence_classes_and_exact_deletion_ids(self):
        inventory = self.inventory.collect_inventory_v2(self.request, self.runner)
        topology = inventory["topology"]
        self.assertEqual(
            {
                "expected_name_sha256": list(self.request.expected_name_sha256),
                "expected_path_sha256": list(self.request.expected_path_sha256),
                "approved_repo_digest_sha256": list(self.request.approved_repo_digest_sha256),
                "allowed_registry_dns_sha256": [
                    digest_text(value) for value in self.request.allowed_registry_dns_prefixes
                ],
            },
            topology["privacy_expectations"],
        )
        self.assertEqual(70, topology["container_count"])
        self.assertEqual(sorted(item["Id"] for item in self.containers), topology["deletion_vector"])
        kinds = {
            item["kind"]
            for record in topology["containers"]
            for item in record["mounts"]
        }
        self.assertEqual({"named_volume", "anonymous_volume", "bind", "tmpfs"}, kinds)
        self.assertEqual(inventory, self.inventory.validate_inventory_v2(inventory))

    def test_topology_and_observation_have_disjoint_structural_volatile_facts(self):
        inventory = self.inventory.collect_inventory_v2(self.request, self.runner)
        topology_raw = self.inventory.canonical_bytes(inventory["topology"])
        observation_raw = self.inventory.canonical_bytes(inventory["observation"])
        for forbidden in (b'"running"', b'"health"', b'"ctime_ns"', b'"size_bytes"', b'"apparent_size_bytes"', b'"capacity_bytes"'):
            self.assertNotIn(forbidden, topology_raw)
        for required in (b'"running"', b'"health"', b'"ctime_ns"', b'"apparent_size_bytes"', b'"capacity_bytes"'):
            self.assertIn(required, observation_raw)

    def test_emits_raw_identifiers_only_after_syntax_and_expected_hash_match(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        first = next(item for item in topology["containers"] if item["id"] == self.containers[0]["Id"])
        second = next(item for item in topology["containers"] if item["id"] == self.containers[1]["Id"])
        self.assertEqual("raw", first["name"]["kind"])
        self.assertEqual("workload-0", first["name"]["value"])
        self.assertEqual({"kind", "sha256"}, set(second["name"]))
        self.assertEqual("hashed", second["name"]["kind"])
        self.assertEqual("raw", first["repo_digests"][0]["kind"])
        self.assertEqual("hashed", second["repo_digests"][0]["kind"])
        self.assertEqual(
            topology,
            self.inventory.validate_topology_v2(topology, self.request),
        )

    def test_embedded_privacy_expectations_never_self_authorize_raw_projection(self):
        restricted = self.request_variant(
            expected_name_sha256=[],
            expected_path_sha256=[],
            approved_repo_digest_sha256=[],
        )
        baseline = self.inventory.collect_topology_v2(
            restricted,
            FakeRunner(self.containers, self.volumes, self.networks),
        )

        def authorize(candidate, field, digest):
            values = candidate["privacy_expectations"][field]
            values.append(digest)
            values.sort()

        def rawify(candidate, record, value, field):
            digest = digest_text(value)
            record.clear()
            record.update({"kind": "raw", "sha256": digest, "value": value})
            authorize(candidate, field, digest)

        def refresh_mount_links(candidate):
            for container_record in candidate["containers"]:
                container_record["mounts"].sort(key=self.inventory.canonical_bytes)
            container_by_id = {item["id"]: item for item in candidate["containers"]}
            for redis_record in candidate["redis"]:
                redis_record["persistence_mount_sha256"] = sorted(
                    self.inventory.identity_sha256(mount)
                    for mount in container_by_id[redis_record["container_id"]]["mounts"]
                    if mount["destination"]["sha256"] == digest_text("/data")
                )

        def container_name(candidate):
            rawify(
                candidate,
                candidate["containers"][2]["name"],
                "workload-2",
                "expected_name_sha256",
            )

        def ownership_label(candidate):
            label = next(
                item for item in candidate["containers"][2]["ownership_labels"]
                if item["key"] == "com.docker.compose.project"
            )
            rawify(
                candidate, label["value"], "workload-2", "expected_name_sha256",
            )

        def network_name(candidate):
            rawify(
                candidate,
                candidate["networks"][0]["name"],
                "apps",
                "expected_name_sha256",
            )
            for container_record in candidate["containers"]:
                membership = container_record["network_memberships"][0]
                membership["name"] = copy.deepcopy(candidate["networks"][0]["name"])

        def network_driver(candidate):
            rawify(
                candidate,
                candidate["networks"][0]["driver"],
                "bridge",
                "expected_name_sha256",
            )

        def volume_name(candidate):
            volume = next(
                item for item in candidate["volumes"]
                if item["name"]["sha256"] == digest_text("accepted-volume")
            )
            rawify(
                candidate, volume["name"], "accepted-volume", "expected_name_sha256",
            )
            mount = next(
                item for item in candidate["containers"][0]["mounts"]
                if item["kind"] == "named_volume"
            )
            mount["name"] = copy.deepcopy(volume["name"])
            candidate["volumes"].sort(
                key=lambda item: self.inventory.canonical_bytes(item["name"]),
            )
            refresh_mount_links(candidate)

        def volume_driver(candidate):
            authorize(candidate, "expected_name_sha256", digest_text("local"))
            for volume in candidate["volumes"]:
                volume["driver"] = {
                    "kind": "raw", "sha256": digest_text("local"), "value": "local",
                }
            for container_record in candidate["containers"]:
                for mount in container_record["mounts"]:
                    if mount["kind"] in {"named_volume", "anonymous_volume"}:
                        mount["driver"] = {
                            "kind": "raw", "sha256": digest_text("local"), "value": "local",
                        }
            refresh_mount_links(candidate)

        def mount_destination(candidate):
            mount = next(
                item for item in candidate["containers"][0]["mounts"]
                if item["kind"] == "bind"
            )
            rawify(
                candidate, mount["destination"], "/host", "expected_path_sha256",
            )
            refresh_mount_links(candidate)

        def mount_source(candidate):
            mount = next(
                item for item in candidate["containers"][0]["mounts"]
                if item["kind"] == "bind"
            )
            rawify(
                candidate,
                mount["source"]["path"],
                str(self.bind),
                "expected_path_sha256",
            )
            refresh_mount_links(candidate)

        def volume_mountpoint(candidate):
            volume = next(
                item for item in candidate["volumes"]
                if item["name"]["sha256"] == digest_text("accepted-volume")
            )
            rawify(
                candidate,
                volume["mountpoint"]["path"],
                str(self.volume_named),
                "expected_path_sha256",
            )
            mount = next(
                item for item in candidate["containers"][0]["mounts"]
                if item["kind"] == "named_volume"
            )
            mount["source"] = copy.deepcopy(volume["mountpoint"]["path"])
            refresh_mount_links(candidate)

        def trusted_ancestor(candidate):
            rawify(
                candidate,
                candidate["trusted_ancestors"][0]["path"],
                str(self.root),
                "expected_path_sha256",
            )

        def caddy_file(candidate):
            rawify(
                candidate,
                candidate["caddy"]["files"][0]["path"],
                str(self.caddy),
                "expected_path_sha256",
            )

        def caddy_owner(candidate):
            rawify(
                candidate,
                candidate["caddy"]["owners"][0]["host"],
                "app.example.invalid",
                "expected_name_sha256",
            )

        def repo_digest(candidate):
            raw_value = self.images[2]["RepoDigests"][0]
            rawify(
                candidate,
                candidate["containers"][2]["repo_digests"][0],
                raw_value,
                "approved_repo_digest_sha256",
            )

        mutations = {
            "container-name": container_name,
            "ownership-label": ownership_label,
            "network-name": network_name,
            "network-driver": network_driver,
            "volume-name": volume_name,
            "volume-driver": volume_driver,
            "mount-destination": mount_destination,
            "mount-source": mount_source,
            "volume-mountpoint": volume_mountpoint,
            "trusted-ancestor": trusted_ancestor,
            "caddy-file": caddy_file,
            "caddy-owner": caddy_owner,
            "repo-digest": repo_digest,
        }
        for label, mutate in mutations.items():
            candidate = copy.deepcopy(baseline)
            mutate(candidate)
            with self.subTest(label=label):
                self.assertEqual(
                    candidate,
                    self.inventory.validate_topology_v2(candidate),
                )
                with self.assertRaisesRegex(
                    self.inventory.InventoryError,
                    "E_TOPOLOGY_REQUEST_BINDING",
                ):
                    self.inventory.validate_topology_v2(candidate, restricted)

    def test_request_aware_inventory_rejects_self_authorized_raw_escalation(self):
        restricted = self.request_variant(
            expected_name_sha256=[],
            expected_path_sha256=[],
            approved_repo_digest_sha256=[],
        )
        inventory = self.inventory.collect_inventory_v2(
            restricted,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        invalid = copy.deepcopy(inventory)
        raw_value = "workload-2"
        digest = digest_text(raw_value)
        invalid["topology"]["containers"][2]["name"] = {
            "kind": "raw", "sha256": digest, "value": raw_value,
        }
        invalid["topology"]["privacy_expectations"]["expected_name_sha256"].append(digest)
        invalid["topology"]["privacy_expectations"]["expected_name_sha256"].sort()
        invalid["observation"]["topology_sha256"] = self.inventory.identity_sha256(
            invalid["topology"],
        )
        self.assertEqual(invalid, self.inventory.validate_inventory_v2(invalid))
        with self.assertRaisesRegex(
            self.inventory.InventoryError,
            "E_TOPOLOGY_REQUEST_BINDING",
        ):
            self.inventory.validate_inventory_v2(invalid, restricted)

    def test_request_aware_inventory_binds_each_observed_source_role_path_and_identity(self):
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        self.assertEqual(
            inventory,
            self.inventory.validate_inventory_v2(inventory, self.request),
        )

        mutations = []
        invalid = copy.deepcopy(inventory)
        invalid["observation"]["observed_sources"][0]["path_sha256"] = "b" * 64
        mutations.append(("arbitrary-path", invalid))

        invalid = copy.deepcopy(inventory)
        invalid["observation"]["observed_sources"][0]["identity_sha256"] = "b" * 64
        mutations.append(("arbitrary-identity", invalid))

        invalid = copy.deepcopy(inventory)
        first, second = invalid["observation"]["observed_sources"][:2]
        first["role"], second["role"] = second["role"], first["role"]
        invalid["observation"]["observed_sources"].sort(
            key=lambda item: (item["role"], item["identity_sha256"]),
        )
        mutations.append(("role-swap", invalid))

        for label, candidate in mutations:
            with self.subTest(label=label):
                self.assertEqual(
                    candidate,
                    self.inventory.validate_inventory_v2(candidate),
                )
                with self.assertRaisesRegex(
                    self.inventory.InventoryError,
                    "E_INVENTORY_REQUEST_BINDING",
                ):
                    self.inventory.validate_inventory_v2(candidate, self.request)

    def test_request_aware_topology_binds_exact_ancestor_and_caddy_path_sets(self):
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        topology = inventory["topology"]
        self.assertEqual(
            topology,
            self.inventory.validate_topology_v2(topology, self.request),
        )

        substitutions = []
        invalid = copy.deepcopy(topology)
        invalid["trusted_ancestors"][0]["path"] = {
            "kind": "hashed", "sha256": "b" * 64,
        }
        substitutions.append(("ancestor-substitute", invalid, self.request))
        invalid = copy.deepcopy(topology)
        invalid["caddy"]["files"][0]["path"] = {
            "kind": "hashed", "sha256": "c" * 64,
        }
        invalid["caddy"]["owners"][0]["source_path_sha256"] = "c" * 64
        substitutions.append(("caddy-substitute", invalid, self.request))

        missing_ancestor_request = self.request_variant(
            trusted_ancestor_paths=sorted([str(self.root), str(self.opt)]),
        )
        substitutions.append((
            "ancestor-missing",
            self.rebind_inventory(inventory, missing_ancestor_request)["topology"],
            missing_ancestor_request,
        ))
        missing_caddy_request = self.request_variant(
            caddy_roots=sorted([str(self.caddy), str(self.root / "extra.caddy")]),
        )
        substitutions.append((
            "caddy-missing",
            self.rebind_inventory(inventory, missing_caddy_request)["topology"],
            missing_caddy_request,
        ))

        invalid = copy.deepcopy(topology)
        extra = copy.deepcopy(invalid["trusted_ancestors"][0])
        extra["path"] = {"kind": "hashed", "sha256": "d" * 64}
        invalid["trusted_ancestors"].append(extra)
        invalid["trusted_ancestors"].sort(
            key=lambda item: self.inventory.canonical_bytes(item["path"]),
        )
        substitutions.append(("ancestor-extra", invalid, self.request))
        invalid = copy.deepcopy(topology)
        extra = copy.deepcopy(invalid["caddy"]["files"][0])
        extra["path"] = {"kind": "hashed", "sha256": "e" * 64}
        invalid["caddy"]["files"].append(extra)
        invalid["caddy"]["files"].sort(
            key=lambda item: self.inventory.canonical_bytes(item["path"]),
        )
        substitutions.append(("caddy-extra", invalid, self.request))

        for label, candidate, request in substitutions:
            with self.subTest(label=label):
                self.assertEqual(candidate, self.inventory.validate_topology_v2(candidate))
                with self.assertRaisesRegex(
                    self.inventory.InventoryError,
                    "E_TOPOLOGY_REQUEST_BINDING",
                ):
                    self.inventory.validate_topology_v2(candidate, request)

        overlap_request = self.request_variant(
            trusted_ancestor_paths=sorted([str(self.root), str(self.opt)]),
        )
        overlap = self.inventory.collect_topology_v2(
            overlap_request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        self.assertEqual(
            {digest_text(str(self.root)), digest_text(str(self.opt))},
            {item["path"]["sha256"] for item in overlap["trusted_ancestors"]},
        )
        self.assertEqual(
            overlap,
            self.inventory.validate_topology_v2(overlap, overlap_request),
        )

    def test_caddy_owner_identity_matches_the_referenced_file(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        for field in ("writer_uid", "writer_gid"):
            invalid = copy.deepcopy(topology)
            invalid["caddy"]["owners"][0][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(
                self.inventory.InventoryError,
                "E_CADDY_LINK",
            ):
                self.inventory.validate_topology_v2(invalid)

    def test_regular_bind_and_caddy_files_require_single_links_but_directories_do_not(self):
        directory_inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        directory_topology = directory_inventory["topology"]
        directory_bind = next(
            mount for mount in directory_topology["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        self.assertEqual("directory", directory_bind["source"]["type"])
        directory_candidate = copy.deepcopy(directory_topology)
        directory_candidate_bind = next(
            mount for mount in directory_candidate["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        directory_candidate_bind["source"]["nlink"] = 2
        directory_candidate["containers"][0]["mounts"].sort(
            key=self.inventory.canonical_bytes,
        )
        self.assertEqual(
            directory_candidate,
            self.inventory.validate_topology_v2(directory_candidate),
        )

        bind_file = self.root / "bind-file"
        bind_file.write_bytes(b"regular-bind")
        fixtures = copy.deepcopy(self.containers)
        fixtures[0]["Mounts"][2]["Source"] = str(bind_file)
        request = self.request_variant(expected_path_sha256=sorted({
            *self.request.expected_path_sha256,
            digest_text(str(bind_file)),
        }))
        topology = self.inventory.collect_topology_v2(
            request,
            FakeRunner(fixtures, self.volumes, self.networks, images=self.images),
        )
        regular_bind = next(
            mount for mount in topology["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        self.assertEqual(1, regular_bind["source"]["nlink"])

        invalid = copy.deepcopy(topology)
        invalid_bind = next(
            mount for mount in invalid["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        invalid_bind["source"]["nlink"] = 2
        invalid["containers"][0]["mounts"].sort(key=self.inventory.canonical_bytes)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_MOUNT_RECORD"):
            self.inventory.validate_topology_v2(invalid)

        invalid_inventory = copy.deepcopy(directory_inventory)
        invalid_inventory_bind = next(
            mount for mount in invalid_inventory["topology"]["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        invalid_inventory_bind["source"]["type"] = "regular"
        invalid_inventory_bind["source"]["nlink"] = 2
        invalid_inventory["topology"]["containers"][0]["mounts"].sort(
            key=self.inventory.canonical_bytes,
        )
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_MOUNT_RECORD"):
            self.inventory.validate_inventory_v2(invalid_inventory)

        caddy_hardlink = self.root / "Caddyfile-hardlink"
        os.link(self.caddy, caddy_hardlink)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_FILE_TYPE"):
            self.inventory.collect_topology_v2(
                self.request,
                FakeRunner(self.containers, self.volumes, self.networks, images=self.images),
            )
        caddy_hardlink.unlink()

        hardlink = self.root / "bind-file-hardlink"
        os.link(bind_file, hardlink)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_MOUNT"):
            self.inventory.collect_topology_v2(
                request,
                FakeRunner(fixtures, self.volumes, self.networks, images=self.images),
            )

        invalid = copy.deepcopy(directory_topology)
        invalid["caddy"]["files"][0]["nlink"] = 2
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_CADDY_FILE"):
            self.inventory.validate_topology_v2(invalid)

        schema = json.loads((SCHEMA_DIR / "topology.schema.json").read_text())
        self.assertEqual(1, schema["$defs"]["caddy_file"]["properties"]["nlink"]["const"])
        bind_source = schema["$defs"]["bind_source"]
        self.assertEqual(
            1,
            bind_source["allOf"][1]["then"]["properties"]["nlink"]["const"],
        )

    def test_request_aware_validators_enforce_only_reconstructible_request_limits(self):
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )

        topology_cases = []
        for label, field, value in (
            ("containers", "max_containers", 69),
            ("volumes", "max_volumes", 1),
            ("mounts", "max_mounts_per_container", 3),
            ("ports", "max_ports_per_container", 2),
        ):
            request = self.request_variant(**{field: value})
            topology_cases.append((label, self.rebind_inventory(inventory, request)["topology"], request))

        request = self.request_variant(max_networks=1)
        candidate = self.rebind_inventory(inventory, request)["topology"]
        extra_network = copy.deepcopy(candidate["networks"][0])
        extra_network["id"] = "b" * 64
        extra_network["name"] = {"kind": "hashed", "sha256": "b" * 64}
        candidate["networks"].append(extra_network)
        candidate["networks"].sort(key=lambda item: item["id"])
        candidate["network_count"] = len(candidate["networks"])
        topology_cases.append(("networks", candidate, request))

        topology_bytes = len(self.inventory.canonical_bytes(inventory["topology"]))
        request = self.request_variant(max_topology_bytes=topology_bytes - 1)
        topology_cases.append((
            "topology-bytes", self.rebind_inventory(inventory, request)["topology"], request,
        ))

        request = self.request_variant(max_acl_entries=1)
        candidate = self.rebind_inventory(inventory, request)["topology"]
        candidate["trusted_ancestors"][0]["acl_count"] = 1
        candidate["trusted_ancestors"][0]["xattr_count"] = 1
        topology_cases.append(("topology-acl-xattr", candidate, request))

        request = self.request_variant(max_acl_bytes_per_path=1)
        candidate = self.rebind_inventory(inventory, request)["topology"]
        candidate["trusted_ancestors"][0]["metadata_bytes"] = 2
        topology_cases.append(("topology-metadata-bytes", candidate, request))

        embedded_paths = [
            self.request.docker_config_path,
            self.request.docker_socket_path,
            *(path for _role, path in self.request.observed_sources),
            *self.request.trusted_ancestor_paths,
            *self.request.caddy_roots,
        ]
        max_embedded_path_bytes = max(len(path.encode("utf-8")) for path in embedded_paths)
        oversized_raw_path = "/" + "x" * max_embedded_path_bytes
        request = self.request_variant(
            max_path_bytes=max_embedded_path_bytes,
            expected_path_sha256=sorted({
                *self.request.expected_path_sha256,
                digest_text(oversized_raw_path),
            }),
        )
        candidate = self.rebind_inventory(inventory, request)["topology"]
        mount = next(
            item for item in candidate["containers"][0]["mounts"]
            if item["kind"] == "anonymous_volume"
        )
        mount["destination"] = {
            "kind": "raw",
            "sha256": digest_text(oversized_raw_path),
            "value": oversized_raw_path,
        }
        candidate["containers"][0]["mounts"].sort(key=self.inventory.canonical_bytes)
        topology_cases.append(("visible-raw-path-bytes", candidate, request))

        for label, candidate, request in topology_cases:
            with self.subTest(topology=label):
                self.inventory.validate_topology_v2(candidate)
                with self.assertRaisesRegex(
                    self.inventory.InventoryError,
                    "E_REQUEST_EVIDENCE_LIMIT",
                ):
                    self.inventory.validate_topology_v2(candidate, request)

        observation_cases = []
        request = self.request_variant(max_containers=69)
        observation_cases.append((
            "containers", self.rebind_inventory(inventory, request)["observation"], request,
        ))

        observation_bytes = len(self.inventory.canonical_bytes(inventory["observation"]))
        request = self.request_variant(max_observation_bytes=observation_bytes - 1)
        observation_cases.append((
            "observation-bytes", self.rebind_inventory(inventory, request)["observation"], request,
        ))

        request = self.request_variant(max_acl_entries=1)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        candidate["observed_sources"][0]["acl_count"] = 1
        candidate["observed_sources"][0]["xattr_count"] = 1
        observation_cases.append(("observation-acl-xattr", candidate, request))

        request = self.request_variant(max_acl_bytes_per_path=1)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        candidate["observed_sources"][0]["metadata_bytes"] = 2
        observation_cases.append(("observation-metadata-bytes", candidate, request))

        request = self.request_variant(max_recursive_entries=8)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        for item in candidate["containers"]:
            item["writable_layer"] = {
                "count": 0,
                "classification": "empty",
                "operations": [],
                "sha256": self.inventory.identity_sha256([]),
            }
        candidate["containers"][0]["writable_layer"] = {
            "count": 9,
            "classification": "metadata_or_content_changed",
            "operations": ["A"],
            "sha256": "b" * 64,
        }
        observation_cases.append(("writable-item", candidate, request))

        request = self.request_variant(max_recursive_entries=69)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        for item in candidate["containers"]:
            item["writable_layer"] = {
                "count": 1,
                "classification": "metadata_or_content_changed",
                "operations": ["A"],
                "sha256": "b" * 64,
            }
        observation_cases.append(("writable-total", candidate, request))

        request = self.request_variant(max_recursive_entries=8)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        for item in candidate["containers"]:
            item["writable_layer"] = {
                "count": 0,
                "classification": "empty",
                "operations": [],
                "sha256": self.inventory.identity_sha256([]),
            }
        candidate["observed_sources"][0]["entry_count"] = 9
        observation_cases.append(("path-entry-count", candidate, request))

        distinct_roots = {
            item["path_sha256"]
            for item in inventory["observation"]["observed_sources"]
            + inventory["observation"]["persistence"]
            if item["role"] != "tmpfs"
        }
        request = self.request_variant(max_recursive_entries=len(distinct_roots) - 1)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        for item in candidate["containers"]:
            item["writable_layer"] = {
                "count": 0,
                "classification": "empty",
                "operations": [],
                "sha256": self.inventory.identity_sha256([]),
            }
        observation_cases.append(("distinct-path-roots", candidate, request))

        request = self.request_variant(max_recursive_entries=150)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        template = copy.deepcopy(candidate["redis_persistence_members"][0])
        candidate["redis_persistence_members"] = []
        for index in range(151):
            item = copy.deepcopy(template)
            item["path_sha256"] = f"{index + 1:064x}"
            item["size_bytes"] = 0
            candidate["redis_persistence_members"].append(item)
        candidate["redis_persistence_members"].sort(key=self.inventory.canonical_bytes)
        candidate["redis_persistence_member_count"] = 151
        candidate["redis_persistence_members_sha256"] = self.inventory.identity_sha256(
            candidate["redis_persistence_members"],
        )
        observation_cases.append(("redis-member-count", candidate, request))

        request = self.request_variant(max_persistence_file_bytes=1)
        observation_cases.append((
            "redis-member-size", self.rebind_inventory(inventory, request)["observation"], request,
        ))

        request = self.request_variant(max_persistence_file_bytes=10)
        candidate = self.rebind_inventory(inventory, request)["observation"]
        for item in candidate["redis_persistence_members"]:
            item["size_bytes"] = 6
        candidate["redis_persistence_members"].sort(key=self.inventory.canonical_bytes)
        candidate["redis_persistence_members_sha256"] = self.inventory.identity_sha256(
            candidate["redis_persistence_members"],
        )
        observation_cases.append(("redis-total-size", candidate, request))

        for label, candidate, request in observation_cases:
            with self.subTest(observation=label):
                self.inventory.validate_observation_v2(candidate)
                with self.assertRaisesRegex(
                    self.inventory.InventoryError,
                    "E_REQUEST_EVIDENCE_LIMIT",
                ):
                    self.inventory.validate_observation_v2(candidate, request)

        inventory_bytes = len(self.inventory.canonical_bytes(inventory))
        request = self.request_variant(max_inventory_bytes=inventory_bytes - 1)
        candidate = self.rebind_inventory(inventory, request)
        self.inventory.validate_inventory_v2(candidate)
        with self.assertRaisesRegex(
            self.inventory.InventoryError,
            "E_REQUEST_EVIDENCE_LIMIT",
        ):
            self.inventory.validate_inventory_v2(candidate, request)

        command_only = self.request_variant(
            max_command_output_bytes=1,
            max_command_seconds=1,
            max_command_calls=1,
            max_total_command_output_bytes=1,
            max_total_command_seconds=1,
        )
        rebound = self.rebind_inventory(inventory, command_only)
        self.assertEqual(
            rebound,
            self.inventory.validate_inventory_v2(rebound, command_only),
        )

        overlap_request = self.request_variant(max_recursive_entries=10)
        overlap_observation = self.rebind_inventory(
            inventory, overlap_request,
        )["observation"]
        for item in overlap_observation["containers"]:
            item["writable_layer"] = {
                "count": 0,
                "classification": "empty",
                "operations": [],
                "sha256": self.inventory.identity_sha256([]),
            }
        first_path = overlap_observation["persistence"][0]["path_sha256"]
        for item in overlap_observation["persistence"][:2]:
            item["path_sha256"] = first_path
            item["entry_count"] = 10
        overlap_observation["persistence"].sort(
            key=lambda item: (item["role"], item["identity_sha256"]),
        )
        self.assertEqual(
            overlap_observation,
            self.inventory.validate_observation_v2(
                overlap_observation, overlap_request,
            ),
        )

    def test_unapproved_discovered_paths_stay_hashed_but_are_still_observed(self):
        private_paths = {
            str(self.bind), str(self.volume_named), str(self.volume_anon),
        }
        expected = [
            item for item in self.request_dict["expected_path_sha256"]
            if item not in {digest_text(path) for path in private_paths}
        ]
        request = self.request_variant(expected_path_sha256=expected)
        inventory = self.inventory.collect_inventory_v2(
            request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        raw = self.inventory.canonical_bytes(inventory)
        for path in private_paths:
            self.assertNotIn(path.encode("utf-8"), raw)
        self.assertTrue(all(
            item["mountpoint"]["path"]["kind"] == "hashed"
            for item in inventory["topology"]["volumes"]
        ))
        bind = next(
            mount for mount in inventory["topology"]["containers"][0]["mounts"]
            if mount["kind"] == "bind"
        )
        self.assertEqual("hashed", bind["source"]["path"]["kind"])
        persistence_hashes = {
            item["path_sha256"] for item in inventory["observation"]["persistence"]
        }
        self.assertTrue({digest_text(path) for path in private_paths} <= persistence_hashes)

    def test_regular_file_bind_is_observed_without_a_recursive_directory_walk(self):
        bind_file = self.root / "single.conf"
        bind_file.write_bytes(b"fixed-file-bind")
        self.containers[0]["Mounts"][2]["Source"] = str(bind_file)
        expected = sorted({
            *self.request_dict["expected_path_sha256"],
            digest_text(str(bind_file)),
        })
        request = self.request_variant(expected_path_sha256=expected)
        inventory = self.inventory.collect_inventory_v2(
            request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        record = next(
            item for item in inventory["observation"]["persistence"]
            if item["path_sha256"] == digest_text(str(bind_file))
        )
        self.assertEqual(len(b"fixed-file-bind"), record["apparent_size_bytes"])
        self.assertEqual(1, record["entry_count"])

    def test_supports_both_deployment_label_keys_without_emitting_arbitrary_labels(self):
        self.containers[0]["Config"]["Labels"]["deployment.example/id"] = SENSITIVE
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        labels = topology["containers"][0]["ownership_labels"]
        keys = {item["key"] for item in labels}
        self.assertIn("io.deploydesk.deployment-id", keys)
        self.assertIn("com.deploydesk.deployment-id", keys)
        self.assertNotIn("private.secret", keys)
        self.assertNotIn("deployment.example/id", keys)

    def test_network_membership_ports_and_raw_addresses_are_bounded(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        first = topology["containers"][0]
        self.assertEqual("a" * 64, first["network_memberships"][0]["id"])
        self.assertEqual({"wildcard", "loopback", "private"}, {
            item["host_address_class"] for item in first["published_ports"]
        })
        raw = self.inventory.canonical_bytes(topology)
        self.assertNotIn(b"10.23.45.67", raw)
        self.assertNotIn(b"10.23.45.1", raw)

    def test_mount_destinations_and_docker_drivers_require_hash_authorization(self):
        fixtures = copy.deepcopy(self.containers)
        private_destination = "/private-safe-token"
        private_volume_driver = "private-volume-driver"
        private_network_driver = "private-network-driver"
        fixtures[0]["Mounts"][0]["Destination"] = private_destination
        fixtures[0]["Mounts"][0]["Driver"] = private_volume_driver
        volumes = copy.deepcopy(self.volumes)
        networks = copy.deepcopy(self.networks)
        volumes[0]["Driver"] = private_volume_driver
        networks[0]["Driver"] = private_network_driver
        topology = self.inventory.collect_topology_v2(
            self.request,
            FakeRunner(fixtures, volumes, networks, images=self.images),
        )
        raw = self.inventory.canonical_bytes(topology)
        for private in (private_destination, private_volume_driver, private_network_driver):
            self.assertNotIn(private.encode(), raw)
            self.assertIn(digest_text(private).encode(), raw)

        request = self.request_variant(
            expected_path_sha256=sorted({
                *self.request.expected_path_sha256, digest_text(private_destination),
            }),
            expected_name_sha256=sorted({
                *self.request.expected_name_sha256,
                digest_text(private_volume_driver), digest_text(private_network_driver),
            }),
        )
        authorized = self.inventory.canonical_bytes(self.inventory.collect_topology_v2(
            request,
            FakeRunner(fixtures, volumes, networks, images=self.images),
        ))
        for visible in (private_destination, private_volume_driver, private_network_driver):
            self.assertIn(visible.encode(), authorized)

        unsafe_volume_driver = "plugin/example:stable"
        unsafe_network_driver = "plugin/network:stable"
        fixtures[0]["Mounts"][0]["Driver"] = unsafe_volume_driver
        volumes[0]["Driver"] = unsafe_volume_driver
        networks[0]["Driver"] = unsafe_network_driver
        unsafe_request = self.request_variant(
            expected_name_sha256=sorted({
                *self.request.expected_name_sha256,
                digest_text(unsafe_volume_driver), digest_text(unsafe_network_driver),
            }),
        )
        unsafe_raw = self.inventory.canonical_bytes(self.inventory.collect_topology_v2(
            unsafe_request,
            FakeRunner(fixtures, volumes, networks, images=self.images),
        ))
        for private in (unsafe_volume_driver, unsafe_network_driver):
            self.assertNotIn(private.encode(), unsafe_raw)
            self.assertIn(digest_text(private).encode(), unsafe_raw)

    def test_missing_docker_facts_do_not_default_to_empty_values(self):
        deletions = (
            ("container", ("Mounts",)),
            ("labels", ("Config", "Labels")),
            ("entrypoint", ("Config", "Entrypoint")),
            ("command", ("Config", "Cmd")),
            ("ports", ("NetworkSettings", "Ports")),
            ("networks", ("NetworkSettings", "Networks")),
            ("mount-rw", ("Mounts", 0, "RW")),
            ("bind-mode", ("Mounts", 2, "Mode")),
            ("tmpfs-options", ("HostConfig", "Tmpfs")),
            ("structured-mounts", ("HostConfig", "Mounts")),
            ("volume-name", ("Mounts", 0, "Name")),
            ("volume-driver", ("Mounts", 0, "Driver")),
            ("volume-source", ("Mounts", 0, "Source")),
            ("volume-destination", ("Mounts", 0, "Destination")),
            ("volume-mode", ("Mounts", 0, "Mode")),
            ("volume-propagation", ("Mounts", 0, "Propagation")),
            ("bind-source", ("Mounts", 2, "Source")),
            ("bind-propagation", ("Mounts", 2, "Propagation")),
            ("tmpfs-source", ("Mounts", 3, "Source")),
            ("tmpfs-mode", ("Mounts", 3, "Mode")),
            ("tmpfs-propagation", ("Mounts", 3, "Propagation")),
        )
        for label, path in deletions:
            fixtures = copy.deepcopy(self.containers)
            target = fixtures[0]
            for part in path[:-1]:
                target = target[part]
            del target[path[-1]]
            with self.subTest(label=label), self.assertRaises(self.inventory.InventoryError):
                self.inventory.collect_topology_v2(
                    self.request,
                    FakeRunner(fixtures, self.volumes, self.networks, images=self.images),
                )

    def test_volume_options_accept_explicit_null_but_reject_missing_or_nonobject(self):
        volumes = copy.deepcopy(self.volumes)
        volumes[0]["Options"] = None
        topology = self.inventory.collect_topology_v2(
            self.request,
            FakeRunner(self.containers, volumes, self.networks, images=self.images),
        )
        expected = self.inventory.identity_sha256(None)
        self.assertIn(expected, {item["options_sha256"] for item in topology["volumes"]})
        for marker in ("missing", [], "value", {"nested": {}}, {"numeric": 1}):
            invalid = copy.deepcopy(self.volumes)
            if marker == "missing":
                del invalid[0]["Options"]
            else:
                invalid[0]["Options"] = marker
            with self.subTest(marker=marker), self.assertRaises(self.inventory.InventoryError):
                self.inventory.collect_topology_v2(
                    self.request,
                    FakeRunner(self.containers, invalid, self.networks, images=self.images),
                )

    def test_tmpfs_options_bind_real_runtime_mounts_to_one_hostconfig_source(self):
        fixtures = copy.deepcopy(self.containers)
        fixtures[0]["HostConfig"]["Tmpfs"] = {}
        fixtures[0]["HostConfig"]["Mounts"] = [{
            "Type": "tmpfs", "Target": "/tmp",
            "TmpfsOptions": {"SizeBytes": 4096, "Mode": 0o1777},
        }]
        self.inventory.collect_topology_v2(
            self.request,
            FakeRunner(fixtures, self.volumes, self.networks, images=self.images),
        )
        bad = []
        conflict = copy.deepcopy(fixtures)
        conflict[0]["HostConfig"]["Tmpfs"] = {"/tmp": "size=8192"}
        bad.append(conflict)
        orphan = copy.deepcopy(fixtures)
        orphan[0]["HostConfig"]["Mounts"].append({
            "Type": "tmpfs", "Target": "/orphan", "TmpfsOptions": {},
        })
        bad.append(orphan)
        missing = copy.deepcopy(fixtures)
        missing[0]["HostConfig"]["Mounts"][0].pop("TmpfsOptions")
        bad.append(missing)
        numeric_key = copy.deepcopy(fixtures)
        numeric_key[0]["HostConfig"]["Mounts"][0]["TmpfsOptions"] = {1: "unsafe"}
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_MOUNT"):
            self.inventory._tmpfs_option_records(
                numeric_key[0]["HostConfig"],
                numeric_key[0]["Mounts"],
                self.request,
            )
        control_value = copy.deepcopy(fixtures)
        control_value[0]["HostConfig"]["Mounts"][0]["TmpfsOptions"] = {
            "Options": ["safe", "bad\x00value"],
        }
        bad.append(control_value)
        nonfinite = copy.deepcopy(fixtures)
        nonfinite[0]["HostConfig"]["Mounts"][0]["TmpfsOptions"] = {
            "SizeBytes": float("nan"),
        }
        bad.append(nonfinite)
        for item in bad:
            with self.subTest(item=item[0]["HostConfig"]), self.assertRaises(self.inventory.InventoryError):
                self.inventory.collect_topology_v2(
                    self.request,
                    FakeRunner(item, self.volumes, self.networks, images=self.images),
                )

    def test_secret_bearing_docker_fields_and_raw_caddy_upstream_never_escape(self):
        inventory = self.inventory.collect_inventory_v2(self.request, self.runner)
        raw = self.inventory.canonical_bytes(inventory)
        self.assertNotIn(SENSITIVE.encode("utf-8"), raw)
        self.assertNotIn(b"PASSWORD", raw)
        self.assertNotIn(b"10.23.45.67", raw)
        self.assertNotIn(b"upstream-neutral", raw)
        self.assertNotIn(b"Config", raw)

    def test_repo_digest_parser_rejects_mutable_or_unsafe_references(self):
        bad = (
            "registry.example.invalid/team/image:latest",
            "registry.example.invalid/team/image:latest@sha256:" + "a" * 64,
            "https://registry.example.invalid/team/image@sha256:" + "a" * 64,
            "user@registry.example.invalid/team/image@sha256:" + "a" * 64,
            "10.23.45.67/team/image@sha256:" + "a" * 64,
            "Registry.example.invalid/team/image@sha256:" + "a" * 64,
        )
        for value in bad:
            fixture = copy.deepcopy(self.containers[0])
            image_fixture = {"Id": fixture["Image"], "RepoDigests": [value]}
            with self.subTest(value=value), self.assertRaises(self.inventory.InventoryError):
                self.inventory.collect_topology_v2(
                    self.request,
                    FakeRunner([fixture], self.volumes, self.networks, images=[image_fixture]),
                )
        suffix_fixture = copy.deepcopy(self.containers[0])
        caddy_fixture = copy.deepcopy(self.containers[1])
        suffix_image = {"Id": suffix_fixture["Image"], "RepoDigests": [
            "registry.example.invalid.evil/team/image@sha256:" + "a" * 64
        ]}
        topology = self.inventory.collect_topology_v2(
            self.request,
            FakeRunner(
                [suffix_fixture, caddy_fixture], self.volumes, self.networks,
                images=[suffix_image, self.images[1]],
            ),
        )
        self.assertEqual("hashed", topology["containers"][0]["repo_digests"][0]["kind"])
        with self.assertRaises(self.inventory.InventoryError):
            self.request_variant(allowed_registry_dns_prefixes=["999.999.999.999"])

    def test_collect_inventory_rejects_topology_drift_around_one_observation(self):
        runner = FakeRunner(self.containers, self.volumes, self.networks, topology_change_at=3)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_TOPOLOGY_DRIFT"):
            self.inventory.collect_inventory_v2(self.request, runner)

    def test_topology_never_walks_or_diffs_and_observation_diffs_each_container_once(self):
        topology_runner = FakeRunner(self.containers, self.volumes, self.networks)
        with mock.patch.object(self.inventory, "_walk_observed_sources", side_effect=AssertionError("walk in topology")):
            self.inventory.collect_topology_v2(self.request, topology_runner)
        self.assertFalse(any(call[0][-3:-1] == ("diff", "--") for call in topology_runner.calls))
        observation_runner = FakeRunner(self.containers, self.volumes, self.networks)
        topology = self.inventory.collect_topology_v2(self.request, observation_runner)
        observation_runner.calls.clear()
        with mock.patch.object(self.inventory, "_walk_observed_sources", wraps=self.inventory._walk_observed_sources) as walk:
            self.inventory.collect_observation_v2(self.request, observation_runner, topology)
        self.assertEqual(1, walk.call_count)
        diff_ids = [call[0][-1] for call in observation_runner.calls if call[0][-3:-1] == ("diff", "--")]
        self.assertEqual(sorted(item["Id"] for item in self.containers), sorted(diff_ids))
        self.assertEqual(len(diff_ids), len(set(diff_ids)))

    def test_observation_rejects_a_validated_topology_bound_to_another_request(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        wrong = copy.deepcopy(topology)
        wrong["service_role_sha256"] = {
            "caddy": ["8" * 64],
            "redis": ["9" * 64],
        }
        with mock.patch.object(
            self.inventory,
            "validate_topology_v2",
            return_value=wrong,
        ), self.assertRaisesRegex(
            self.inventory.InventoryError,
            "E_OBSERVATION_REQUEST_BINDING",
        ):
            self.inventory.collect_observation_v2(self.request, self.runner, topology)

    def test_same_device_capacity_is_counted_once_but_source_sizes_stay_separate(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        with mock.patch.object(
            self.inventory.os,
            "fstatvfs",
            wraps=self.inventory.os.fstatvfs,
        ) as fstatvfs, mock.patch.object(
            self.inventory.os,
            "statvfs",
            side_effect=AssertionError("path-based statvfs is forbidden"),
        ):
            observation = self.inventory.collect_observation_v2(self.request, self.runner, topology)
        devices = [item["device"] for item in observation["filesystems"]]
        self.assertEqual(len(devices), len(set(devices)))
        self.assertEqual(len(devices), fstatvfs.call_count)
        self.assertEqual({"opt", "postgresql", "redis"}, {
            item["role"] for item in observation["observed_sources"]
        })
        self.assertEqual(5, next(item for item in observation["observed_sources"] if item["role"] == "opt")["apparent_size_bytes"])
        self.assertEqual(13, next(item for item in observation["observed_sources"] if item["role"] == "postgresql")["apparent_size_bytes"])
        self.assertEqual(12, next(item for item in observation["observed_sources"] if item["role"] == "redis")["apparent_size_bytes"])

    def test_union_walker_visits_overlapping_roots_once_and_projects_each_logical_root(self):
        child = self.opt / "nested"
        child.mkdir()
        (child / "child.bin").write_bytes(b"child-data")
        specs = [
            {"role": "opt", "path": str(self.opt), "identity_sha256": "0" * 64},
            {"role": "postgresql", "path": str(child), "identity_sha256": "1" * 64},
            {"role": "persistence", "path": str(self.opt), "identity_sha256": "2" * 64},
            {"role": "redis", "path": str(self.redis), "identity_sha256": "3" * 64},
        ]
        real_scandir = self.inventory.os.scandir
        with mock.patch.object(
            self.inventory, "_observation_walk_specs", return_value=specs,
        ), mock.patch.object(
            self.inventory.os, "scandir", wraps=real_scandir,
        ) as scandir:
            records, filesystems, _members = self.inventory._walk_observed_sources(
                self.request, {}, {}, {},
            )
        self.assertEqual(3, scandir.call_count)
        by_identity = {item["identity_sha256"]: item for item in records}
        self.assertEqual(15, by_identity["0" * 64]["apparent_size_bytes"])
        self.assertEqual(10, by_identity["1" * 64]["apparent_size_bytes"])
        self.assertEqual(
            by_identity["0" * 64]["apparent_size_bytes"],
            by_identity["2" * 64]["apparent_size_bytes"],
        )
        self.assertEqual(len(filesystems), len({item["device"] for item in records}))

        exact_budget = self.request_variant(max_recursive_entries=7)
        with mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs):
            self.inventory._walk_observed_sources(exact_budget, {}, {}, {})
        too_small = self.request_variant(max_recursive_entries=6)
        with mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_LIMIT"):
            self.inventory._walk_observed_sources(too_small, {}, {}, {})

    def test_cross_device_child_projection_never_leaks_descendants_into_parent(self):
        nodes = {
            "/parent": {
                "direct_entry_count": 0,
                "direct_regular_bytes": 0,
                "children": [],
            },
            "/parent/mounted": {
                "direct_entry_count": 0,
                "direct_regular_bytes": 0,
                "children": [],
            },
        }
        self.assertFalse(
            self.inventory._record_physical_child(
                nodes["/parent"],
                "/parent/mounted",
                mock.Mock(st_dev=22, st_size=0),
                is_directory=True,
                traversal_device=11,
                declared_paths={"/parent", "/parent/mounted"},
            ),
        )
        self.assertFalse(
            self.inventory._record_physical_child(
                nodes["/parent/mounted"],
                "/parent/mounted/file",
                mock.Mock(st_dev=22, st_size=5),
                is_directory=False,
                traversal_device=22,
                declared_paths={"/parent", "/parent/mounted"},
            ),
        )
        aggregates = self.inventory._fold_directory_aggregates(
            nodes,
            ["/parent", "/parent/mounted"],
        )
        self.assertEqual((1, 0), aggregates["/parent"])
        self.assertEqual((1, 5), aggregates["/parent/mounted"])

        regular_parent = {
            "direct_entry_count": 0,
            "direct_regular_bytes": 0,
            "children": [],
        }
        self.assertFalse(
            self.inventory._record_physical_child(
                regular_parent,
                "/parent/mounted-file",
                mock.Mock(st_dev=22, st_size=9),
                is_directory=False,
                traversal_device=11,
                declared_paths={"/parent", "/parent/mounted-file"},
            ),
        )
        self.assertEqual(
            (1, 0),
            self.inventory._fold_directory_aggregates(
                {"/parent": regular_parent}, ["/parent"],
            )["/parent"],
        )

        with self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_DEVICE"):
            self.inventory._record_physical_child(
                {
                    "direct_entry_count": 0,
                    "direct_regular_bytes": 0,
                    "children": [],
                },
                "/parent/undeclared",
                mock.Mock(st_dev=22, st_size=0),
                is_directory=True,
                traversal_device=11,
                declared_paths={"/parent"},
            )

    def test_physical_root_selection_uses_only_the_nearest_declared_directory(self):
        facts = {
            "/a": mock.Mock(st_dev=1),
            "/a/nested": mock.Mock(st_dev=1),
            "/a/mount": mock.Mock(st_dev=2),
            "/a/mount/back": mock.Mock(st_dev=1),
        }
        self.assertEqual(
            ["/a", "/a/mount", "/a/mount/back"],
            self.inventory._select_physical_directory_roots(facts),
        )

    def test_unified_walker_keeps_declared_cross_device_subtrees_disjoint(self):
        parent = self.root / "physical-parent"
        mounted = parent / "mounted"
        back = mounted / "back"
        back.mkdir(parents=True)
        (mounted / "payload.bin").write_bytes(b"1234567")
        (back / "dump.rdb").write_bytes(b"12345")
        specs = [
            {"role": "opt", "path": str(parent), "identity_sha256": "0" * 64},
            {"role": "postgresql", "path": str(mounted), "identity_sha256": "1" * 64},
            {"role": "redis", "path": str(back), "identity_sha256": "2" * 64},
        ]

        real_open = self.inventory.os.open
        real_close = self.inventory.os.close
        real_fstat = self.inventory.os.fstat
        real_scandir = self.inventory.os.scandir
        descriptor_paths = {}

        def device_for(path):
            path = os.fspath(Path(path))
            if path == str(back) or path.startswith(str(back) + "/"):
                return 11
            if path == str(mounted) or path.startswith(str(mounted) + "/"):
                return 22
            if path == str(parent) or path.startswith(str(parent) + "/"):
                return 11
            return None

        def with_device(facts, path):
            device = device_for(path)
            if device is None:
                return facts
            projected = types.SimpleNamespace(**{
                name: getattr(facts, name)
                for name in dir(facts)
                if name.startswith("st_")
            })
            projected.st_dev = device
            return projected

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if dir_fd is not None and dir_fd in descriptor_paths:
                full_path = os.path.join(descriptor_paths[dir_fd], os.fspath(path))
            else:
                full_path = os.fspath(path)
            descriptor_paths[descriptor] = os.path.normpath(full_path)
            return descriptor

        def tracked_close(descriptor):
            descriptor_paths.pop(descriptor, None)
            return real_close(descriptor)

        def projected_fstat(descriptor):
            facts = real_fstat(descriptor)
            path = descriptor_paths.get(descriptor)
            return facts if path is None else with_device(facts, path)

        class EntryProxy:
            def __init__(self, entry, directory):
                self._entry = entry
                self._directory = directory
                self.name = entry.name

            def stat(self, *, follow_symlinks=True):
                return with_device(
                    self._entry.stat(follow_symlinks=follow_symlinks),
                    os.path.join(self._directory, self.name),
                )

        class ScandirProxy:
            def __init__(self, iterator, directory):
                self._iterator = iterator
                self._directory = directory

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self._iterator.__exit__(*args)

            def __iter__(self):
                return (
                    EntryProxy(entry, self._directory)
                    for entry in self._iterator
                )

        def projected_scandir(path):
            directory = descriptor_paths[path] if isinstance(path, int) else os.fspath(path)
            return ScandirProxy(real_scandir(path), directory)

        empty_metadata = {
            "acl_count": 0,
            "acl_sha256": self.inventory.identity_sha256([]),
            "xattr_count": 0,
            "xattr_sha256": self.inventory.identity_sha256([]),
            "metadata_bytes": 0,
        }
        patches = (
            mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs),
            mock.patch.object(self.inventory, "_metadata_hashes", return_value=empty_metadata),
            mock.patch.object(self.inventory.os, "open", side_effect=tracked_open),
            mock.patch.object(self.inventory.os, "close", side_effect=tracked_close),
            mock.patch.object(self.inventory.os, "fstat", side_effect=projected_fstat),
            mock.patch.object(self.inventory.os, "scandir", side_effect=projected_scandir),
        )
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            records, filesystems, members = self.inventory._walk_observed_sources(
                self.request, {}, {}, {},
            )
        by_role = {item["role"]: item for item in records}
        self.assertEqual((1, 0), (
            by_role["opt"]["entry_count"], by_role["opt"]["apparent_size_bytes"],
        ))
        self.assertEqual((2, 7), (
            by_role["postgresql"]["entry_count"],
            by_role["postgresql"]["apparent_size_bytes"],
        ))
        self.assertEqual((1, 5), (
            by_role["redis"]["entry_count"], by_role["redis"]["apparent_size_bytes"],
        ))
        self.assertEqual({11, 22}, {item["device"] for item in filesystems})
        self.assertEqual([5], [item["size_bytes"] for item in members])

        undeclared_specs = [specs[0], specs[2]]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                self.inventory, "_observation_walk_specs", return_value=undeclared_specs,
            ))
            stack.enter_context(mock.patch.object(
                self.inventory, "_metadata_hashes", return_value=empty_metadata,
            ))
            stack.enter_context(mock.patch.object(
                self.inventory.os, "open", side_effect=tracked_open,
            ))
            stack.enter_context(mock.patch.object(
                self.inventory.os, "close", side_effect=tracked_close,
            ))
            stack.enter_context(mock.patch.object(
                self.inventory.os, "fstat", side_effect=projected_fstat,
            ))
            stack.enter_context(mock.patch.object(
                self.inventory.os, "scandir", side_effect=projected_scandir,
            ))
            with self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_DEVICE"):
                self.inventory._walk_observed_sources(self.request, {}, {}, {})

    def test_same_path_clones_do_not_multiply_per_entry_coverage_work(self):
        shared = self.root / "shared-root"
        shared.mkdir()
        for index in range(101):
            (shared / f"entry-{index:03d}").write_bytes(b"x")
        specs = [
            {
                "role": "redis" if index == 0 else "persistence",
                "path": str(shared),
                "identity_sha256": f"{index + 1:064x}",
            }
            for index in range(101)
        ]
        with mock.patch.object(
            self.inventory, "_observation_walk_specs", return_value=specs,
        ), mock.patch.object(
            self.inventory,
            "_record_physical_child",
            wraps=self.inventory._record_physical_child,
        ) as coverage:
            records, _filesystems, _members = self.inventory._walk_observed_sources(
                self.request, {}, {}, {},
            )
        self.assertEqual(101, coverage.call_count)
        projected = {
            (
                item["path_sha256"], item["device"], item["ctime_ns"],
                item["apparent_size_bytes"], item["entry_count"],
                item["acl_count"], item["acl_sha256"], item["xattr_count"],
                item["xattr_sha256"], item["metadata_bytes"],
            )
            for item in records
        }
        self.assertEqual(1, len(projected))
        self.assertEqual(101, len(records))

    def test_early_observation_size_gate_runs_before_any_filesystem_probe(self):
        request = self.request_variant(max_observation_bytes=1)
        topology = self.inventory.collect_topology_v2(
            request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        forbidden = AssertionError("filesystem probe before size gate")
        with mock.patch.object(
            self.inventory, "_observation_walk_specs", side_effect=forbidden,
        ), mock.patch.object(
            self.inventory, "_stable_identity", side_effect=forbidden,
        ), mock.patch.object(
            self.inventory, "_open_nofollow", side_effect=forbidden,
        ), mock.patch.object(
            self.inventory.os, "scandir", side_effect=forbidden,
        ), mock.patch.object(
            self.inventory, "_path_metadata", side_effect=forbidden,
        ), self.assertRaisesRegex(self.inventory.InventoryError, "E_OBSERVATION_LIMIT"):
            self.inventory.collect_observation_v2(
                request,
                FakeRunner(self.containers, self.volumes, self.networks),
                topology,
            )

    def test_redis_persistence_projection_is_hashed_once_per_observation(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        with mock.patch.object(
            self.inventory,
            "_redis_persistence_members",
            wraps=self.inventory._redis_persistence_members,
        ) as redis_members:
            self.inventory.collect_observation_v2(
                self.request,
                FakeRunner(self.containers, self.volumes, self.networks),
                topology,
            )
        self.assertEqual(1, redis_members.call_count)

    def test_union_walker_rejects_duplicate_logical_identity(self):
        specs = [
            {"role": "opt", "path": str(self.opt), "identity_sha256": "0" * 64},
            {"role": "postgresql", "path": str(self.pg), "identity_sha256": "0" * 64},
            {"role": "redis", "path": str(self.redis), "identity_sha256": "1" * 64},
        ]
        with mock.patch.object(
            self.inventory,
            "_observation_walk_specs",
            return_value=specs,
        ), self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_IDENTITY"):
            self.inventory._walk_observed_sources(self.request, {}, {}, {})

    def test_fd_capacity_rejects_root_replacement_and_never_uses_path_statvfs(self):
        specs = [
            {"role": "opt", "path": str(self.opt), "identity_sha256": "0" * 64},
            {"role": "postgresql", "path": str(self.pg), "identity_sha256": "1" * 64},
            {"role": "redis", "path": str(self.redis), "identity_sha256": "2" * 64},
        ]
        real_fstatvfs = self.inventory.os.fstatvfs
        moved = self.root / "opt-moved"
        changed = False

        def replacing_fstatvfs(descriptor):
            nonlocal changed
            result = real_fstatvfs(descriptor)
            if not changed:
                changed = True
                self.opt.rename(moved)
                self.opt.mkdir()
            return result

        with mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs), \
             mock.patch.object(self.inventory.os, "fstatvfs", side_effect=replacing_fstatvfs), \
             mock.patch.object(self.inventory.os, "statvfs", side_effect=AssertionError("forbidden")), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_FILESYSTEM_DRIFT"):
            self.inventory._walk_observed_sources(self.request, {}, {}, {})

    def test_missing_xattr_api_is_distinct_from_supported_empty_metadata(self):
        with mock.patch.object(self.inventory.os, "listxattr", None, create=True), \
             mock.patch.object(self.inventory.os, "getxattr", None, create=True):
            topology = self.inventory.collect_topology_v2(self.request, self.runner)
        self.assertFalse(topology["capabilities"]["os"]["xattr_supported"])
        ancestor = topology["trusted_ancestors"][0]
        self.assertNotEqual(self.inventory.identity_sha256([]), ancestor["acl_sha256"])
        self.assertNotEqual(self.inventory.identity_sha256([]), ancestor["xattr_sha256"])

    def test_public_redis_evidence_is_structural_and_unauthenticated_only(self):
        inventory = self.inventory.collect_inventory_v2(self.request, self.runner)
        redis = inventory["topology"]["redis"]
        self.assertNotIn("server_version", redis[0])
        self.assertRegex(redis[0]["command_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            self.inventory.identity_sha256(["/etc/redis/redis.conf"]),
            redis[0]["config_path_sha256"],
        )
        members = inventory["observation"]["redis_persistence_members"]
        self.assertEqual(2, len(members))
        self.assertEqual(2, inventory["observation"]["redis_persistence_member_count"])
        self.assertEqual(
            self.inventory.identity_sha256(members),
            inventory["observation"]["redis_persistence_members_sha256"],
        )
        self.assertEqual({3, 9}, {item["size_bytes"] for item in members})
        self.assertEqual(
            {hashlib.sha256(b"aof").hexdigest(), hashlib.sha256(b"redis-rdb").hexdigest()},
            {item["content_sha256"] for item in members},
        )
        raw = self.inventory.canonical_bytes(inventory).lower()
        for forbidden in (b"redis-cli", b'"auth"', b'"info"', b'"scan"', b'"keys"', b'"dataset"'):
            self.assertNotIn(forbidden, raw)

    def test_empty_redis_persistence_layout_has_an_explicit_empty_commitment(self):
        (self.redis / "dump.rdb").unlink()
        (self.redis / "appendonly.aof").unlink()
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        observation = inventory["observation"]
        self.assertEqual([], observation["redis_persistence_members"])
        self.assertEqual(0, observation["redis_persistence_member_count"])
        self.assertEqual(
            self.inventory.identity_sha256([]),
            observation["redis_persistence_members_sha256"],
        )
        self.assertEqual(inventory, self.inventory.validate_inventory_v2(inventory))

    def test_optional_host_tool_capabilities_are_explicitly_unavailable(self):
        optional = {
            ("/usr/bin/tar", "--version"),
            ("/usr/bin/zstd", "--version"),
            ("/usr/bin/psql", "--version"),
            ("/usr/bin/pg_dump", "--version"),
            ("/usr/bin/redis-server", "--version"),
            ("/usr/bin/caddy", "version"),
            ("/usr/sbin/visudo", "-V"),
        }

        class MissingOptionalRunner(FakeRunner):
            def run(self, argv, *, max_output_bytes, timeout_seconds):
                if tuple(argv) in optional:
                    self.calls.append((tuple(argv), max_output_bytes, timeout_seconds))
                    raise self_inventory.InventoryError("E_COMMAND_NOT_FOUND")
                return super().run(
                    argv,
                    max_output_bytes=max_output_bytes,
                    timeout_seconds=timeout_seconds,
                )

        self_inventory = self.inventory
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            MissingOptionalRunner(self.containers, self.volumes, self.networks),
        )
        capabilities = inventory["topology"]["capabilities"]
        self.assertEqual(
            {
                "host_tar", "host_zstd", "host_psql", "host_pg_dump",
                "host_redis_server", "host_caddy", "host_visudo",
            },
            {key for key in capabilities if key.startswith("host_")},
        )
        for key, value in capabilities.items():
            if key.startswith("host_"):
                self.assertEqual({"available": False}, value)
        self.assertIn("server_version", capabilities["docker"])

        class FailedOptionalRunner(MissingOptionalRunner):
            def run(self, argv, *, max_output_bytes, timeout_seconds):
                if tuple(argv) == ("/usr/bin/caddy", "version"):
                    raise self_inventory.InventoryError("E_COMMAND_FAILED")
                return super().run(
                    argv,
                    max_output_bytes=max_output_bytes,
                    timeout_seconds=timeout_seconds,
                )

        with self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_FAILED"):
            self.inventory.collect_topology_v2(
                self.request,
                FailedOptionalRunner(self.containers, self.volumes, self.networks),
            )

    def test_only_process_enoent_maps_to_command_not_found(self):
        with mock.patch.object(
            self.inventory.subprocess,
            "Popen",
            side_effect=FileNotFoundError("private missing path " + SENSITIVE),
        ), self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_NOT_FOUND"):
            self.inventory.SubprocessRunner().run(
                ("/usr/bin/zstd", "--version"),
                max_output_bytes=16,
                timeout_seconds=1,
            )
        with mock.patch.object(
            self.inventory.subprocess,
            "Popen",
            side_effect=PermissionError("private denied path " + SENSITIVE),
        ), self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_FAILED"):
            self.inventory.SubprocessRunner().run(
                ("/usr/bin/zstd", "--version"),
                max_output_bytes=16,
                timeout_seconds=1,
            )

    def test_persistence_hashing_streams_and_binds_the_open_file_identity(self):
        path = self.redis / "dump.rdb"
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        facts = os.lstat(path)
        with mock.patch.object(
            self.inventory,
            "stable_read_file",
            side_effect=AssertionError("persistence hashing must not buffer the whole file"),
        ):
            self.assertEqual(
                (expected, facts.st_size),
                self.inventory._hash_regular_file(
                    str(path),
                    self.request,
                    expected_facts=facts,
                ),
            )
        changed = list(facts)
        changed[1] += 1
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_FILE_UNSTABLE"):
            self.inventory._hash_regular_file(
                str(path),
                self.request,
                expected_facts=os.stat_result(changed),
            )

    def test_redis_aof_manifest_is_closed_and_never_reads_config_lookalikes(self):
        (self.redis / "dump.rdb").unlink()
        (self.redis / "appendonly.aof").unlink()
        aof_dir = self.redis / "appendonlydir"
        aof_dir.mkdir()
        base = aof_dir / "appendonly.aof.1.base.rdb"
        incr = aof_dir / "appendonly.aof.1.incr.aof"
        manifest = aof_dir / "appendonly.aof.manifest"
        base.write_bytes(b"base")
        incr.write_bytes(b"increment")
        manifest.write_text(
            "file appendonly.aof.1.base.rdb seq 1 type b\n"
            "file appendonly.aof.1.incr.aof seq 1 type i\n",
            encoding="ascii",
        )
        lookalike = aof_dir / "appendonly-private.conf"
        lookalike.write_text(SENSITIVE, encoding="utf-8")
        hashed_paths = []
        original = self.inventory._hash_regular_file

        def recording_hash(path, request, **kwargs):
            hashed_paths.append(path)
            return original(path, request, **kwargs)

        with mock.patch.object(self.inventory, "_hash_regular_file", side_effect=recording_hash):
            inventory = self.inventory.collect_inventory_v2(
                self.request,
                FakeRunner(self.containers, self.volumes, self.networks),
            )
        self.assertNotIn(str(lookalike), hashed_paths)
        expected_paths = {
            "appendonlydir/appendonly.aof.manifest",
            "appendonlydir/appendonly.aof.1.base.rdb",
            "appendonlydir/appendonly.aof.1.incr.aof",
        }
        self.assertEqual(
            {digest_text(path) for path in expected_paths},
            {
                item["path_sha256"]
                for item in inventory["observation"]["redis_persistence_members"]
            },
        )

        bad_manifests = (
            "file ../escape.aof seq 1 type i\n",
            "file appendonly.aof.1.incr.aof seq 1 type i\n"
            "file appendonly.aof.1.base.rdb seq 1 type b\n",
            "file appendonly.aof.1.base.rdb seq 1 type b\n"
            "file appendonly.aof.1.base.rdb seq 1 type b\n",
        )
        for value in bad_manifests:
            manifest.write_text(value, encoding="ascii")
            with self.subTest(value=value), self.assertRaisesRegex(
                self.inventory.InventoryError, "E_REDIS_MANIFEST"
            ):
                topology = self.inventory.collect_topology_v2(
                    self.request,
                    FakeRunner(self.containers, self.volumes, self.networks),
                )
                self.inventory.collect_observation_v2(
                    self.request,
                    FakeRunner(self.containers, self.volumes, self.networks),
                    topology,
                )

        manifest.write_text(
            "file appendonly.aof.1.base.rdb seq 1 type b\n"
            "file appendonly.aof.1.incr.aof seq 1 type i\n",
            encoding="ascii",
        )
        (self.redis / "appendonly.aof").write_bytes(b"ambiguous-legacy")
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_REDIS_MANIFEST"):
            topology = self.inventory.collect_topology_v2(
                self.request,
                FakeRunner(self.containers, self.volumes, self.networks),
            )
            self.inventory.collect_observation_v2(
                self.request,
                FakeRunner(self.containers, self.volumes, self.networks),
                topology,
            )

    def test_recursive_walk_uses_nofollow_directory_fds_and_rejects_nested_drift(self):
        nested = self.redis / "nested"
        nested.mkdir()
        (nested / "stable.bin").write_bytes(b"stable")
        spec = {"role": "redis", "path": str(self.redis), "identity_sha256": "8" * 64}
        scandir_arguments = []
        real_scandir = self.inventory.os.scandir
        original_hash = self.inventory._hash_regular_file
        changed = False

        def recording_scandir(path):
            scandir_arguments.append(path)
            return real_scandir(path)

        def mutate_nested(path, request, **kwargs):
            nonlocal changed
            result = original_hash(path, request, **kwargs)
            if not changed:
                changed = True
                (nested / "late.bin").write_bytes(b"late")
            return result

        with mock.patch.object(self.inventory.os, "scandir", side_effect=recording_scandir), \
             mock.patch.object(self.inventory, "_hash_regular_file", side_effect=mutate_nested), \
             mock.patch.object(self.inventory, "_observation_walk_specs", return_value=[spec]), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_DRIFT"):
            self.inventory._walk_observed_sources(self.request, {}, {}, {})
        self.assertTrue(scandir_arguments)
        self.assertTrue(all(isinstance(item, int) for item in scandir_arguments))

    def test_validator_rejects_unknown_nested_keys_and_noncanonical_order(self):
        inventory = self.inventory.collect_inventory_v2(self.request, self.runner)
        invalid = copy.deepcopy(inventory)
        invalid["topology"]["containers"][0]["environment"] = [SENSITIVE]
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)
        invalid = copy.deepcopy(inventory)
        raw_name = invalid["topology"]["containers"][0]["name"]
        raw_name["sha256"] = "0" * 64
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)
        invalid = copy.deepcopy(inventory)
        invalid["topology"]["containers"] = list(reversed(invalid["topology"]["containers"]))
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)

    def test_validators_reject_duplicate_overlimit_and_unlinked_records(self):
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )

        topology_mutations = []
        invalid = copy.deepcopy(inventory["topology"])
        invalid["containers"][0]["mounts"] = [
            copy.deepcopy(invalid["containers"][0]["mounts"][0]) for _ in range(257)
        ]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["containers"][0]["published_ports"] = [
            copy.deepcopy(invalid["containers"][0]["published_ports"][0]) for _ in range(1025)
        ]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["containers"][0]["network_memberships"] *= 2
        topology_mutations.append(invalid)
        for list_name, count_name in (("volumes", "volume_count"), ("networks", "network_count")):
            invalid = copy.deepcopy(inventory["topology"])
            invalid[list_name].append(copy.deepcopy(invalid[list_name][0]))
            invalid[list_name] = sorted(
                invalid[list_name],
                key=(
                    (lambda item: self.inventory.canonical_bytes(item["name"]))
                    if list_name == "volumes" else (lambda item: item["id"])
                ),
            )
            invalid[count_name] += 1
            topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["trusted_ancestors"] *= 2
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["files"] *= 2
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["redis"] *= 2
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["trusted_ancestors"][0]["acl_count"] = 257
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        first = invalid["containers"][0]
        deployment = next(
            item for item in first["ownership_labels"]
            if item["key"] == "com.deploydesk.deployment-id"
        )
        deployment["value"] = {"kind": "hashed", "sha256": "f" * 64}
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        repo = invalid["containers"][0]["repo_digests"][0]
        repo["value"] = "10.23.45.67/team/image@sha256:" + "a" * 64
        repo["sha256"] = digest_text(repo["value"])
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["containers"][0]["network_memberships"][0]["id"] = "b" * 64
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["containers"][0]["network_memberships"][0]["name"] = {
            "kind": "hashed", "sha256": "b" * 64,
        }
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        membership = invalid["containers"][0]["network_memberships"][0]
        membership["name"] = {
            "kind": "hashed", "sha256": membership["name"]["sha256"],
        }
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        volume_mount = next(
            item for item in invalid["containers"][0]["mounts"]
            if item["kind"] in {"named_volume", "anonymous_volume"}
        )
        volume_mount["name"] = {"kind": "hashed", "sha256": "b" * 64}
        invalid["containers"][0]["mounts"].sort(key=self.inventory.canonical_bytes)
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        volume_mount = next(
            item for item in invalid["containers"][0]["mounts"]
            if item["kind"] == "named_volume"
        )
        volume_mount["name"] = {
            "kind": "hashed",
            "sha256": volume_mount["name"]["sha256"],
        }
        invalid["containers"][0]["mounts"].sort(key=self.inventory.canonical_bytes)
        invalid["redis"][0]["persistence_mount_sha256"] = [
            self.inventory.identity_sha256(volume_mount),
        ]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["redis"][0]["container_id"] = invalid["containers"][1]["id"]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["redis"][0]["persistence_mount_sha256"] = ["b" * 64]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["container_ids"] = [invalid["containers"][0]["id"]]
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["owners"][0]["source_path_sha256"] = "b" * 64
        invalid["caddy"]["owners"].sort(key=self.inventory.canonical_bytes)
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["behaviors"][0]["source_host_sha256"] = "b" * 64
        invalid["caddy"]["behaviors"].sort(key=self.inventory.canonical_bytes)
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        extra_file = copy.deepcopy(invalid["caddy"]["files"][0])
        extra_file["path"] = {"kind": "hashed", "sha256": "b" * 64}
        invalid["caddy"]["files"].append(extra_file)
        invalid["caddy"]["files"].sort(
            key=lambda item: self.inventory.canonical_bytes(item["path"]),
        )
        extra_owner = copy.deepcopy(invalid["caddy"]["owners"][0])
        extra_owner["source_path_sha256"] = "b" * 64
        invalid["caddy"]["owners"].append(extra_owner)
        invalid["caddy"]["owners"].sort(key=self.inventory.canonical_bytes)
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["trusted_ancestors"] = []
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["files"] = []
        invalid["caddy"]["owners"] = []
        invalid["caddy"]["behaviors"] = []
        topology_mutations.append(invalid)
        for capability in ("nofollow_supported", "dir_fd_supported"):
            invalid = copy.deepcopy(inventory["topology"])
            invalid["capabilities"]["os"][capability] = False
            topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["caddy"]["files"][0]["type"] = "directory"
        topology_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["topology"])
        invalid["trusted_ancestors"][0]["type"] = "regular"
        topology_mutations.append(invalid)
        for index, invalid in enumerate(topology_mutations):
            with self.subTest(topology=index), self.assertRaises(self.inventory.InventoryError):
                self.inventory.validate_topology_v2(invalid)

        observation_mutations = []
        invalid = copy.deepcopy(inventory["observation"])
        invalid["containers"] *= 2
        invalid["containers"].sort(key=lambda item: item["id"])
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["observed_sources"] = []
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["persistence"] *= 2
        invalid["persistence"].sort(key=lambda item: (item["role"], item["identity_sha256"]))
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["redis_persistence_members"] *= 2
        invalid["redis_persistence_members"].sort(key=self.inventory.canonical_bytes)
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        writable = invalid["containers"][0]["writable_layer"]
        writable["count"] = 0
        writable["classification"] = "metadata_or_content_changed"
        writable["operations"] = ["A"]
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        for container_record in invalid["containers"]:
            writable = container_record["writable_layer"]
            writable["count"] = 4_000
            writable["classification"] = "metadata_or_content_changed"
            writable["operations"] = ["A"]
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["observed_sources"][0]["acl_count"] = 200
        invalid["observed_sources"][0]["xattr_count"] = 100
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        for member in invalid["redis_persistence_members"]:
            member["size_bytes"] = 5 * 1024 * 1024 * 1024
        invalid["redis_persistence_members_sha256"] = self.inventory.identity_sha256(
            invalid["redis_persistence_members"],
        )
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["persistence"][0]["identity_sha256"] = invalid["observed_sources"][0]["identity_sha256"]
        invalid["persistence"].sort(
            key=lambda item: (item["role"], item["identity_sha256"]),
        )
        observation_mutations.append(invalid)
        invalid = copy.deepcopy(inventory["observation"])
        invalid["filesystems"][0]["available_bytes"] = (
            invalid["filesystems"][0]["capacity_bytes"] + 1
        )
        observation_mutations.append(invalid)
        for index, invalid in enumerate(observation_mutations):
            with self.subTest(observation=index), self.assertRaises(self.inventory.InventoryError):
                self.inventory.validate_observation_v2(invalid)

        for field in ("persistence", "filesystems"):
            invalid = copy.deepcopy(inventory)
            invalid["observation"][field] = []
            with self.subTest(unlinked=field), self.assertRaises(self.inventory.InventoryError):
                self.inventory.validate_inventory_v2(invalid)
        invalid = copy.deepcopy(inventory)
        invalid["observation"]["persistence"][0]["path_sha256"] = "b" * 64
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)
        invalid = copy.deepcopy(inventory)
        invalid["observation"]["redis_persistence_members"] = []
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)
        invalid = copy.deepcopy(inventory)
        tmpfs = next(
            item for item in invalid["observation"]["persistence"]
            if item["role"] == "tmpfs"
        )
        tmpfs["ctime_ns"] = 1
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.validate_inventory_v2(invalid)

    def test_path_aliases_symlinks_hardlinks_and_oversized_paths_are_rejected(self):
        for path in ("relative", "/tmp//alias", "/tmp/../escape", "/tmp/trailing/"):
            with self.subTest(path=path), self.assertRaises(self.inventory.InventoryError):
                self.inventory.safe_absolute_path(path, 4096)
        self.inventory.safe_absolute_path("/" + "a" * 4095, 4096)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.safe_absolute_path("/" + "a" * 4096, 4096)
        target = self.root / "regular"
        target.write_text("x", encoding="utf-8")
        alias = self.root / "alias"
        alias.symlink_to(target)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.stable_read_file(alias, max_bytes=10, require_owner_only=False)
        hard = self.root / "hard"
        os.link(target, hard)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.stable_read_file(target, max_bytes=10, require_owner_only=False)
        directory = self.root / "real-directory"
        directory.mkdir()
        nested = directory / "nested"
        nested.write_text("safe", encoding="utf-8")
        intermediate = self.root / "intermediate"
        intermediate.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory._path_metadata(str(intermediate / "nested"), self.request)

    def test_request_file_requires_canonical_owner_only_regular_single_link_bytes(self):
        path = self.root / "request.json"
        raw = self.inventory.canonical_bytes(self.request_dict)
        path.write_bytes(raw)
        path.chmod(0o600)
        self.assertEqual(
            self.request,
            self.inventory.read_request_file_v2(path, hashlib.sha256(raw).hexdigest(), require_root=False),
        )
        path.chmod(0o644)
        with self.assertRaises(self.inventory.InventoryError):
            self.inventory.read_request_file_v2(path, hashlib.sha256(raw).hexdigest(), require_root=False)

    def test_nofollow_is_mandatory_and_special_leaf_open_is_nonblocking(self):
        path = self.root / "request.json"
        path.write_text("{}", encoding="utf-8")
        with mock.patch.object(self.inventory.os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(self.inventory.InventoryError, "E_FILE_UNSAFE"):
                self.inventory.stable_read_file(
                    path,
                    max_bytes=10,
                    require_owner_only=False,
                )

        fifo = self.root / "request.fifo"
        os.mkfifo(fifo)
        real_open = self.inventory.os.open
        leaf_flags = []

        def guarded_open(name, flags, *args, **kwargs):
            if name == fifo.name:
                leaf_flags.append(flags)
                if not flags & self.inventory.os.O_NONBLOCK:
                    raise AssertionError("FIFO leaf was opened in blocking mode")
            return real_open(name, flags, *args, **kwargs)

        with mock.patch.object(self.inventory.os, "open", side_effect=guarded_open):
            with self.assertRaisesRegex(self.inventory.InventoryError, "E_FILE_UNSAFE|E_FILE_TYPE"):
                self.inventory.stable_read_file(
                    fifo,
                    max_bytes=10,
                    require_owner_only=False,
                )
        self.assertTrue(leaf_flags)
        self.assertTrue(leaf_flags[-1] & self.inventory.os.O_NONBLOCK)

    def test_subprocess_failures_always_close_kill_and_reap(self):
        class Pipe:
            def __init__(self):
                self.closed = False

            def fileno(self):
                return 123

            def close(self):
                self.closed = True

        class Process:
            def __init__(self, *, wait_timeout):
                self.stdout = Pipe()
                self.wait_timeout = wait_timeout
                self.killed = False
                self.reaped = False

            def poll(self):
                return -9 if self.reaped else None

            def kill(self):
                self.killed = True

            def wait(self, timeout=None):
                if timeout is not None and self.wait_timeout:
                    raise self.inventory_timeout
                self.reaped = True
                return -9 if self.killed else 0

        class Selector:
            def __init__(self):
                self.closed = False

            def register(self, *_args):
                return None

            def select(self, _remaining):
                return [(object(), object())]

            def close(self):
                self.closed = True

        for scenario in ("wait_timeout", "read_error", "read_enoent"):
            process = Process(wait_timeout=scenario == "wait_timeout")
            process.inventory_timeout = self.inventory.subprocess.TimeoutExpired(("safe",), 1)
            selector = Selector()
            read_mock = mock.Mock()
            if scenario == "wait_timeout":
                read_mock.return_value = b""
            elif scenario == "read_enoent":
                read_mock.side_effect = FileNotFoundError(
                    "post-creation missing path " + SENSITIVE
                )
            else:
                read_mock.side_effect = OSError("private stdout failure " + SENSITIVE)
            with self.subTest(scenario=scenario), \
                 mock.patch.object(self.inventory.subprocess, "Popen", return_value=process), \
                 mock.patch.object(self.inventory.selectors, "DefaultSelector", return_value=selector), \
                 mock.patch.object(self.inventory.os, "read", read_mock):
                code = "E_COMMAND_TIMEOUT" if scenario == "wait_timeout" else "E_COMMAND_FAILED"
                with self.assertRaisesRegex(self.inventory.InventoryError, code):
                    self.inventory.SubprocessRunner().run(
                        ("/usr/bin/uname", "-r"),
                        max_output_bytes=16,
                        timeout_seconds=1,
                    )
            self.assertTrue(process.killed)
            self.assertTrue(process.reaped)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(selector.closed)

    def test_command_vectors_are_absolute_fixed_and_exclude_mutating_or_secret_commands(self):
        self.inventory.collect_inventory_v2(self.request, self.runner)
        forbidden = {"sh", "bash", "-c", "eval", "logs", "login", "pull", "push", "exec", "cp", "export", "save", "redis-cli", "--format"}
        for argv, max_bytes, seconds in self.runner.calls:
            self.assertTrue(argv[0].startswith("/"), argv)
            self.assertFalse(forbidden & set(argv), argv)
            self.assertGreater(max_bytes, 0)
            self.assertGreater(seconds, 0)
        docker_suffixes = [
            argv[5:] for argv, _max_bytes, _seconds in self.runner.calls
            if argv[:5] == (
                "/usr/bin/docker", "--config", "/etc/docker",
                "--host", "unix:///var/run/docker.sock",
            )
        ]
        self.assertIn(("volume", "ls", "-q"), docker_suffixes)
        self.assertNotIn(("volume", "ls", "-q", "--no-trunc"), docker_suffixes)

        docker_prefix = (
            "/usr/bin/docker", "--config", "/etc/docker",
            "--host", "unix:///var/run/docker.sock",
        )
        identifier = self.containers[0]["Id"]
        for argv in (
            ("/usr/bin/docker", "stats"),
            docker_prefix + ("container", "stats", identifier),
            docker_prefix + ("container", "diff", "--", identifier, SENSITIVE),
        ):
            with self.subTest(argv=argv), self.assertRaisesRegex(
                self.inventory.InventoryError, "E_COMMAND_VECTOR"
            ):
                self.inventory._run(self.request, self.runner, argv)

    def test_capability_parsers_reject_duplicate_versions_and_appended_text(self):
        class PoisonedRunner(FakeRunner):
            def __init__(self, outer, poisoned_argv, poisoned_output):
                super().__init__(outer.containers, outer.volumes, outer.networks)
                self.poisoned_argv = poisoned_argv
                self.poisoned_output = poisoned_output

            def run(self, argv, *, max_output_bytes, timeout_seconds):
                if tuple(argv) == self.poisoned_argv:
                    self.calls.append((tuple(argv), max_output_bytes, timeout_seconds))
                    return self.poisoned_output
                return super().run(
                    argv,
                    max_output_bytes=max_output_bytes,
                    timeout_seconds=timeout_seconds,
                )

        docker_prefix = (
            "/usr/bin/docker", "--config", "/etc/docker",
            "--host", "unix:///var/run/docker.sock",
        )
        cases = (
            (
                docker_prefix + ("version",),
                "Client:\n Version: 27.5.1\n API version: 1.47\n"
                "Server:\n Version: 27.5.1\n API version: 1.47\n"
                " Version: 99.99\n",
                "E_CAP_DOCKER",
            ),
            (("/usr/bin/tar", "--version"), "tar (GNU tar) 1.35\n" + SENSITIVE + "\n", "E_CAP_TAR"),
            (("/usr/bin/zstd", "--version"), "*** Zstandard CLI (64-bit) v1.5.6\n" + SENSITIVE + "\n", "E_CAP_ZSTD"),
            (("/usr/bin/psql", "--version"), "psql (PostgreSQL) 16.4\n" + SENSITIVE + "\n", "E_CAP_POSTGRESQL"),
            (("/usr/bin/pg_dump", "--version"), "pg_dump (PostgreSQL) 16.4\n" + SENSITIVE + "\n", "E_CAP_POSTGRESQL"),
            (("/usr/bin/redis-server", "--version"), "Redis server v=7.2.5 sha=00000000:0 malloc=libc bits=64 build=abc\n" + SENSITIVE + "\n", "E_CAP_REDIS"),
            (("/usr/bin/caddy", "version"), "v2.8.4\n" + SENSITIVE + "\n", "E_CAP_CADDY"),
            (("/usr/sbin/visudo", "-V"), "Visudo version 1.9.15p5\n" + SENSITIVE + "\n", "E_CAP_VISUDO"),
        )
        for argv, output, code in cases:
            with self.subTest(argv=argv), self.assertRaisesRegex(
                self.inventory.InventoryError, code
            ):
                self.inventory._collect_capabilities(
                    self.request,
                    PoisonedRunner(self, argv, output),
                )

    def test_capability_parsers_accept_closed_standard_linux_outputs(self):
        docker_prefix = (
            "/usr/bin/docker", "--config", "/etc/docker",
            "--host", "unix:///var/run/docker.sock",
        )
        standard = {
            docker_prefix + ("version",): (
                "Client: Docker Engine - Community\n"
                " Version:           27.5.1\n"
                " API version:       1.47\n"
                " Go version:        go1.22.11\n"
                " Git commit:        9f9e405\n"
                " Built:             Wed Jan 22 13:41:51 2025\n"
                " OS/Arch:           linux/amd64\n"
                " Context:           default\n\n"
                "Server: Docker Engine - Community\n"
                " Engine:\n"
                "  Version:          27.5.1\n"
                "  API version:      1.47 (minimum version 1.24)\n"
                "  Go version:       go1.22.11\n"
                "  Git commit:       4c9b3b0\n"
                "  Built:            Wed Jan 22 13:41:51 2025\n"
                "  OS/Arch:          linux/amd64\n"
                "  Experimental:     false\n"
                " containerd:\n"
                "  Version:          1.7.25\n"
                "  GitCommit:        bcf6a65\n"
                " runc:\n"
                "  Version:          1.2.4\n"
                "  GitCommit:        v1.2.4-0-g6c52b3f\n"
                " docker-init:\n"
                "  Version:          0.19.0\n"
                "  GitCommit:        de40ad0\n"
            ),
            ("/usr/bin/psql", "--version"): (
                "psql (PostgreSQL) 16.4 (Ubuntu 16.4-0ubuntu0.24.04.2)\n"
            ),
            ("/usr/bin/pg_dump", "--version"): (
                "pg_dump (PostgreSQL) 16.4 (Debian 16.4-1.pgdg120+2)\n"
            ),
            ("/usr/sbin/visudo", "-V"): (
                "visudo version 1.9.15p5\nvisudo grammar version 50\n"
            ),
        }

        class StandardRunner(FakeRunner):
            def run(self, argv, *, max_output_bytes, timeout_seconds):
                if tuple(argv) in standard:
                    self.calls.append((tuple(argv), max_output_bytes, timeout_seconds))
                    return standard[tuple(argv)]
                return super().run(
                    argv,
                    max_output_bytes=max_output_bytes,
                    timeout_seconds=timeout_seconds,
                )

        capabilities = self.inventory._collect_capabilities(
            self.request,
            StandardRunner(self.containers, self.volumes, self.networks),
        )
        self.assertEqual("27.5.1", capabilities["docker"]["server_version"])
        self.assertEqual(
            {"available": True, "version": "16.4"},
            capabilities["host_psql"],
        )
        self.assertEqual(
            {"available": True, "version": "16.4"},
            capabilities["host_pg_dump"],
        )
        self.assertEqual(
            {"available": True, "version": "1.9.15p5"},
            capabilities["host_visudo"],
        )

    def test_resource_overflow_is_rejected_before_canonical_output(self):
        too_many = self.containers + [container(71)]
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_CONTAINER_LIMIT"):
            self.inventory.collect_topology_v2(
                self.request,
                FakeRunner(too_many, self.volumes, self.networks),
            )
        limited_mapping = {
            key: value for key, value in self.request_dict.items()
            if key not in {"request_identity_projection_sha256", "inventory_target_claim_sha256"}
        }
        limited_mapping["max_topology_bytes"] = 512
        limited_mapping["request_identity_projection_sha256"] = self.inventory.identity_sha256(limited_mapping)
        limited_mapping["inventory_target_claim_sha256"] = "7" * 64
        limited = self.inventory.InventoryRequestV2.from_mapping(limited_mapping)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_TOPOLOGY_LIMIT"):
            self.inventory.collect_topology_v2(limited, self.runner)

    def test_request_specific_observation_and_combined_byte_limits_are_enforced(self):
        topology = self.inventory.collect_topology_v2(self.request, self.runner)
        observation = self.inventory.collect_observation_v2(self.request, self.runner, topology)
        observation_limit = len(self.inventory.canonical_bytes(observation)) - 1
        limited_observation = self.request_variant(max_observation_bytes=observation_limit)
        limited_topology = self.inventory.collect_topology_v2(limited_observation, FakeRunner(self.containers, self.volumes, self.networks))
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_OBSERVATION_LIMIT"):
            self.inventory.collect_observation_v2(
                limited_observation,
                FakeRunner(self.containers, self.volumes, self.networks),
                limited_topology,
            )
        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        inventory_limit = len(self.inventory.canonical_bytes(inventory)) - 1
        limited_inventory = self.request_variant(max_inventory_bytes=inventory_limit)
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_INVENTORY_LIMIT"):
            self.inventory.collect_inventory_v2(
                limited_inventory,
                FakeRunner(self.containers, self.volumes, self.networks),
            )

    def test_recursive_and_acl_xattr_budgets_accept_n_and_reject_n_plus_one(self):
        empty = self.root / "empty"
        empty.mkdir()
        request = self.request_variant(max_recursive_entries=1)
        specs = [
            {"role": "opt", "path": str(empty), "identity_sha256": "8" * 64},
            {"role": "redis", "path": str(empty), "identity_sha256": "9" * 64},
        ]
        with mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs):
            self.inventory._walk_observed_sources(request, {}, {}, {})
        (empty / "one").write_bytes(b"x")
        with mock.patch.object(self.inventory, "_observation_walk_specs", return_value=specs), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_WALK_LIMIT"):
            self.inventory._walk_observed_sources(request, {}, {}, {})
        acl_request = self.request_variant(max_acl_entries=2, max_acl_bytes_per_path=2)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a", "b"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"", create=True):
            self.inventory._metadata_hashes(str(empty), acl_request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a", "b", "c"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"", create=True), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_METADATA_ENTRY_LIMIT"):
            self.inventory._metadata_hashes(str(empty), acl_request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"x", create=True):
            self.inventory._metadata_hashes(str(empty), acl_request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"xx", create=True), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_METADATA_BYTE_LIMIT"):
            self.inventory._metadata_hashes(str(empty), acl_request)
        hard_names = [f"x{index:03d}" for index in range(256)]
        with mock.patch.object(self.inventory.os, "listxattr", return_value=hard_names, create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"", create=True):
            self.inventory._metadata_hashes(str(empty), self.request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=hard_names + ["overflow"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"", create=True), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_METADATA_ENTRY_LIMIT"):
            self.inventory._metadata_hashes(str(empty), self.request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"x" * 65_535, create=True):
            self.inventory._metadata_hashes(str(empty), self.request)
        with mock.patch.object(self.inventory.os, "listxattr", return_value=["a"], create=True), \
             mock.patch.object(self.inventory.os, "getxattr", return_value=b"x" * 65_536, create=True), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_METADATA_BYTE_LIMIT"):
            self.inventory._metadata_hashes(str(empty), self.request)

    def test_acl_xattr_collection_is_bound_to_the_nofollow_descriptor(self):
        seen = []

        def listxattr(target, **kwargs):
            seen.append(("list", target, kwargs))
            return ["user.safe"]

        def getxattr(target, name, **kwargs):
            seen.append(("get", target, kwargs))
            self.assertEqual("user.safe", name)
            return b"value"

        with mock.patch.object(self.inventory.os, "listxattr", side_effect=listxattr, create=True), \
             mock.patch.object(self.inventory.os, "getxattr", side_effect=getxattr, create=True):
            self.inventory._metadata_hashes(str(self.opt), self.request)
        self.assertEqual(["list", "get"], [item[0] for item in seen])
        self.assertTrue(all(isinstance(item[1], int) for item in seen))
        self.assertTrue(all(item[2] == {} for item in seen))

    def test_global_command_count_byte_and_elapsed_time_budgets_fail_closed(self):
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_CALL_BUDGET"):
            self.inventory.collect_topology_v2(
                self.request_variant(max_command_calls=1),
                FakeRunner(self.containers, self.volumes, self.networks),
            )
        with self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_BYTE_BUDGET"):
            self.inventory.collect_topology_v2(
                self.request_variant(max_total_command_output_bytes=1),
                FakeRunner(self.containers, self.volumes, self.networks),
            )
        timed_request = self.request_variant(max_total_command_seconds=1)
        with mock.patch.object(self.inventory.time, "monotonic", side_effect=[0.0, 2.0]), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_TIME_BUDGET"):
            self.inventory._BudgetedRunner(timed_request, FakeRunner([], [], [])).run(
                ("/usr/bin/uname", "-r"), max_output_bytes=100, timeout_seconds=1,
            )

        class SlowMissingRunner:
            def run(self, argv, *, max_output_bytes, timeout_seconds):
                raise self_inventory.InventoryError("E_COMMAND_NOT_FOUND")

        self_inventory = self.inventory
        with mock.patch.object(self.inventory.time, "monotonic", side_effect=[0.0, 2.0]), \
             self.assertRaisesRegex(self.inventory.InventoryError, "E_COMMAND_TIME_BUDGET"):
            self.inventory._BudgetedRunner(timed_request, SlowMissingRunner()).run(
                ("/usr/bin/zstd", "--version"), max_output_bytes=100, timeout_seconds=1,
            )

    def test_cli_rejects_duplicate_or_secret_bearing_arguments_without_echo(self):
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()
                self.text = io.StringIO()
            def write(self, value):
                return self.text.write(value)

        cases = (
            ["--request-file", "/safe", "--request-file", "/other", "--expected-request-sha256", "0" * 64],
            ["--request-file", "/safe", "--expected-request-sha256", "0" * 64, "--unknown", SENSITIVE],
        )
        for arguments in cases:
            stdout = Output()
            stderr = io.StringIO()
            with self.subTest(arguments=arguments), \
                 mock.patch.object(self.inventory.sys, "stdout", stdout), \
                 contextlib.redirect_stderr(stderr):
                self.assertEqual(2, self.inventory.main(arguments))
            self.assertEqual(b"", stdout.buffer.getvalue())
            self.assertEqual("inventory-v2-error:E_CLI_ARGUMENT\n", stderr.getvalue())
            self.assertNotIn(SENSITIVE, stderr.getvalue())

    def test_cli_success_is_one_canonical_line_and_unexpected_failure_is_fixed(self):
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, value):
                raise AssertionError("text stdout is forbidden")

        inventory = self.inventory.collect_inventory_v2(
            self.request,
            FakeRunner(self.containers, self.volumes, self.networks),
        )
        arguments = [
            "--request-file", "/safe/request.json",
            "--expected-request-sha256", "0" * 64,
        ]
        stdout = Output()
        stderr = io.StringIO()
        with mock.patch.object(self.inventory.sys, "stdout", stdout), \
             contextlib.redirect_stderr(stderr), \
             mock.patch.object(self.inventory, "require_root"), \
             mock.patch.object(self.inventory, "read_request_file_v2", return_value=self.request), \
             mock.patch.object(self.inventory, "collect_inventory_v2", return_value=inventory):
            self.assertEqual(0, self.inventory.main(arguments))
        self.assertEqual(self.inventory.canonical_bytes(inventory), stdout.buffer.getvalue())
        self.assertEqual(1, stdout.buffer.getvalue().count(b"\n"))
        self.assertEqual("", stderr.getvalue())

        stdout = Output()
        stderr = io.StringIO()
        with mock.patch.object(self.inventory.sys, "stdout", stdout), \
             contextlib.redirect_stderr(stderr), \
             mock.patch.object(self.inventory, "require_root"), \
             mock.patch.object(self.inventory, "read_request_file_v2", return_value=self.request), \
             mock.patch.object(
                 self.inventory,
                 "collect_inventory_v2",
                 side_effect=RuntimeError(SENSITIVE),
             ):
            self.assertEqual(3, self.inventory.main(arguments))
        self.assertEqual(b"", stdout.buffer.getvalue())
        self.assertEqual("inventory-v2-error:E_INVENTORY\n", stderr.getvalue())
        self.assertNotIn(SENSITIVE, stderr.getvalue())

    def test_cli_exit_codes_separate_invalid_input_from_host_and_collection_failures(self):
        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, value):
                raise AssertionError("text stdout is forbidden")

        arguments = [
            "--request-file", "/safe/request.json",
            "--expected-request-sha256", "0" * 64,
        ]
        cases = (
            ("request_semantics", "read", self.inventory.InventoryError("E_REQUEST_PROJECTION"), 2, "E_REQUEST_PROJECTION"),
            ("request_file_mode", "read", self.inventory.InventoryError("E_FILE_MODE"), 3, "E_FILE_MODE"),
            ("root_required", "root", self.inventory.InventoryError("E_ROOT_REQUIRED"), 3, "E_ROOT_REQUIRED"),
            ("topology_drift", "collect", self.inventory.InventoryError("E_TOPOLOGY_DRIFT"), 3, "E_TOPOLOGY_DRIFT"),
            ("capability_failure", "collect", self.inventory.InventoryError("E_CAP_DOCKER"), 3, "E_CAP_DOCKER"),
            ("unknown_collection", "collect", RuntimeError(SENSITIVE), 3, "E_INVENTORY"),
        )
        observed_codes = set()
        for name, stage, failure, expected_exit, expected_code in cases:
            stdout = Output()
            stderr = io.StringIO()
            root_effect = failure if stage == "root" else None
            read_effect = failure if stage == "read" else None
            collect_effect = failure if stage == "collect" else None
            with self.subTest(name=name), \
                 mock.patch.object(self.inventory.sys, "stdout", stdout), \
                 contextlib.redirect_stderr(stderr), \
                 mock.patch.object(self.inventory, "require_root", side_effect=root_effect), \
                 mock.patch.object(
                     self.inventory,
                     "read_request_file_v2",
                     side_effect=read_effect,
                     return_value=self.request,
                 ), \
                 mock.patch.object(
                     self.inventory,
                     "collect_inventory_v2",
                     side_effect=collect_effect,
                 ):
                actual = self.inventory.main(arguments)
            observed_codes.add(actual)
            self.assertEqual(expected_exit, actual)
            self.assertEqual(b"", stdout.buffer.getvalue())
            self.assertEqual(
                f"inventory-v2-error:{expected_code}\n",
                stderr.getvalue(),
            )
            self.assertNotIn(SENSITIVE, stderr.getvalue())
        self.assertNotIn(4, observed_codes)

    def test_cli_validates_lexical_arguments_before_root_or_file_access(self):
        cases = (
            ["--request-file", "relative/request.json", "--expected-request-sha256", "0" * 64],
            ["--request-file", "/safe/request.json", "--expected-request-sha256", "A" * 64],
        )
        for arguments in cases:
            stderr = io.StringIO()
            with self.subTest(arguments=arguments), \
                 contextlib.redirect_stderr(stderr), \
                 mock.patch.object(self.inventory, "require_root") as require_root, \
                 mock.patch.object(self.inventory, "read_request_file_v2") as read_request:
                self.assertEqual(2, self.inventory.main(arguments))
            require_root.assert_not_called()
            read_request.assert_not_called()
            self.assertRegex(stderr.getvalue(), r"\Ainventory-v2-error:E_[A-Z0-9_]+\n\Z")


class InventoryV2QuickValidateTests(unittest.TestCase):
    def test_quick_validator_accepts_the_separate_v2_flag(self):
        module = load_module(self)
        del module
        spec = importlib.util.spec_from_file_location("quick_validate", ROOT / "tests" / "quick_validate.py")
        quick = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(quick)
        self.assertEqual(
            (True, "Docker inventory v2 script is valid!"),
            quick.validate_docker_inventory_v2_script(MODULE_PATH),
        )


if __name__ == "__main__":
    unittest.main()
