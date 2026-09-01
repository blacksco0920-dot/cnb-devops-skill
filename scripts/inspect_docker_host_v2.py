#!/usr/bin/env python3
"""Collect a strict, bounded, read-only Docker host inventory v2.

The output is secret-free but owner-only operational evidence.  This module
never mutates Docker or the host and deliberately does not implement transport,
compression, chunking, or vendor envelopes.
"""

import argparse
import dataclasses
import hashlib
import ipaddress
import json
import math
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from types import MappingProxyType
from pathlib import Path, PurePosixPath
from typing import Protocol


REQUEST_SCHEMA = "deploydesk-docker-host-inventory-request/v2"
TOPOLOGY_SCHEMA = "deploydesk-docker-host-topology/v2"
OBSERVATION_SCHEMA = "deploydesk-docker-host-observation/v2"
INVENTORY_SCHEMA = "deploydesk-docker-host-inventory/v2"

HARD_MAX_CONTAINERS = 70
HARD_MAX_VOLUMES = 4096
HARD_MAX_NETWORKS = 4096
HARD_MAX_MOUNTS_PER_CONTAINER = 256
HARD_MAX_PORTS_PER_CONTAINER = 1024
HARD_MAX_REPO_DIGESTS_PER_CONTAINER = 4096
HARD_MAX_TRUSTED_ANCESTORS = 4096
HARD_MAX_CADDY_RECORDS = 4096
HARD_MAX_SERVICE_ROLE_HASHES = HARD_MAX_CONTAINERS
HARD_MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
HARD_MAX_COMMAND_SECONDS = 300
HARD_MAX_COMMAND_CALLS = 1024
HARD_MAX_TOTAL_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024
HARD_MAX_TOTAL_COMMAND_SECONDS = 1800
HARD_MAX_TOPOLOGY_BYTES = 1_572_864
HARD_MAX_OBSERVATION_BYTES = 524_288
HARD_MAX_INVENTORY_BYTES = 2_097_152
HARD_MAX_RECURSIVE_ENTRIES = 250_000
HARD_MAX_ACL_ENTRIES = 256
HARD_MAX_ACL_BYTES_PER_PATH = 65_536
HARD_MAX_PATH_BYTES = 4096
HARD_MAX_PERSISTENCE_FILE_BYTES = 8 * 1024 * 1024 * 1024
HARD_MAX_REQUEST_BYTES = 1_000_000
OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
DNS_NAME_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.ASCII,
)
REPO_DIGEST_RE = re.compile(
    r"(?P<registry>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)/"
    r"(?P<path>[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"@sha256:(?P<digest>[0-9a-f]{64})\Z",
    re.ASCII,
)
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+._a-z0-9]*)?\Z", re.ASCII)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

OWNERSHIP_LABELS = frozenset({
    "com.docker.compose.project",
    "com.docker.compose.service",
    "io.deploydesk.deployment-id",
    "com.deploydesk.deployment-id",
})
HEALTH_VALUES = frozenset({"none", "starting", "healthy", "unhealthy"})
ADDRESS_CLASSES = frozenset({"wildcard", "loopback", "private", "link_local", "public"})
SOURCE_ROLES = frozenset({"opt", "postgresql", "redis"})
DERIVED_REQUEST_FIELDS = frozenset({
    "request_identity_projection_sha256", "inventory_target_claim_sha256",
})
REQUEST_BASE_FIELDS = frozenset({
    "schema_version", "inventory_nonce", "request_policy_sha256", "source_lock_sha256",
    "collector_sha256", "docker_command", "docker_config_path", "docker_socket_path",
    "observed_sources", "trusted_ancestor_paths", "caddy_roots",
    "allowed_registry_dns_prefixes", "expected_name_sha256", "expected_path_sha256",
    "approved_repo_digest_sha256", "service_role_sha256", "max_containers", "max_volumes", "max_networks",
    "max_mounts_per_container", "max_ports_per_container", "max_command_output_bytes",
    "max_command_seconds", "max_command_calls", "max_total_command_output_bytes",
    "max_total_command_seconds", "max_topology_bytes", "max_observation_bytes",
    "max_inventory_bytes", "max_recursive_entries", "max_acl_entries",
    "max_acl_bytes_per_path", "max_path_bytes", "max_persistence_file_bytes",
})
REQUEST_FIELDS = REQUEST_BASE_FIELDS | DERIVED_REQUEST_FIELDS


class InventoryError(ValueError):
    """A request or observed fact cannot form a safe, complete inventory."""


class CommandRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> str:
        """Run one already-validated fixed argv vector and return stdout only."""


def _validate_json_shape_depth(value: object, code: str) -> None:
    nodes = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 256 or nodes > HARD_MAX_RECURSIVE_ENTRIES:
            raise InventoryError(code)
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend((child, depth + 1) for child in item)


def canonical_bytes(value: object) -> bytes:
    """Return the sole canonical JSON encoding, including one final newline."""
    _validate_json_shape_depth(value, "E_CANONICAL_JSON")
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise InventoryError("E_CANONICAL_JSON") from exc


def identity_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json(value: str) -> object:
    def reject_duplicate(pairs):
        result = {}
        for key, item in pairs:
            if not isinstance(key, str) or key in result:
                raise InventoryError("E_JSON_DUPLICATE")
            result[key] = item
        return result

    def reject_constant(_value):
        raise InventoryError("E_JSON_NUMBER")

    def finite_float(raw):
        result = float(raw)
        if not math.isfinite(result):
            raise InventoryError("E_JSON_NUMBER")
        return result

    try:
        result = json.loads(
            value,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise InventoryError("E_JSON_INVALID") from exc
    _validate_json_shape_depth(result, "E_JSON_DEPTH")
    return result


def _sha256_text(value: str) -> str:
    if not isinstance(value, str) or CONTROL_RE.search(value):
        raise InventoryError("E_TEXT_INVALID")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _exact_dict(value: object, keys: frozenset[str] | set[str], code: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise InventoryError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise InventoryError(code)
    return value


def _integer(value: object, code: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise InventoryError(code)
    if maximum is not None and value > maximum:
        raise InventoryError(code)
    return value


def _sorted_unique_strings(values: object, code: str, *, digest: bool = False) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise InventoryError(code)
    result = tuple(values)
    if any(not isinstance(item, str) for item in result):
        raise InventoryError(code)
    if list(result) != sorted(set(result)):
        raise InventoryError(code)
    if digest and any(not SHA256_RE.fullmatch(item) for item in result):
        raise InventoryError(code)
    return result


def safe_absolute_path(value: str, max_path_bytes: int = HARD_MAX_PATH_BYTES) -> str:
    """Validate one canonical absolute POSIX path without resolving aliases."""
    if not isinstance(value, str) or CONTROL_RE.search(value):
        raise InventoryError("E_PATH_INVALID")
    if not isinstance(max_path_bytes, int) or max_path_bytes <= 0:
        raise InventoryError("E_PATH_LIMIT")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise InventoryError("E_PATH_INVALID") from exc
    if len(raw) > max_path_bytes or not value.startswith("/"):
        raise InventoryError("E_PATH_INVALID")
    if value != "/" and (value.endswith("/") or "//" in value):
        raise InventoryError("E_PATH_ALIAS")
    pure = PurePosixPath(value)
    if any(part in {".", ".."} for part in value.split("/")):
        raise InventoryError("E_PATH_TRAVERSAL")
    if str(pure) != value:
        raise InventoryError("E_PATH_ALIAS")
    return value


def _stat_identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_ctime_ns,
        item.st_mtime_ns,
    )


def _stable_identity(path: str, max_path_bytes: int) -> os.stat_result:
    safe_absolute_path(path, max_path_bytes)
    descriptor = None
    try:
        descriptor = _open_nofollow(Path(path))
        facts = os.fstat(descriptor)
    except (OSError, InventoryError) as exc:
        raise InventoryError("E_PATH_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return facts


def _open_nofollow(path: Path) -> int:
    raw = safe_absolute_path(os.fspath(path), HARD_MAX_PATH_BYTES)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not directory or not nonblock or not OPEN_SUPPORTS_DIR_FD:
        raise InventoryError("E_FILE_NOFOLLOW")
    parts = PurePosixPath(raw).parts[1:]
    descriptor = os.open("/", os.O_RDONLY | directory | nofollow | nonblock)
    try:
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | nofollow | nonblock
            if index < len(parts) - 1:
                flags |= directory
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def stable_read_file(
    path: Path,
    *,
    max_bytes: int,
    require_owner_only: bool,
    require_root: bool = False,
    expected_facts: os.stat_result | None = None,
    return_facts: bool = False,
) -> bytes | tuple[bytes, os.stat_result]:
    """Read a stable regular single-link file through a no-follow descriptor chain."""
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise InventoryError("E_FILE_LIMIT")
    try:
        descriptor = _open_nofollow(path)
    except (OSError, InventoryError) as exc:
        raise InventoryError("E_FILE_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InventoryError("E_FILE_TYPE")
        if expected_facts is not None and _stat_identity(before) != _stat_identity(expected_facts):
            raise InventoryError("E_FILE_UNSTABLE")
        if require_owner_only and stat.S_IMODE(before.st_mode) != 0o600:
            raise InventoryError("E_FILE_MODE")
        expected_uid = 0 if require_root else os.geteuid()
        if require_owner_only and before.st_uid != expected_uid:
            raise InventoryError("E_FILE_OWNER")
        if before.st_size > max_bytes:
            raise InventoryError("E_FILE_LIMIT")
        raw = bytearray()
        while len(raw) <= max_bytes:
            block = os.read(descriptor, min(65_536, max_bytes + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > max_bytes:
            raise InventoryError("E_FILE_LIMIT")
        after = os.fstat(descriptor)
        final_path = _stable_identity(os.fspath(path), HARD_MAX_PATH_BYTES)
        if _stat_identity(before) != _stat_identity(after) or _stat_identity(before) != _stat_identity(final_path):
            raise InventoryError("E_FILE_UNSTABLE")
        result = bytes(raw)
        return (result, before) if return_facts else result
    except OSError as exc:
        raise InventoryError("E_FILE_READ") from exc
    finally:
        os.close(descriptor)


@dataclasses.dataclass(frozen=True)
class InventoryRequestV2:
    schema_version: str
    inventory_nonce: str
    request_policy_sha256: str
    source_lock_sha256: str
    collector_sha256: str
    docker_command: tuple[str, ...]
    docker_config_path: str
    docker_socket_path: str
    observed_sources: tuple[tuple[str, str], ...]
    trusted_ancestor_paths: tuple[str, ...]
    caddy_roots: tuple[str, ...]
    allowed_registry_dns_prefixes: tuple[str, ...]
    expected_name_sha256: tuple[str, ...]
    expected_path_sha256: tuple[str, ...]
    approved_repo_digest_sha256: tuple[str, ...]
    service_role_sha256: dict[str, tuple[str, ...]]
    max_containers: int
    max_volumes: int
    max_networks: int
    max_mounts_per_container: int
    max_ports_per_container: int
    max_command_output_bytes: int
    max_command_seconds: int
    max_command_calls: int
    max_total_command_output_bytes: int
    max_total_command_seconds: int
    max_topology_bytes: int
    max_observation_bytes: int
    max_inventory_bytes: int
    max_recursive_entries: int
    max_acl_entries: int
    max_acl_bytes_per_path: int
    max_path_bytes: int
    max_persistence_file_bytes: int
    request_identity_projection_sha256: str
    inventory_target_claim_sha256: str

    @classmethod
    def from_mapping(cls, value: object):
        mapping = _exact_dict(value, REQUEST_FIELDS, "E_REQUEST_KEYS")
        normalized = dict(mapping)
        sequences = (
            "docker_command", "trusted_ancestor_paths", "caddy_roots",
            "allowed_registry_dns_prefixes", "expected_name_sha256", "expected_path_sha256",
            "approved_repo_digest_sha256",
        )
        for key in sequences:
            if not isinstance(normalized[key], list):
                raise InventoryError("E_REQUEST_SEQUENCE")
            normalized[key] = tuple(normalized[key])
        roles = _exact_dict(
            normalized["service_role_sha256"], {"caddy", "redis"}, "E_REQUEST_SERVICE_ROLE",
        )
        if any(not isinstance(values, list) for values in roles.values()):
            raise InventoryError("E_REQUEST_SERVICE_ROLE")
        normalized["service_role_sha256"] = MappingProxyType({
            role: _sorted_unique_strings(values, "E_REQUEST_SERVICE_ROLE", digest=True)
            for role, values in roles.items()
        })
        if not isinstance(normalized["observed_sources"], list):
            raise InventoryError("E_REQUEST_SOURCES")
        sources = []
        for item in normalized["observed_sources"]:
            item = _exact_dict(item, {"role", "path"}, "E_REQUEST_SOURCE")
            sources.append((item["role"], item["path"]))
        normalized["observed_sources"] = tuple(sources)
        return cls(**normalized)

    def __post_init__(self):
        if self.schema_version != REQUEST_SCHEMA:
            raise InventoryError("E_REQUEST_SCHEMA")
        for value in (
            self.inventory_nonce, self.request_policy_sha256, self.source_lock_sha256,
            self.collector_sha256, self.request_identity_projection_sha256,
            self.inventory_target_claim_sha256,
        ):
            _digest(value, "E_REQUEST_DIGEST")
        if self.request_identity_projection_sha256 == self.inventory_target_claim_sha256:
            raise InventoryError("E_REQUEST_HASH_CYCLE")
        if self.docker_command != ("/usr/bin/docker",):
            raise InventoryError("E_DOCKER_COMMAND")
        if self.docker_config_path != "/etc/docker":
            raise InventoryError("E_DOCKER_CONFIG")
        if self.docker_socket_path not in {"/var/run/docker.sock", "/run/docker.sock"}:
            raise InventoryError("E_DOCKER_SOCKET")
        safe_absolute_path(self.docker_config_path, self.max_path_bytes)
        safe_absolute_path(self.docker_socket_path, self.max_path_bytes)
        if not self.observed_sources or [role for role, _ in self.observed_sources] != ["opt", "postgresql", "redis"]:
            raise InventoryError("E_REQUEST_SOURCES")
        source_paths = []
        for role, path in self.observed_sources:
            if role not in SOURCE_ROLES:
                raise InventoryError("E_REQUEST_SOURCE")
            source_paths.append(safe_absolute_path(path, self.max_path_bytes))
        if len(set(source_paths)) != len(source_paths):
            raise InventoryError("E_REQUEST_SOURCE")
        for values, code in (
            (self.trusted_ancestor_paths, "E_REQUEST_ANCESTOR"),
            (self.caddy_roots, "E_REQUEST_CADDY"),
        ):
            if (
                not values
                or len(values) > HARD_MAX_TRUSTED_ANCESTORS
                or list(values) != sorted(set(values))
            ):
                raise InventoryError(code)
            for path in values:
                safe_absolute_path(path, self.max_path_bytes)
        registries = _sorted_unique_strings(self.allowed_registry_dns_prefixes, "E_REQUEST_REGISTRY")
        if (
            not registries
            or len(registries) > HARD_MAX_TRUSTED_ANCESTORS
            or any(not DNS_NAME_RE.fullmatch(item) for item in registries)
            or any(re.fullmatch(r"[0-9.]+", item, re.ASCII) for item in registries)
        ):
            raise InventoryError("E_REQUEST_REGISTRY")
        for values in (
            self.expected_name_sha256, self.expected_path_sha256,
            self.approved_repo_digest_sha256,
        ):
            _sorted_unique_strings(values, "E_REQUEST_EXPECTED", digest=True)
            if len(values) > HARD_MAX_TRUSTED_ANCESTORS:
                raise InventoryError("E_REQUEST_EXPECTED")
        role_hashes = self.service_role_sha256
        if (
            not isinstance(role_hashes, MappingProxyType)
            or set(role_hashes) != {"caddy", "redis"}
            or any(
                not isinstance(values, tuple)
                or not values
                or len(values) > HARD_MAX_SERVICE_ROLE_HASHES
                or _sorted_unique_strings(
                    values, "E_REQUEST_SERVICE_ROLE", digest=True,
                ) != values
                for values in role_hashes.values()
            )
            or set(role_hashes["caddy"]) & set(role_hashes["redis"])
        ):
            raise InventoryError("E_REQUEST_SERVICE_ROLE")
        caps = {
            "max_containers": HARD_MAX_CONTAINERS,
            "max_volumes": HARD_MAX_VOLUMES,
            "max_networks": HARD_MAX_NETWORKS,
            "max_mounts_per_container": HARD_MAX_MOUNTS_PER_CONTAINER,
            "max_ports_per_container": HARD_MAX_PORTS_PER_CONTAINER,
            "max_command_output_bytes": HARD_MAX_COMMAND_OUTPUT_BYTES,
            "max_command_seconds": HARD_MAX_COMMAND_SECONDS,
            "max_command_calls": HARD_MAX_COMMAND_CALLS,
            "max_total_command_output_bytes": HARD_MAX_TOTAL_COMMAND_OUTPUT_BYTES,
            "max_total_command_seconds": HARD_MAX_TOTAL_COMMAND_SECONDS,
            "max_topology_bytes": HARD_MAX_TOPOLOGY_BYTES,
            "max_observation_bytes": HARD_MAX_OBSERVATION_BYTES,
            "max_inventory_bytes": HARD_MAX_INVENTORY_BYTES,
            "max_recursive_entries": HARD_MAX_RECURSIVE_ENTRIES,
            "max_acl_entries": HARD_MAX_ACL_ENTRIES,
            "max_acl_bytes_per_path": HARD_MAX_ACL_BYTES_PER_PATH,
            "max_path_bytes": HARD_MAX_PATH_BYTES,
            "max_persistence_file_bytes": HARD_MAX_PERSISTENCE_FILE_BYTES,
        }
        for field, maximum in caps.items():
            _integer(getattr(self, field), "E_REQUEST_LIMIT", minimum=1, maximum=maximum)
        projection = self.identity_projection()
        if identity_sha256(projection) != self.request_identity_projection_sha256:
            raise InventoryError("E_REQUEST_PROJECTION")
        final_hash = identity_sha256(self.to_mapping())
        if final_hash in {
            self.request_identity_projection_sha256,
            self.inventory_target_claim_sha256,
        }:
            raise InventoryError("E_REQUEST_HASH_CYCLE")

    def identity_projection(self) -> dict[str, object]:
        value = self.to_mapping()
        for field in DERIVED_REQUEST_FIELDS:
            del value[field]
        if set(value) != REQUEST_BASE_FIELDS:
            raise InventoryError("E_REQUEST_PROJECTION")
        return value

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "inventory_nonce": self.inventory_nonce,
            "request_policy_sha256": self.request_policy_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "collector_sha256": self.collector_sha256,
            "docker_command": list(self.docker_command),
            "docker_config_path": self.docker_config_path,
            "docker_socket_path": self.docker_socket_path,
            "observed_sources": [
                {"role": role, "path": path} for role, path in self.observed_sources
            ],
            "trusted_ancestor_paths": list(self.trusted_ancestor_paths),
            "caddy_roots": list(self.caddy_roots),
            "allowed_registry_dns_prefixes": list(self.allowed_registry_dns_prefixes),
            "expected_name_sha256": list(self.expected_name_sha256),
            "expected_path_sha256": list(self.expected_path_sha256),
            "approved_repo_digest_sha256": list(self.approved_repo_digest_sha256),
            "service_role_sha256": {
                role: list(self.service_role_sha256[role]) for role in ("caddy", "redis")
            },
            "max_containers": self.max_containers,
            "max_volumes": self.max_volumes,
            "max_networks": self.max_networks,
            "max_mounts_per_container": self.max_mounts_per_container,
            "max_ports_per_container": self.max_ports_per_container,
            "max_command_output_bytes": self.max_command_output_bytes,
            "max_command_seconds": self.max_command_seconds,
            "max_command_calls": self.max_command_calls,
            "max_total_command_output_bytes": self.max_total_command_output_bytes,
            "max_total_command_seconds": self.max_total_command_seconds,
            "max_topology_bytes": self.max_topology_bytes,
            "max_observation_bytes": self.max_observation_bytes,
            "max_inventory_bytes": self.max_inventory_bytes,
            "max_recursive_entries": self.max_recursive_entries,
            "max_acl_entries": self.max_acl_entries,
            "max_acl_bytes_per_path": self.max_acl_bytes_per_path,
            "max_path_bytes": self.max_path_bytes,
            "max_persistence_file_bytes": self.max_persistence_file_bytes,
            "request_identity_projection_sha256": self.request_identity_projection_sha256,
            "inventory_target_claim_sha256": self.inventory_target_claim_sha256,
        }


class SubprocessRunner:
    """No-shell runner with bounded stdout, discarded stderr, and a hard timeout."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        max_output_bytes: int,
        timeout_seconds: int,
    ) -> str:
        if (
            not isinstance(argv, tuple)
            or not argv
            or any(not isinstance(item, str) or CONTROL_RE.search(item) for item in argv)
            or not os.path.isabs(argv[0])
        ):
            raise InventoryError("E_COMMAND_VECTOR")
        _integer(max_output_bytes, "E_COMMAND_LIMIT", minimum=1, maximum=HARD_MAX_COMMAND_OUTPUT_BYTES)
        _integer(timeout_seconds, "E_COMMAND_TIMEOUT", minimum=1, maximum=HARD_MAX_COMMAND_SECONDS)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except FileNotFoundError as exc:
            raise InventoryError("E_COMMAND_NOT_FOUND") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            raise InventoryError("E_COMMAND_FAILED") from exc
        selector = None
        try:
            if process.stdout is None:
                raise InventoryError("E_COMMAND_FAILED")
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout_seconds
            output = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InventoryError("E_COMMAND_TIMEOUT")
                events = selector.select(remaining)
                if not events:
                    raise InventoryError("E_COMMAND_TIMEOUT")
                block = os.read(process.stdout.fileno(), min(65_536, max_output_bytes + 1 - len(output)))
                if not block:
                    break
                output.extend(block)
                if len(output) > max_output_bytes:
                    raise InventoryError("E_COMMAND_OUTPUT")
            try:
                return_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise InventoryError("E_COMMAND_TIMEOUT") from exc
            if return_code != 0:
                raise InventoryError("E_COMMAND_FAILED")
            try:
                return bytes(output).decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise InventoryError("E_COMMAND_UTF8") from exc
        except InventoryError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise InventoryError("E_COMMAND_FAILED") from exc
        finally:
            if selector is not None:
                try:
                    selector.close()
                except Exception:
                    pass
            try:
                if process.poll() is None:
                    process.kill()
            except Exception:
                pass
            try:
                if process.poll() is None:
                    process.wait()
            except Exception:
                pass
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except Exception:
                    pass


class _BudgetedRunner:
    """Share one count/byte/wall-clock budget across a complete collection."""

    def __init__(self, request: InventoryRequestV2, runner: CommandRunner):
        self.request = request
        self.runner = runner
        self.calls = 0
        self.output_bytes = 0
        self.elapsed_seconds = 0.0

    def run(self, argv, *, max_output_bytes, timeout_seconds):
        self.calls += 1
        if self.calls > self.request.max_command_calls:
            raise InventoryError("E_COMMAND_CALL_BUDGET")
        remaining = self.request.max_total_command_seconds - self.elapsed_seconds
        if remaining < 1:
            raise InventoryError("E_COMMAND_TIME_BUDGET")
        bounded_timeout = min(timeout_seconds, max(1, int(remaining)))
        started = time.monotonic()
        try:
            value = self.runner.run(
                argv,
                max_output_bytes=max_output_bytes,
                timeout_seconds=bounded_timeout,
            )
        except Exception as exc:
            self.elapsed_seconds += time.monotonic() - started
            if self.elapsed_seconds > self.request.max_total_command_seconds:
                raise InventoryError("E_COMMAND_TIME_BUDGET") from exc
            raise
        self.elapsed_seconds += time.monotonic() - started
        if self.elapsed_seconds > self.request.max_total_command_seconds:
            raise InventoryError("E_COMMAND_TIME_BUDGET")
        if not isinstance(value, str):
            raise InventoryError("E_COMMAND_TEXT")
        self.output_bytes += len(value.encode("utf-8"))
        if self.output_bytes > self.request.max_total_command_output_bytes:
            raise InventoryError("E_COMMAND_BYTE_BUDGET")
        return value


def _budgeted_runner(request: InventoryRequestV2, runner: CommandRunner) -> _BudgetedRunner:
    if isinstance(runner, _BudgetedRunner):
        if runner.request != request:
            raise InventoryError("E_COMMAND_BUDGET_REQUEST")
        return runner
    return _BudgetedRunner(request, runner)


def read_request_file_v2(
    path: Path,
    expected_sha256: str,
    *,
    require_root: bool = True,
) -> InventoryRequestV2:
    _digest(expected_sha256, "E_REQUEST_FILE_DIGEST")
    raw = stable_read_file(
        path,
        max_bytes=HARD_MAX_REQUEST_BYTES,
        require_owner_only=True,
        require_root=require_root,
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise InventoryError("E_REQUEST_FILE_DIGEST")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InventoryError("E_REQUEST_FILE_UTF8") from exc
    value = strict_json(text)
    if canonical_bytes(value) != raw:
        raise InventoryError("E_REQUEST_FILE_CANONICAL")
    return InventoryRequestV2.from_mapping(value)


def _lines(value: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, str) or CONTROL_RE.search(value.replace("\n", "")):
        raise InventoryError("E_COMMAND_TEXT")
    result = value.splitlines()
    if any(not line or line.strip() != line for line in result):
        raise InventoryError("E_COMMAND_TEXT")
    if not allow_empty and not result:
        raise InventoryError("E_COMMAND_TEXT")
    return result


def _run(request: InventoryRequestV2, runner: CommandRunner, argv: tuple[str, ...]) -> str:
    if not isinstance(argv, tuple) or not argv or not os.path.isabs(argv[0]):
        raise InventoryError("E_COMMAND_VECTOR")
    docker_prefix = _docker_prefix(request)
    fixed = frozenset({
        ("/usr/bin/uname", "-r"),
        ("/usr/bin/tar", "--version"),
        ("/usr/bin/zstd", "--version"),
        ("/usr/bin/psql", "--version"),
        ("/usr/bin/pg_dump", "--version"),
        ("/usr/bin/redis-server", "--version"),
        ("/usr/bin/caddy", "version"),
        ("/usr/sbin/visudo", "-V"),
    })
    allowed = argv in fixed
    if argv[:len(docker_prefix)] == docker_prefix:
        suffix = argv[len(docker_prefix):]
        allowed = suffix in {
            ("version",),
            ("ps", "-aq", "--no-trunc"),
            ("volume", "ls", "-q"),
            ("network", "ls", "-q", "--no-trunc"),
        }
        if len(suffix) >= 4 and suffix[:3] in {
            ("container", "inspect", "--"),
            ("network", "inspect", "--"),
        }:
            identifiers = suffix[3:]
            allowed = (
                bool(identifiers)
                and len(identifiers) <= (
                    request.max_containers if suffix[0] == "container" else request.max_networks
                )
                and list(identifiers) == sorted(set(identifiers))
                and all(CONTAINER_ID_RE.fullmatch(item) for item in identifiers)
            )
        elif len(suffix) >= 4 and suffix[:3] == ("image", "inspect", "--"):
            identifiers = suffix[3:]
            allowed = (
                bool(identifiers)
                and len(identifiers) <= request.max_containers
                and list(identifiers) == sorted(set(identifiers))
                and all(IMAGE_ID_RE.fullmatch(item) for item in identifiers)
            )
        elif len(suffix) >= 4 and suffix[:3] == ("volume", "inspect", "--"):
            identifiers = suffix[3:]
            allowed = (
                bool(identifiers)
                and len(identifiers) <= request.max_volumes
                and list(identifiers) == sorted(set(identifiers))
                and all(SAFE_NAME_RE.fullmatch(item) for item in identifiers)
            )
        elif (
            len(suffix) == 4
            and suffix[:3] == ("container", "diff", "--")
            and CONTAINER_ID_RE.fullmatch(suffix[3])
        ):
            allowed = True
    if not allowed:
        raise InventoryError("E_COMMAND_VECTOR")
    return runner.run(
        argv,
        max_output_bytes=request.max_command_output_bytes,
        timeout_seconds=request.max_command_seconds,
    )


def _docker_prefix(request: InventoryRequestV2) -> tuple[str, ...]:
    return request.docker_command + (
        "--config", request.docker_config_path,
        "--host", "unix://" + request.docker_socket_path,
    )


def _strict_command_json(value: str) -> object:
    # Docker inspect emits pretty JSON.  Parsing is duplicate/nonfinite-safe;
    # only our public output is required to use the canonical encoding.
    return strict_json(value)


def _checked_ids(
    values: list[str],
    *,
    limit: int,
    pattern: re.Pattern,
    code: str,
) -> list[str]:
    if len(values) > limit:
        raise InventoryError(code + "_LIMIT")
    if len(values) != len(set(values)):
        raise InventoryError(code + "_DUPLICATE")
    if any(not pattern.fullmatch(item) for item in values):
        raise InventoryError(code + "_INVALID")
    return sorted(values)


def _enumerate(
    request: InventoryRequestV2,
    runner: CommandRunner,
    suffix: tuple[str, ...],
    *,
    limit: int,
    pattern: re.Pattern,
    code: str,
) -> list[str]:
    return _checked_ids(
        _lines(_run(request, runner, _docker_prefix(request) + suffix)),
        limit=limit,
        pattern=pattern,
        code=code,
    )


def _inspect_exact(
    request: InventoryRequestV2,
    runner: CommandRunner,
    kind: str,
    identifiers: list[str],
    identity_key: str,
) -> dict[str, dict]:
    if not identifiers:
        return {}
    suffix = (kind, "inspect", "--") + tuple(identifiers)
    parsed = _strict_command_json(_run(request, runner, _docker_prefix(request) + suffix))
    if not isinstance(parsed, list):
        raise InventoryError("E_INSPECT_SHAPE")
    result = {}
    for item in parsed:
        if not isinstance(item, dict) or not isinstance(item.get(identity_key), str):
            raise InventoryError("E_INSPECT_SHAPE")
        identity = item[identity_key]
        if identity in result:
            raise InventoryError("E_INSPECT_DUPLICATE")
        result[identity] = item
    if set(result) != set(identifiers):
        raise InventoryError("E_INSPECT_INCOMPLETE")
    return result


def _stable_inspect(
    request: InventoryRequestV2,
    runner: CommandRunner,
    *,
    list_suffix: tuple[str, ...],
    inspect_kind: str,
    limit: int,
    pattern: re.Pattern,
    identity_key: str,
    code: str,
) -> tuple[list[str], dict[str, dict]]:
    before = _enumerate(
        request, runner, list_suffix, limit=limit, pattern=pattern, code=code,
    )
    inspected = _inspect_exact(request, runner, inspect_kind, before, identity_key)
    after = _enumerate(
        request, runner, list_suffix, limit=limit, pattern=pattern, code=code,
    )
    if before != after:
        raise InventoryError(code + "_DRIFT")
    return before, inspected


def _name_record(value: str, expected_hashes: tuple[str, ...]) -> dict[str, str]:
    if not isinstance(value, str) or CONTROL_RE.search(value) or len(value.encode("utf-8")) > 128:
        raise InventoryError("E_NAME_INVALID")
    digest = _sha256_text(value)
    if SAFE_NAME_RE.fullmatch(value) and digest in expected_hashes:
        return {"kind": "raw", "sha256": digest, "value": value}
    return {"kind": "hashed", "sha256": digest}


def _path_record(value: str, request: InventoryRequestV2) -> dict[str, str]:
    normalized = safe_absolute_path(value, request.max_path_bytes)
    digest = _sha256_text(normalized)
    if digest in request.expected_path_sha256:
        return {"kind": "raw", "sha256": digest, "value": normalized}
    return {"kind": "hashed", "sha256": digest}


def _repo_digest_record(value: object, request: InventoryRequestV2) -> dict[str, str]:
    if not isinstance(value, str) or CONTROL_RE.search(value) or len(value.encode("ascii", errors="ignore")) != len(value):
        raise InventoryError("E_REPO_DIGEST")
    match = REPO_DIGEST_RE.fullmatch(value)
    if not match:
        raise InventoryError("E_REPO_DIGEST")
    registry = match.group("registry")
    if re.fullmatch(r"[0-9.]+", registry, re.ASCII):
        raise InventoryError("E_REPO_REGISTRY")
    try:
        ipaddress.ip_address(registry)
    except ValueError:
        pass
    else:
        raise InventoryError("E_REPO_REGISTRY")
    digest = _sha256_text(value)
    if registry in request.allowed_registry_dns_prefixes and digest in request.approved_repo_digest_sha256:
        return {"kind": "raw", "sha256": digest, "value": value}
    return {"kind": "hashed", "sha256": digest}


def _path_metadata(path: str, request: InventoryRequestV2) -> dict[str, object]:
    facts = _stable_identity(path, request.max_path_bytes)
    return _path_metadata_from_facts(path, facts, request)


def _path_metadata_from_facts(
    path: str,
    facts: os.stat_result,
    request: InventoryRequestV2,
) -> dict[str, object]:
    if not (stat.S_ISDIR(facts.st_mode) or stat.S_ISREG(facts.st_mode)):
        raise InventoryError("E_PATH_TYPE")
    return {
        "path": _path_record(path, request),
        "type": "directory" if stat.S_ISDIR(facts.st_mode) else "regular",
        "device": facts.st_dev,
        "inode": facts.st_ino,
        "mode": stat.S_IMODE(facts.st_mode),
        "uid": facts.st_uid,
        "gid": facts.st_gid,
        "nlink": facts.st_nlink,
    }


def _validate_bounded_json_value(
    value: object,
    *,
    code: str,
    depth: int = 0,
    nodes: list[int] | None = None,
) -> None:
    """Accept only a small, canonical JSON tree before hashing opaque options."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 16 or nodes[0] > 4096:
        raise InventoryError(code)
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        try:
            canonical_bytes(value)
        except InventoryError as exc:
            raise InventoryError(code) from exc
        return
    if isinstance(value, str):
        if CONTROL_RE.search(value):
            raise InventoryError(code)
        return
    if isinstance(value, list):
        for item in value:
            _validate_bounded_json_value(item, code=code, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or CONTROL_RE.search(key):
                raise InventoryError(code)
            _validate_bounded_json_value(item, code=code, depth=depth + 1, nodes=nodes)
        return
    raise InventoryError(code)


def _tmpfs_option_records(
    host_config: object,
    runtime_mounts: object,
    request: InventoryRequestV2,
) -> dict[str, object]:
    if (
        not isinstance(host_config, dict)
        or any(key not in host_config for key in ("Tmpfs", "Mounts"))
        or not isinstance(runtime_mounts, list)
    ):
        raise InventoryError("E_MOUNT")
    legacy = {} if host_config["Tmpfs"] is None else host_config["Tmpfs"]
    structured = [] if host_config["Mounts"] is None else host_config["Mounts"]
    if not isinstance(legacy, dict) or not isinstance(structured, list):
        raise InventoryError("E_MOUNT")
    records = {}
    for destination, options in legacy.items():
        safe_absolute_path(destination, request.max_path_bytes)
        if not isinstance(options, str) or CONTROL_RE.search(options):
            raise InventoryError("E_MOUNT")
        records[destination] = {
            "source_kind": "hostconfig_tmpfs",
            "options_sha256": identity_sha256(options),
        }
    for item in structured:
        if not isinstance(item, dict) or not isinstance(item.get("Type"), str):
            raise InventoryError("E_MOUNT")
        if item["Type"] != "tmpfs":
            continue
        if any(key not in item for key in ("Target", "TmpfsOptions")):
            raise InventoryError("E_MOUNT")
        destination = safe_absolute_path(item["Target"], request.max_path_bytes)
        if destination in records:
            raise InventoryError("E_MOUNT")
        options = item["TmpfsOptions"]
        if options is not None and not isinstance(options, dict):
            raise InventoryError("E_MOUNT")
        _validate_bounded_json_value(options, code="E_MOUNT")
        raw = canonical_bytes(options)
        if len(raw) > request.max_command_output_bytes:
            raise InventoryError("E_MOUNT")
        records[destination] = {
            "source_kind": "hostconfig_mounts",
            "options_sha256": hashlib.sha256(raw).hexdigest(),
        }
    runtime_destinations = []
    for item in runtime_mounts:
        if not isinstance(item, dict) or "Type" not in item:
            raise InventoryError("E_MOUNT")
        if item["Type"] == "tmpfs":
            if "Destination" not in item:
                raise InventoryError("E_MOUNT")
            runtime_destinations.append(
                safe_absolute_path(item["Destination"], request.max_path_bytes)
            )
    if (
        len(runtime_destinations) != len(set(runtime_destinations))
        or set(runtime_destinations) != set(records)
    ):
        raise InventoryError("E_MOUNT")
    return records


def _mount_record(
    value: object,
    request: InventoryRequestV2,
    tmpfs_options: dict[str, object],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InventoryError("E_MOUNT")
    if any(key not in value for key in ("Type", "Source", "Destination", "Mode", "RW", "Propagation")):
        raise InventoryError("E_MOUNT")
    mount_type = value["Type"]
    source = value["Source"]
    mode = value["Mode"]
    propagation = value["Propagation"]
    if any(not isinstance(item, str) or CONTROL_RE.search(item) for item in (source, mode, propagation)):
        raise InventoryError("E_MOUNT")
    destination = _path_record(value["Destination"], request)
    if not isinstance(value["RW"], bool):
        raise InventoryError("E_MOUNT")
    read_only = not value["RW"]
    base = {"destination": destination, "read_only": read_only}
    if mount_type == "volume":
        if "Name" not in value or "Driver" not in value:
            raise InventoryError("E_MOUNT")
        name = value["Name"]
        driver = value["Driver"]
        if not isinstance(name, str) or not isinstance(driver, str):
            raise InventoryError("E_MOUNT")
        kind = "anonymous_volume" if CONTAINER_ID_RE.fullmatch(name) else "named_volume"
        return {
            "kind": kind,
            "name": _name_record(name, request.expected_name_sha256),
            "driver": _name_record(driver, request.expected_name_sha256),
            "source": _path_record(source, request),
            **base,
            "options_sha256": identity_sha256({"mode": mode, "propagation": propagation}),
        }
    if mount_type == "bind":
        metadata = _path_metadata(source, request)
        if metadata["type"] == "regular" and metadata["nlink"] != 1:
            raise InventoryError("E_MOUNT")
        return {
            "kind": "bind", **base, "source": metadata,
            "options_sha256": identity_sha256({"mode": mode, "propagation": propagation}),
        }
    if mount_type == "tmpfs":
        raw_destination = value["Destination"]
        if source != "" or raw_destination not in tmpfs_options:
            raise InventoryError("E_MOUNT")
        options = tmpfs_options[raw_destination]
        return {
            "kind": "tmpfs", **base,
            "options_sha256": identity_sha256({
                "runtime": {"mode": mode, "propagation": propagation, "source": source},
                "host_config": options,
            }),
        }
    raise InventoryError("E_MOUNT_UNSUPPORTED")


def _address_class(value: object) -> str:
    if value in {"", "0.0.0.0", "::"}:
        return "wildcard"
    if not isinstance(value, str) or CONTROL_RE.search(value):
        raise InventoryError("E_PORT_ADDRESS")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InventoryError("E_PORT_ADDRESS") from exc
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    return "public"


def _published_ports(value: object, request: InventoryRequestV2) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise InventoryError("E_PORTS")
    records = []
    for key, bindings in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]{0,4}/(?:tcp|udp|sctp)", key):
            raise InventoryError("E_PORT")
        port_text, protocol = key.split("/", 1)
        container_port = int(port_text)
        if not 1 <= container_port <= 65_535:
            raise InventoryError("E_PORT")
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            raise InventoryError("E_PORT")
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"}:
                raise InventoryError("E_PORT")
            host_port = binding["HostPort"]
            if not isinstance(host_port, str) or not host_port.isascii() or not host_port.isdigit():
                raise InventoryError("E_PORT")
            host_port_value = int(host_port)
            if not 1 <= host_port_value <= 65_535:
                raise InventoryError("E_PORT")
            records.append({
                "container_port": container_port,
                "host_port": host_port_value,
                "protocol": protocol,
                "host_address_class": _address_class(binding["HostIp"]),
            })
    if len(records) > request.max_ports_per_container:
        raise InventoryError("E_PORT_LIMIT")
    return sorted(records, key=canonical_bytes)


def _ownership_labels(value: object, request: InventoryRequestV2) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise InventoryError("E_LABELS")
    records = []
    for key in sorted(OWNERSHIP_LABELS & set(value)):
        label_value = value[key]
        if not isinstance(label_value, str) or not SAFE_NAME_RE.fullmatch(label_value):
            raise InventoryError("E_LABEL_VALUE")
        records.append({"key": key, "value": _name_record(label_value, request.expected_name_sha256)})
    deployment_values = {
        item["value"]["sha256"] for item in records
        if item["key"] in {"io.deploydesk.deployment-id", "com.deploydesk.deployment-id"}
    }
    if len(deployment_values) > 1:
        raise InventoryError("E_DEPLOYMENT_LABEL_CONFLICT")
    return records


def _network_memberships(value: object, request: InventoryRequestV2) -> list[dict[str, object]]:
    if not isinstance(value, dict):
        raise InventoryError("E_NETWORK_MEMBERSHIP")
    records = []
    for name, membership in value.items():
        if not isinstance(name, str) or not isinstance(membership, dict):
            raise InventoryError("E_NETWORK_MEMBERSHIP")
        identifier = membership.get("NetworkID")
        if not isinstance(identifier, str) or not CONTAINER_ID_RE.fullmatch(identifier):
            raise InventoryError("E_NETWORK_MEMBERSHIP")
        records.append({
            "id": identifier,
            "name": _name_record(name, request.expected_name_sha256),
        })
    return sorted(records, key=lambda item: (item["id"], canonical_bytes(item["name"])))


def _metadata_hashes(path: str, request: InventoryRequestV2) -> dict[str, object]:
    """Hash ACL/xattr metadata without emitting names or values."""
    if not callable(getattr(os, "listxattr", None)) or not callable(getattr(os, "getxattr", None)):
        # This is not represented as an empty supported result.  The capability
        # record is false and the distinct hashes make unsupported evidence
        # impossible to confuse with a supported path that has no metadata.
        return {
            "acl_count": 0,
            "acl_sha256": identity_sha256({"kind": "acl", "status": "unsupported"}),
            "xattr_count": 0,
            "xattr_sha256": identity_sha256({"kind": "xattr", "status": "unsupported"}),
            "metadata_bytes": 0,
        }
    descriptor = None
    try:
        descriptor = _open_nofollow(Path(path))
        before = os.fstat(descriptor)
        if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
            raise InventoryError("E_METADATA_TYPE")
        names = sorted(os.listxattr(descriptor))
        if len(names) > request.max_acl_entries:
            raise InventoryError("E_METADATA_ENTRY_LIMIT")
        acl_records = []
        xattr_records = []
        total_bytes = 0
        for name in names:
            if not isinstance(name, str) or CONTROL_RE.search(name):
                raise InventoryError("E_METADATA_NAME")
            value = os.getxattr(descriptor, name)
            total_bytes += len(name.encode("utf-8")) + len(value)
            if total_bytes > request.max_acl_bytes_per_path:
                raise InventoryError("E_METADATA_BYTE_LIMIT")
            record = {
                "name_sha256": _sha256_text(name),
                "value_sha256": hashlib.sha256(value).hexdigest(),
                "value_bytes": len(value),
            }
            if "acl" in name.lower():
                acl_records.append(record)
            else:
                xattr_records.append(record)
        after = os.fstat(descriptor)
        final_path = _stable_identity(path, request.max_path_bytes)
        if (
            _stat_identity(before) != _stat_identity(after)
            or _stat_identity(before) != _stat_identity(final_path)
        ):
            raise InventoryError("E_METADATA_DRIFT")
    except InventoryError:
        raise
    except (OSError, AttributeError, TypeError) as exc:
        raise InventoryError("E_METADATA_READ") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return {
        "acl_count": len(acl_records),
        "acl_sha256": identity_sha256(acl_records),
        "xattr_count": len(xattr_records),
        "xattr_sha256": identity_sha256(xattr_records),
        "metadata_bytes": total_bytes,
    }


def _trusted_ancestors(request: InventoryRequestV2) -> list[dict[str, object]]:
    records = []
    for path in request.trusted_ancestor_paths:
        metadata = _path_metadata(path, request)
        if metadata["type"] != "directory":
            raise InventoryError("E_ANCESTOR_TYPE")
        records.append({**metadata, **_metadata_hashes(path, request)})
    return sorted(records, key=lambda item: canonical_bytes(item["path"]))


def _parse_caddy_file(
    path: str,
    raw: bytes,
    request: InventoryRequestV2,
    facts: os.stat_result,
) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InventoryError("E_CADDY_UTF8") from exc
    if CONTROL_RE.search(text.replace("\n", "").replace("\t", "")):
        raise InventoryError("E_CADDY_CONTROL")
    source_path_sha256 = _sha256_text(path)
    owners = []
    behaviors = []
    current_hosts: list[str] = []
    state = "root"
    pending_proxy = None
    site_encode = False
    site_route = False

    def proxy_target(value: str) -> tuple[str, str, int]:
        if value.startswith("https://"):
            scheme = "https"
            target_host = value[len("https://"):]
            target_port_text = "443"
            if not DNS_NAME_RE.fullmatch(target_host):
                raise InventoryError("E_CADDY_TARGET")
        else:
            scheme = "http"
            if "://" in value or value.count(":") != 1:
                raise InventoryError("E_CADDY_TARGET")
            target_host, target_port_text = value.rsplit(":", 1)
        if (
            not SAFE_NAME_RE.fullmatch(target_host)
            or target_host != target_host.lower()
            or target_host.endswith(".")
            or not target_port_text.isdigit()
            or not 1 <= int(target_port_text) <= 65_535
        ):
            raise InventoryError("E_CADDY_TARGET")
        return scheme, target_host, int(target_port_text)

    def emit_proxy(proxy: dict[str, object]) -> None:
        nonlocal site_route
        if site_route or not site_encode:
            raise InventoryError("E_CADDY_PARSE")
        kind = "https_proxy" if proxy["target_scheme"] == "https" else "docker_proxy"
        for host in current_hosts:
            record = {
                "kind": kind,
                "source_host_sha256": _sha256_text(host),
                "encodings": ["zstd", "gzip"],
                "target_scheme": proxy["target_scheme"],
                "target_host_sha256": proxy["target_host_sha256"],
                "target_port": proxy["target_port"],
                "header_up_host_sha256": proxy["header_up_host_sha256"],
                "tls_server_name_sha256": proxy["tls_server_name_sha256"],
            }
            behaviors.append({**record, "behavior_sha256": identity_sha256(record)})
        site_route = True

    for original in text.splitlines():
        line = original.split("#", 1)[0].strip()
        if not line:
            continue
        if state == "root":
            if not line.endswith("{"):
                raise InventoryError("E_CADDY_PARSE")
            header = line[:-1].strip()
            hosts = [item.strip() for item in header.split(",")]
            if not hosts or any(not DNS_NAME_RE.fullmatch(item) for item in hosts):
                raise InventoryError("E_CADDY_HOST")
            current_hosts = sorted(set(hosts))
            if len(current_hosts) != len(hosts):
                raise InventoryError("E_CADDY_HOST")
            for host in current_hosts:
                owners.append({
                    "host": _name_record(host, request.expected_name_sha256),
                    "source_path_sha256": source_path_sha256,
                    "writer_uid": facts.st_uid,
                    "writer_gid": facts.st_gid,
                })
            state = "site"
            site_encode = False
            site_route = False
            continue
        if state == "site" and line == "}":
            if not site_route:
                raise InventoryError("E_CADDY_PARSE")
            state = "root"
            current_hosts = []
            continue
        if state == "site" and line == "encode zstd gzip":
            if site_encode or site_route:
                raise InventoryError("E_CADDY_PARSE")
            site_encode = True
            continue
        if state == "site" and line.startswith("redir "):
            parts = line.split()
            if len(parts) != 3 or site_encode or site_route:
                raise InventoryError("E_CADDY_REDIR")
            target = parts[1]
            status_values = {"permanent": 308, "301": 301, "308": 308}
            status_code = status_values.get(parts[2])
            if status_code is None or CONTROL_RE.search(target) or "\\" in target:
                raise InventoryError("E_CADDY_REDIR")
            absolute = re.fullmatch(
                r"https://(?P<host>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\{uri\}",
                target,
                re.ASCII,
            )
            if absolute is None:
                raise InventoryError("E_CADDY_REDIR")
            target_sha256 = _sha256_text(target)
            for host in current_hosts:
                record = {
                    "kind": "redirect", "source_host_sha256": _sha256_text(host),
                    "target_class": "absolute_https", "target_sha256": target_sha256,
                    "status_code": status_code, "preserve_uri": True,
                }
                behaviors.append({**record, "behavior_sha256": identity_sha256(record)})
            site_route = True
            continue
        if state == "site" and line.startswith("reverse_proxy "):
            block = line.endswith("{")
            target = line[len("reverse_proxy "):].strip()
            if block:
                target = target[:-1].strip()
            if not target or any(character.isspace() for character in target):
                raise InventoryError("E_CADDY_TARGET")
            scheme, target_host, target_port = proxy_target(target)
            if (block and (scheme != "https" or target_port != 443)) or (not block and scheme != "http"):
                raise InventoryError("E_CADDY_TARGET")
            pending_proxy = {
                "target_scheme": scheme,
                "target_host_sha256": _sha256_text(target_host),
                "target_port": target_port,
                "header_up_host_sha256": None,
                "tls_server_name_sha256": None,
            }
            if block:
                state = "proxy"
            else:
                emit_proxy(pending_proxy)
                pending_proxy = None
            continue
        if state == "proxy" and line.startswith("header_up Host "):
            parts = line.split()
            if len(parts) != 3 or pending_proxy["header_up_host_sha256"] is not None:
                raise InventoryError("E_CADDY_PARSE")
            header_host = parts[2]
            if not DNS_NAME_RE.fullmatch(header_host):
                raise InventoryError("E_CADDY_HOST")
            pending_proxy["header_up_host_sha256"] = _sha256_text(header_host)
            continue
        if state == "proxy" and line == "transport http {":
            if pending_proxy["tls_server_name_sha256"] is not None:
                raise InventoryError("E_CADDY_PARSE")
            state = "transport"
            continue
        if state == "transport" and line.startswith("tls_server_name "):
            parts = line.split()
            if len(parts) != 2 or pending_proxy["tls_server_name_sha256"] is not None:
                raise InventoryError("E_CADDY_PARSE")
            tls_host = parts[1]
            if not DNS_NAME_RE.fullmatch(tls_host):
                raise InventoryError("E_CADDY_HOST")
            pending_proxy["tls_server_name_sha256"] = _sha256_text(tls_host)
            continue
        if state == "transport" and line == "}":
            if pending_proxy["tls_server_name_sha256"] is None:
                raise InventoryError("E_CADDY_PARSE")
            state = "proxy"
            continue
        if state == "proxy" and line == "}":
            if (
                pending_proxy["header_up_host_sha256"] is None
                or pending_proxy["tls_server_name_sha256"] is None
                or pending_proxy["header_up_host_sha256"] != pending_proxy["target_host_sha256"]
                or pending_proxy["tls_server_name_sha256"] != pending_proxy["target_host_sha256"]
            ):
                raise InventoryError("E_CADDY_PARSE")
            emit_proxy(pending_proxy)
            pending_proxy = None
            state = "site"
            continue
        raise InventoryError("E_CADDY_PARSE")
    if state != "root" or pending_proxy is not None:
        raise InventoryError("E_CADDY_PARSE")
    return {
        "file": {
            **_path_metadata_from_facts(path, facts, request),
            "content_sha256": hashlib.sha256(raw).hexdigest(),
        },
        "owners": sorted(owners, key=canonical_bytes),
        "behaviors": sorted(behaviors, key=canonical_bytes),
    }


def _collect_caddy(request: InventoryRequestV2) -> dict[str, object]:
    files = []
    owners = []
    behaviors = []
    for path in request.caddy_roots:
        raw, facts = stable_read_file(
            Path(path),
            max_bytes=request.max_command_output_bytes,
            require_owner_only=False,
            return_facts=True,
        )
        parsed = _parse_caddy_file(path, raw, request, facts)
        files.append(parsed["file"])
        owners.extend(parsed["owners"])
        behaviors.extend(parsed["behaviors"])
        if any(len(items) > HARD_MAX_CADDY_RECORDS for items in (files, owners, behaviors)):
            raise InventoryError("E_CADDY_LIMIT")
    if len(owners) != len({item["source_host_sha256"] for item in behaviors} | {
        item["host"]["sha256"] for item in owners
    }):
        # Duplicate ownership is ambiguous even when the behavior tuple matches.
        owner_hashes = [item["host"]["sha256"] for item in owners]
        if len(owner_hashes) != len(set(owner_hashes)):
            raise InventoryError("E_CADDY_DUPLICATE_OWNER")
    return {
        "files": sorted(files, key=lambda item: canonical_bytes(item["path"])),
        "owners": sorted(owners, key=canonical_bytes),
        "behaviors": sorted(behaviors, key=canonical_bytes),
    }


def _version(value: str, code: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise InventoryError(code)
    return value


def _full_version(pattern: str, value: str, code: str) -> str:
    if not isinstance(value, str):
        raise InventoryError(code)
    match = re.fullmatch(pattern, value, re.ASCII)
    if not match:
        raise InventoryError(code)
    return _version(match.group("version"), code)


def _parse_docker_version(value: str) -> dict[str, str]:
    if not isinstance(value, str) or not value.endswith("\n") or "\r" in value:
        raise InventoryError("E_CAP_DOCKER")
    section = None
    component = "root"
    seen_sections = set()
    seen_components = set()
    seen_fields = set()
    versions = {"client_version": None, "client_api_version": None, "server_version": None, "server_api_version": None}
    for line in value[:-1].split("\n"):
        if re.fullmatch(r"Client:(?: Docker Engine - Community)?", line, re.ASCII):
            if "client" in seen_sections:
                raise InventoryError("E_CAP_DOCKER")
            section = "client"
            component = "root"
            seen_sections.add(section)
            seen_components.add((section, component))
            continue
        if re.fullmatch(r"Server:(?: Docker Engine - Community)?", line, re.ASCII):
            if "server" in seen_sections:
                raise InventoryError("E_CAP_DOCKER")
            section = "server"
            component = "root"
            seen_sections.add(section)
            seen_components.add((section, component))
            continue
        component_match = re.fullmatch(r" (Engine|containerd|runc|docker-init):", line, re.ASCII)
        if component_match and section == "server":
            component = component_match.group(1).lower()
            if (section, component) in seen_components:
                raise InventoryError("E_CAP_DOCKER")
            seen_components.add((section, component))
            continue
        if line == "":
            continue
        field_match = re.fullmatch(
            r" {1,2}(Version|API version|Go version|Git commit|GitCommit|Built|OS/Arch|Context|Experimental): {1,20}(.{1,256})",
            line,
            re.ASCII,
        )
        if not field_match or section is None:
            raise InventoryError("E_CAP_DOCKER")
        field, raw = field_match.groups()
        if (section, component, field) in seen_fields:
            raise InventoryError("E_CAP_DOCKER")
        seen_fields.add((section, component, field))
        if CONTROL_RE.search(raw):
            raise InventoryError("E_CAP_DOCKER")
        target_component = component == "root" if section == "client" else component in {"root", "engine"}
        if field == "Version" and target_component:
            key = section + "_version"
            if versions[key] is not None:
                raise InventoryError("E_CAP_DOCKER")
            versions[key] = _version(raw, "E_CAP_DOCKER")
        elif field == "API version" and target_component:
            match = re.fullmatch(
                r"(?P<version>[0-9]+(?:\.[0-9]+){1,3})(?: \(minimum version [0-9]+(?:\.[0-9]+){1,3}\))?",
                raw,
                re.ASCII,
            )
            key = section + "_api_version"
            if match is None or versions[key] is not None:
                raise InventoryError("E_CAP_DOCKER")
            versions[key] = _version(match.group("version"), "E_CAP_DOCKER")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:+/@(),~-]{0,255}", raw, re.ASCII):
            raise InventoryError("E_CAP_DOCKER")
    if any(item is None for item in versions.values()):
        raise InventoryError("E_CAP_DOCKER")
    return versions


def _optional_host_tool(
    request: InventoryRequestV2,
    runner: CommandRunner,
    argv: tuple[str, ...],
    parser,
) -> dict[str, object]:
    """Collect one optional host binary without weakening failure handling."""
    try:
        raw = _run(request, runner, argv)
    except InventoryError as exc:
        if exc.args == ("E_COMMAND_NOT_FOUND",):
            return {"available": False}
        raise
    parsed = parser(raw)
    if not isinstance(parsed, dict) or not parsed:
        raise InventoryError("E_CAPABILITY")
    return {"available": True, **parsed}


def _collect_capabilities(request: InventoryRequestV2, runner: CommandRunner) -> dict[str, object]:
    uname = _lines(_run(request, runner, ("/usr/bin/uname", "-r")), allow_empty=False)
    if len(uname) != 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", uname[0], re.ASCII):
        raise InventoryError("E_CAP_OS")
    docker = _parse_docker_version(_run(request, runner, _docker_prefix(request) + ("version",)))
    return {
        "os": {
            "kernel_release_sha256": _sha256_text(uname[0]),
            "nofollow_supported": bool(getattr(os, "O_NOFOLLOW", 0)),
            "dir_fd_supported": os.open in os.supports_dir_fd,
            "xattr_supported": callable(getattr(os, "listxattr", None)) and callable(getattr(os, "getxattr", None)),
        },
        "docker": {
            **docker,
        },
        "host_tar": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/tar", "--version"),
            lambda value: {"implementation": "gnu", "version": _full_version(
                r"tar \(GNU tar\) (?P<version>[0-9][A-Za-z0-9.+_-]*)\n"
                r"(?:Copyright \(C\) [0-9]{4} Free Software Foundation, Inc\.\n"
                r"License GPLv3\+: GNU GPL version 3 or later <https://gnu\.org/licenses/gpl\.html>\.\n"
                r"This is free software: you are free to change and redistribute it\.\n"
                r"There is NO WARRANTY, to the extent permitted by law\.\n\n"
                r"Written by John Gilmore and Jay Fenlason\.\n)?",
                value,
                "E_CAP_TAR",
            )},
        ),
        "host_zstd": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/zstd", "--version"),
            lambda value: {"version": _full_version(
                r"\*\*\* Zstandard CLI \(64-bit\) v(?P<version>[0-9][A-Za-z0-9.+_-]*)(?:, by [A-Za-z .-]{1,80} \*\*\*)?\n",
                value,
                "E_CAP_ZSTD",
            )},
        ),
        "host_psql": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/psql", "--version"),
            lambda value: {"version": _full_version(
                r"psql \(PostgreSQL\) (?P<version>[0-9][A-Za-z0-9.+_-]*)"
                r"(?: \((?:Ubuntu|Debian) [A-Za-z0-9.+:~_-]{1,96}\))?\n",
                value,
                "E_CAP_POSTGRESQL",
            )},
        ),
        "host_pg_dump": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/pg_dump", "--version"),
            lambda value: {"version": _full_version(
                r"pg_dump \(PostgreSQL\) (?P<version>[0-9][A-Za-z0-9.+_-]*)"
                r"(?: \((?:Ubuntu|Debian) [A-Za-z0-9.+:~_-]{1,96}\))?\n",
                value,
                "E_CAP_POSTGRESQL",
            )},
        ),
        "host_redis_server": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/redis-server", "--version"),
            lambda value: {"version": _full_version(
                r"Redis server v=(?P<version>[0-9][A-Za-z0-9.+_-]*) sha=[0-9a-f]{8,40}:[0-9]+ malloc=[A-Za-z0-9._+-]+ bits=(?:32|64) build=[0-9a-f]+\n",
                value,
                "E_CAP_REDIS",
            )},
        ),
        "host_caddy": _optional_host_tool(
            request,
            runner,
            ("/usr/bin/caddy", "version"),
            lambda value: {"version": _full_version(
                r"v(?P<version>[0-9][A-Za-z0-9.+_-]*)(?: h1:[A-Za-z0-9+/=]{20,})?\n",
                value,
                "E_CAP_CADDY",
            )},
        ),
        "host_visudo": _optional_host_tool(
            request,
            runner,
            ("/usr/sbin/visudo", "-V"),
            lambda value: {"version": _full_version(
                r"(?i:visudo) version (?P<version>[0-9][A-Za-z0-9.+_-]*)\n"
                r"(?:(?i:visudo) grammar version [0-9]+\n)?",
                value,
                "E_CAP_VISUDO",
            )},
        ),
    }


def _container_topology(
    record: object,
    request: InventoryRequestV2,
    repo_digests: object,
) -> tuple[dict[str, object], dict[str, object] | None]:
    if not isinstance(record, dict):
        raise InventoryError("E_CONTAINER_INSPECT")
    identifier = record.get("Id")
    name = record.get("Name")
    image_id = record.get("Image")
    if not isinstance(identifier, str) or not CONTAINER_ID_RE.fullmatch(identifier):
        raise InventoryError("E_CONTAINER_ID")
    if not isinstance(name, str) or not name.startswith("/") or name.startswith("//"):
        raise InventoryError("E_CONTAINER_NAME")
    name = name[1:]
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        raise InventoryError("E_IMAGE_ID")
    if (
        not isinstance(repo_digests, list)
        or not repo_digests
        or len(repo_digests) > HARD_MAX_REPO_DIGESTS_PER_CONTAINER
    ):
        raise InventoryError("E_REPO_DIGEST")
    normalized_repo_digests = sorted(
        (_repo_digest_record(item, request) for item in repo_digests),
        key=canonical_bytes,
    )
    if len({item["sha256"] for item in normalized_repo_digests}) != len(normalized_repo_digests):
        raise InventoryError("E_REPO_DIGEST_DUPLICATE")
    config = record.get("Config")
    if not isinstance(config, dict):
        raise InventoryError("E_CONTAINER_CONFIG")
    if any(key not in config for key in ("Labels", "Entrypoint", "Cmd")):
        raise InventoryError("E_CONTAINER_CONFIG")
    for key in ("Entrypoint", "Cmd"):
        command = config[key]
        if command is not None and (
            not isinstance(command, list)
            or any(not isinstance(item, str) or CONTROL_RE.search(item) for item in command)
        ):
            raise InventoryError("E_CONTAINER_CONFIG")
    labels = _ownership_labels(config["Labels"], request)
    network_settings = record.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        raise InventoryError("E_NETWORK_SETTINGS")
    host_config = record.get("HostConfig")
    if (
        any(key not in network_settings for key in ("Networks", "Ports"))
        or "Mounts" not in record
        or not isinstance(host_config, dict)
    ):
        raise InventoryError("E_CONTAINER_INSPECT")
    mounts = record["Mounts"]
    if not isinstance(mounts, list) or len(mounts) > request.max_mounts_per_container:
        raise InventoryError("E_MOUNT_LIMIT")
    tmpfs_options = _tmpfs_option_records(host_config, mounts, request)
    mount_records = sorted(
        (_mount_record(item, request, tmpfs_options) for item in mounts), key=canonical_bytes,
    )
    topology = {
        "id": identifier,
        "name": _name_record(name, request.expected_name_sha256),
        "image_id": image_id,
        "repo_digests": normalized_repo_digests,
        "ownership_labels": labels,
        "network_memberships": _network_memberships(network_settings["Networks"], request),
        "published_ports": _published_ports(network_settings["Ports"], request),
        "mounts": mount_records,
    }
    service_digest = None
    raw_labels = config["Labels"]
    if isinstance(raw_labels, dict):
        service = raw_labels.get("com.docker.compose.service")
        if isinstance(service, str) and not CONTROL_RE.search(service):
            service_digest = _sha256_text(service)
    redis = None
    if service_digest in request.service_role_sha256["redis"]:
        command_projection = {
            "entrypoint": config["Entrypoint"],
            "command": config["Cmd"],
        }
        if not isinstance(command_projection["entrypoint"], (list, type(None))) or not isinstance(command_projection["command"], (list, type(None))):
            raise InventoryError("E_REDIS_COMMAND")
        arguments = []
        for group in (command_projection["entrypoint"], command_projection["command"]):
            if group:
                if any(not isinstance(item, str) or CONTROL_RE.search(item) for item in group):
                    raise InventoryError("E_REDIS_COMMAND")
                arguments.extend(group)
        config_paths = []
        for argument in arguments:
            if argument.startswith("/") and argument.endswith(".conf"):
                config_paths.append(safe_absolute_path(argument, request.max_path_bytes))
        redis = {
            "container_id": identifier,
            "command_sha256": identity_sha256(command_projection),
            "config_path_sha256": identity_sha256(sorted(set(config_paths))),
            "persistence_mount_sha256": sorted(
                identity_sha256(item)
                for item in mount_records
                if item["destination"]["sha256"] == _sha256_text("/data")
            ),
        }
    return topology, redis


def _image_repo_digests(
    request: InventoryRequestV2,
    runner: CommandRunner,
    container_inspects: dict[str, dict],
) -> dict[str, list[object]]:
    raw_image_ids = [item.get("Image") for item in container_inspects.values()]
    if any(not isinstance(item, str) or not IMAGE_ID_RE.fullmatch(item) for item in raw_image_ids):
        raise InventoryError("E_IMAGE_ID")
    image_ids = sorted(set(raw_image_ids))
    inspected = _inspect_exact(request, runner, "image", image_ids, "Id")
    result = {}
    for image_id in image_ids:
        record = inspected[image_id]
        if record.get("Id") != image_id:
            raise InventoryError("E_IMAGE_BINDING")
        repo_digests = record.get("RepoDigests")
        if (
            not isinstance(repo_digests, list)
            or not repo_digests
            or len(repo_digests) > HARD_MAX_REPO_DIGESTS_PER_CONTAINER
        ):
            raise InventoryError("E_REPO_DIGEST")
        if any(not isinstance(item, str) for item in repo_digests):
            raise InventoryError("E_REPO_DIGEST")
        if len(repo_digests) != len(set(repo_digests)):
            raise InventoryError("E_REPO_DIGEST_DUPLICATE")
        result[image_id] = sorted(repo_digests)
    return result


def _validate_service_roles(value: object, code: str) -> dict[str, list[str]]:
    value = _exact_dict(value, {"caddy", "redis"}, code)
    result = {}
    for role in ("caddy", "redis"):
        items = value[role]
        if (
            not isinstance(items, list)
            or not items
            or len(items) > HARD_MAX_SERVICE_ROLE_HASHES
            or items != sorted(set(items))
        ):
            raise InventoryError(code)
        for item in items:
            _digest(item, code)
        result[role] = list(items)
    if set(result["caddy"]) & set(result["redis"]):
        raise InventoryError(code)
    return result


def _validate_privacy_expectations(value: object) -> dict[str, list[str]]:
    keys = {
        "expected_name_sha256", "expected_path_sha256",
        "approved_repo_digest_sha256", "allowed_registry_dns_sha256",
    }
    value = _exact_dict(value, keys, "E_PRIVACY_EXPECTATIONS")
    result = {}
    for key in sorted(keys):
        items = value[key]
        if (
            not isinstance(items, list)
            or len(items) > HARD_MAX_TRUSTED_ANCESTORS
            or items != sorted(set(items))
        ):
            raise InventoryError("E_PRIVACY_EXPECTATIONS")
        for item in items:
            _digest(item, "E_PRIVACY_EXPECTATIONS")
        result[key] = items
    if not result["allowed_registry_dns_sha256"]:
        raise InventoryError("E_PRIVACY_EXPECTATIONS")
    return result


def _volume_topology(record: object, request: InventoryRequestV2) -> dict[str, object]:
    if not isinstance(record, dict):
        raise InventoryError("E_VOLUME_INSPECT")
    required = ("Name", "Driver", "Mountpoint", "Options", "Scope")
    if any(key not in record for key in required):
        raise InventoryError("E_VOLUME_INSPECT")
    name = record["Name"]
    driver = record["Driver"]
    scope = record["Scope"]
    mountpoint = record["Mountpoint"]
    options = record["Options"]
    if (
        not isinstance(name, str)
        or not SAFE_NAME_RE.fullmatch(name)
        or not isinstance(driver, str)
        or not isinstance(scope, str)
        or scope not in {"local", "global", "swarm"}
        or not isinstance(mountpoint, str)
        or not (options is None or isinstance(options, dict))
    ):
        raise InventoryError("E_VOLUME_INSPECT")
    try:
        options_raw = canonical_bytes(options)
    except InventoryError as exc:
        raise InventoryError("E_VOLUME_INSPECT") from exc
    if len(options_raw) > request.max_command_output_bytes:
        raise InventoryError("E_VOLUME_INSPECT")
    if isinstance(options, dict):
        if any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or CONTROL_RE.search(key)
            or CONTROL_RE.search(item)
            for key, item in options.items()
        ):
            raise InventoryError("E_VOLUME_INSPECT")
    metadata = _path_metadata(mountpoint, request)
    return {
        "name": _name_record(name, request.expected_name_sha256),
        "kind": "anonymous_volume" if CONTAINER_ID_RE.fullmatch(name) else "named_volume",
        "driver": _name_record(driver, request.expected_name_sha256),
        "scope": scope,
        "mountpoint": metadata,
        "options_sha256": hashlib.sha256(options_raw).hexdigest(),
    }


def _network_topology(record: object, request: InventoryRequestV2) -> dict[str, object]:
    if not isinstance(record, dict):
        raise InventoryError("E_NETWORK_INSPECT")
    required = ("Id", "Name", "Driver", "Scope", "Internal", "Attachable", "Ingress", "IPAM")
    if any(key not in record for key in required):
        raise InventoryError("E_NETWORK_INSPECT")
    identifier = record["Id"]
    name = record["Name"]
    driver = record["Driver"]
    scope = record["Scope"]
    booleans = (record["Internal"], record["Attachable"], record["Ingress"])
    if (
        not isinstance(identifier, str)
        or not CONTAINER_ID_RE.fullmatch(identifier)
        or not isinstance(name, str)
        or not isinstance(driver, str)
        or not isinstance(scope, str)
        or scope not in {"local", "global", "swarm"}
        or any(not isinstance(item, bool) for item in booleans)
        or not isinstance(record["IPAM"], dict)
    ):
        raise InventoryError("E_NETWORK_INSPECT")
    return {
        "id": identifier,
        "name": _name_record(name, request.expected_name_sha256),
        "driver": _name_record(driver, request.expected_name_sha256),
        "scope": scope,
        "internal": record["Internal"],
        "attachable": record["Attachable"],
        "ingress": record["Ingress"],
        "ipam_sha256": identity_sha256(record["IPAM"]),
    }


def _identity_fields(request: InventoryRequestV2) -> dict[str, str]:
    return {
        "request_identity_projection_sha256": request.request_identity_projection_sha256,
        "inventory_target_claim_sha256": request.inventory_target_claim_sha256,
        "inventory_nonce": request.inventory_nonce,
        "request_policy_sha256": request.request_policy_sha256,
        "source_lock_sha256": request.source_lock_sha256,
        "collector_sha256": request.collector_sha256,
    }


def _privacy_expectations(request: InventoryRequestV2) -> dict[str, list[str]]:
    return {
        "expected_name_sha256": list(request.expected_name_sha256),
        "expected_path_sha256": list(request.expected_path_sha256),
        "approved_repo_digest_sha256": list(request.approved_repo_digest_sha256),
        "allowed_registry_dns_sha256": sorted(
            _sha256_text(value) for value in request.allowed_registry_dns_prefixes
        ),
    }


def collect_topology_v2(
    request: InventoryRequestV2,
    runner: CommandRunner,
) -> dict[str, object]:
    """Collect only stable structural facts; no recursive walk or Docker diff."""
    if not isinstance(request, InventoryRequestV2):
        raise InventoryError("E_REQUEST_TYPE")
    runner = _budgeted_runner(request, runner)
    volume_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
    container_ids, container_inspects = _stable_inspect(
        request,
        runner,
        list_suffix=("ps", "-aq", "--no-trunc"),
        inspect_kind="container",
        limit=request.max_containers,
        pattern=CONTAINER_ID_RE,
        identity_key="Id",
        code="E_CONTAINER",
    )
    volume_ids, volume_inspects = _stable_inspect(
        request,
        runner,
        list_suffix=("volume", "ls", "-q"),
        inspect_kind="volume",
        limit=request.max_volumes,
        pattern=volume_pattern,
        identity_key="Name",
        code="E_VOLUME",
    )
    network_ids, network_inspects = _stable_inspect(
        request,
        runner,
        list_suffix=("network", "ls", "-q", "--no-trunc"),
        inspect_kind="network",
        limit=request.max_networks,
        pattern=CONTAINER_ID_RE,
        identity_key="Id",
        code="E_NETWORK",
    )
    repo_digests_by_image = _image_repo_digests(request, runner, container_inspects)
    containers = []
    redis_records = []
    for identifier in container_ids:
        inspected_container = container_inspects[identifier]
        container_record, redis_record = _container_topology(
            inspected_container,
            request,
            repo_digests_by_image[inspected_container["Image"]],
        )
        containers.append(container_record)
        if redis_record is not None:
            redis_records.append(redis_record)
    containers.sort(key=lambda item: item["id"])
    volumes = sorted(
        (_volume_topology(volume_inspects[identifier], request) for identifier in volume_ids),
        key=lambda item: canonical_bytes(item["name"]),
    )
    networks = sorted(
        (_network_topology(network_inspects[identifier], request) for identifier in network_ids),
        key=lambda item: item["id"],
    )
    capabilities = _collect_capabilities(request, runner)
    caddy = _collect_caddy(request)
    service_by_id = {}
    for identifier in container_ids:
        config = container_inspects[identifier].get("Config", {})
        labels = config.get("Labels", {}) if isinstance(config, dict) else {}
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        service_by_id[identifier] = (
            _sha256_text(service)
            if isinstance(service, str) and not CONTROL_RE.search(service)
            else None
        )
    caddy_container_ids = sorted(
        identifier for identifier, service in service_by_id.items()
        if service in request.service_role_sha256["caddy"]
    )
    topology = {
        "schema_version": TOPOLOGY_SCHEMA,
        **_identity_fields(request),
        "privacy_expectations": _privacy_expectations(request),
        "service_role_sha256": {
            role: list(request.service_role_sha256[role]) for role in ("caddy", "redis")
        },
        "container_count": len(containers),
        "containers": containers,
        "deletion_vector": list(container_ids),
        "volume_count": len(volumes),
        "volumes": volumes,
        "network_count": len(networks),
        "networks": networks,
        "trusted_ancestors": _trusted_ancestors(request),
        "caddy": {**caddy, "container_ids": caddy_container_ids},
        "redis": sorted(redis_records, key=lambda item: item["container_id"]),
        "capabilities": capabilities,
    }
    raw = canonical_bytes(topology)
    if len(raw) > min(request.max_topology_bytes, HARD_MAX_TOPOLOGY_BYTES):
        raise InventoryError("E_TOPOLOGY_LIMIT")
    return validate_topology_v2(topology, request)


def _health_state(value: object) -> tuple[bool, str]:
    if not isinstance(value, dict) or not isinstance(value.get("Running"), bool):
        raise InventoryError("E_CONTAINER_STATE")
    running = value["Running"]
    health_value = value.get("Health")
    if health_value is None:
        health = "none"
    elif isinstance(health_value, dict) and set(health_value) >= {"Status"}:
        health = health_value["Status"]
    else:
        raise InventoryError("E_CONTAINER_HEALTH")
    if health not in HEALTH_VALUES:
        raise InventoryError("E_CONTAINER_HEALTH")
    return running, health


def _writable_layer(
    identifier: str,
    request: InventoryRequestV2,
    runner: CommandRunner,
) -> dict[str, object]:
    raw_lines = _lines(_run(
        request,
        runner,
        _docker_prefix(request) + ("container", "diff", "--", identifier),
    ))
    if len(raw_lines) > request.max_recursive_entries:
        raise InventoryError("E_DIFF_LIMIT")
    projections = []
    operations = set()
    for line in raw_lines:
        if len(line) < 3 or line[0] not in {"A", "C", "D"} or line[1] != " ":
            raise InventoryError("E_DIFF_FORMAT")
        path = line[2:]
        safe_absolute_path(path, request.max_path_bytes)
        operations.add(line[0])
        projections.append({"operation": line[0], "path_sha256": _sha256_text(path)})
    projections.sort(key=canonical_bytes)
    classification = "empty" if not projections else "metadata_or_content_changed"
    return {
        "count": len(projections),
        "classification": classification,
        "operations": sorted(operations),
        "sha256": identity_sha256(projections),
    }


def _observation_walk_specs(
    request: InventoryRequestV2,
    topology: dict[str, object],
    container_inspects: dict[str, dict],
    volume_inspects: dict[str, dict],
) -> list[dict[str, str]]:
    specs = [
        {"role": role, "path": path, "identity_sha256": _sha256_text("source:" + role + ":" + path)}
        for role, path in request.observed_sources
    ]
    public_volumes = {
        canonical_bytes(item): item for item in topology["volumes"]
    }
    if len(public_volumes) != len(topology["volumes"]):
        raise InventoryError("E_OBSERVATION_VOLUME_DUPLICATE")
    for raw_volume in volume_inspects.values():
        volume = _volume_topology(raw_volume, request)
        if canonical_bytes(volume) not in public_volumes:
            raise InventoryError("E_OBSERVATION_VOLUME_DRIFT")
        path = safe_absolute_path(raw_volume["Mountpoint"], request.max_path_bytes)
        specs.append({
            "role": "persistence",
            "path": path,
            "identity_sha256": identity_sha256({
                "kind": volume["kind"], "name": volume["name"], "path": volume["mountpoint"]["path"],
            }),
        })
    if len(volume_inspects) != len(public_volumes):
        raise InventoryError("E_OBSERVATION_VOLUME_DRIFT")
    public_containers = {item["id"]: item for item in topology["containers"]}
    for identifier, raw_container in container_inspects.items():
        container = public_containers.get(identifier)
        if container is None:
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
        if "Mounts" not in raw_container:
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
        raw_mounts = raw_container["Mounts"]
        if not isinstance(raw_mounts, list):
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
        host_config = raw_container.get("HostConfig")
        if not isinstance(host_config, dict):
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
        tmpfs_options = _tmpfs_option_records(host_config, raw_mounts, request)
        pairs = [(_mount_record(item, request, tmpfs_options), item) for item in raw_mounts]
        if sorted((item for item, _raw in pairs), key=canonical_bytes) != container["mounts"]:
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
        for mount, raw_mount in pairs:
            if mount["kind"] == "bind":
                path = safe_absolute_path(raw_mount.get("Source"), request.max_path_bytes)
                specs.append({
                    "role": "persistence",
                    "path": path,
                    "identity_sha256": identity_sha256({
                        "container_id": container["id"], "mount": mount,
                    }),
                })
            elif mount["kind"] == "tmpfs":
                specs.append({
                    "role": "tmpfs",
                    "path": "",
                    "identity_sha256": identity_sha256({
                        "container_id": container["id"], "mount": mount,
                    }),
                })
    deduplicated = {}
    for item in specs:
        key = (item["role"], item["path"], item["identity_sha256"])
        deduplicated[key] = item
    return [deduplicated[key] for key in sorted(deduplicated)]


def _hash_regular_file(
    path: str,
    request: InventoryRequestV2,
    *,
    expected_facts: os.stat_result | None = None,
    byte_budget: list[int] | None = None,
) -> tuple[str, int]:
    """Hash one stable regular file without buffering its content."""
    safe_absolute_path(path, request.max_path_bytes)
    try:
        descriptor = _open_nofollow(Path(path))
    except (OSError, InventoryError) as exc:
        raise InventoryError("E_FILE_UNSAFE") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InventoryError("E_FILE_TYPE")
        if expected_facts is not None and _stat_identity(before) != _stat_identity(expected_facts):
            raise InventoryError("E_FILE_UNSTABLE")
        if before.st_size > request.max_persistence_file_bytes:
            raise InventoryError("E_FILE_LIMIT")
        if byte_budget is not None and byte_budget[0] + before.st_size > request.max_persistence_file_bytes:
            raise InventoryError("E_PERSISTENCE_TOTAL_LIMIT")
        digest = hashlib.sha256()
        total = 0
        while total <= request.max_persistence_file_bytes:
            block = os.read(
                descriptor,
                min(65_536, request.max_persistence_file_bytes + 1 - total),
            )
            if not block:
                break
            digest.update(block)
            total += len(block)
        if total > request.max_persistence_file_bytes:
            raise InventoryError("E_FILE_LIMIT")
        after = os.fstat(descriptor)
        final_path = _stable_identity(path, request.max_path_bytes)
        if (
            total != before.st_size
            or _stat_identity(before) != _stat_identity(after)
            or _stat_identity(before) != _stat_identity(final_path)
        ):
            raise InventoryError("E_FILE_UNSTABLE")
        if byte_budget is not None:
            byte_budget[0] += total
        return digest.hexdigest(), total
    except OSError as exc:
        raise InventoryError("E_FILE_READ") from exc
    finally:
        os.close(descriptor)


REDIS_MANIFEST_PATH = "appendonlydir/appendonly.aof.manifest"
REDIS_AOF_DATA_RE = re.compile(
    r"appendonlydir/appendonly\.aof\.[1-9][0-9]*\.(?:base\.(?:rdb|aof)|incr\.aof)\Z",
    re.ASCII,
)
REDIS_MANIFEST_LINE_RE = re.compile(
    r"file (?P<name>appendonly\.aof\.(?P<file_seq>[1-9][0-9]*)\."
    r"(?P<suffix>base\.(?:rdb|aof)|incr\.aof)) seq (?P<seq>[1-9][0-9]*) type (?P<kind>[bi])\Z",
    re.ASCII,
)


def _redis_member_record(
    root: str,
    relative: str,
    facts: os.stat_result,
    request: InventoryRequestV2,
    byte_budget: list[int],
) -> dict[str, object]:
    path = os.path.join(root, relative)
    digest, size = _hash_regular_file(
        path,
        request,
        expected_facts=facts,
        byte_budget=byte_budget,
    )
    return {
        "path_sha256": _sha256_text(relative),
        "content_sha256": digest,
        "size_bytes": size,
        "ctime_ns": facts.st_ctime_ns,
    }


def _redis_persistence_members(
    root: str,
    candidates: dict[str, tuple[str, os.stat_result]],
    request: InventoryRequestV2,
    byte_budget: list[int],
) -> list[dict[str, object]]:
    selected: list[tuple[str, os.stat_result]] = []
    records: list[dict[str, object]] = []
    for direct in ("dump.rdb", "appendonly.aof"):
        if direct in candidates:
            selected.append((direct, candidates[direct][1]))

    manifest_item = candidates.get(REDIS_MANIFEST_PATH)
    if manifest_item is not None:
        if "appendonly.aof" in candidates:
            raise InventoryError("E_REDIS_MANIFEST")
        manifest_path, manifest_expected = manifest_item
        manifest_raw, manifest_facts = stable_read_file(
            Path(manifest_path),
            max_bytes=min(65_536, request.max_persistence_file_bytes),
            require_owner_only=False,
            expected_facts=manifest_expected,
            return_facts=True,
        )
        if byte_budget[0] + len(manifest_raw) > request.max_persistence_file_bytes:
            raise InventoryError("E_PERSISTENCE_TOTAL_LIMIT")
        byte_budget[0] += len(manifest_raw)
        records.append({
            "path_sha256": _sha256_text(REDIS_MANIFEST_PATH),
            "content_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "size_bytes": len(manifest_raw),
            "ctime_ns": manifest_facts.st_ctime_ns,
        })
        try:
            manifest_text = manifest_raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise InventoryError("E_REDIS_MANIFEST") from exc
        if not manifest_text or not manifest_text.endswith("\n") or "\r" in manifest_text:
            raise InventoryError("E_REDIS_MANIFEST")
        declared = []
        seen = set()
        base_seen = False
        last_incremental_seq = 0
        for line in manifest_text[:-1].split("\n"):
            match = REDIS_MANIFEST_LINE_RE.fullmatch(line)
            if match is None:
                raise InventoryError("E_REDIS_MANIFEST")
            name = match.group("name")
            seq = int(match.group("seq"))
            if seq != int(match.group("file_seq")) or name in seen:
                raise InventoryError("E_REDIS_MANIFEST")
            seen.add(name)
            if match.group("kind") == "b":
                if base_seen or declared or not match.group("suffix").startswith("base."):
                    raise InventoryError("E_REDIS_MANIFEST")
                base_seen = True
            else:
                if not base_seen or match.group("suffix") != "incr.aof" or seq <= last_incremental_seq:
                    raise InventoryError("E_REDIS_MANIFEST")
                last_incremental_seq = seq
            relative = "appendonlydir/" + name
            if relative not in candidates:
                raise InventoryError("E_REDIS_MANIFEST")
            declared.append(relative)
        if not base_seen:
            raise InventoryError("E_REDIS_MANIFEST")
        data_candidates = {item for item in candidates if REDIS_AOF_DATA_RE.fullmatch(item)}
        if data_candidates != set(declared):
            raise InventoryError("E_REDIS_MANIFEST")
        selected.extend((item, candidates[item][1]) for item in declared)
    elif any(REDIS_AOF_DATA_RE.fullmatch(item) for item in candidates):
        raise InventoryError("E_REDIS_MANIFEST")

    for relative, facts in selected:
        records.append(_redis_member_record(root, relative, facts, request, byte_budget))
    return sorted(records, key=canonical_bytes)


def _select_physical_directory_roots(
    facts_by_path: dict[str, os.stat_result],
) -> list[str]:
    """Select roots using only the nearest declared directory ancestor.

    A device transition starts a new physical traversal even if a more distant
    declared ancestor happens to be on the same device.  Looking up ancestors
    by path components keeps selection bounded by path depth rather than by the
    number of requested logical roots.
    """
    declared: dict[str, os.stat_result] = {}
    selected = []
    for path in sorted(
        facts_by_path,
        key=lambda item: (len(PurePosixPath(item).parts), PurePosixPath(item).parts),
    ):
        nearest = next(
            (
                str(parent)
                for parent in PurePosixPath(path).parents
                if str(parent) in declared
            ),
            None,
        )
        if nearest is None or facts_by_path[path].st_dev != declared[nearest].st_dev:
            selected.append(path)
        declared[path] = facts_by_path[path]
    return selected


def _nearest_declared_directory(
    path: str,
    facts_by_path: dict[str, os.stat_result],
) -> str | None:
    return next(
        (
            str(parent)
            for parent in PurePosixPath(path).parents
            if str(parent) in facts_by_path
        ),
        None,
    )


def _record_physical_child(
    node: dict[str, object],
    child: str,
    child_facts: os.stat_result,
    *,
    is_directory: bool,
    traversal_device: int,
    declared_paths: set[str],
) -> bool:
    """Record one direct child and return whether this walk may descend."""
    same_device = child_facts.st_dev == traversal_device
    if not same_device and child not in declared_paths:
        raise InventoryError("E_WALK_DEVICE")
    node["direct_entry_count"] += 1
    if not is_directory and same_device:
        node["direct_regular_bytes"] += child_facts.st_size
    if is_directory and same_device:
        node["children"].append(child)
        return True
    return False


def _fold_directory_aggregates(
    directory_nodes: dict[str, dict[str, object]],
    visit_order: list[str],
) -> dict[str, tuple[int, int]]:
    aggregates: dict[str, tuple[int, int]] = {}
    for path in reversed(visit_order):
        node = directory_nodes[path]
        entry_count = node["direct_entry_count"]
        apparent_size = node["direct_regular_bytes"]
        for child in node["children"]:
            child_count, child_size = aggregates[child]
            entry_count += child_count
            apparent_size += child_size
        aggregates[path] = (entry_count, apparent_size)
    return aggregates


def _walk_observed_sources(
    request: InventoryRequestV2,
    topology: dict[str, object],
    container_inspects: dict[str, dict],
    volume_inspects: dict[str, dict],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    """Perform one bounded union walk and project it onto every logical root."""
    specs = _observation_walk_specs(
        request,
        topology,
        container_inspects,
        volume_inspects,
    )
    records: list[dict[str, object]] = []
    groups: dict[str, dict[str, object]] = {}
    inode_paths: dict[tuple[int, int, int], str] = {}
    observed_facts: dict[str, os.stat_result] = {}
    budget = 0

    logical_identities = [spec.get("identity_sha256") for spec in specs]
    if (
        any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in logical_identities)
        or len(logical_identities) != len(set(logical_identities))
    ):
        raise InventoryError("E_WALK_IDENTITY")

    for spec in specs:
        if spec["role"] == "tmpfs":
            records.append({
                "identity_sha256": spec["identity_sha256"],
                "role": "tmpfs",
                "path_sha256": identity_sha256(None),
                "device": 0,
                "ctime_ns": 0,
                "apparent_size_bytes": 0,
                "entry_count": 0,
                "acl_count": 0,
                "acl_sha256": identity_sha256([]),
                "xattr_count": 0,
                "xattr_sha256": identity_sha256([]),
                "metadata_bytes": 0,
            })
            continue
        path = safe_absolute_path(spec["path"], request.max_path_bytes)
        group = groups.setdefault(path, {"path": path, "specs": []})
        group["specs"].append(spec)

    for path in sorted(groups, key=lambda item: PurePosixPath(item).parts):
        group = groups[path]
        facts = _stable_identity(path, request.max_path_bytes)
        if not (stat.S_ISDIR(facts.st_mode) or stat.S_ISREG(facts.st_mode)):
            raise InventoryError("E_WALK_ROOT")
        if stat.S_ISREG(facts.st_mode) and facts.st_nlink != 1:
            raise InventoryError("E_WALK_TYPE")
        descriptor = None
        try:
            descriptor = _open_nofollow(Path(path))
            opened = os.fstat(descriptor)
        except (OSError, InventoryError) as exc:
            raise InventoryError("E_WALK_DRIFT") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if _stat_identity(opened) != _stat_identity(facts):
            raise InventoryError("E_WALK_DRIFT")
        mode_type = stat.S_IFMT(facts.st_mode)
        inode_key = (facts.st_dev, facts.st_ino, mode_type)
        prior_path = inode_paths.get(inode_key)
        if prior_path is not None and prior_path != path:
            raise InventoryError("E_WALK_ALIAS")
        if prior_path is None:
            inode_paths[inode_key] = path
            budget += 1
            if budget > request.max_recursive_entries:
                raise InventoryError("E_WALK_LIMIT")
        observed_facts[path] = facts
        group["facts"] = facts
        group["is_directory"] = stat.S_ISDIR(facts.st_mode)

    redis_specs = [
        (path, spec)
        for path, group in groups.items()
        for spec in group["specs"]
        if spec["role"] == "redis"
    ]
    if len(redis_specs) != 1:
        raise InventoryError("E_REDIS_MEMBER")
    redis_path = redis_specs[0][0]
    redis_candidates: dict[str, tuple[str, os.stat_result]] = {}
    declared_paths = set(groups)

    declared_directory_facts = {
        path: group["facts"]
        for path, group in groups.items()
        if group["is_directory"]
    }
    top_roots = _select_physical_directory_roots(declared_directory_facts)
    for path, group in groups.items():
        if group["is_directory"]:
            continue
        nearest = _nearest_declared_directory(path, declared_directory_facts)
        if (
            nearest is None
            or group["facts"].st_dev != declared_directory_facts[nearest].st_dev
        ):
            top_roots.append(path)
    top_roots.sort(key=lambda item: PurePosixPath(item).parts)

    seen_directories = set()
    directory_nodes: dict[str, dict[str, object]] = {}
    visit_order: list[str] = []
    for top_path in top_roots:
        top_facts = groups[top_path]["facts"]
        if stat.S_ISREG(top_facts.st_mode):
            continue
        stack = [(top_path, top_facts, top_path == redis_path)]
        while stack:
            directory, expected_directory, redis_active = stack.pop()
            descriptor = None
            try:
                descriptor = _open_nofollow(Path(directory))
                directory_facts = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(directory_facts.st_mode)
                    or _stat_identity(directory_facts) != _stat_identity(expected_directory)
                ):
                    raise InventoryError("E_WALK_DRIFT")
                directory_key = (directory_facts.st_dev, directory_facts.st_ino)
                if directory_key in seen_directories:
                    raise InventoryError("E_WALK_CYCLE")
                seen_directories.add(directory_key)
                node = {
                    "direct_entry_count": 0,
                    "direct_regular_bytes": 0,
                    "children": [],
                }
                directory_nodes[directory] = node
                visit_order.append(directory)
                entry_data = []
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        if (
                            not isinstance(entry.name, str)
                            or not entry.name
                            or entry.name in {".", ".."}
                            or "/" in entry.name
                            or CONTROL_RE.search(entry.name)
                        ):
                            raise InventoryError("E_WALK_NAME")
                        child = os.path.join(directory, entry.name)
                        safe_absolute_path(child, request.max_path_bytes)
                        child_facts = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(child_facts.st_mode):
                            raise InventoryError("E_WALK_LINK")
                        is_directory = stat.S_ISDIR(child_facts.st_mode)
                        if not (is_directory or stat.S_ISREG(child_facts.st_mode)):
                            raise InventoryError("E_WALK_TYPE")
                        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                        if is_directory:
                            flags |= os.O_DIRECTORY
                        child_descriptor = os.open(entry.name, flags, dir_fd=descriptor)
                        try:
                            opened_child = os.fstat(child_descriptor)
                        finally:
                            os.close(child_descriptor)
                        if _stat_identity(opened_child) != _stat_identity(child_facts):
                            raise InventoryError("E_WALK_DRIFT")
                        if stat.S_ISREG(opened_child.st_mode) and opened_child.st_nlink != 1:
                            raise InventoryError("E_WALK_TYPE")
                        if (
                            opened_child.st_dev != top_facts.st_dev
                            and child not in declared_paths
                        ):
                            raise InventoryError("E_WALK_DEVICE")
                        inode_key = (
                            opened_child.st_dev, opened_child.st_ino,
                            stat.S_IFMT(opened_child.st_mode),
                        )
                        prior_path = inode_paths.get(inode_key)
                        if prior_path is not None and prior_path != child:
                            raise InventoryError("E_WALK_ALIAS")
                        if prior_path is None:
                            budget += 1
                            if budget > request.max_recursive_entries:
                                raise InventoryError("E_WALK_LIMIT")
                            inode_paths[inode_key] = child
                        entry_data.append((entry.name, child, opened_child, is_directory))
                if _stat_identity(directory_facts) != _stat_identity(os.fstat(descriptor)):
                    raise InventoryError("E_WALK_DRIFT")
            except InventoryError:
                raise
            except OSError as exc:
                raise InventoryError("E_WALK_READ") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)

            for _name, child, child_facts, is_directory in sorted(entry_data):
                previous = observed_facts.get(child)
                if previous is not None and _stat_identity(previous) != _stat_identity(child_facts):
                    raise InventoryError("E_WALK_DRIFT")
                observed_facts[child] = child_facts
                descend = _record_physical_child(
                    node,
                    child,
                    child_facts,
                    is_directory=is_directory,
                    traversal_device=top_facts.st_dev,
                    declared_paths=declared_paths,
                )
                if not is_directory:
                    if redis_active and child_facts.st_dev == top_facts.st_dev:
                        relative = os.path.relpath(child, redis_path)
                        if (
                            relative.startswith("../")
                            or relative == ".."
                            or relative in redis_candidates
                        ):
                            raise InventoryError("E_REDIS_MEMBER")
                        redis_candidates[relative] = (child, child_facts)
                if descend:
                    stack.append((child, child_facts, redis_active or child == redis_path))

    aggregates = _fold_directory_aggregates(directory_nodes, visit_order)

    redis_members = _redis_persistence_members(
        redis_path, redis_candidates, request, [0],
    )
    metadata_by_path = {
        path: _metadata_hashes(path, request) for path in sorted(groups)
    }
    for observed_path, expected in sorted(observed_facts.items()):
        descriptor = None
        try:
            descriptor = _open_nofollow(Path(observed_path))
            current = os.fstat(descriptor)
        except (OSError, InventoryError) as exc:
            raise InventoryError("E_WALK_DRIFT") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if _stat_identity(current) != _stat_identity(expected):
            raise InventoryError("E_WALK_DRIFT")
    for path in sorted(groups):
        group = groups[path]
        facts = group["facts"]
        if group["is_directory"]:
            entry_count, apparent_size = aggregates[path]
        else:
            entry_count, apparent_size = 1, facts.st_size
        for spec in group["specs"]:
            records.append({
                "identity_sha256": spec["identity_sha256"],
                "role": spec["role"],
                "path_sha256": _sha256_text(path),
                "device": facts.st_dev,
                "ctime_ns": facts.st_ctime_ns,
                "apparent_size_bytes": apparent_size,
                "entry_count": entry_count,
                **metadata_by_path[path],
            })

    filesystems = {}
    filesystem_paths: dict[int, str] = {}
    for path in sorted(groups, key=lambda item: PurePosixPath(item).parts):
        device = groups[path]["facts"].st_dev
        filesystem_paths.setdefault(device, path)
    for device in sorted(filesystem_paths):
        path = filesystem_paths[device]
        expected = groups[path]["facts"]
        if device in filesystems:
            continue
        descriptor = None
        try:
            descriptor = _open_nofollow(Path(path))
            before = os.fstat(descriptor)
            if _stat_identity(before) != _stat_identity(expected):
                raise InventoryError("E_FILESYSTEM_DRIFT")
            usage = os.fstatvfs(descriptor)
            after = os.fstat(descriptor)
            final_path = _stable_identity(path, request.max_path_bytes)
            if (
                _stat_identity(before) != _stat_identity(after)
                or _stat_identity(before) != _stat_identity(final_path)
            ):
                raise InventoryError("E_FILESYSTEM_DRIFT")
        except InventoryError:
            raise
        except OSError as exc:
            raise InventoryError("E_FILESYSTEM") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        capacity = usage.f_blocks * usage.f_frsize
        available = usage.f_bavail * usage.f_frsize
        filesystems[device] = {
            "device": device,
            "capacity_bytes": capacity,
            "available_bytes": available,
        }
    return (
        sorted(records, key=lambda item: (item["role"], item["identity_sha256"])),
        [filesystems[key] for key in sorted(filesystems)],
        sorted(redis_members, key=canonical_bytes),
    )


def _minimal_observed_path_record(
    identity: str,
    role: str,
    path_sha256: str,
) -> dict[str, object]:
    return {
        "identity_sha256": identity,
        "role": role,
        "path_sha256": path_sha256,
        "device": 0,
        "ctime_ns": 0,
        "apparent_size_bytes": 0,
        "entry_count": 0,
        "acl_count": 0,
        "acl_sha256": "0" * 64,
        "xattr_count": 0,
        "xattr_sha256": "0" * 64,
        "metadata_bytes": 0,
    }


def _enforce_observation_size_lower_bound(
    request: InventoryRequestV2,
    topology: dict[str, object],
) -> None:
    """Reject impossible output limits using topology only, before host I/O."""
    observed_sources = [
        _minimal_observed_path_record(
            item["identity_sha256"], item["role"], item["path_sha256"],
        )
        for item in _expected_observed_sources(request)
    ]
    persistence = []
    for volume in topology["volumes"]:
        persistence.append(_minimal_observed_path_record(
            identity_sha256({
                "kind": volume["kind"],
                "name": volume["name"],
                "path": volume["mountpoint"]["path"],
            }),
            "persistence",
            volume["mountpoint"]["path"]["sha256"],
        ))
    for container in topology["containers"]:
        for mount in container["mounts"]:
            if mount["kind"] not in {"bind", "tmpfs"}:
                continue
            is_tmpfs = mount["kind"] == "tmpfs"
            persistence.append(_minimal_observed_path_record(
                identity_sha256({"container_id": container["id"], "mount": mount}),
                "tmpfs" if is_tmpfs else "persistence",
                identity_sha256(None) if is_tmpfs else mount["source"]["path"]["sha256"],
            ))
    persistence.sort(key=lambda item: (item["role"], item["identity_sha256"]))
    minimum = {
        "schema_version": OBSERVATION_SCHEMA,
        **_identity_fields(request),
        "topology_sha256": identity_sha256(topology),
        "containers": [
            {
                "id": item["id"],
                "running": True,
                "health": "none",
                "writable_layer": {
                    "count": 0,
                    "classification": "empty",
                    "operations": [],
                    "sha256": identity_sha256([]),
                },
            }
            for item in topology["containers"]
        ],
        "observed_sources": observed_sources,
        "persistence": persistence,
        "filesystems": [],
        "redis_persistence_member_count": 0,
        "redis_persistence_members": [],
        "redis_persistence_members_sha256": identity_sha256([]),
    }
    if len(canonical_bytes(minimum)) > min(
        request.max_observation_bytes, HARD_MAX_OBSERVATION_BYTES,
    ):
        raise InventoryError("E_OBSERVATION_LIMIT")


def collect_observation_v2(
    request: InventoryRequestV2,
    runner: CommandRunner,
    topology: object,
) -> dict[str, object]:
    """Collect volatile facts for exactly the container IDs in one topology."""
    if not isinstance(request, InventoryRequestV2):
        raise InventoryError("E_REQUEST_TYPE")
    runner = _budgeted_runner(request, runner)
    topology = validate_topology_v2(topology, request)
    if any(topology[key] != value for key, value in _identity_fields(request).items()):
        raise InventoryError("E_OBSERVATION_REQUEST_BINDING")
    if topology["service_role_sha256"] != {
        role: list(request.service_role_sha256[role]) for role in ("caddy", "redis")
    }:
        raise InventoryError("E_OBSERVATION_REQUEST_BINDING")
    if topology["privacy_expectations"] != _privacy_expectations(request):
        raise InventoryError("E_OBSERVATION_REQUEST_BINDING")
    _enforce_observation_size_lower_bound(request, topology)
    expected_ids = topology["deletion_vector"]
    before = _enumerate(
        request,
        runner,
        ("ps", "-aq", "--no-trunc"),
        limit=request.max_containers,
        pattern=CONTAINER_ID_RE,
        code="E_CONTAINER",
    )
    if before != expected_ids:
        raise InventoryError("E_OBSERVATION_TOPOLOGY_DRIFT")
    inspected = _inspect_exact(request, runner, "container", before, "Id")
    repo_digests_by_image = _image_repo_digests(request, runner, inspected)
    expected_containers = {item["id"]: item for item in topology["containers"]}
    for identifier in expected_ids:
        current_record = inspected[identifier]
        current, _redis = _container_topology(
            current_record,
            request,
            repo_digests_by_image[current_record["Image"]],
        )
        if canonical_bytes(current) != canonical_bytes(expected_containers[identifier]):
            raise InventoryError("E_OBSERVATION_CONTAINER_DRIFT")
    volume_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
    _volume_ids, volume_inspects = _stable_inspect(
        request,
        runner,
        list_suffix=("volume", "ls", "-q"),
        inspect_kind="volume",
        limit=request.max_volumes,
        pattern=volume_pattern,
        identity_key="Name",
        code="E_VOLUME",
    )
    containers = []
    total_diff_entries = 0
    for identifier in expected_ids:
        running, health = _health_state(inspected[identifier].get("State"))
        writable = _writable_layer(identifier, request, runner)
        total_diff_entries += writable["count"]
        if total_diff_entries > request.max_recursive_entries:
            raise InventoryError("E_DIFF_LIMIT")
        containers.append({
            "id": identifier,
            "running": running,
            "health": health,
            "writable_layer": writable,
        })
    after = _enumerate(
        request,
        runner,
        ("ps", "-aq", "--no-trunc"),
        limit=request.max_containers,
        pattern=CONTAINER_ID_RE,
        code="E_CONTAINER",
    )
    if after != expected_ids:
        raise InventoryError("E_OBSERVATION_TOPOLOGY_DRIFT")
    path_records, filesystems, redis_members = _walk_observed_sources(
        request,
        topology,
        inspected,
        volume_inspects,
    )
    observed_sources = [
        item for item in path_records if item["role"] in SOURCE_ROLES
    ]
    persistence = [
        item for item in path_records if item["role"] in {"persistence", "tmpfs"}
    ]
    observation = {
        "schema_version": OBSERVATION_SCHEMA,
        **_identity_fields(request),
        "topology_sha256": identity_sha256(topology),
        "containers": containers,
        "observed_sources": observed_sources,
        "persistence": persistence,
        "filesystems": filesystems,
        "redis_persistence_member_count": len(redis_members),
        "redis_persistence_members": redis_members,
        "redis_persistence_members_sha256": identity_sha256(redis_members),
    }
    raw = canonical_bytes(observation)
    if len(raw) > min(request.max_observation_bytes, HARD_MAX_OBSERVATION_BYTES):
        raise InventoryError("E_OBSERVATION_LIMIT")
    return validate_observation_v2(observation, request)


def collect_inventory_v2(
    request: InventoryRequestV2,
    runner: CommandRunner,
) -> dict[str, object]:
    runner = _budgeted_runner(request, runner)
    topology_before = collect_topology_v2(request, runner)
    try:
        observation = collect_observation_v2(request, runner, topology_before)
    except InventoryError as exc:
        if str(exc) == "E_OBSERVATION_TOPOLOGY_DRIFT":
            raise InventoryError("E_TOPOLOGY_DRIFT") from exc
        raise
    try:
        topology_after = collect_topology_v2(request, runner)
    except InventoryError as exc:
        raise InventoryError("E_TOPOLOGY_DRIFT") from exc
    if canonical_bytes(topology_before) != canonical_bytes(topology_after):
        raise InventoryError("E_TOPOLOGY_DRIFT")
    inventory = {
        "schema_version": INVENTORY_SCHEMA,
        "topology": topology_before,
        "observation": observation,
    }
    raw = canonical_bytes(inventory)
    if len(raw) > min(request.max_inventory_bytes, HARD_MAX_INVENTORY_BYTES):
        raise InventoryError("E_INVENTORY_LIMIT")
    return validate_inventory_v2(inventory, request)


def _validate_identity_fields(value: dict[str, object]) -> None:
    for key in (
        "request_identity_projection_sha256", "inventory_target_claim_sha256",
        "inventory_nonce", "request_policy_sha256", "source_lock_sha256", "collector_sha256",
    ):
        _digest(value.get(key), "E_IDENTITY_FIELD")
    if value["request_identity_projection_sha256"] == value["inventory_target_claim_sha256"]:
        raise InventoryError("E_IDENTITY_FIELD")


def _validate_name_record(
    value: object,
    expected_raw_sha256: set[str],
) -> dict[str, str]:
    if not isinstance(value, dict) or value.get("kind") not in {"raw", "hashed"}:
        raise InventoryError("E_NAME_RECORD")
    _digest(value.get("sha256"), "E_NAME_RECORD")
    if value["kind"] == "raw":
        _exact_dict(value, {"kind", "sha256", "value"}, "E_NAME_RECORD")
        if not isinstance(value["value"], str) or not SAFE_NAME_RE.fullmatch(value["value"]):
            raise InventoryError("E_NAME_RECORD")
        if (
            _sha256_text(value["value"]) != value["sha256"]
            or value["sha256"] not in expected_raw_sha256
        ):
            raise InventoryError("E_NAME_RECORD")
    else:
        _exact_dict(value, {"kind", "sha256"}, "E_NAME_RECORD")
    return value


def _validate_path_record(
    value: object,
    expected_raw_sha256: set[str],
) -> dict[str, str]:
    if not isinstance(value, dict) or value.get("kind") not in {"raw", "hashed"}:
        raise InventoryError("E_PATH_RECORD")
    _digest(value.get("sha256"), "E_PATH_RECORD")
    if value["kind"] == "raw":
        _exact_dict(value, {"kind", "sha256", "value"}, "E_PATH_RECORD")
        safe_absolute_path(value["value"], HARD_MAX_PATH_BYTES)
        if (
            _sha256_text(value["value"]) != value["sha256"]
            or value["sha256"] not in expected_raw_sha256
        ):
            raise InventoryError("E_PATH_RECORD")
    else:
        _exact_dict(value, {"kind", "sha256"}, "E_PATH_RECORD")
    return value


def _validate_repo_record(
    value: object,
    approved_raw_sha256: set[str],
    allowed_registry_sha256: set[str],
) -> dict[str, str]:
    if not isinstance(value, dict) or value.get("kind") not in {"raw", "hashed"}:
        raise InventoryError("E_REPO_RECORD")
    _digest(value.get("sha256"), "E_REPO_RECORD")
    if value["kind"] == "raw":
        _exact_dict(value, {"kind", "sha256", "value"}, "E_REPO_RECORD")
        if not isinstance(value["value"], str):
            raise InventoryError("E_REPO_RECORD")
        match = REPO_DIGEST_RE.fullmatch(value["value"])
        if match is None:
            raise InventoryError("E_REPO_RECORD")
        if re.fullmatch(r"[0-9.]+", match.group("registry"), re.ASCII):
            raise InventoryError("E_REPO_RECORD")
        try:
            ipaddress.ip_address(match.group("registry"))
        except ValueError:
            pass
        else:
            raise InventoryError("E_REPO_RECORD")
        if (
            _sha256_text(value["value"]) != value["sha256"]
            or value["sha256"] not in approved_raw_sha256
            or _sha256_text(match.group("registry")) not in allowed_registry_sha256
        ):
            raise InventoryError("E_REPO_RECORD")
    else:
        _exact_dict(value, {"kind", "sha256"}, "E_REPO_RECORD")
    return value


PATH_METADATA_KEYS = frozenset({
    "path", "type", "device", "inode", "mode", "uid", "gid", "nlink",
})


def _validate_path_metadata(
    value: object,
    expected_raw_sha256: set[str],
) -> dict[str, object]:
    value = _exact_dict(value, PATH_METADATA_KEYS, "E_PATH_METADATA")
    _validate_path_record(value["path"], expected_raw_sha256)
    if value["type"] not in {"directory", "regular"}:
        raise InventoryError("E_PATH_METADATA")
    for key in ("device", "inode", "mode", "uid", "gid", "nlink"):
        _integer(value[key], "E_PATH_METADATA", minimum=0)
    if value["nlink"] < 1:
        raise InventoryError("E_PATH_METADATA")
    return value


def _validate_mount(
    value: object,
    expected_name_sha256: set[str],
    expected_path_sha256: set[str],
) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("kind") not in {
        "named_volume", "anonymous_volume", "bind", "tmpfs",
    }:
        raise InventoryError("E_MOUNT_RECORD")
    if value["kind"] in {"named_volume", "anonymous_volume"}:
        _exact_dict(
            value,
            {"kind", "name", "driver", "source", "destination", "read_only", "options_sha256"},
            "E_MOUNT_RECORD",
        )
        _validate_name_record(value["name"], expected_name_sha256)
        _validate_name_record(value["driver"], expected_name_sha256)
        _validate_path_record(value["source"], expected_path_sha256)
        _digest(value["options_sha256"], "E_MOUNT_RECORD")
    elif value["kind"] == "bind":
        _exact_dict(value, {"kind", "source", "destination", "read_only", "options_sha256"}, "E_MOUNT_RECORD")
        _validate_path_metadata(value["source"], expected_path_sha256)
        if value["source"]["type"] == "regular" and value["source"]["nlink"] != 1:
            raise InventoryError("E_MOUNT_RECORD")
        _digest(value["options_sha256"], "E_MOUNT_RECORD")
    else:
        _exact_dict(value, {"kind", "destination", "read_only", "options_sha256"}, "E_MOUNT_RECORD")
        _digest(value["options_sha256"], "E_MOUNT_RECORD")
    _validate_path_record(value["destination"], expected_path_sha256)
    if not isinstance(value["read_only"], bool):
        raise InventoryError("E_MOUNT_RECORD")
    return value


def _validate_container_topology(
    value: object,
    expected_name_sha256: set[str],
    expected_path_sha256: set[str],
    approved_repo_digest_sha256: set[str],
    allowed_registry_dns_sha256: set[str],
) -> dict[str, object]:
    keys = {
        "id", "name", "image_id", "repo_digests", "ownership_labels",
        "network_memberships", "published_ports", "mounts",
    }
    value = _exact_dict(value, keys, "E_CONTAINER_RECORD")
    if not isinstance(value["id"], str) or not CONTAINER_ID_RE.fullmatch(value["id"]):
        raise InventoryError("E_CONTAINER_RECORD")
    if not isinstance(value["image_id"], str) or not IMAGE_ID_RE.fullmatch(value["image_id"]):
        raise InventoryError("E_CONTAINER_RECORD")
    _validate_name_record(value["name"], expected_name_sha256)
    if (
        not isinstance(value["repo_digests"], list)
        or not value["repo_digests"]
        or len(value["repo_digests"]) > HARD_MAX_REPO_DIGESTS_PER_CONTAINER
        or value["repo_digests"] != sorted(value["repo_digests"], key=canonical_bytes)
    ):
        raise InventoryError("E_CONTAINER_RECORD")
    for item in value["repo_digests"]:
        _validate_repo_record(
            item,
            approved_repo_digest_sha256,
            allowed_registry_dns_sha256,
        )
    if len({item["sha256"] for item in value["repo_digests"]}) != len(value["repo_digests"]):
        raise InventoryError("E_CONTAINER_RECORD")
    if not isinstance(value["ownership_labels"], list):
        raise InventoryError("E_CONTAINER_RECORD")
    label_keys = []
    for item in value["ownership_labels"]:
        item = _exact_dict(item, {"key", "value"}, "E_LABEL_RECORD")
        if item["key"] not in OWNERSHIP_LABELS:
            raise InventoryError("E_LABEL_RECORD")
        label_keys.append(item["key"])
        _validate_name_record(item["value"], expected_name_sha256)
    if label_keys != sorted(set(label_keys)):
        raise InventoryError("E_LABEL_RECORD")
    deployment_values = {
        item["value"]["sha256"] for item in value["ownership_labels"]
        if item["key"] in {"io.deploydesk.deployment-id", "com.deploydesk.deployment-id"}
    }
    if len(deployment_values) > 1:
        raise InventoryError("E_LABEL_RECORD")
    if not isinstance(value["network_memberships"], list):
        raise InventoryError("E_NETWORK_MEMBERSHIP_RECORD")
    for item in value["network_memberships"]:
        item = _exact_dict(item, {"id", "name"}, "E_NETWORK_MEMBERSHIP_RECORD")
        if not isinstance(item["id"], str) or not CONTAINER_ID_RE.fullmatch(item["id"]):
            raise InventoryError("E_NETWORK_MEMBERSHIP_RECORD")
        _validate_name_record(item["name"], expected_name_sha256)
    if (
        len(value["network_memberships"]) > HARD_MAX_NETWORKS
        or value["network_memberships"] != sorted(value["network_memberships"], key=lambda item: (item["id"], canonical_bytes(item["name"])))
        or len({item["id"] for item in value["network_memberships"]}) != len(value["network_memberships"])
    ):
        raise InventoryError("E_NETWORK_MEMBERSHIP_RECORD")
    if not isinstance(value["published_ports"], list):
        raise InventoryError("E_PORT_RECORD")
    for item in value["published_ports"]:
        item = _exact_dict(item, {"container_port", "host_port", "protocol", "host_address_class"}, "E_PORT_RECORD")
        _integer(item["container_port"], "E_PORT_RECORD", minimum=1, maximum=65_535)
        _integer(item["host_port"], "E_PORT_RECORD", minimum=1, maximum=65_535)
        if item["protocol"] not in {"tcp", "udp", "sctp"} or item["host_address_class"] not in ADDRESS_CLASSES:
            raise InventoryError("E_PORT_RECORD")
    if (
        len(value["published_ports"]) > HARD_MAX_PORTS_PER_CONTAINER
        or value["published_ports"] != sorted(value["published_ports"], key=canonical_bytes)
        or len({canonical_bytes(item) for item in value["published_ports"]}) != len(value["published_ports"])
    ):
        raise InventoryError("E_PORT_RECORD")
    if (
        not isinstance(value["mounts"], list)
        or len(value["mounts"]) > HARD_MAX_MOUNTS_PER_CONTAINER
        or value["mounts"] != sorted(value["mounts"], key=canonical_bytes)
        or len({canonical_bytes(item) for item in value["mounts"]}) != len(value["mounts"])
    ):
        raise InventoryError("E_MOUNT_RECORD")
    for item in value["mounts"]:
        _validate_mount(item, expected_name_sha256, expected_path_sha256)
    return value


def _validate_capabilities(value: object) -> dict[str, object]:
    host_keys = {
        "host_tar", "host_zstd", "host_psql", "host_pg_dump",
        "host_redis_server", "host_caddy", "host_visudo",
    }
    value = _exact_dict(value, {"os", "docker", *host_keys}, "E_CAPABILITIES")
    os_value = _exact_dict(value["os"], {"kernel_release_sha256", "nofollow_supported", "dir_fd_supported", "xattr_supported"}, "E_CAP_OS")
    _digest(os_value["kernel_release_sha256"], "E_CAP_OS")
    if any(not isinstance(os_value[key], bool) for key in ("nofollow_supported", "dir_fd_supported", "xattr_supported")):
        raise InventoryError("E_CAP_OS")
    if os_value["nofollow_supported"] is not True or os_value["dir_fd_supported"] is not True:
        raise InventoryError("E_CAP_OS")
    docker = _exact_dict(value["docker"], {"client_version", "client_api_version", "server_version", "server_api_version"}, "E_CAP_DOCKER")
    for item in docker.values():
        _version(item, "E_CAP_DOCKER")
    for key in host_keys:
        item = value[key]
        if isinstance(item, dict) and item == {"available": False}:
            continue
        expected = {"available", "version", "implementation"} if key == "host_tar" else {"available", "version"}
        item = _exact_dict(item, expected, "E_CAPABILITY")
        if item["available"] is not True:
            raise InventoryError("E_CAPABILITY")
        if key == "host_tar" and item["implementation"] != "gnu":
            raise InventoryError("E_CAPABILITY")
        _version(item["version"], "E_CAPABILITY")
    return value


def _visible_raw_paths(value: object):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if (
                item.get("kind") == "raw"
                and isinstance(item.get("value"), str)
                and item["value"].startswith("/")
            ):
                yield item["value"]
                continue
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _validate_topology_request_limits(
    value: dict[str, object],
    request: InventoryRequestV2,
) -> None:
    if (
        len(value["containers"]) > request.max_containers
        or len(value["volumes"]) > request.max_volumes
        or len(value["networks"]) > request.max_networks
        or any(
            len(item["mounts"]) > request.max_mounts_per_container
            or len(item["published_ports"]) > request.max_ports_per_container
            for item in value["containers"]
        )
        or any(
            item["acl_count"] + item["xattr_count"] > request.max_acl_entries
            or item["metadata_bytes"] > request.max_acl_bytes_per_path
            for item in value["trusted_ancestors"]
        )
        or any(
            len(path.encode("utf-8")) > request.max_path_bytes
            for path in _visible_raw_paths(value)
        )
        or len(canonical_bytes(value)) > request.max_topology_bytes
    ):
        raise InventoryError("E_REQUEST_EVIDENCE_LIMIT")


def _expected_observed_sources(
    request: InventoryRequestV2,
) -> list[dict[str, str]]:
    return [
        {
            "role": role,
            "path_sha256": _sha256_text(path),
            "identity_sha256": _sha256_text("source:" + role + ":" + path),
        }
        for role, path in request.observed_sources
    ]


def validate_topology_v2(
    value: object,
    request: InventoryRequestV2 | None = None,
) -> dict[str, object]:
    """Validate topology structure; supply ``request`` to enforce privacy authorization.

    The one-argument form is structural-only.  ``privacy_expectations`` is an
    unauthenticated diagnostic projection and never grants permission to emit
    raw names, paths, or repository digests.
    """
    keys = {
        "schema_version", "request_identity_projection_sha256", "inventory_target_claim_sha256",
        "inventory_nonce", "request_policy_sha256", "source_lock_sha256", "collector_sha256",
        "privacy_expectations", "service_role_sha256",
        "container_count", "containers", "deletion_vector", "volume_count", "volumes",
        "network_count", "networks", "trusted_ancestors", "caddy", "redis", "capabilities",
    }
    value = _exact_dict(value, keys, "E_TOPOLOGY_KEYS")
    if value["schema_version"] != TOPOLOGY_SCHEMA:
        raise InventoryError("E_TOPOLOGY_SCHEMA")
    _validate_identity_fields(value)
    privacy = _validate_privacy_expectations(value["privacy_expectations"])
    service_roles = _validate_service_roles(value["service_role_sha256"], "E_SERVICE_ROLE")
    if request is not None:
        if not isinstance(request, InventoryRequestV2):
            raise InventoryError("E_REQUEST_TYPE")
        if any(value[key] != expected for key, expected in _identity_fields(request).items()):
            raise InventoryError("E_TOPOLOGY_REQUEST_BINDING")
        if privacy != _privacy_expectations(request):
            raise InventoryError("E_TOPOLOGY_REQUEST_BINDING")
        expected_service_roles = {
            role: list(request.service_role_sha256[role]) for role in ("caddy", "redis")
        }
        if service_roles != expected_service_roles:
            raise InventoryError("E_TOPOLOGY_REQUEST_BINDING")
        expected_name_sha256 = set(request.expected_name_sha256)
        expected_path_sha256 = set(request.expected_path_sha256)
        approved_repo_digest_sha256 = set(request.approved_repo_digest_sha256)
        allowed_registry_dns_sha256 = {
            _sha256_text(value) for value in request.allowed_registry_dns_prefixes
        }
    else:
        expected_name_sha256 = set(privacy["expected_name_sha256"])
        expected_path_sha256 = set(privacy["expected_path_sha256"])
        approved_repo_digest_sha256 = set(privacy["approved_repo_digest_sha256"])
        allowed_registry_dns_sha256 = set(privacy["allowed_registry_dns_sha256"])
    if not isinstance(value["containers"], list) or value["containers"] != sorted(value["containers"], key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
        raise InventoryError("E_TOPOLOGY_CONTAINERS")
    for item in value["containers"]:
        _validate_container_topology(
            item,
            expected_name_sha256,
            expected_path_sha256,
            approved_repo_digest_sha256,
            allowed_registry_dns_sha256,
        )
    image_projection = {}
    for item in value["containers"]:
        projected = canonical_bytes(item["repo_digests"])
        previous = image_projection.setdefault(item["image_id"], projected)
        if previous != projected:
            raise InventoryError("E_IMAGE_BINDING")
    _integer(value["container_count"], "E_TOPOLOGY_COUNT", maximum=HARD_MAX_CONTAINERS)
    if value["container_count"] != len(value["containers"]):
        raise InventoryError("E_TOPOLOGY_COUNT")
    if not isinstance(value["deletion_vector"], list) or value["deletion_vector"] != sorted(value["deletion_vector"]):
        raise InventoryError("E_DELETION_VECTOR")
    if value["deletion_vector"] != [item["id"] for item in value["containers"]]:
        raise InventoryError("E_DELETION_VECTOR")
    if len(value["deletion_vector"]) != len(set(value["deletion_vector"])):
        raise InventoryError("E_DELETION_VECTOR")
    if not isinstance(value["volumes"], list) or value["volumes"] != sorted(value["volumes"], key=lambda item: canonical_bytes(item.get("name")) if isinstance(item, dict) else b""):
        raise InventoryError("E_VOLUME_RECORD")
    for item in value["volumes"]:
        item = _exact_dict(item, {"name", "kind", "driver", "scope", "mountpoint", "options_sha256"}, "E_VOLUME_RECORD")
        _validate_name_record(item["name"], expected_name_sha256)
        _validate_name_record(item["driver"], expected_name_sha256)
        if item["kind"] not in {"named_volume", "anonymous_volume"} or item["scope"] not in {"local", "global", "swarm"}:
            raise InventoryError("E_VOLUME_RECORD")
        _validate_path_metadata(item["mountpoint"], expected_path_sha256)
        if item["mountpoint"]["type"] != "directory":
            raise InventoryError("E_VOLUME_RECORD")
        _digest(item["options_sha256"], "E_VOLUME_RECORD")
    _integer(value["volume_count"], "E_TOPOLOGY_COUNT", maximum=HARD_MAX_VOLUMES)
    if value["volume_count"] != len(value["volumes"]):
        raise InventoryError("E_TOPOLOGY_COUNT")
    if len({item["name"]["sha256"] for item in value["volumes"]}) != len(value["volumes"]):
        raise InventoryError("E_VOLUME_RECORD")
    if not isinstance(value["networks"], list) or value["networks"] != sorted(value["networks"], key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
        raise InventoryError("E_NETWORK_RECORD")
    for item in value["networks"]:
        item = _exact_dict(item, {"id", "name", "driver", "scope", "internal", "attachable", "ingress", "ipam_sha256"}, "E_NETWORK_RECORD")
        if not CONTAINER_ID_RE.fullmatch(item["id"]) or item["scope"] not in {"local", "global", "swarm"}:
            raise InventoryError("E_NETWORK_RECORD")
        _validate_name_record(item["name"], expected_name_sha256)
        _validate_name_record(item["driver"], expected_name_sha256)
        if any(not isinstance(item[field], bool) for field in ("internal", "attachable", "ingress")):
            raise InventoryError("E_NETWORK_RECORD")
        _digest(item["ipam_sha256"], "E_NETWORK_RECORD")
    _integer(value["network_count"], "E_TOPOLOGY_COUNT", maximum=HARD_MAX_NETWORKS)
    if value["network_count"] != len(value["networks"]):
        raise InventoryError("E_TOPOLOGY_COUNT")
    if len({item["id"] for item in value["networks"]}) != len(value["networks"]):
        raise InventoryError("E_NETWORK_RECORD")
    if not isinstance(value["trusted_ancestors"], list) or value["trusted_ancestors"] != sorted(value["trusted_ancestors"], key=lambda item: canonical_bytes(item.get("path")) if isinstance(item, dict) else b""):
        raise InventoryError("E_ANCESTOR_RECORD")
    ancestor_keys = PATH_METADATA_KEYS | {"acl_count", "acl_sha256", "xattr_count", "xattr_sha256", "metadata_bytes"}
    for item in value["trusted_ancestors"]:
        item = _exact_dict(item, ancestor_keys, "E_ANCESTOR_RECORD")
        _validate_path_metadata(
            {key: item[key] for key in PATH_METADATA_KEYS},
            expected_path_sha256,
        )
        if item["type"] != "directory":
            raise InventoryError("E_ANCESTOR_RECORD")
        for key in ("acl_count", "xattr_count"):
            _integer(item[key], "E_ANCESTOR_RECORD", maximum=HARD_MAX_ACL_ENTRIES)
        _integer(item["metadata_bytes"], "E_ANCESTOR_RECORD", maximum=HARD_MAX_ACL_BYTES_PER_PATH)
        _digest(item["acl_sha256"], "E_ANCESTOR_RECORD")
        _digest(item["xattr_sha256"], "E_ANCESTOR_RECORD")
        if item["acl_count"] + item["xattr_count"] > HARD_MAX_ACL_ENTRIES:
            raise InventoryError("E_ANCESTOR_RECORD")
    if (
        not value["trusted_ancestors"]
        or len(value["trusted_ancestors"]) > HARD_MAX_TRUSTED_ANCESTORS
        or len({item["path"]["sha256"] for item in value["trusted_ancestors"]}) != len(value["trusted_ancestors"])
    ):
        raise InventoryError("E_ANCESTOR_RECORD")
    caddy = _exact_dict(value["caddy"], {"files", "owners", "behaviors", "container_ids"}, "E_CADDY_RECORD")
    if not all(isinstance(caddy[key], list) for key in caddy):
        raise InventoryError("E_CADDY_RECORD")
    file_keys = PATH_METADATA_KEYS | {"content_sha256"}
    for item in caddy["files"]:
        item = _exact_dict(item, file_keys, "E_CADDY_FILE")
        _validate_path_metadata(
            {key: item[key] for key in PATH_METADATA_KEYS},
            expected_path_sha256,
        )
        if item["type"] != "regular":
            raise InventoryError("E_CADDY_FILE")
        if item["nlink"] != 1:
            raise InventoryError("E_CADDY_FILE")
        _digest(item["content_sha256"], "E_CADDY_FILE")
    if (
        not caddy["files"]
        or len(caddy["files"]) > HARD_MAX_CADDY_RECORDS
        or caddy["files"] != sorted(caddy["files"], key=lambda item: canonical_bytes(item["path"]))
        or len({item["path"]["sha256"] for item in caddy["files"]}) != len(caddy["files"])
    ):
        raise InventoryError("E_CADDY_FILE")
    for item in caddy["owners"]:
        item = _exact_dict(item, {"host", "source_path_sha256", "writer_uid", "writer_gid"}, "E_CADDY_OWNER")
        _validate_name_record(item["host"], expected_name_sha256)
        _digest(item["source_path_sha256"], "E_CADDY_OWNER")
        _integer(item["writer_uid"], "E_CADDY_OWNER")
        _integer(item["writer_gid"], "E_CADDY_OWNER")
    if (
        not caddy["owners"]
        or len(caddy["owners"]) > HARD_MAX_CADDY_RECORDS
        or caddy["owners"] != sorted(caddy["owners"], key=canonical_bytes)
        or len({(item["host"]["sha256"], item["source_path_sha256"]) for item in caddy["owners"]}) != len(caddy["owners"])
        or len({item["host"]["sha256"] for item in caddy["owners"]}) != len(caddy["owners"])
    ):
        raise InventoryError("E_CADDY_OWNER")
    for item in caddy["behaviors"]:
        if not isinstance(item, dict):
            raise InventoryError("E_CADDY_BEHAVIOR")
        kind = item.get("kind")
        if kind == "redirect":
            item = _exact_dict(
                item,
                {"kind", "source_host_sha256", "target_class", "target_sha256", "status_code", "preserve_uri", "behavior_sha256"},
                "E_CADDY_BEHAVIOR",
            )
            if item["target_class"] != "absolute_https" or item["preserve_uri"] is not True:
                raise InventoryError("E_CADDY_BEHAVIOR")
            _digest(item["target_sha256"], "E_CADDY_BEHAVIOR")
            if item["status_code"] not in {301, 308}:
                raise InventoryError("E_CADDY_BEHAVIOR")
        elif kind in {"docker_proxy", "https_proxy"}:
            item = _exact_dict(
                item,
                {
                    "kind", "source_host_sha256",
                    "target_scheme", "target_host_sha256", "target_port",
                    "header_up_host_sha256", "tls_server_name_sha256", "encodings", "behavior_sha256",
                },
                "E_CADDY_BEHAVIOR",
            )
            if item["encodings"] != ["zstd", "gzip"]:
                raise InventoryError("E_CADDY_BEHAVIOR")
            for key in ("target_host_sha256", "header_up_host_sha256", "tls_server_name_sha256"):
                if item[key] is not None:
                    _digest(item[key], "E_CADDY_BEHAVIOR")
            if kind == "docker_proxy" and (
                item["target_scheme"] != "http"
                or item["header_up_host_sha256"] is not None
                or item["tls_server_name_sha256"] is not None
            ):
                raise InventoryError("E_CADDY_BEHAVIOR")
            if kind == "https_proxy" and (
                item["target_scheme"] != "https"
                or item["target_port"] != 443
                or item["header_up_host_sha256"] != item["target_host_sha256"]
                or item["tls_server_name_sha256"] != item["target_host_sha256"]
            ):
                raise InventoryError("E_CADDY_BEHAVIOR")
            _integer(item["target_port"], "E_CADDY_BEHAVIOR", minimum=1, maximum=65_535)
        else:
            raise InventoryError("E_CADDY_BEHAVIOR")
        for key in ("source_host_sha256", "behavior_sha256"):
            _digest(item[key], "E_CADDY_BEHAVIOR")
        if identity_sha256({key: value for key, value in item.items() if key != "behavior_sha256"}) != item["behavior_sha256"]:
            raise InventoryError("E_CADDY_BEHAVIOR")
    if (
        not caddy["behaviors"]
        or len(caddy["behaviors"]) > HARD_MAX_CADDY_RECORDS
        or caddy["behaviors"] != sorted(caddy["behaviors"], key=canonical_bytes)
        or len({item["behavior_sha256"] for item in caddy["behaviors"]}) != len(caddy["behaviors"])
    ):
        raise InventoryError("E_CADDY_BEHAVIOR")
    if (
        not caddy["container_ids"]
        or len(caddy["container_ids"]) > HARD_MAX_CONTAINERS
        or caddy["container_ids"] != sorted(set(caddy["container_ids"]))
        or any(not CONTAINER_ID_RE.fullmatch(item) for item in caddy["container_ids"])
    ):
        raise InventoryError("E_CADDY_RECORD")
    if not isinstance(value["redis"], list) or value["redis"] != sorted(value["redis"], key=lambda item: item.get("container_id", "") if isinstance(item, dict) else ""):
        raise InventoryError("E_REDIS_RECORD")
    for item in value["redis"]:
        item = _exact_dict(item, {"container_id", "command_sha256", "config_path_sha256", "persistence_mount_sha256"}, "E_REDIS_RECORD")
        if not CONTAINER_ID_RE.fullmatch(item["container_id"]):
            raise InventoryError("E_REDIS_RECORD")
        for key in ("command_sha256", "config_path_sha256"):
            _digest(item[key], "E_REDIS_RECORD")
        if (
            not isinstance(item["persistence_mount_sha256"], list)
            or len(item["persistence_mount_sha256"]) > HARD_MAX_MOUNTS_PER_CONTAINER
            or item["persistence_mount_sha256"] != sorted(set(item["persistence_mount_sha256"]))
        ):
            raise InventoryError("E_REDIS_RECORD")
        for digest in item["persistence_mount_sha256"]:
            _digest(digest, "E_REDIS_RECORD")
    if (
        not value["redis"]
        or len(value["redis"]) > HARD_MAX_CONTAINERS
        or len({item["container_id"] for item in value["redis"]}) != len(value["redis"])
    ):
        raise InventoryError("E_REDIS_RECORD")

    network_by_id = {item["id"]: item for item in value["networks"]}
    for container in value["containers"]:
        if any(
            item["id"] not in network_by_id
            or item["name"] != network_by_id[item["id"]]["name"]
            for item in container["network_memberships"]
        ):
            raise InventoryError("E_NETWORK_MEMBERSHIP_RECORD")

    volume_by_key = {
        (item["kind"], item["name"]["sha256"]): item
        for item in value["volumes"]
    }
    for container in value["containers"]:
        for mount in container["mounts"]:
            if (
                mount["kind"] in {"named_volume", "anonymous_volume"}
                and (
                    (mount["kind"], mount["name"]["sha256"]) not in volume_by_key
                    or mount["name"]
                    != volume_by_key[(mount["kind"], mount["name"]["sha256"])]["name"]
                    or mount["driver"]
                    != volume_by_key[(mount["kind"], mount["name"]["sha256"])]["driver"]
                    or mount["source"]
                    != volume_by_key[(mount["kind"], mount["name"]["sha256"])]["mountpoint"]["path"]
                )
            ):
                raise InventoryError("E_VOLUME_MOUNT_LINK")

    service_by_id = {}
    for container in value["containers"]:
        service = next((
            item["value"]["sha256"]
            for item in container["ownership_labels"]
            if item["key"] == "com.docker.compose.service"
        ), None)
        service_by_id[container["id"]] = service
    expected_caddy_ids = sorted(
        identifier for identifier, service in service_by_id.items()
        if service in service_roles["caddy"]
    )
    if caddy["container_ids"] != expected_caddy_ids:
        raise InventoryError("E_CADDY_RECORD")
    caddy_files_by_hash = {
        item["path"]["sha256"]: item for item in caddy["files"]
    }
    caddy_file_hashes = set(caddy_files_by_hash)
    owner_host_hashes = {item["host"]["sha256"] for item in caddy["owners"]}
    behavior_host_hashes = [item["source_host_sha256"] for item in caddy["behaviors"]]
    if (
        any(item["source_path_sha256"] not in caddy_file_hashes for item in caddy["owners"])
        or any(
            item["writer_uid"]
            != caddy_files_by_hash[item["source_path_sha256"]]["uid"]
            or item["writer_gid"]
            != caddy_files_by_hash[item["source_path_sha256"]]["gid"]
            for item in caddy["owners"]
            if item["source_path_sha256"] in caddy_files_by_hash
        )
        or set(behavior_host_hashes) != owner_host_hashes
        or len(behavior_host_hashes) != len(set(behavior_host_hashes))
    ):
        raise InventoryError("E_CADDY_LINK")

    redis_by_id = {item["container_id"]: item for item in value["redis"]}
    expected_redis_ids = {
        identifier for identifier, service in service_by_id.items()
        if service in service_roles["redis"]
    }
    if set(redis_by_id) != expected_redis_ids:
        raise InventoryError("E_REDIS_RECORD")
    container_by_id = {item["id"]: item for item in value["containers"]}
    for identifier, record in redis_by_id.items():
        expected_mounts = sorted(
            identity_sha256(mount)
            for mount in container_by_id[identifier]["mounts"]
            if mount["destination"]["sha256"] == _sha256_text("/data")
        )
        if record["persistence_mount_sha256"] != expected_mounts:
            raise InventoryError("E_REDIS_RECORD")
    if request is not None:
        expected_ancestor_paths = {
            _sha256_text(path) for path in request.trusted_ancestor_paths
        }
        expected_caddy_paths = {_sha256_text(path) for path in request.caddy_roots}
        if (
            {item["path"]["sha256"] for item in value["trusted_ancestors"]}
            != expected_ancestor_paths
            or {item["path"]["sha256"] for item in caddy["files"]}
            != expected_caddy_paths
        ):
            raise InventoryError("E_TOPOLOGY_REQUEST_BINDING")
        _validate_topology_request_limits(value, request)
    _validate_capabilities(value["capabilities"])
    if len(canonical_bytes(value)) > HARD_MAX_TOPOLOGY_BYTES:
        raise InventoryError("E_TOPOLOGY_LIMIT")
    return value


def _validate_observed_path(value: object) -> dict[str, object]:
    keys = {
        "identity_sha256", "role", "path_sha256", "device", "ctime_ns",
        "apparent_size_bytes", "entry_count", "acl_count", "acl_sha256",
        "xattr_count", "xattr_sha256", "metadata_bytes",
    }
    value = _exact_dict(value, keys, "E_OBSERVED_PATH")
    for key in ("identity_sha256", "path_sha256", "acl_sha256", "xattr_sha256"):
        _digest(value[key], "E_OBSERVED_PATH")
    if value["role"] not in SOURCE_ROLES | {"persistence", "tmpfs"}:
        raise InventoryError("E_OBSERVED_PATH")
    for key in ("device", "ctime_ns", "apparent_size_bytes"):
        _integer(value[key], "E_OBSERVED_PATH")
    _integer(value["entry_count"], "E_OBSERVED_PATH", maximum=HARD_MAX_RECURSIVE_ENTRIES)
    for key in ("acl_count", "xattr_count"):
        _integer(value[key], "E_OBSERVED_PATH", maximum=HARD_MAX_ACL_ENTRIES)
    _integer(value["metadata_bytes"], "E_OBSERVED_PATH", maximum=HARD_MAX_ACL_BYTES_PER_PATH)
    if value["acl_count"] + value["xattr_count"] > HARD_MAX_ACL_ENTRIES:
        raise InventoryError("E_OBSERVED_PATH")
    if value["role"] == "tmpfs" and value != {
        "identity_sha256": value["identity_sha256"],
        "role": "tmpfs",
        "path_sha256": identity_sha256(None),
        "device": 0,
        "ctime_ns": 0,
        "apparent_size_bytes": 0,
        "entry_count": 0,
        "acl_count": 0,
        "acl_sha256": identity_sha256([]),
        "xattr_count": 0,
        "xattr_sha256": identity_sha256([]),
        "metadata_bytes": 0,
    }:
        raise InventoryError("E_OBSERVED_PATH")
    return value


def validate_observation_v2(
    value: object,
    request: InventoryRequestV2 | None = None,
) -> dict[str, object]:
    """Validate observation structure and, when supplied, request limits/binding."""
    keys = {
        "schema_version", "request_identity_projection_sha256", "inventory_target_claim_sha256",
        "inventory_nonce", "request_policy_sha256", "source_lock_sha256", "collector_sha256",
        "topology_sha256", "containers", "observed_sources", "persistence", "filesystems",
        "redis_persistence_member_count", "redis_persistence_members",
        "redis_persistence_members_sha256",
    }
    value = _exact_dict(value, keys, "E_OBSERVATION_KEYS")
    if value["schema_version"] != OBSERVATION_SCHEMA:
        raise InventoryError("E_OBSERVATION_SCHEMA")
    _validate_identity_fields(value)
    _digest(value["topology_sha256"], "E_OBSERVATION_TOPOLOGY")
    if not isinstance(value["containers"], list) or value["containers"] != sorted(value["containers"], key=lambda item: item.get("id", "") if isinstance(item, dict) else ""):
        raise InventoryError("E_CONTAINER_OBSERVATION")
    total_writable_entries = 0
    empty_writable_sha256 = identity_sha256([])
    for item in value["containers"]:
        item = _exact_dict(item, {"id", "running", "health", "writable_layer"}, "E_CONTAINER_OBSERVATION")
        if not CONTAINER_ID_RE.fullmatch(item["id"]) or not isinstance(item["running"], bool) or item["health"] not in HEALTH_VALUES:
            raise InventoryError("E_CONTAINER_OBSERVATION")
        writable = _exact_dict(item["writable_layer"], {"count", "classification", "operations", "sha256"}, "E_WRITABLE_LAYER")
        _integer(
            writable["count"],
            "E_WRITABLE_LAYER",
            maximum=HARD_MAX_RECURSIVE_ENTRIES,
        )
        if writable["classification"] not in {"empty", "metadata_or_content_changed"}:
            raise InventoryError("E_WRITABLE_LAYER")
        if not isinstance(writable["operations"], list) or writable["operations"] != sorted(set(writable["operations"])) or any(op not in {"A", "C", "D"} for op in writable["operations"]):
            raise InventoryError("E_WRITABLE_LAYER")
        _digest(writable["sha256"], "E_WRITABLE_LAYER")
        if writable["count"] == 0:
            if (
                writable["classification"] != "empty"
                or writable["operations"]
                or writable["sha256"] != empty_writable_sha256
            ):
                raise InventoryError("E_WRITABLE_LAYER")
        elif (
            writable["classification"] != "metadata_or_content_changed"
            or not writable["operations"]
            or writable["sha256"] == empty_writable_sha256
            or writable["count"] < len(writable["operations"])
        ):
            raise InventoryError("E_WRITABLE_LAYER")
        total_writable_entries += writable["count"]
    if (
        len(value["containers"]) > HARD_MAX_CONTAINERS
        or len({item["id"] for item in value["containers"]}) != len(value["containers"])
        or total_writable_entries > HARD_MAX_RECURSIVE_ENTRIES
    ):
        raise InventoryError("E_CONTAINER_OBSERVATION")
    for list_key, allowed_roles in (("observed_sources", SOURCE_ROLES), ("persistence", {"persistence", "tmpfs"})):
        if not isinstance(value[list_key], list) or value[list_key] != sorted(value[list_key], key=lambda item: (item.get("role", ""), item.get("identity_sha256", "")) if isinstance(item, dict) else ("", "")):
            raise InventoryError("E_OBSERVED_PATH")
        for item in value[list_key]:
            _validate_observed_path(item)
            if item["role"] not in allowed_roles:
                raise InventoryError("E_OBSERVED_PATH")
        if (
            len(value[list_key]) > HARD_MAX_RECURSIVE_ENTRIES
            or len({item["identity_sha256"] for item in value[list_key]}) != len(value[list_key])
        ):
            raise InventoryError("E_OBSERVED_PATH")
    if [item["role"] for item in value["observed_sources"]] != ["opt", "postgresql", "redis"]:
        raise InventoryError("E_OBSERVED_PATH")
    all_path_identities = [
        item["identity_sha256"]
        for item in value["observed_sources"] + value["persistence"]
    ]
    if len(all_path_identities) != len(set(all_path_identities)):
        raise InventoryError("E_OBSERVED_PATH")
    if not isinstance(value["filesystems"], list) or value["filesystems"] != sorted(value["filesystems"], key=lambda item: item.get("device", -1) if isinstance(item, dict) else -1):
        raise InventoryError("E_FILESYSTEM_RECORD")
    devices = []
    for item in value["filesystems"]:
        item = _exact_dict(item, {"device", "capacity_bytes", "available_bytes"}, "E_FILESYSTEM_RECORD")
        for field in item:
            _integer(item[field], "E_FILESYSTEM_RECORD")
        if item["available_bytes"] > item["capacity_bytes"]:
            raise InventoryError("E_FILESYSTEM_RECORD")
        devices.append(item["device"])
    if len(devices) != len(set(devices)):
        raise InventoryError("E_FILESYSTEM_RECORD")
    if len(devices) > HARD_MAX_RECURSIVE_ENTRIES:
        raise InventoryError("E_FILESYSTEM_RECORD")
    if not isinstance(value["redis_persistence_members"], list) or value["redis_persistence_members"] != sorted(value["redis_persistence_members"], key=canonical_bytes):
        raise InventoryError("E_REDIS_MEMBER")
    for item in value["redis_persistence_members"]:
        item = _exact_dict(item, {"path_sha256", "content_sha256", "size_bytes", "ctime_ns"}, "E_REDIS_MEMBER")
        _digest(item["path_sha256"], "E_REDIS_MEMBER")
        _digest(item["content_sha256"], "E_REDIS_MEMBER")
        _integer(
            item["size_bytes"],
            "E_REDIS_MEMBER",
            maximum=HARD_MAX_PERSISTENCE_FILE_BYTES,
        )
        _integer(item["ctime_ns"], "E_REDIS_MEMBER")
    if (
        len(value["redis_persistence_members"]) > HARD_MAX_RECURSIVE_ENTRIES
        or len({item["path_sha256"] for item in value["redis_persistence_members"]}) != len(value["redis_persistence_members"])
        or sum(item["size_bytes"] for item in value["redis_persistence_members"])
        > HARD_MAX_PERSISTENCE_FILE_BYTES
    ):
        raise InventoryError("E_REDIS_MEMBER")
    _integer(
        value["redis_persistence_member_count"],
        "E_REDIS_MEMBER",
        maximum=HARD_MAX_RECURSIVE_ENTRIES,
    )
    _digest(value["redis_persistence_members_sha256"], "E_REDIS_MEMBER")
    if (
        value["redis_persistence_member_count"] != len(value["redis_persistence_members"])
        or value["redis_persistence_members_sha256"] != identity_sha256(value["redis_persistence_members"])
    ):
        raise InventoryError("E_REDIS_MEMBER")
    if request is not None:
        if not isinstance(request, InventoryRequestV2):
            raise InventoryError("E_REQUEST_TYPE")
        if any(
            value[key] != expected for key, expected in _identity_fields(request).items()
        ):
            raise InventoryError("E_INVENTORY_REQUEST_BINDING")
        observed_source_projection = [
            {
                "role": item["role"],
                "path_sha256": item["path_sha256"],
                "identity_sha256": item["identity_sha256"],
            }
            for item in value["observed_sources"]
        ]
        all_paths = value["observed_sources"] + value["persistence"]
        total_writable = sum(
            item["writable_layer"]["count"] for item in value["containers"]
        )
        redis_total_size = sum(
            item["size_bytes"] for item in value["redis_persistence_members"]
        )
        if observed_source_projection != _expected_observed_sources(request):
            raise InventoryError("E_INVENTORY_REQUEST_BINDING")
        if (
            len(value["containers"]) > request.max_containers
            or any(
                item["writable_layer"]["count"] > request.max_recursive_entries
                for item in value["containers"]
            )
            or total_writable > request.max_recursive_entries
            or any(
                item["entry_count"] > request.max_recursive_entries
                or item["acl_count"] + item["xattr_count"] > request.max_acl_entries
                or item["metadata_bytes"] > request.max_acl_bytes_per_path
                for item in all_paths
            )
            or len({
                item["path_sha256"] for item in all_paths if item["role"] != "tmpfs"
            }) > request.max_recursive_entries
            or len(value["redis_persistence_members"]) > request.max_recursive_entries
            or any(
                item["size_bytes"] > request.max_persistence_file_bytes
                for item in value["redis_persistence_members"]
            )
            or redis_total_size > request.max_persistence_file_bytes
            or len(canonical_bytes(value)) > request.max_observation_bytes
        ):
            raise InventoryError("E_REQUEST_EVIDENCE_LIMIT")
    if len(canonical_bytes(value)) > HARD_MAX_OBSERVATION_BYTES:
        raise InventoryError("E_OBSERVATION_LIMIT")
    return value


def validate_inventory_v2(
    value: object,
    request: InventoryRequestV2 | None = None,
) -> dict[str, object]:
    """Validate inventory structure; supply ``request`` for authorization checks.

    The one-argument form is structural-only and must not be used as an
    authorization decision for raw privacy-sensitive projections.
    """
    value = _exact_dict(value, {"schema_version", "topology", "observation"}, "E_INVENTORY_KEYS")
    if value["schema_version"] != INVENTORY_SCHEMA:
        raise InventoryError("E_INVENTORY_SCHEMA")
    topology = validate_topology_v2(value["topology"], request)
    observation = validate_observation_v2(value["observation"], request)
    if request is not None and any(
        observation[key] != expected for key, expected in _identity_fields(request).items()
    ):
        raise InventoryError("E_INVENTORY_REQUEST_BINDING")
    if request is not None:
        expected_sources = _expected_observed_sources(request)
        observed_sources = [
            {
                "role": item["role"],
                "path_sha256": item["path_sha256"],
                "identity_sha256": item["identity_sha256"],
            }
            for item in observation["observed_sources"]
        ]
        if observed_sources != expected_sources:
            raise InventoryError("E_INVENTORY_REQUEST_BINDING")
    for key in (
        "request_identity_projection_sha256", "inventory_target_claim_sha256", "inventory_nonce",
        "request_policy_sha256", "source_lock_sha256", "collector_sha256",
    ):
        if topology[key] != observation[key]:
            raise InventoryError("E_INVENTORY_IDENTITY")
    if observation["topology_sha256"] != identity_sha256(topology):
        raise InventoryError("E_INVENTORY_TOPOLOGY")
    if [item["id"] for item in observation["containers"]] != topology["deletion_vector"]:
        raise InventoryError("E_INVENTORY_CONTAINER_SET")
    expected_persistence = {}
    for volume in topology["volumes"]:
        identity = identity_sha256({
            "kind": volume["kind"],
            "name": volume["name"],
            "path": volume["mountpoint"]["path"],
        })
        expected_persistence[identity] = {
            "role": "persistence",
            "path_sha256": volume["mountpoint"]["path"]["sha256"],
            "device": volume["mountpoint"]["device"],
        }
    for container in topology["containers"]:
        for mount in container["mounts"]:
            if mount["kind"] in {"bind", "tmpfs"}:
                identity = identity_sha256({
                    "container_id": container["id"],
                    "mount": mount,
                })
                expected_persistence[identity] = {
                    "role": "tmpfs" if mount["kind"] == "tmpfs" else "persistence",
                    "path_sha256": (
                        identity_sha256(None)
                        if mount["kind"] == "tmpfs"
                        else mount["source"]["path"]["sha256"]
                    ),
                    "device": 0 if mount["kind"] == "tmpfs" else mount["source"]["device"],
                }
    observed_persistence = {
        item["identity_sha256"]: {
            "role": item["role"],
            "path_sha256": item["path_sha256"],
            "device": item["device"],
        }
        for item in observation["persistence"]
    }
    if observed_persistence != expected_persistence:
        raise InventoryError("E_INVENTORY_PERSISTENCE")
    observed_devices = {
        item["device"] for item in observation["observed_sources"] + observation["persistence"]
        if item["role"] != "tmpfs"
    }
    if {item["device"] for item in observation["filesystems"]} != observed_devices:
        raise InventoryError("E_INVENTORY_FILESYSTEM")
    if not topology["redis"] and observation["redis_persistence_members"]:
        raise InventoryError("E_INVENTORY_REDIS")
    if request is not None and len(canonical_bytes(value)) > request.max_inventory_bytes:
        raise InventoryError("E_REQUEST_EVIDENCE_LIMIT")
    if len(canonical_bytes(value)) > HARD_MAX_INVENTORY_BYTES:
        raise InventoryError("E_INVENTORY_LIMIT")
    return value


class _FixedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise InventoryError("E_CLI_ARGUMENT")


def require_root() -> None:
    if os.geteuid() != 0:
        raise InventoryError("E_ROOT_REQUIRED")


def _fixed_cli_error(error: Exception, exit_code: int) -> int:
    code = str(error) if isinstance(error, InventoryError) else "E_INVENTORY"
    if not re.fullmatch(r"E_[A-Z0-9_]{1,64}", code):
        code = "E_INVENTORY"
    sys.stderr.write("inventory-v2-error:" + code + "\n")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = _FixedArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--expected-request-sha256", required=True)
    try:
        provided = list(sys.argv[1:] if argv is None else argv)
        if (
            len(provided) != 4
            or provided.count("--request-file") != 1
            or provided.count("--expected-request-sha256") != 1
        ):
            raise InventoryError("E_CLI_ARGUMENT")
        arguments = parser.parse_args(provided)
        safe_absolute_path(arguments.request_file, HARD_MAX_PATH_BYTES)
        _digest(arguments.expected_request_sha256, "E_REQUEST_FILE_DIGEST")
    except InventoryError as exc:
        return _fixed_cli_error(exc, 2)
    except Exception as exc:
        return _fixed_cli_error(exc, 2)
    try:
        require_root()
        request = read_request_file_v2(
            Path(arguments.request_file),
            arguments.expected_request_sha256,
        )
    except InventoryError as exc:
        host_failure = str(exc) == "E_ROOT_REQUIRED" or str(exc).startswith("E_FILE_")
        return _fixed_cli_error(exc, 3 if host_failure else 2)
    except Exception as exc:
        return _fixed_cli_error(exc, 3)
    try:
        inventory = collect_inventory_v2(request, SubprocessRunner())
        sys.stdout.buffer.write(canonical_bytes(inventory))
        return 0
    except InventoryError as exc:
        return _fixed_cli_error(exc, 3)
    except Exception as exc:
        return _fixed_cli_error(exc, 3)


if __name__ == "__main__":
    raise SystemExit(main())
