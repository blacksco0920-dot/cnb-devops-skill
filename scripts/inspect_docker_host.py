#!/usr/bin/env python3
"""Produce a deterministic, bounded, read-only Docker host inventory."""

import argparse
import dataclasses
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Protocol


REQUEST_SCHEMA = "deploydesk-docker-host-inventory-request/v1"
INVENTORY_SCHEMA = "deploydesk-docker-host-inventory/v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
ALLOWED_LABELS = frozenset({
    "com.docker.compose.project",
    "com.docker.compose.service",
    "deployment.example/id",
    "io.deploydesk.deployment-id",
})
INVENTORY_KEYS = frozenset({
    "schema_version", "complete", "request_sha256", "container_count", "containers",
    "deletion_vector", "volume_count", "volumes", "network_count", "networks",
    "filesystems", "expected_caddy_paths",
})


class InventoryError(ValueError):
    """The observed host facts cannot safely form a complete inventory."""


class CommandRunner(Protocol):
    def run(self, argv: tuple[str, ...]) -> str:
        """Run one fixed argv vector and return only stdout."""


def canonical_bytes(value: object) -> bytes:
    """Return the sole accepted JSON encoding, terminated by one newline."""
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InventoryError("value is not canonical JSON") from exc


def identity_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _safe_absolute_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise InventoryError(f"unsafe {label}")
    pure = Path(value)
    if ".." in pure.parts or "\x00" in value:
        raise InventoryError(f"unsafe {label}")
    return str(pure)


@dataclasses.dataclass(frozen=True)
class InventoryRequest:
    schema_version: str
    docker_command: tuple[str, ...]
    docker_config_path: str
    docker_socket_path: str
    observed_roots: tuple[str, ...]
    max_containers: int
    max_volumes: int
    max_networks: int
    max_output_bytes: int
    expected_caddy_paths: tuple[str, ...]

    def __post_init__(self):
        if self.schema_version != REQUEST_SCHEMA:
            raise InventoryError("unsupported request schema")
        if not isinstance(self.docker_command, tuple) or not self.docker_command:
            raise InventoryError("unsafe docker command")
        for item in self.docker_command:
            if not isinstance(item, str) or not item or "\x00" in item:
                raise InventoryError("unsafe docker command")
        _safe_absolute_path(self.docker_command[0], "docker command")
        config = _safe_absolute_path(self.docker_config_path, "docker config path")
        socket = _safe_absolute_path(self.docker_socket_path, "docker socket path")
        if config != "/etc/docker" or socket not in {"/var/run/docker.sock", "/run/docker.sock"}:
            raise InventoryError("unsafe Docker endpoint/config path")
        if not isinstance(self.observed_roots, tuple) or not self.observed_roots:
            raise InventoryError("missing observed roots")
        for root in self.observed_roots:
            _safe_absolute_path(root, "observed root")
        if len(set(self.observed_roots)) != len(self.observed_roots):
            raise InventoryError("duplicate observed root")
        for limit in (self.max_containers, self.max_volumes, self.max_networks, self.max_output_bytes):
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise InventoryError("invalid inventory limit")
        if not isinstance(self.expected_caddy_paths, tuple):
            raise InventoryError("invalid expected Caddy paths")
        for path in self.expected_caddy_paths:
            _safe_absolute_path(path, "expected Caddy path")
            if not path.startswith("/etc/caddy/"):
                raise InventoryError("unsafe expected Caddy path")


class SubprocessRunner:
    """A no-shell runner that intentionally never forwards stderr."""

    def run(self, argv: tuple[str, ...]) -> str:
        try:
            completed = subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", errors="strict", shell=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise InventoryError("required Docker command failed") from exc
        return completed.stdout


def lines(value: str) -> list[str]:
    if not isinstance(value, str):
        raise InventoryError("command stdout is not text")
    result = value.splitlines()
    if any(not line or line.strip() != line for line in result):
        raise InventoryError("invalid command output")
    return result


def strict_json(value: str) -> object:
    def no_duplicates(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise InventoryError("duplicate JSON key")
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=no_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(InventoryError("invalid JSON constant")))
    except (json.JSONDecodeError, TypeError) as exc:
        raise InventoryError("invalid JSON output") from exc


def _checked_ids(values: list[str], kind: str, limit: int, pattern=CONTAINER_ID_RE) -> list[str]:
    if len(values) > limit:
        raise InventoryError(f"{kind} inventory exceeds limit")
    if len(set(values)) != len(values):
        raise InventoryError(f"duplicate {kind} id")
    if any(not pattern.fullmatch(value) for value in values):
        raise InventoryError(f"invalid {kind} id")
    return values


def _stable_ids(runner: CommandRunner, docker: tuple[str, ...], argv: tuple[str, ...], kind: str,
                limit: int, pattern=CONTAINER_ID_RE) -> list[str]:
    before = _checked_ids(lines(runner.run(docker + argv)), kind, limit, pattern)
    return before


def _stable_inspect(runner: CommandRunner, docker: tuple[str, ...], list_argv: tuple[str, ...],
                    inspect_argv: tuple[str, ...], kind: str, limit: int, pattern=CONTAINER_ID_RE):
    before = _stable_ids(runner, docker, list_argv, kind, limit, pattern)
    inspected = strict_json(runner.run(docker + inspect_argv + tuple(before))) if before else []
    after = _stable_ids(runner, docker, list_argv, kind, limit, pattern)
    if before != after:
        raise InventoryError(f"{kind} inventory changed during observation")
    if not isinstance(inspected, list):
        raise InventoryError(f"invalid {kind} inspection")
    return before, inspected


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _mount_record(mount: object) -> dict[str, object]:
    if not isinstance(mount, dict):
        raise InventoryError("unknown persistence")
    mount_type = mount.get("Type")
    destination = mount.get("Destination")
    if not isinstance(destination, str) or not destination.startswith("/"):
        raise InventoryError("unknown persistence")
    base = {"destination": destination, "read_only": not bool(mount.get("RW", True))}
    if mount_type == "volume":
        name = mount.get("Name")
        if not isinstance(name, str) or not name:
            raise InventoryError("unknown persistence")
        kind = "anonymous_volume" if CONTAINER_ID_RE.fullmatch(name) else "named_volume"
        return {"kind": kind, "name_sha256": _sha256_text(name), **base}
    if mount_type == "bind":
        source = mount.get("Source")
        if not isinstance(source, str) or not source.startswith("/"):
            raise InventoryError("unknown persistence")
        try:
            facts = os.stat(source, follow_symlinks=False)
        except OSError as exc:
            raise InventoryError("missing bind host metadata") from exc
        options = mount.get("Mode", "")
        if not isinstance(options, str):
            raise InventoryError("unknown persistence")
        return {
            "kind": "bind", **base, "device": facts.st_dev, "inode": facts.st_ino,
            "ctime_ns": facts.st_ctime_ns, "mode": stat.S_IMODE(facts.st_mode),
            "uid": facts.st_uid, "gid": facts.st_gid, "options_sha256": _sha256_text(options),
        }
    if mount_type == "tmpfs":
        options = mount.get("TmpfsOptions", {})
        return {"kind": "tmpfs", **base, "options_sha256": identity_sha256(options)}
    raise InventoryError("unknown persistence")


def _container_record(record: object, runner: CommandRunner, docker: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(record, dict):
        raise InventoryError("invalid container inspection")
    identifier = record.get("Id")
    image_id = record.get("Image")
    repo_digests = record.get("RepoDigests")
    if not isinstance(identifier, str) or not CONTAINER_ID_RE.fullmatch(identifier):
        raise InventoryError("invalid container id")
    if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
        raise InventoryError("invalid image id")
    if not isinstance(repo_digests, list) or not repo_digests or any(not isinstance(item, str) or "@sha256:" not in item for item in repo_digests):
        raise InventoryError("missing RepoDigests")
    config = record.get("Config")
    labels = config.get("Labels", {}) if isinstance(config, dict) else {}
    if not isinstance(labels, dict):
        raise InventoryError("invalid labels")
    safe_labels = {key: labels[key] for key in sorted(ALLOWED_LABELS & set(labels)) if isinstance(labels[key], str)}
    networks = record.get("NetworkSettings", {}).get("Networks", {}) if isinstance(record.get("NetworkSettings"), dict) else {}
    if not isinstance(networks, dict):
        raise InventoryError("invalid network memberships")
    memberships = []
    for name, membership in networks.items():
        if not isinstance(name, str) or not isinstance(membership, dict):
            raise InventoryError("invalid network memberships")
        network_id = membership.get("NetworkID", "")
        if not isinstance(network_id, str):
            raise InventoryError("invalid network memberships")
        memberships.append({"name_sha256": _sha256_text(name), "id_sha256": _sha256_text(network_id)})
    mounts = record.get("Mounts", [])
    if not isinstance(mounts, list):
        raise InventoryError("unknown persistence")
    diff = lines(runner.run(docker + ("diff", identifier)))
    return {
        "id": identifier, "image_id": image_id, "repo_digests_sha256": [_sha256_text(item) for item in sorted(repo_digests)],
        "labels": safe_labels, "networks": sorted(memberships, key=canonical_bytes),
        "mounts": sorted((_mount_record(item) for item in mounts), key=canonical_bytes),
        "writable_layer": {"count": len(diff), "sha256": _sha256_text("\n".join(sorted(diff)))},
    }


def _filesystem_records(roots: tuple[str, ...]) -> list[dict[str, int]]:
    records = {}
    seen = set()
    for root in roots:
        try:
            root_facts = os.stat(root, follow_symlinks=False)
            usage = os.statvfs(root)
        except OSError as exc:
            raise InventoryError("missing filesystem host metadata") from exc
        if stat.S_ISLNK(root_facts.st_mode):
            raise InventoryError("unsafe observed root")
        entry = records.setdefault(root_facts.st_dev, {
            "device": root_facts.st_dev, "capacity_bytes": usage.f_blocks * usage.f_frsize,
            "available_bytes": usage.f_bavail * usage.f_frsize, "apparent_size_bytes": 0,
        })
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames if not os.path.islink(os.path.join(directory, name)))
            for filename in sorted(filenames):
                path = os.path.join(directory, filename)
                try:
                    facts = os.lstat(path)
                except OSError as exc:
                    raise InventoryError("missing filesystem host metadata") from exc
                inode = (facts.st_dev, facts.st_ino)
                if inode not in seen:
                    seen.add(inode)
                    entry["apparent_size_bytes"] += facts.st_size
    return [records[key] for key in sorted(records)]


def collect_inventory(request: InventoryRequest, runner: CommandRunner) -> dict[str, object]:
    if not isinstance(request, InventoryRequest):
        raise InventoryError("invalid request")
    docker = request.docker_command + ("--config", request.docker_config_path, "--host", "unix://" + request.docker_socket_path)
    container_ids, container_inspects = _stable_inspect(runner, docker, ("ps", "-aq", "--no-trunc"), ("inspect",), "container", request.max_containers)
    container_map = {}
    for record in container_inspects:
        if not isinstance(record, dict) or not isinstance(record.get("Id"), str):
            raise InventoryError("invalid container inspection")
        if record["Id"] in container_map:
            raise InventoryError("duplicate container id")
        container_map[record["Id"]] = record
    if set(container_map) != set(container_ids):
        raise InventoryError("container inspection is incomplete")
    containers = [_container_record(container_map[identifier], runner, docker) for identifier in sorted(container_ids)]
    volume_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
    volume_ids, volume_inspects = _stable_inspect(runner, docker, ("volume", "ls", "-q", "--no-trunc"), ("volume", "inspect"), "volume", request.max_volumes, volume_pattern)
    volume_map = {record.get("Name"): record for record in volume_inspects if isinstance(record, dict)}
    if len(volume_map) != len(volume_inspects) or set(volume_map) != set(volume_ids):
        raise InventoryError("volume inspection is incomplete")
    volumes = [{"name_sha256": _sha256_text(identifier), "driver": volume_map[identifier].get("Driver", "")}
               for identifier in sorted(volume_ids)]
    if any(not isinstance(item["driver"], str) for item in volumes):
        raise InventoryError("invalid volume inspection")
    network_ids, network_inspects = _stable_inspect(runner, docker, ("network", "ls", "-q", "--no-trunc"), ("network", "inspect"), "network", request.max_networks)
    network_map = {record.get("Id"): record for record in network_inspects if isinstance(record, dict)}
    if len(network_map) != len(network_inspects) or set(network_map) != set(network_ids):
        raise InventoryError("network inspection is incomplete")
    networks = [{"id": identifier, "name_sha256": _sha256_text(str(network_map[identifier].get("Name", "")))}
                for identifier in sorted(network_ids)]
    value = {
        "schema_version": INVENTORY_SCHEMA, "complete": True,
        "request_sha256": identity_sha256(dataclasses.asdict(request)),
        "container_count": len(containers), "containers": containers,
        "deletion_vector": sorted(container_ids), "volume_count": len(volumes), "volumes": volumes,
        "network_count": len(networks), "networks": networks,
        "filesystems": _filesystem_records(request.observed_roots),
        "expected_caddy_paths": list(request.expected_caddy_paths),
    }
    raw = canonical_bytes(value)
    if len(raw) > request.max_output_bytes:
        raise InventoryError("output limit exceeded")
    validated = validate_inventory(value)
    if canonical_bytes(validated) != raw:
        raise InventoryError("non-canonical output")
    return validated


def validate_inventory(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != INVENTORY_KEYS:
        raise InventoryError("inventory does not have the exact key set")
    if value.get("schema_version") != INVENTORY_SCHEMA or value.get("complete") is not True:
        raise InventoryError("invalid inventory schema")
    for key in ("request_sha256",):
        if not isinstance(value.get(key), str) or not SHA256_RE.fullmatch(value[key]):
            raise InventoryError("invalid inventory digest")
    for count_key, records_key in (("container_count", "containers"), ("volume_count", "volumes"), ("network_count", "networks")):
        if not isinstance(value.get(count_key), int) or isinstance(value[count_key], bool) or not isinstance(value.get(records_key), list) or value[count_key] != len(value[records_key]):
            raise InventoryError("invalid inventory count")
    if not isinstance(value["deletion_vector"], list) or value["deletion_vector"] != sorted(value["deletion_vector"]):
        raise InventoryError("invalid deletion vector")
    container_keys = {"id", "image_id", "repo_digests_sha256", "labels", "networks", "mounts", "writable_layer"}
    for item in value["containers"]:
        if not isinstance(item, dict) or set(item) != container_keys:
            raise InventoryError("invalid container record")
        if not isinstance(item["id"], str) or not CONTAINER_ID_RE.fullmatch(item["id"]):
            raise InventoryError("invalid container record")
        if not isinstance(item["image_id"], str) or not IMAGE_ID_RE.fullmatch(item["image_id"]):
            raise InventoryError("invalid container record")
        if not isinstance(item["repo_digests_sha256"], list) or any(not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) for digest in item["repo_digests_sha256"]):
            raise InventoryError("invalid container record")
        if not isinstance(item["labels"], dict) or set(item["labels"]) - ALLOWED_LABELS or any(not isinstance(label, str) for label in item["labels"].values()):
            raise InventoryError("invalid container record")
        for membership in item["networks"] if isinstance(item["networks"], list) else ():
            if not isinstance(membership, dict) or set(membership) != {"name_sha256", "id_sha256"} or any(not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) for digest in membership.values()):
                raise InventoryError("invalid container record")
        if not isinstance(item["networks"], list):
            raise InventoryError("invalid container record")
        for mount in item["mounts"] if isinstance(item["mounts"], list) else ():
            if not isinstance(mount, dict) or mount.get("kind") not in {"named_volume", "anonymous_volume", "bind", "tmpfs"}:
                raise InventoryError("invalid container record")
            expected = ({"kind", "destination", "read_only", "name_sha256"}
                        if mount["kind"] in {"named_volume", "anonymous_volume"}
                        else {"kind", "destination", "read_only", "options_sha256"}
                        if mount["kind"] == "tmpfs"
                        else {"kind", "destination", "read_only", "device", "inode", "ctime_ns", "mode", "uid", "gid", "options_sha256"})
            if set(mount) != expected or not isinstance(mount.get("destination"), str) or not mount["destination"].startswith("/") or not isinstance(mount.get("read_only"), bool):
                raise InventoryError("invalid container record")
            for key in ("name_sha256", "options_sha256"):
                if key in mount and (not isinstance(mount[key], str) or not SHA256_RE.fullmatch(mount[key])):
                    raise InventoryError("invalid container record")
            for key in ("device", "inode", "ctime_ns", "mode", "uid", "gid"):
                if key in mount and (not isinstance(mount[key], int) or isinstance(mount[key], bool) or mount[key] < 0):
                    raise InventoryError("invalid container record")
        if not isinstance(item["mounts"], list) or not isinstance(item["writable_layer"], dict) or set(item["writable_layer"]) != {"count", "sha256"} or not isinstance(item["writable_layer"].get("count"), int) or isinstance(item["writable_layer"]["count"], bool) or item["writable_layer"]["count"] < 0 or not isinstance(item["writable_layer"].get("sha256"), str) or not SHA256_RE.fullmatch(item["writable_layer"]["sha256"]):
            raise InventoryError("invalid container record")
    if [item["id"] for item in value["containers"]] != value["deletion_vector"]:
        raise InventoryError("deletion vector does not match containers")
    if any(not isinstance(item, str) or not CONTAINER_ID_RE.fullmatch(item) for item in value["deletion_vector"]):
        raise InventoryError("invalid deletion vector")
    for item in value["volumes"]:
        if not isinstance(item, dict) or set(item) != {"name_sha256", "driver"} or not isinstance(item["name_sha256"], str) or not SHA256_RE.fullmatch(item["name_sha256"]) or not isinstance(item["driver"], str):
            raise InventoryError("invalid volume record")
    for item in value["networks"]:
        if not isinstance(item, dict) or set(item) != {"id", "name_sha256"} or not isinstance(item["id"], str) or not CONTAINER_ID_RE.fullmatch(item["id"]) or not isinstance(item["name_sha256"], str) or not SHA256_RE.fullmatch(item["name_sha256"]):
            raise InventoryError("invalid network record")
    filesystem_keys = {"device", "capacity_bytes", "available_bytes", "apparent_size_bytes"}
    if not isinstance(value["filesystems"], list) or any(not isinstance(item, dict) or set(item) != filesystem_keys or any(not isinstance(number, int) or isinstance(number, bool) or number < 0 for number in item.values()) for item in value["filesystems"]) or len({item["device"] for item in value["filesystems"]}) != len(value["filesystems"]):
        raise InventoryError("invalid filesystem evidence")
    if not isinstance(value["expected_caddy_paths"], list) or any(not isinstance(path, str) or not path.startswith("/etc/caddy/") for path in value["expected_caddy_paths"]):
        raise InventoryError("invalid Caddy paths")
    return value


def _request_object(value: object) -> InventoryRequest:
    required = {
        "schema_version", "docker_command", "docker_config_path", "docker_socket_path", "observed_roots",
        "max_containers", "max_volumes", "max_networks", "max_output_bytes", "expected_caddy_paths",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise InventoryError("request does not have the exact key set")
    for key in ("docker_command", "observed_roots", "expected_caddy_paths"):
        if not isinstance(value[key], list):
            raise InventoryError("invalid request sequence")
    return InventoryRequest(**{**value, "docker_command": tuple(value["docker_command"]),
                               "observed_roots": tuple(value["observed_roots"]),
                               "expected_caddy_paths": tuple(value["expected_caddy_paths"])})


def read_request_file(path: Path, expected_sha256: str, *, require_root: bool = True) -> InventoryRequest:
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise InventoryError("expected request digest must be lowercase SHA-256")
    try:
        facts = os.lstat(path)
    except OSError as exc:
        raise InventoryError("request file is unavailable") from exc
    if stat.S_ISLNK(facts.st_mode):
        raise InventoryError("request file is a symlink")
    if not stat.S_ISREG(facts.st_mode):
        raise InventoryError("request file is not regular")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise InventoryError("request file is unreadable") from exc
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode):
            raise InventoryError("request file is not regular")
        if require_root and facts.st_uid != 0:
            raise InventoryError("request file is not root-owned")
        if facts.st_size > 1_000_000:
            raise InventoryError("request file exceeds size limit")
        raw = bytearray()
        while len(raw) <= 1_000_000:
            block = os.read(descriptor, min(65536, 1_000_001 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > 1_000_000:
            raise InventoryError("request file exceeds size limit")
        raw = bytes(raw)
    except OSError as exc:
        raise InventoryError("request file is unreadable") from exc
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise InventoryError("request digest mismatch")
    value = strict_json(raw.decode("utf-8"))
    if canonical_bytes(value) != raw:
        raise InventoryError("request bytes are not canonical")
    return _request_object(value)


def require_root() -> None:
    if os.geteuid() != 0:
        raise InventoryError("root is required to collect host metadata")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", required=True)
    parser.add_argument("--expected-request-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        require_root()
        request = read_request_file(Path(arguments.request_file), arguments.expected_request_sha256)
        result = collect_inventory(request, SubprocessRunner())
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except InventoryError as exc:
        print(f"inventory error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
