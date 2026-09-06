#!/usr/bin/env python3
"""Deploy one immutable test release using a root-installed project policy.

Extracted transaction/snapshot/retention controller; provenance is in bundle.json.
Ordinary release requires a previously provisioned application and valid release record."""

import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, unquote, urlsplit


# Populated exclusively from the fixed installed host-policy.json in main().
# Importing the module performs no host access and is safe for local generation/tests.
POLICY = {}
POLICY_SHA256 = None
DOCKER = "/usr/bin/docker"
CURL = "/usr/bin/curl"
BASE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
}
ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*?)(\r?\n)?$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
BUILD_ID = re.compile(r"^cnb-[a-z0-9][a-z0-9-]{2,127}$")
GIB = 1024**3
MAX_IMAGE_COMPRESSED_BYTES = 1 * GIB
MAX_RELEASE_COMPRESSED_BYTES = 3 * GIB
MAX_PUBLIC_IDENTITY_BYTES = 4096
RETRIABLE_CURL_EXIT_CODES = frozenset({5, 6, 7, 22, 28, 35, 51, 52, 55, 56, 60})
SNAPSHOT_FILES = (
    "env.before",
    "docker-compose.before.yml",
    "database.dump",
)
SNAPSHOT_MANIFEST = "snapshot-manifest.json"
SNAPSHOT_SCHEMA = "cnb-test-backup/v1"
SNAPSHOT_INCOMPLETE = ".snapshot-incomplete"
RETENTION_TOMBSTONE_PREFIX = ".retention-"
SNAPSHOT_NAME = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
SNAPSHOT_CREATED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RELEASE_SCHEMA_V1 = "cnb-test-release/v1"
RELEASE_SCHEMA_V2 = "cnb-test-release/v2"
EMPTY_BASELINE_SCHEMA = "cnb-test-empty-baseline/v1"
TRANSACTION_SCHEMA_V1 = "cnb-test-release-transaction/v1"
TRANSACTION_SCHEMA_V2 = "cnb-test-release-transaction/v2"
RELEASE_TRANSACTION_PHASES = frozenset(
    {
        "prepared",
        "migrating",
        "migration_complete",
        "installing_runtime_config",
        "starting_runtime",
        "migrate",
        "install",
        "up",
        "runtime",
        "probe",
        "record",
    }
)
SNAPSHOT_FILE_LIMITS = {
    "env.before": 1024 * 1024,
    "docker-compose.before.yml": 64 * 1024,
    "database.dump": 8 * 1024 * 1024 * 1024,
}
BASE64URL = re.compile(rb"^[A-Za-z0-9_-]{1,16384}$")


class DeploymentError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code if re.fullmatch(r"[a-z0-9_]{1,64}", code) else "deployment_failed"


class SnapshotRef(NamedTuple):
    name: str
    manifest_path: Path
    manifest_sha256: str


class RetentionAuthority(NamedTuple):
    release_raw: bytes
    release_sha256: str
    release_record: dict
    transaction_raw: bytes | None
    transaction_sha256: str | None
    transaction_record: dict | None
    protected_names: frozenset


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


TAT_TEMPLATE = """#!/bin/sh
set -u
umask 077
[ "$(/usr/bin/id -u)" = "$(/usr/bin/id -u @RELEASE_USER@)" ] || exit 90
[ "$(/bin/pwd -P)" = "@RELEASE_HOME@" ] || exit 91
controller_sha256='@CONTROLLER_SHA256@'
policy_sha256='@POLICY_SHA256@'
[ "$(/usr/bin/stat -c '%u:%g:%a' @INSTALL_DIR@)" = "0:0:755" ] || exit 92
[ "$(/usr/bin/stat -c '%u:%g:%a' @INSTALL_DIR@/tat-deploy-test.py)" = "0:0:555" ] || exit 93
[ "$(/usr/bin/sha256sum @INSTALL_DIR@/tat-deploy-test.py | /usr/bin/cut -d ' ' -f 1)" = "$controller_sha256" ] || exit 94
[ "$(/usr/bin/stat -c '%u:%g:%a' @INSTALL_DIR@/host-policy.json)" = "0:0:444" ] || exit 95
[ "$(/usr/bin/sha256sum @INSTALL_DIR@/host-policy.json | /usr/bin/cut -d ' ' -f 1)" = "$policy_sha256" ] || exit 96
/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=@RELEASE_HOME@ LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC /usr/bin/python3 -I @INSTALL_DIR@/tat-deploy-test.py --tat-script "$0"
rc=$?
exit "$rc"
__CNB_RELEASE_REQUEST_V1__
{{release_request_b64url}}
"""


def validate_host_policy(model):
    """Validate trusted installation inputs; no policy comes from a release request."""
    required = {"schema", "project", "environment", "controller_id", "install_dir", "release_user",
                "release_home", "app_dir", "docker_config", "recovery_root", "compose_sha256",
                "services", "networks", "required_env", "database", "migration",
                "availability_probes", "identity_probes"}
    optional = {"redis", "proxy_container", "startup_timeout_seconds"}

    def require(condition):
        if not condition:
            raise ValueError("invalid installed host policy")

    def name(value):
        return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", value) is not None

    def env_key(value):
        return type(value) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value) is not None

    def path(value, prefix=None):
        valid = (type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
                 and str(Path(value)) == value and not {".", ".."}.intersection(value.split("/")))
        return valid and (prefix is None or value.startswith(prefix + "/"))

    def url(value):
        if type(value) is not str or len(value) > 2048 or any(ord(c) <= 32 for c in value):
            return False
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None
                and parsed.password is None and not parsed.fragment)

    try:
        require(type(model) is dict and required <= set(model) <= required | optional)
        require(type(model.get("startup_timeout_seconds", 300)) is int
                and 1 <= model.get("startup_timeout_seconds", 300) <= 1200)
        require(model["schema"] == "cnb-devops-host-policy/v1" and model["environment"] == "test")
        require(name(model["project"]) and type(model["controller_id"]) is str
                and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", model["controller_id"]))
        require(name(model["release_user"]) and model["release_user"] != "root")
        require(path(model["install_dir"], "/opt/cnb-devops") and path(model["app_dir"], "/opt/apps"))
        require(path(model["recovery_root"], "/opt/cnb-devops"))
        require(model["release_home"] == "/home/" + model["release_user"])
        require(model["docker_config"] == model["release_home"] + "/.docker/config.json")
        require(type(model["compose_sha256"]) is str and SHA256.fullmatch(model["compose_sha256"]))
        networks = model["networks"]
        require(type(networks) is list and 1 <= len(networks) <= 16
                and all(name(n) for n in networks) and len(set(networks)) == len(networks))
        env_keys = model["required_env"]
        require(type(env_keys) is list and len(env_keys) <= 256 and all(env_key(k) for k in env_keys)
                and len(set(env_keys)) == len(env_keys))
        services = model["services"]
        require(type(services) is dict and 1 <= len(services) <= 16 and all(name(n) for n in services))
        image_keys, containers, repositories, published_ports = set(), set(), set(), set()
        for service in services.values():
            fields = {
                "image_repository", "image_env", "container", "networks", "environment",
                "environment_refs", "runtime_env", "healthcheck", "mounts"}
            require(type(service) is dict and fields <= set(service) <= fields | {"loopback_port"})
            if "loopback_port" in service:
                port = service["loopback_port"]
                require(type(port) is dict and set(port) == {"host_ip", "protocol", "published", "target"}
                        and port["host_ip"] == "127.0.0.1" and port["protocol"] == "tcp"
                        and type(port["published"]) is int and 1024 <= port["published"] <= 65535
                        and type(port["target"]) is int and 1 <= port["target"] <= 65535
                        and port["published"] not in published_ports)
                published_ports.add(port["published"])
            repository = service["image_repository"]
            require(type(repository) is str and re.fullmatch(
                r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]{0,240}", repository))
            require("//" not in repository and not {".", ".."}.intersection(repository.split("/")))
            require(repository not in repositories)
            repositories.add(repository)
            require(env_key(service["image_env"]) and service["image_env"] not in image_keys)
            image_keys.add(service["image_env"])
            require(type(service["container"]) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,191}", service["container"])
                    and service["container"] not in containers)
            containers.add(service["container"])
            require(type(service["networks"]) is list and bool(service["networks"])
                    and set(service["networks"]) <= set(networks)
                    and len(set(service["networks"])) == len(service["networks"]))
            require(type(service["runtime_env"]) is bool and type(service["healthcheck"]) is bool)
            for field in ("environment", "environment_refs"):
                require(type(service[field]) is dict and len(service[field]) <= 256
                        and all(env_key(k) for k in service[field]))
            require(all(type(v) is str and "\0" not in v and len(v) <= 4096 for v in service["environment"].values()))
            require(all(env_key(v) and v in env_keys for v in service["environment_refs"].values()))
            require(not set(service["environment"]) & set(service["environment_refs"]))
            require(type(service["mounts"]) is list and len(service["mounts"]) <= 32)
            targets = set()
            for mount in service["mounts"]:
                require(type(mount) is dict and set(mount) == {"type", "source", "target"}
                        and mount["type"] == "bind" and path(mount["source"], model["app_dir"])
                        and path(mount["target"]) and mount["target"] not in targets)
                targets.add(mount["target"])
        database = model["database"]
        require(type(database) is dict and set(database) == {
            "url_env", "host", "port", "name", "user", "container", "admin_user"})
        require(database["url_env"] in env_keys and env_key(database["url_env"]))
        require(all(name(database[k]) for k in ("host", "container", "name", "user", "admin_user")))
        require(type(database["port"]) is int and 1 <= database["port"] <= 65535)
        migration = model["migration"]
        if migration is not None:
            require(type(migration) is dict and set(migration) == {"service", "argv"}
                    and migration["service"] in services and type(migration["argv"]) is list
                    and 1 <= len(migration["argv"]) <= 64
                    and all(type(a) is str and 0 < len(a) <= 4096 and "\0" not in a for a in migration["argv"]))
            require(not migration["argv"][0].startswith("-"))
        require(type(model["availability_probes"]) is list and len(model["availability_probes"]) <= 64
                and all(url(v) for v in model["availability_probes"]))
        probes = model["identity_probes"]
        require(type(probes) is list and len(probes) == len(services))
        probe_services, probe_urls = set(), set()
        for probe in probes:
            require(type(probe) is dict and set(probe) == {"url", "service", "api_envelope"}
                    and probe["service"] in services and probe["service"] not in probe_services
                    and url(probe["url"]) and probe["url"] not in probe_urls
                    and type(probe["api_envelope"]) is bool)
            probe_services.add(probe["service"])
            probe_urls.add(probe["url"])
        if model.get("redis") is not None:
            redis = model["redis"]
            fields = {"url_env", "host", "port", "database", "container"}
            require(type(redis) is dict and set(redis) in (fields, fields | {"prefix_env", "prefix"}))
            require(redis["url_env"] in env_keys and env_key(redis["url_env"]))
            require(name(redis["host"]) and name(redis["container"])
                    and type(redis["port"]) is int and 1 <= redis["port"] <= 65535
                    and type(redis["database"]) is int and 0 <= redis["database"] <= 15)
            if "prefix_env" in redis:
                require(redis["prefix_env"] in env_keys and env_key(redis["prefix_env"])
                        and type(redis["prefix"]) is str and redis["prefix"].startswith(model["project"] + "-test:")
                        and re.fullmatch(r"[a-z0-9:_-]{1,128}", redis["prefix"]))
            else:
                require(redis["host"] == redis["container"] == model["project"] + "-test-redis"
                        and redis["database"] == 0)
        if model.get("proxy_container") is not None:
            require(name(model["proxy_container"]))
        # Detach validated input from the caller so later mutation cannot change release authority.
        return json.loads(json.dumps(model))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise DeploymentError("host_policy_invalid") from exc


def configure_policy(model, *, policy_sha256=None):
    global POLICY, POLICY_SHA256, APP_DIR, ENV_PATH, COMPOSE_PATH, RELEASE_PATH, DOCKER_CONFIG
    global LOCK_PATH, TRANSACTION_PATH, RECOVERY_ROOT, RECOVERY_STATE_DIR, RECOVERY_TRANSACTION_PATH
    global CONTROLLER_COMPOSE_PATH, CONTROLLER_ID, CONTROLLER_COMPOSE_SHA256, PROJECT
    global SERVICES, IMAGE_KEYS, CONTAINERS, REQUIRED_ENV_KEYS, AVAILABILITY_PROBES, IDENTITY_PROBES
    global PUBLIC_PROBES, LEGACY_PUBLIC_PROBES
    checked = validate_host_policy(model)
    if policy_sha256 is not None and (type(policy_sha256) is not str or not SHA256.fullmatch(policy_sha256)):
        raise DeploymentError("host_policy_invalid")
    POLICY, POLICY_SHA256 = checked, policy_sha256
    APP_DIR = Path(checked["app_dir"])
    ENV_PATH, COMPOSE_PATH, RELEASE_PATH = APP_DIR / ".env", APP_DIR / "docker-compose.yml", APP_DIR / ".release.json"
    PROJECT = checked["project"] + "-test"
    DOCKER_CONFIG = Path(checked["docker_config"])
    LOCK_PATH = APP_DIR.parent / ("." + PROJECT + ".deploy.lock")
    TRANSACTION_PATH = APP_DIR / ".release.transaction.json"
    RECOVERY_ROOT = Path(checked["recovery_root"])
    RECOVERY_STATE_DIR = RECOVERY_ROOT / "state"
    RECOVERY_TRANSACTION_PATH = RECOVERY_STATE_DIR / (PROJECT + ".transaction.json")
    CONTROLLER_COMPOSE_PATH = Path(checked["install_dir"]) / "docker-compose.yml"
    CONTROLLER_ID, CONTROLLER_COMPOSE_SHA256 = checked["controller_id"], checked["compose_sha256"]
    SERVICES = tuple(sorted(checked["services"]))
    IMAGE_KEYS = {s: checked["services"][s]["image_env"] for s in SERVICES}
    CONTAINERS = {s: checked["services"][s]["container"] for s in SERVICES}
    REQUIRED_ENV_KEYS = frozenset(checked["required_env"]) | frozenset(IMAGE_KEYS.values())
    AVAILABILITY_PROBES = tuple(checked["availability_probes"])
    IDENTITY_PROBES = tuple((p["url"], p["service"], p["api_envelope"]) for p in checked["identity_probes"])
    PUBLIC_PROBES = tuple(sorted(set(AVAILABILITY_PROBES) | {p[0] for p in IDENTITY_PROBES}))
    LEGACY_PUBLIC_PROBES = PUBLIC_PROBES
    BASE_ENV["HOME"] = checked["release_home"]


def render_tat_template(policy, controller_sha256, policy_sha256):
    checked = validate_host_policy(policy)
    if any(type(v) is not str or not SHA256.fullmatch(v) for v in (controller_sha256, policy_sha256)):
        raise DeploymentError("controller_program_identity")
    text = TAT_TEMPLATE
    for key, value in {"RELEASE_USER": checked["release_user"], "RELEASE_HOME": checked["release_home"],
                       "INSTALL_DIR": checked["install_dir"], "CONTROLLER_SHA256": controller_sha256,
                       "POLICY_SHA256": policy_sha256}.items():
        text = text.replace("@" + key + "@", value)
    return text.encode("ascii")


def read_root_owned_json(path):
    """Read a no-follow root-owned 0444 JSON file through non-writable ancestors."""
    descriptor = -1
    file_descriptor = -1
    try:
        if not path.is_absolute() or str(path) != str(Path(os.path.abspath(path))):
            raise ValueError("noncanonical policy path")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for part in path.parts[1:-1]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError("unsafe policy ancestor")
        file_descriptor = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
        before = os.fstat(file_descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444 or not 0 < before.st_size <= 128 * 1024):
            raise ValueError("unsafe policy file")
        raw = os.read(file_descriptor, 128 * 1024 + 1)
        after = os.fstat(file_descriptor)
        current = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        def identity(info):
            # Access time may change merely by reading; bind all security/write metadata.
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
                    info.st_size, info.st_mtime, info.st_ctime)
        if identity(before) != identity(after) or identity(after) != identity(current) or len(raw) != before.st_size:
            raise ValueError("policy changed while reading")
        model = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object,
                           parse_constant=_reject_json_constant)
        return model, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise DeploymentError("host_policy_unsafe") from exc
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def read_root_owned_policy(path):
    model, digest = read_root_owned_json(path)
    return validate_host_policy(model), digest


def install_policy():
    # This entry point has no path argument and reads no environment overrides.
    program = Path(os.path.abspath(__file__))
    policy, digest = read_root_owned_policy(program.parent / "host-policy.json")
    if program != Path(policy["install_dir"]) / "tat-deploy-test.py":
        raise DeploymentError("controller_program_identity")
    program_info = _regular_file(program, 256 * 1024, 0o555)
    if program_info.st_uid != 0 or program_info.st_gid != 0:
        raise DeploymentError("controller_file_unsafe")
    configure_policy(policy, policy_sha256=digest)


def validate_public_release_identity(service, raw, git_sha, build_id, *, api_envelope=False):
    """Return one exact public release identity or fail closed."""
    try:
        if (
            service not in SERVICES
            or not isinstance(raw, bytes)
            or len(raw) > MAX_PUBLIC_IDENTITY_BYTES
            or not isinstance(git_sha, str)
            or not GIT_SHA.fullmatch(git_sha)
            or not isinstance(build_id, str)
            or not BUILD_ID.fullmatch(build_id)
        ):
            raise ValueError("invalid public release identity")
        model = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if api_envelope:
            if (
                type(model) is not dict
                or set(model) != {"code", "message", "data"}
                or type(model["code"]) is not int
                or model["code"] != 0
                or model["message"] != "ok"
                or type(model["data"]) is not dict
                or "release" not in model["data"]
                or set(model["data"]) - {"release", "status", "service"}
            ):
                raise ValueError("invalid API release envelope")
            model = model["data"]["release"]
        if (
            type(model) is not dict
            or set(model) != {"build_id", "git_sha", "schema", "service"}
            or model["schema"] != "cnb-release-identity/v1"
            or model["service"] != service
            or model["git_sha"] != git_sha
            or model["build_id"] != build_id
            or any(type(model[name]) is not str for name in model)
        ):
            raise ValueError("release identity mismatch")
        return model
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise DeploymentError("release_identity_mismatch") from exc


def controller_program_sha256():
    try:
        data = Path(__file__).read_bytes()
    except OSError as exc:
        raise DeploymentError("controller_program_identity") from exc
    if not data or len(data) > 256 * 1024:
        raise DeploymentError("controller_program_identity")
    return hashlib.sha256(data).hexdigest()


def validate_image(service, value):
    repository = POLICY.get("services", {}).get(service, {}).get("image_repository")
    if (
        not isinstance(repository, str)
        or not isinstance(value, str)
        or not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", value)
    ):
        raise ValueError("invalid immutable service image")
    return value


def parse_tat_release_script(data):
    prefix = render_tat_template(POLICY, controller_program_sha256(), POLICY_SHA256)
    before, after = prefix.split(b"{{release_request_b64url}}")
    if not isinstance(data, bytes) or len(data) > 64 * 1024 or not data.startswith(before):
        raise DeploymentError("release_request_invalid")
    encoded = data[len(before):]
    if after and not encoded.endswith(after):
        raise DeploymentError("release_request_invalid")
    if after:
        encoded = encoded[:-len(after)]
    if not BASE64URL.fullmatch(encoded):
        raise DeploymentError("release_request_invalid")
    try:
        raw = base64.b64decode(encoded + b"=" * ((4 - len(encoded) % 4) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).rstrip(b"=") != encoded:
            raise ValueError("non-canonical base64url")
        model = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object,
                           parse_constant=_reject_json_constant)
        if (
            type(model) is not dict
            or set(model) != {"schema", "project", "environment", "controller", "git_sha", "controller_commit", "build_id", "images"}
            or model["schema"] != "cnb-release-request/v1"
            or model["project"] != POLICY["project"]
            or model["environment"] != POLICY["environment"]
            or model["controller"] != CONTROLLER_ID
            or type(model["git_sha"]) is not str or not GIT_SHA.fullmatch(model["git_sha"])
            or model["controller_commit"] != model["git_sha"]
            or type(model["build_id"]) is not str or not BUILD_ID.fullmatch(model["build_id"])
            or type(model["images"]) is not dict or set(model["images"]) != set(SERVICES)
            or raw != json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        ):
            raise ValueError("invalid request binding")
        images = {service: validate_image(service, model["images"][service]) for service in SERVICES}
    except (ValueError, UnicodeError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise DeploymentError("release_request_invalid") from exc
    return {"git_sha": model["git_sha"], "controller_commit": model["controller_commit"],
            "build_id": model["build_id"], "images": images}


def _parse_env(text):
    if not isinstance(text, str) or "\0" in text or len(text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("invalid environment file")
    lines = text.splitlines(keepends=True)
    values = {}
    indexes = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ENV_LINE.fullmatch(line)
        if not match:
            raise ValueError("invalid environment line")
        key, value = match.group(1), match.group(2)
        if key in values:
            raise ValueError(f"duplicate environment key: {key}")
        values[key] = value
        indexes[key] = index
    missing = sorted(REQUIRED_ENV_KEYS - values.keys())
    if missing:
        raise ValueError(f"missing environment key: {missing[0]}")
    return lines, values, indexes


def update_env_text(text, images):
    checked_images = {service: validate_image(service, images[service]) for service in SERVICES}
    lines, _values, indexes = _parse_env(text)
    for service, key in IMAGE_KEYS.items():
        line = lines[indexes[key]]
        ending = "\r\n" if line.endswith("\r\n") else "\n"
        lines[indexes[key]] = f"{key}={checked_images[service]}{ending}"
    updated = "".join(lines)
    if updated and not updated.endswith(("\n", "\r")):
        updated += "\n"
    return updated


def parse_test_database_url(value):
    try:
        parsed = urlsplit(value)
        query = parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid test database target") from exc
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or parsed.hostname != POLICY["database"]["host"]
        or port != POLICY["database"]["port"]
        or parsed.path != "/" + POLICY["database"]["name"]
        or unquote(parsed.username or "") != POLICY["database"]["user"]
        or not unquote(parsed.password or "")
        or query not in ({}, {"schema": ["public"]})
        or parsed.fragment
    ):
        raise ValueError("invalid test database target")
    return {
        "username": unquote(parsed.username),
        "password": unquote(parsed.password),
        "database": POLICY["database"]["name"],
    }


def parse_test_redis_url(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid test Redis target") from exc
    if (
        parsed.scheme not in {"redis", "rediss"}
        or parsed.hostname != POLICY["redis"]["host"]
        or port != POLICY["redis"]["port"]
        or parsed.path != "/" + str(POLICY["redis"]["database"])
        or parsed.username not in {None, ""}
        or not unquote(parsed.password or "")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid test Redis target")
    return {"database": POLICY["redis"]["database"]}


def validate_test_redis_prefix(value):
    if value != POLICY["redis"]["prefix"]:
        raise ValueError("invalid test Redis prefix")
    return value


def required_capacity_bytes(database_size, release_compressed_bytes=0):
    if not isinstance(database_size, int) or database_size <= 0 or database_size > 8 * 1024**4:
        raise ValueError("invalid test database size")
    if (
        not isinstance(release_compressed_bytes, int)
        or release_compressed_bytes < 0
        or release_compressed_bytes > MAX_RELEASE_COMPRESSED_BYTES
    ):
        raise ValueError("invalid release image size")
    return max(6 * GIB, database_size * 3 + 2 * GIB) + release_compressed_bytes * 2


def manifest_compressed_bytes(model):
    items = model if isinstance(model, list) else [model]
    if not items or len(items) > 16:
        raise DeploymentError("image_manifest_invalid")
    total = 0
    for item in items:
        if not isinstance(item, dict):
            raise DeploymentError("image_manifest_invalid")
        manifest = item.get("OCIManifest") or item.get("SchemaV2Manifest") or item
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
            raise DeploymentError("image_manifest_invalid")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or not layers or len(layers) > 256:
            raise DeploymentError("image_manifest_invalid")
        for layer in layers:
            size = layer.get("size") if isinstance(layer, dict) else None
            digest = layer.get("digest") if isinstance(layer, dict) else None
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                or not isinstance(digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            ):
                raise DeploymentError("image_manifest_invalid")
            total += size
            if total > MAX_IMAGE_COMPRESSED_BYTES:
                raise DeploymentError("image_manifest_invalid")
    return total


def _release_manifest_bytes(images):
    total = 0
    for service in SERVICES:
        try:
            output = _run(
                _docker_prefix() + ["manifest", "inspect", "--verbose", images[service]],
                timeout=60,
                max_output=4 * 1024 * 1024,
            )
            model = json.loads(output.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DeploymentError("image_manifest_invalid") from exc
        total += manifest_compressed_bytes(model)
        if total > MAX_RELEASE_COMPRESSED_BYTES:
            raise DeploymentError("release_images_too_large")
    return total


def validate_compose_model(model, images, runtime_values):
    if type(model) is not dict or model.get("name") != PROJECT:
        raise DeploymentError("compose_contract_top")
    services = model.get("services")
    networks = model.get("networks")
    if type(services) is not dict or set(services) != set(SERVICES):
        raise DeploymentError("compose_contract_services")
    if type(networks) is not dict or set(networks) != set(POLICY["networks"]):
        raise DeploymentError("compose_contract_networks")
    for name in POLICY["networks"]:
        network = networks[name]
        if type(network) is not dict or network.get("external") is not True or network.get("name") != name:
            raise DeploymentError("compose_contract_networks")
    for key in ("volumes", "secrets", "configs"):
        if model.get(key) not in (None, {}):
            raise DeploymentError("compose_contract_top_resource")
    forbidden = ("devices", "device_cgroup_rules", "cap_add", "cap_drop", "security_opt",
                 "sysctls", "extra_hosts", "volumes_from", "group_add", "ulimits", "runtime", "pid",
                 "ipc", "uts", "userns_mode", "cgroup", "cgroup_parent", "build", "secrets", "configs", "env_file")
    for name in SERVICES:
        service = services[name]
        approved = POLICY["services"][name]
        if type(service) is not dict:
            raise DeploymentError("compose_contract_service")
        if (service.get("container_name") != CONTAINERS[name] or service.get("image") != images[name]
            or service.get("privileged") not in (None, False) or service.get("network_mode") not in (None, "")):
            raise DeploymentError("compose_contract_identity")
        for key in forbidden:
            if service.get(key) not in (None, False, [], {}):
                raise DeploymentError("compose_contract_privilege")
        ports = service.get("ports") or []
        if "loopback_port" in approved:
            expected_port = dict(approved["loopback_port"], published=str(approved["loopback_port"]["published"]))
            if type(ports) is not list or len(ports) != 1 or type(ports[0]) is not dict:
                raise DeploymentError("compose_contract_ports")
            actual_port = dict(ports[0])
            if actual_port.pop("mode", "ingress") != "ingress" or actual_port != expected_port:
                raise DeploymentError("compose_contract_ports")
        elif ports:
            raise DeploymentError("compose_contract_ports")
        actual_networks = service.get("networks", {})
        if type(actual_networks) not in (dict, list) or set(actual_networks) != set(approved["networks"]):
            raise DeploymentError("compose_contract_service_network")
        volumes = service.get("volumes") or []
        if type(volumes) is not list or any(type(v) is not dict for v in volumes):
            raise DeploymentError("compose_contract_mount")
        actual = {(v.get("type"), v.get("source"), v.get("target")) for v in volumes}
        expected = {(v["type"], v["source"], v["target"]) for v in approved["mounts"]}
        if actual != expected or len(volumes) != len(expected):
            raise DeploymentError("compose_contract_mount")
        environment = dict(runtime_values) if approved["runtime_env"] else {}
        environment.update({key: runtime_values[ref] for key, ref in approved["environment_refs"].items()})
        environment.update(approved["environment"])
        if (service.get("environment") or {}) != environment:
            raise DeploymentError("compose_contract_environment")
    return model


def _regular_file(path, maximum, exact_mode=None):
    try:
        info = path.lstat()
    except OSError as exc:
        raise DeploymentError("required_file_missing") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise DeploymentError("unsafe_required_file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise DeploymentError("required_file_size")
    if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
        raise DeploymentError("required_file_mode")
    return info


def _directory(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise DeploymentError("required_directory_missing") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise DeploymentError("unsafe_required_directory")
    return info


def _run(
    argv,
    *,
    input_bytes=None,
    output=None,
    timeout=300,
    extra_env=None,
    max_output=2 * 1024 * 1024,
    classify_curl_transport=False,
):
    environment = dict(BASE_ENV)
    if extra_env:
        environment.update(extra_env)
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            input=input_bytes,
            stdout=subprocess.PIPE if output is None else output,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError("command_failed") from exc
    if result.returncode != 0:
        if classify_curl_transport and result.returncode in RETRIABLE_CURL_EXIT_CODES:
            raise DeploymentError("public_probe_transport")
        raise DeploymentError("command_failed")
    if output is None and len(result.stdout) > max_output:
        raise DeploymentError("command_output_limit")
    return result.stdout if output is None else b""


def _docker_prefix():
    return [DOCKER, "--config", str(DOCKER_CONFIG.parent), "--host", "unix:///var/run/docker.sock"]


def validate_controller_compose_bytes(data):
    if (
        not isinstance(data, bytes)
        or not data
        or len(data) > 64 * 1024
        or hashlib.sha256(data).hexdigest() != CONTROLLER_COMPOSE_SHA256
    ):
        raise DeploymentError("controller_compose_identity")
    return data


def _read_controller_compose():
    info = _regular_file(CONTROLLER_COMPOSE_PATH, 64 * 1024, 0o444)
    if info.st_uid != 0 or info.st_gid != 0:
        raise DeploymentError("controller_file_unsafe")
    return validate_controller_compose_bytes(CONTROLLER_COMPOSE_PATH.read_bytes())


def _image_environment(images):
    return {IMAGE_KEYS[service]: images[service] for service in SERVICES}


def _compose(compose_path, env_path, arguments, images, *, timeout=600):
    command = _docker_prefix() + [
        "compose",
        "--project-name",
        PROJECT,
        "--project-directory",
        str(APP_DIR),
        "--env-file",
        str(env_path),
        "-f",
        str(compose_path),
    ] + list(arguments)
    compose_environment = _image_environment(images)
    compose_environment["CNB_RUNTIME_ENV_FILE"] = str(env_path)
    return _run(command, timeout=timeout, extra_env=compose_environment)


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path, data, mode, uid, gid):
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_new(path, data, mode, uid, gid):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _rename_directory_noreplace_at(directory_fd, source, destination):
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if hasattr(library, "renameat2"):
        result = library.renameat2(
            directory_fd,
            ctypes.c_char_p(source_bytes),
            directory_fd,
            ctypes.c_char_p(destination_bytes),
            1,
        )
    elif hasattr(library, "renameatx_np"):
        result = library.renameatx_np(
            directory_fd,
            ctypes.c_char_p(source_bytes),
            directory_fd,
            ctypes.c_char_p(destination_bytes),
            0x00000004,
        )
    else:
        raise DeploymentError("unsafe_backup_directory")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _safe_mkdir(path, mode, uid, gid):
    """Install a private directory without repairing anything reopened by name.

    POSIX mkdir does not return an fd. The release lock excludes cooperating
    creators; immediately captured entry metadata is the boundary before open.
    """
    path = Path(path)
    parent_descriptor = -1
    directory_descriptor = -1
    staged_name = None
    staged_created = False
    staged_info = None
    try:
        if not path.is_absolute() or path != Path(os.path.abspath(path)):
            raise DeploymentError("unsafe_backup_directory")
        parent_descriptor, parent_info, parent_chain = _open_directory_path_chain(path.parent)
        try:
            directory_descriptor, info = _open_directory_at(parent_descriptor, path.name)
        except DeploymentError:
            staged_name = f".{path.name}.{os.urandom(16).hex()}"
            os.mkdir(staged_name, mode=0o700, dir_fd=parent_descriptor)
            staged_created = True
            created_info = os.stat(staged_name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISDIR(created_info.st_mode)
                or created_info.st_uid != uid
                or created_info.st_gid != gid
                or stat.S_IMODE(created_info.st_mode) != mode
            ):
                raise DeploymentError("unsafe_backup_directory")
            directory_descriptor, opened_info = _open_directory_at(parent_descriptor, staged_name)
            if (
                not _same_directory_info(opened_info, created_info)
                or not _same_directory_entry(parent_descriptor, staged_name, created_info)
            ):
                raise DeploymentError("unsafe_backup_directory")
            info = os.fstat(directory_descriptor)
            staged_info = info
            if not _same_directory_entry(parent_descriptor, staged_name, info):
                raise DeploymentError("unsafe_backup_directory")
            _fsync_directory_fd(directory_descriptor)
            _fsync_directory_fd(parent_descriptor)
            if not _same_exact_directory_path(path.parent, parent_info, parent_chain):
                raise DeploymentError("unsafe_backup_directory")
            try:
                _rename_directory_noreplace_at(parent_descriptor, staged_name, path.name)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                os.close(directory_descriptor)
                directory_descriptor = -1
                directory_descriptor, info = _open_directory_at(parent_descriptor, path.name)
            else:
                staged_name = None
        info = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode
            or not _same_directory_entry(parent_descriptor, path.name, info)
            or not _same_exact_directory_path(path.parent, parent_info, parent_chain)
        ):
            raise DeploymentError("unsafe_backup_directory")
        _fsync_directory_fd(directory_descriptor)
        _fsync_directory_fd(parent_descriptor)
    except DeploymentError as exc:
        if exc.code == "unsafe_backup_directory":
            raise
        raise DeploymentError("unsafe_backup_directory") from exc
    except OSError as exc:
        raise DeploymentError("unsafe_backup_directory") from exc
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        if (
            staged_name is not None
            and staged_created
            and staged_info is not None
            and _same_directory_entry(parent_descriptor, staged_name, staged_info)
        ):
            try:
                os.rmdir(staged_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            else:
                try:
                    _fsync_directory_fd(parent_descriptor)
                except OSError as exc:
                    raise DeploymentError("unsafe_backup_directory") from exc
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _exact_absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or path != Path(os.path.abspath(path)):
        raise DeploymentError("snapshot_manifest_invalid")
    return path


def _snapshot_name(created_at, build_id):
    if (
        type(created_at) is not str
        or not SNAPSHOT_CREATED_AT.fullmatch(created_at)
        or type(build_id) is not str
        or not BUILD_ID.fullmatch(build_id)
    ):
        raise DeploymentError("snapshot_manifest_invalid")
    try:
        instant = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DeploymentError("snapshot_manifest_invalid") from exc
    if instant.strftime("%Y-%m-%dT%H:%M:%SZ") != created_at:
        raise DeploymentError("snapshot_manifest_invalid")
    token = hashlib.sha256(build_id.encode("ascii")).hexdigest()[:16]
    return f'{instant.strftime("%Y%m%dT%H%M%SZ")}-{token}'


def _valid_utc_timestamp(value):
    if type(value) is not str or not UTC_TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _valid_release_images(value):
    if type(value) is not dict or set(value) != set(SERVICES):
        return False
    try:
        return all(validate_image(service, value[service]) == value[service] for service in SERVICES)
    except (KeyError, TypeError, ValueError):
        return False


def _valid_snapshot_binding(model):
    return (
        type(model.get("snapshot")) is str
        and SNAPSHOT_NAME.fullmatch(model["snapshot"])
        and type(model.get("snapshot_manifest_sha256")) is str
        and SHA256.fullmatch(model["snapshot_manifest_sha256"])
    )


def _valid_legacy_backup_path(value, filename):
    if type(value) is not str:
        return False
    path = Path(value)
    expected_root = Path(POLICY["app_dir"]) / "backups" / "releases"
    return (
        path.is_absolute()
        and path == Path(os.path.abspath(path))
        and path.name == filename
        and SNAPSHOT_NAME.fullmatch(path.parent.name) is not None
        and path.parent.parent == expected_root
    )


def _installed_empty_baseline():
    baseline, digest = read_root_owned_json(CONTROLLER_COMPOSE_PATH.parent / "empty-baseline.json")
    expected = {"schema", "status", "images", "project", "environment", "controller", "policy_sha256",
                "database", "runtime_env_sha256", "controller_compose_sha256", "created_at"}
    raw = (json.dumps(baseline, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if (type(baseline) is not dict or set(baseline) != expected
        or baseline["schema"] != EMPTY_BASELINE_SCHEMA or baseline["status"] != "empty"
        or baseline["images"] != {} or baseline["project"] != POLICY["project"]
        or baseline["environment"] != POLICY["environment"] or baseline["controller"] != CONTROLLER_ID
        or baseline["policy_sha256"] != POLICY_SHA256 or baseline["database"] != POLICY["database"]
        or baseline["controller_compose_sha256"] != CONTROLLER_COMPOSE_SHA256
        or type(baseline["runtime_env_sha256"]) is not str or not SHA256.fullmatch(baseline["runtime_env_sha256"])
        or not _valid_utc_timestamp(baseline["created_at"]) or hashlib.sha256(raw).hexdigest() != digest):
        raise DeploymentError("backup_retention_failed")
    return baseline, digest


def _valid_previous_images(model):
    if _valid_release_images(model.get("previous_images")):
        return True
    if model.get("schema") != TRANSACTION_SCHEMA_V2 or model.get("previous_images") != {}:
        return False
    _baseline, digest = _installed_empty_baseline()
    return model.get("previous_release_sha256") == digest


def _assert_database_empty():
    # Fixed SQL, independently scoped by the policy database name passed as an argv item.
    # Exclude PostgreSQL internals, but count application schemas, relations, functions and types.
    sql = """SELECT
      (SELECT count(*) FROM pg_namespace WHERE nspname <> 'public' AND nspname <> 'information_schema' AND nspname !~ '^pg_') +
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_') +
      (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_') +
      (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_')"""
    database = POLICY["database"]
    output = _run(_docker_prefix() + ["exec", database["container"], "psql", "--no-psqlrc",
                  "-U", database["admin_user"], "-d", database["name"], "-At", "--set", "ON_ERROR_STOP=1", "-c", sql],
                  timeout=30, max_output=128)
    if output.strip() != b"0":
        raise DeploymentError("bootstrap_database_not_empty")


def _assert_empty_baseline_runtime(env_bytes, uid, gid):
    _raw, record = _load_private_record(RELEASE_PATH, kind="release", uid=uid, gid=gid, required=False)
    if record is not None and record["schema"] == EMPTY_BASELINE_SCHEMA:
        if record["runtime_env_sha256"] != hashlib.sha256(env_bytes).hexdigest():
            raise DeploymentError("bootstrap_environment_changed")
        _assert_database_empty()


def _validate_release_record_model(model):
    if type(model) is dict and model.get("schema") == EMPTY_BASELINE_SCHEMA:
        baseline, _digest = _installed_empty_baseline()
        if model != baseline:
            raise DeploymentError("backup_retention_failed")
        return model
    common = {
        "build_id",
        "controller",
        "controller_compose_sha256",
        "controller_program_sha256",
        "deployed_at",
        "git_sha",
        "images",
        "probes",
        "schema",
        "status",
    }
    if type(model) is not dict or model.get("schema") not in {RELEASE_SCHEMA_V1, RELEASE_SCHEMA_V2}:
        raise DeploymentError("backup_retention_failed")
    expected = set(common)
    if model["schema"] == RELEASE_SCHEMA_V1:
        expected |= {"database_backup", "database_backup_sha256"}
    else:
        expected |= {"snapshot", "snapshot_manifest_sha256"}
    allowed_probes = (
        {LEGACY_PUBLIC_PROBES, PUBLIC_PROBES}
        if model["schema"] == RELEASE_SCHEMA_V1
        else {PUBLIC_PROBES}
    )
    if (
        set(model) != expected
        or model.get("status") != "passed"
        or model.get("controller") != CONTROLLER_ID
        or type(model.get("controller_program_sha256")) is not str
        or not SHA256.fullmatch(model["controller_program_sha256"])
        or model.get("controller_compose_sha256") != CONTROLLER_COMPOSE_SHA256
        or type(model.get("git_sha")) is not str
        or not GIT_SHA.fullmatch(model["git_sha"])
        or type(model.get("build_id")) is not str
        or not BUILD_ID.fullmatch(model["build_id"])
        or not _valid_release_images(model.get("images"))
        or not _valid_utc_timestamp(model.get("deployed_at"))
        or type(model.get("probes")) is not list
        or tuple(model["probes"]) not in allowed_probes
        or any(type(url) is not str for url in model["probes"])
    ):
        raise DeploymentError("backup_retention_failed")
    if model["schema"] == RELEASE_SCHEMA_V1:
        if (
            not _valid_legacy_backup_path(model.get("database_backup"), "database.dump")
            or type(model.get("database_backup_sha256")) is not str
            or not SHA256.fullmatch(model["database_backup_sha256"])
        ):
            raise DeploymentError("backup_retention_failed")
    elif not _valid_snapshot_binding(model):
        raise DeploymentError("backup_retention_failed")
    return model


def _validate_release_transaction_model(model):
    if type(model) is not dict or model.get("schema") not in {
        TRANSACTION_SCHEMA_V1,
        TRANSACTION_SCHEMA_V2,
    }:
        raise DeploymentError("backup_retention_failed")
    common = {
        "build_id",
        "controller",
        "controller_compose_sha256",
        "controller_program_sha256",
        "git_sha",
        "images",
        "phase",
        "previous_images",
        "schema",
        "status",
        "updated_at",
    }
    expected = set(common)
    if model["schema"] == TRANSACTION_SCHEMA_V1:
        expected |= {
            "compose_backup",
            "database_backup",
            "database_backup_sha256",
            "env_backup",
        }
    else:
        expected |= {
            "previous_release_sha256",
            "snapshot",
            "snapshot_manifest_sha256",
        }
    if model.get("status") == "failed":
        expected.add("reason")
    if (
        set(model) != expected
        or model.get("status") not in {"active", "failed"}
        or model.get("controller") != CONTROLLER_ID
        or type(model.get("controller_program_sha256")) is not str
        or not SHA256.fullmatch(model["controller_program_sha256"])
        or model.get("controller_compose_sha256") != CONTROLLER_COMPOSE_SHA256
        or type(model.get("git_sha")) is not str
        or not GIT_SHA.fullmatch(model["git_sha"])
        or type(model.get("build_id")) is not str
        or not BUILD_ID.fullmatch(model["build_id"])
        or not _valid_release_images(model.get("images"))
        or not _valid_previous_images(model)
        or model.get("phase") not in RELEASE_TRANSACTION_PHASES
        or not _valid_utc_timestamp(model.get("updated_at"))
        or (
            model.get("status") == "failed"
            and (
                type(model.get("reason")) is not str
                or re.fullmatch(r"[a-z0-9_]{1,64}", model["reason"]) is None
            )
        )
    ):
        raise DeploymentError("backup_retention_failed")
    if model["schema"] == TRANSACTION_SCHEMA_V1:
        if (
            not _valid_legacy_backup_path(model.get("database_backup"), "database.dump")
            or not _valid_legacy_backup_path(model.get("env_backup"), "env.before")
            or not _valid_legacy_backup_path(
                model.get("compose_backup"), "docker-compose.before.yml"
            )
            or type(model.get("database_backup_sha256")) is not str
            or not SHA256.fullmatch(model["database_backup_sha256"])
        ):
            raise DeploymentError("backup_retention_failed")
    elif (
        not _valid_snapshot_binding(model)
        or type(model.get("previous_release_sha256")) is not str
        or not SHA256.fullmatch(model["previous_release_sha256"])
    ):
        raise DeploymentError("backup_retention_failed")
    return model


def _parse_snapshot_manifest_bytes(raw, snapshot_name):
    model = json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )
    if type(model) is not dict or set(model) != {
        "build_id",
        "created_at",
        "files",
        "git_sha",
        "schema",
        "snapshot",
    }:
        raise DeploymentError("snapshot_manifest_invalid")
    canonical = (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if raw != canonical:
        raise DeploymentError("snapshot_manifest_invalid")
    if (
        model["schema"] != SNAPSHOT_SCHEMA
        or type(model["schema"]) is not str
        or type(model["git_sha"]) is not str
        or not GIT_SHA.fullmatch(model["git_sha"])
        or type(model["build_id"]) is not str
        or not BUILD_ID.fullmatch(model["build_id"])
        or type(model["snapshot"]) is not str
        or model["snapshot"] != snapshot_name
        or _snapshot_name(model["created_at"], model["build_id"]) != snapshot_name
        or type(model["files"]) is not dict
        or set(model["files"]) != set(SNAPSHOT_FILES)
    ):
        raise DeploymentError("snapshot_manifest_invalid")
    return model


def _open_directory_path(path):
    descriptor, info, _chain = _open_directory_path_chain(path)
    return descriptor, info


def _open_directory_path_chain(path):
    path = _exact_absolute_path(path)
    descriptor = -1
    try:
        descriptor = os.open(
            "/",
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        root_info = os.fstat(descriptor)
        chain = [(root_info.st_dev, root_info.st_ino)]
        for component in path.parts[1:]:
            next_descriptor, next_info = _open_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = next_descriptor
            chain.append((next_info.st_dev, next_info.st_ino))
        info = os.fstat(descriptor)
    except DeploymentError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid") from exc
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid")
    return descriptor, info, tuple(chain)


def _open_directory_at(directory_fd, name):
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid") from exc
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid")
    return descriptor, info


def _same_directory_info(current, expected):
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
        and current.st_uid == expected.st_uid
        and current.st_gid == expected.st_gid
        and stat.S_IMODE(current.st_mode) == stat.S_IMODE(expected.st_mode)
    )


def _same_directory_entry(directory_fd, name, expected):
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return _same_directory_info(current, expected)


def _same_exact_directory_path(path, expected, expected_chain):
    descriptor = -1
    try:
        descriptor, current, current_chain = _open_directory_path_chain(path)
        return (
            current_chain == expected_chain
            and current.st_dev == expected.st_dev
            and current.st_ino == expected.st_ino
            and current.st_uid == expected.st_uid
            and current.st_gid == expected.st_gid
            and stat.S_IMODE(current.st_mode) == stat.S_IMODE(expected.st_mode)
        )
    except DeploymentError:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_directory_info(info, uid, gid):
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == uid
        and info.st_gid == gid
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _require_private_directory(path, uid, gid):
    descriptor = -1
    try:
        descriptor, info = _open_directory_path(path)
        if not _private_directory_info(info, uid, gid):
            raise DeploymentError("unsafe_backup_directory")
        return info
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _same_file_entry(directory_fd, name, expected):
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
        and current.st_nlink == expected.st_nlink == 1
        and current.st_uid == expected.st_uid
        and current.st_gid == expected.st_gid
        and stat.S_IMODE(current.st_mode) == stat.S_IMODE(expected.st_mode) == 0o600
        and current.st_size == expected.st_size
        and current.st_mtime_ns == expected.st_mtime_ns
        and current.st_ctime_ns == expected.st_ctime_ns
    )


def _load_private_record(path, *, kind, uid, gid, required):
    parent_descriptor = -1
    descriptor = -1
    try:
        if kind not in {"release", "transaction"} or type(required) is not bool:
            raise DeploymentError("backup_retention_failed")
        path = _exact_absolute_path(path)
        parent_descriptor, parent_info, parent_chain = _open_directory_path_chain(path.parent)
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            if required:
                raise DeploymentError("backup_retention_failed")
            return None, None
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size <= 0
            or info.st_size > 64 * 1024
        ):
            raise DeploymentError("backup_retention_failed")
        chunks = []
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(64 * 1024, remaining))
            if not block:
                raise DeploymentError("backup_retention_failed")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise DeploymentError("backup_retention_failed")
        raw = b"".join(chunks)
        if (
            not _same_file_entry(parent_descriptor, path.name, info)
            or not _same_exact_directory_path(path.parent, parent_info, parent_chain)
        ):
            raise DeploymentError("backup_retention_failed")
        model = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        canonical = (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        if raw != canonical:
            raise DeploymentError("backup_retention_failed")
        if kind == "release":
            _validate_release_record_model(model)
        else:
            _validate_release_transaction_model(model)
        return raw, model
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError("backup_retention_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _root_owned_public_directory(info):
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == 0
        and stat.S_IMODE(info.st_mode) == 0o755
    )


def _entry_absent_at(directory_fd, name):
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _open_recovery_parent(path):
    try:
        return _open_directory_path_chain(_exact_absolute_path(path).parent)
    except (DeploymentError, OSError, TypeError, ValueError) as exc:
        raise DeploymentError("recovery_required") from exc


def _marker_absent_with_bound_parent(path):
    parent_descriptor = -1
    try:
        path = _exact_absolute_path(path)
        parent_descriptor, parent_info, parent_chain = _open_recovery_parent(path)
        if not _entry_absent_at(parent_descriptor, path.name):
            raise DeploymentError("recovery_required")
        if not _same_exact_directory_path(path.parent, parent_info, parent_chain):
            raise DeploymentError("recovery_required")
    except DeploymentError as exc:
        if exc.code == "recovery_required":
            raise
        raise DeploymentError("recovery_required") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise DeploymentError("recovery_required") from exc
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _assert_release_unblocked():
    """Classify fixed markers through bound no-follow directory walks.

    The shared exclusive lock excludes the cooperating root recovery
    controller. A root process that deliberately ignores that lock is outside
    the same controller-identity boundary preserved from Task 5.
    """
    root_parent_descriptor = -1
    recovery_root_descriptor = -1
    recovery_state_descriptor = -1
    try:
        _marker_absent_with_bound_parent(TRANSACTION_PATH)
        recovery_root = _exact_absolute_path(RECOVERY_ROOT)
        recovery_state = _exact_absolute_path(RECOVERY_STATE_DIR)
        recovery_marker = _exact_absolute_path(RECOVERY_TRANSACTION_PATH)
        if (
            recovery_state != recovery_root / "state"
            or recovery_marker.parent != recovery_state
            or recovery_marker.name != PROJECT + ".transaction.json"
        ):
            raise DeploymentError("recovery_required")

        root_parent_descriptor, root_parent_info, root_parent_chain = _open_recovery_parent(
            recovery_root
        )
        try:
            recovery_root_descriptor, recovery_root_info = _open_directory_at(
                root_parent_descriptor,
                recovery_root.name,
            )
        except DeploymentError as exc:
            if _entry_absent_at(root_parent_descriptor, recovery_root.name):
                if not _same_exact_directory_path(
                    recovery_root.parent,
                    root_parent_info,
                    root_parent_chain,
                ):
                    raise DeploymentError("recovery_required")
                _marker_absent_with_bound_parent(TRANSACTION_PATH)
                return
            raise DeploymentError("recovery_required") from exc
        if (
            not _root_owned_public_directory(recovery_root_info)
            or not _same_directory_entry(
                root_parent_descriptor,
                recovery_root.name,
                recovery_root_info,
            )
        ):
            raise DeploymentError("recovery_required")

        try:
            recovery_state_descriptor, recovery_state_info = _open_directory_at(
                recovery_root_descriptor,
                recovery_state.name,
            )
        except DeploymentError as exc:
            raise DeploymentError("recovery_required") from exc
        if not _root_owned_public_directory(recovery_state_info):
            raise DeploymentError("recovery_required")
        if not _entry_absent_at(recovery_state_descriptor, recovery_marker.name):
            raise DeploymentError("recovery_required")

        root_chain = root_parent_chain + (
            (recovery_root_info.st_dev, recovery_root_info.st_ino),
        )
        state_chain = root_chain + (
            (recovery_state_info.st_dev, recovery_state_info.st_ino),
        )
        if (
            not _entry_absent_at(recovery_state_descriptor, recovery_marker.name)
            or not _same_directory_entry(
                recovery_root_descriptor,
                recovery_state.name,
                recovery_state_info,
            )
            or not _same_directory_entry(
                root_parent_descriptor,
                recovery_root.name,
                recovery_root_info,
            )
            or not _same_exact_directory_path(
                recovery_root,
                recovery_root_info,
                root_chain,
            )
            or not _same_exact_directory_path(
                recovery_state,
                recovery_state_info,
                state_chain,
            )
        ):
            raise DeploymentError("recovery_required")
        _marker_absent_with_bound_parent(TRANSACTION_PATH)
        # The recovery marker is the last classified entry. This check follows
        # the final root/state rewalk and never opens or reads marker contents.
        if not _entry_absent_at(recovery_state_descriptor, recovery_marker.name):
            raise DeploymentError("recovery_required")
    except DeploymentError as exc:
        if exc.code == "recovery_required":
            raise
        raise DeploymentError("recovery_required") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise DeploymentError("recovery_required") from exc
    finally:
        if recovery_state_descriptor >= 0:
            os.close(recovery_state_descriptor)
        if recovery_root_descriptor >= 0:
            os.close(recovery_root_descriptor)
        if root_parent_descriptor >= 0:
            os.close(root_parent_descriptor)


def _open_snapshot_file_at(directory_fd, name, maximum, uid, gid):
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        info = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size <= 0
        or info.st_size > maximum
    ):
        os.close(descriptor)
        raise DeploymentError("snapshot_manifest_invalid")
    return descriptor, info


def _read_snapshot_file_at(directory_fd, name, maximum, uid, gid):
    descriptor, info = _open_snapshot_file_at(directory_fd, name, maximum, uid, gid)
    try:
        chunks = []
        remaining = info.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise DeploymentError("snapshot_manifest_invalid")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise DeploymentError("snapshot_manifest_invalid")
        if not _same_file_entry(directory_fd, name, info):
            raise DeploymentError("snapshot_manifest_invalid")
        return b"".join(chunks), info
    finally:
        os.close(descriptor)


def _validate_database_dump_descriptor(descriptor):
    info = os.fstat(descriptor)
    # Empty databases can produce valid custom archives smaller than 1 KiB.
    # pg_restore must validate the structure of every nonempty archive below.
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise DeploymentError("database_backup_invalid")
    duplicate = os.dup(descriptor)
    os.lseek(duplicate, 0, os.SEEK_SET)
    with os.fdopen(duplicate, "rb", closefd=True) as stream:
        try:
            result = subprocess.run(
                _docker_prefix() + ["exec", "-i", POLICY["database"]["container"], "pg_restore", "--list"],
                stdin=stream,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
                env=BASE_ENV,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeploymentError("database_backup_invalid") from exc
    if result.returncode != 0:
        raise DeploymentError("database_backup_invalid")


def _hash_descriptor_exact(descriptor, expected_size, error_code):
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = expected_size
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            raise DeploymentError(error_code)
        digest.update(block)
        remaining -= len(block)
    if os.read(descriptor, 1):
        raise DeploymentError(error_code)
    return digest.hexdigest()


def _snapshot_file_digest_at(directory_fd, name, maximum, uid, gid, *, validate_dump=False):
    descriptor, info = _open_snapshot_file_at(directory_fd, name, maximum, uid, gid)
    try:
        if validate_dump:
            _validate_database_dump_descriptor(descriptor)
        digest = _hash_descriptor_exact(
            descriptor,
            info.st_size,
            "snapshot_manifest_invalid",
        )
        if not _same_file_entry(directory_fd, name, info):
            raise DeploymentError("snapshot_manifest_invalid")
        return info.st_size, digest, info
    finally:
        os.close(descriptor)


def _write_new_at(directory_fd, name, data, mode, uid, gid):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _fsync_snapshot_file(directory_fd, name, uid, gid):
    descriptor, _info = _open_snapshot_file_at(
        directory_fd,
        name,
        SNAPSHOT_FILE_LIMITS[name],
        uid,
        gid,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory_fd(descriptor):
    os.fsync(descriptor)


def _atomic_write_at(directory_fd, name, data, mode, uid, gid):
    temporary_name = f".{name}.{os.urandom(16).hex()}"
    descriptor = -1
    published = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        published = True
        try:
            _fsync_directory_fd(directory_fd)
        except OSError as publication_error:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError as cleanup_error:
                raise DeploymentError("snapshot_publication_cleanup_failed") from cleanup_error
            try:
                _fsync_directory_fd(directory_fd)
            except OSError as cleanup_error:
                raise DeploymentError("snapshot_publication_cleanup_failed") from cleanup_error
            raise publication_error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def _invalidate_published_snapshot_at(directory_fd, uid, gid):
    """Durably keep a precommit snapshot unmanaged, or report uncertainty."""
    restoration_error = None
    try:
        try:
            sentinel, _sentinel_info = _read_snapshot_file_at(
                directory_fd,
                SNAPSHOT_INCOMPLETE,
                64,
                uid,
                gid,
            )
            if sentinel != b"incomplete\n":
                raise DeploymentError("snapshot_manifest_invalid")
        except DeploymentError:
            try:
                os.unlink(SNAPSHOT_INCOMPLETE, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            _write_new_at(
                directory_fd,
                SNAPSHOT_INCOMPLETE,
                b"incomplete\n",
                0o600,
                uid,
                gid,
            )
        _fsync_directory_fd(directory_fd)
        sentinel, _sentinel_info = _read_snapshot_file_at(
            directory_fd,
            SNAPSHOT_INCOMPLETE,
            64,
            uid,
            gid,
        )
        if sentinel == b"incomplete\n":
            return
    except (DeploymentError, OSError) as exc:
        restoration_error = exc

    try:
        try:
            os.unlink(SNAPSHOT_MANIFEST, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        _fsync_directory_fd(directory_fd)
        try:
            os.stat(SNAPSHOT_MANIFEST, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
    except OSError as cleanup_error:
        raise DeploymentError("backup_durability_unknown") from cleanup_error
    raise DeploymentError("backup_durability_unknown") from restoration_error


def load_snapshot_manifest(snapshot_dir, *, release_root, uid, gid):
    """Validate one v1 snapshot without trusting any manifest-supplied path."""
    root_descriptor = -1
    snapshot_descriptor = -1
    try:
        if (
            type(uid) is not int
            or uid < 0
            or type(gid) is not int
            or gid < 0
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        root = _exact_absolute_path(release_root)
        snapshot = _exact_absolute_path(snapshot_dir)
        if snapshot.parent != root or not SNAPSHOT_NAME.fullmatch(snapshot.name):
            raise DeploymentError("snapshot_manifest_invalid")
        root_descriptor, root_info, root_chain = _open_directory_path_chain(root)
        if not _private_directory_info(root_info, uid, gid):
            raise DeploymentError("snapshot_manifest_invalid")
        snapshot_descriptor, directory_info = _open_directory_at(root_descriptor, snapshot.name)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != uid
            or directory_info.st_gid != gid
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        expected_names = set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST}
        if set(os.listdir(snapshot_descriptor)) != expected_names:
            raise DeploymentError("snapshot_manifest_invalid")

        raw, manifest_info = _read_snapshot_file_at(
            snapshot_descriptor,
            SNAPSHOT_MANIFEST,
            64 * 1024,
            uid,
            gid,
        )
        model = _parse_snapshot_manifest_bytes(raw, snapshot.name)

        payload_info = {}
        for name in SNAPSHOT_FILES:
            metadata = model["files"][name]
            if (
                type(metadata) is not dict
                or set(metadata) != {"bytes", "sha256"}
                or type(metadata["bytes"]) is not int
                or metadata["bytes"] <= 0
                or metadata["bytes"] > SNAPSHOT_FILE_LIMITS[name]
                or type(metadata["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])
            ):
                raise DeploymentError("snapshot_manifest_invalid")
            actual_size, actual_digest, info = _snapshot_file_digest_at(
                snapshot_descriptor,
                name,
                SNAPSHOT_FILE_LIMITS[name],
                uid,
                gid,
                validate_dump=name == "database.dump",
            )
            if actual_size != metadata["bytes"] or actual_digest != metadata["sha256"]:
                raise DeploymentError("snapshot_manifest_invalid")
            payload_info[name] = info
        if (
            not _same_exact_directory_path(root, root_info, root_chain)
            or
            not _same_directory_entry(root_descriptor, snapshot.name, directory_info)
            or set(os.listdir(snapshot_descriptor)) != expected_names
            or not _same_file_entry(snapshot_descriptor, SNAPSHOT_MANIFEST, manifest_info)
            or any(
                not _same_file_entry(snapshot_descriptor, name, payload_info[name])
                for name in SNAPSHOT_FILES
            )
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        return model
    except DeploymentError as exc:
        if exc.code == "snapshot_manifest_invalid":
            raise
        raise DeploymentError("snapshot_manifest_invalid") from exc
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError("snapshot_manifest_invalid") from exc
    finally:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


def create_release_snapshot(
    release_root,
    *,
    env_bytes,
    compose_bytes,
    git_sha,
    build_id,
    created_at,
    uid,
    gid,
):
    """Create one manifest-last v1 snapshot under the same mkdir/open boundary."""
    if (
        type(env_bytes) is not bytes
        or not 0 < len(env_bytes) <= SNAPSHOT_FILE_LIMITS["env.before"]
        or type(compose_bytes) is not bytes
        or not 0 < len(compose_bytes) <= SNAPSHOT_FILE_LIMITS["docker-compose.before.yml"]
        or type(git_sha) is not str
        or not GIT_SHA.fullmatch(git_sha)
        or type(uid) is not int
        or uid < 0
        or type(gid) is not int
        or gid < 0
    ):
        raise DeploymentError("snapshot_manifest_invalid")
    root = _exact_absolute_path(release_root)
    name = _snapshot_name(created_at, build_id)
    snapshot = root / name
    root_descriptor = -1
    snapshot_descriptor = -1
    committed = False
    snapshot_installed = False
    staged_created = False
    staged_name = None
    staged_info = None
    try:
        root_descriptor, root_info, root_chain = _open_directory_path_chain(root)
        if not _private_directory_info(root_info, uid, gid):
            raise DeploymentError("snapshot_manifest_invalid")
        staged_name = f".{name}.{os.urandom(16).hex()}"
        try:
            os.mkdir(staged_name, mode=0o700, dir_fd=root_descriptor)
            staged_created = True
        except FileExistsError as exc:
            raise DeploymentError("snapshot_path_exists") from exc
        created_info = os.stat(staged_name, dir_fd=root_descriptor, follow_symlinks=False)
        if not _private_directory_info(created_info, uid, gid):
            raise DeploymentError("snapshot_manifest_invalid")
        snapshot_descriptor, opened_info = _open_directory_at(root_descriptor, staged_name)
        if (
            not _same_directory_info(opened_info, created_info)
            or not _same_directory_entry(root_descriptor, staged_name, created_info)
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        directory_info = os.fstat(snapshot_descriptor)
        staged_info = directory_info
        if (
            not _same_directory_entry(root_descriptor, staged_name, directory_info)
            or not _same_exact_directory_path(root, root_info, root_chain)
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        _fsync_directory_fd(snapshot_descriptor)
        _fsync_directory_fd(root_descriptor)
        try:
            _rename_directory_noreplace_at(root_descriptor, staged_name, name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise DeploymentError("snapshot_path_exists") from exc
            raise
        snapshot_installed = True
        staged_name = None
        if not _same_directory_entry(root_descriptor, name, directory_info):
            raise DeploymentError("backup_durability_unknown")
        if not _same_exact_directory_path(root, root_info, root_chain):
            raise DeploymentError("snapshot_manifest_invalid")
        _fsync_directory_fd(root_descriptor)

        _write_new_at(snapshot_descriptor, SNAPSHOT_INCOMPLETE, b"incomplete\n", 0o600, uid, gid)
        _fsync_directory_fd(snapshot_descriptor)
        _write_new_at(snapshot_descriptor, "env.before", env_bytes, 0o600, uid, gid)
        _write_new_at(
            snapshot_descriptor,
            "docker-compose.before.yml",
            compose_bytes,
            0o600,
            uid,
            gid,
        )
        database_digest = _backup_database_at(
            snapshot_descriptor,
            "database.dump",
            uid,
            gid,
        )
        for filename in SNAPSHOT_FILES:
            _fsync_snapshot_file(snapshot_descriptor, filename, uid, gid)
        _fsync_directory_fd(snapshot_descriptor)

        files = {}
        payload_info = {}
        for filename in SNAPSHOT_FILES:
            size, digest, info = _snapshot_file_digest_at(
                snapshot_descriptor,
                filename,
                SNAPSHOT_FILE_LIMITS[filename],
                uid,
                gid,
            )
            files[filename] = {"bytes": size, "sha256": digest}
            payload_info[filename] = info
        if database_digest != files["database.dump"]["sha256"]:
            raise DeploymentError("database_backup_invalid")
        if (
            set(os.listdir(snapshot_descriptor)) != set(SNAPSHOT_FILES) | {SNAPSHOT_INCOMPLETE}
            or any(
                not _same_file_entry(snapshot_descriptor, filename, payload_info[filename])
                for filename in SNAPSHOT_FILES
            )
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        manifest = {
            "build_id": build_id,
            "created_at": created_at,
            "files": files,
            "git_sha": git_sha,
            "schema": SNAPSHOT_SCHEMA,
            "snapshot": name,
        }
        manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _atomic_write_at(
            snapshot_descriptor,
            SNAPSHOT_MANIFEST,
            manifest_bytes,
            0o600,
            uid,
            gid,
        )
        published_manifest, manifest_info = _read_snapshot_file_at(
            snapshot_descriptor,
            SNAPSHOT_MANIFEST,
            64 * 1024,
            uid,
            gid,
        )
        if (
            published_manifest != manifest_bytes
            or not _private_directory_info(os.fstat(snapshot_descriptor), uid, gid)
            or not _same_exact_directory_path(root, root_info, root_chain)
            or not _same_directory_entry(root_descriptor, name, directory_info)
            or set(os.listdir(snapshot_descriptor))
            != set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST, SNAPSHOT_INCOMPLETE}
            or not _same_file_entry(snapshot_descriptor, SNAPSHOT_MANIFEST, manifest_info)
            or any(
                not _same_file_entry(snapshot_descriptor, filename, payload_info[filename])
                for filename in SNAPSHOT_FILES
            )
        ):
            raise DeploymentError("snapshot_manifest_invalid")
        snapshot_ref = SnapshotRef(
            name=name,
            manifest_path=snapshot / SNAPSHOT_MANIFEST,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        try:
            os.unlink(SNAPSHOT_INCOMPLETE, dir_fd=snapshot_descriptor)
        except OSError as publication_error:
            raise publication_error
        committed = True
        try:
            _fsync_directory_fd(snapshot_descriptor)
        except OSError as durability_error:
            raise DeploymentError("backup_durability_unknown") from durability_error
        try:
            final_invalid = (
                not _same_exact_directory_path(root, root_info, root_chain)
                or not _same_directory_entry(root_descriptor, name, directory_info)
                or set(os.listdir(snapshot_descriptor))
                != set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST}
                or not _same_file_entry(snapshot_descriptor, SNAPSHOT_MANIFEST, manifest_info)
                or any(
                    not _same_file_entry(snapshot_descriptor, filename, payload_info[filename])
                    for filename in SNAPSHOT_FILES
                )
            )
        except OSError as validation_error:
            raise DeploymentError("backup_durability_unknown") from validation_error
        if final_invalid:
            raise DeploymentError("backup_durability_unknown")
        return snapshot_ref
    except Exception:
        if snapshot_installed and not committed:
            _invalidate_published_snapshot_at(snapshot_descriptor, uid, gid)
        raise
    finally:
        if snapshot_descriptor >= 0:
            try:
                os.close(snapshot_descriptor)
            except OSError:
                if not committed:
                    raise
        if (
            staged_name is not None
            and staged_created
            and staged_info is not None
            and root_descriptor >= 0
            and _same_directory_entry(root_descriptor, staged_name, staged_info)
        ):
            try:
                os.rmdir(staged_name, dir_fd=root_descriptor)
            except FileNotFoundError:
                pass
            else:
                try:
                    _fsync_directory_fd(root_descriptor)
                except OSError as exc:
                    raise DeploymentError("snapshot_manifest_invalid") from exc
        if root_descriptor >= 0:
            try:
                os.close(root_descriptor)
            except OSError:
                if not committed:
                    raise


def protected_snapshot_names(release_record, release_transaction):
    """Return only strict v2 snapshot bindings from known private records."""
    try:
        protected = set()
        if release_record is not None:
            _validate_release_record_model(release_record)
            if release_record["schema"] == RELEASE_SCHEMA_V2:
                protected.add(release_record["snapshot"])
        if release_transaction is not None:
            _validate_release_transaction_model(release_transaction)
            if release_transaction["schema"] == TRANSACTION_SCHEMA_V2:
                protected.add(release_transaction["snapshot"])
        return frozenset(protected)
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise DeploymentError("backup_retention_failed") from exc


def _validated_snapshot_for_deletion(root_descriptor, name, uid, gid):
    snapshot_descriptor = -1
    try:
        snapshot_descriptor, directory_info = _open_directory_at(root_descriptor, name)
        if not _private_directory_info(directory_info, uid, gid):
            raise DeploymentError("backup_retention_failed")
        expected_names = set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST}
        if set(os.listdir(snapshot_descriptor)) != expected_names:
            raise DeploymentError("backup_retention_failed")
        raw, manifest_info = _read_snapshot_file_at(
            snapshot_descriptor,
            SNAPSHOT_MANIFEST,
            64 * 1024,
            uid,
            gid,
        )
        model = _parse_snapshot_manifest_bytes(raw, name)
        file_info = {}
        for filename in SNAPSHOT_FILES:
            metadata = model["files"][filename]
            if (
                type(metadata) is not dict
                or set(metadata) != {"bytes", "sha256"}
                or type(metadata["bytes"]) is not int
                or metadata["bytes"] <= 0
                or metadata["bytes"] > SNAPSHOT_FILE_LIMITS[filename]
                or type(metadata["sha256"]) is not str
                or not SHA256.fullmatch(metadata["sha256"])
            ):
                raise DeploymentError("backup_retention_failed")
            actual_size, actual_digest, info = _snapshot_file_digest_at(
                snapshot_descriptor,
                filename,
                SNAPSHOT_FILE_LIMITS[filename],
                uid,
                gid,
                validate_dump=filename == "database.dump",
            )
            if actual_size != metadata["bytes"] or actual_digest != metadata["sha256"]:
                raise DeploymentError("backup_retention_failed")
            file_info[filename] = info
        file_info[SNAPSHOT_MANIFEST] = manifest_info
        if (
            not _same_directory_entry(root_descriptor, name, directory_info)
            or set(os.listdir(snapshot_descriptor)) != expected_names
            or any(
                not _same_file_entry(snapshot_descriptor, filename, file_info[filename])
                for filename in (*SNAPSHOT_FILES, SNAPSHOT_MANIFEST)
            )
        ):
            raise DeploymentError("backup_retention_failed")
        return (
            snapshot_descriptor,
            directory_info,
            file_info,
            hashlib.sha256(raw).hexdigest(),
            model,
        )
    except Exception:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        raise


def _delete_managed_snapshot(
    root,
    root_descriptor,
    root_info,
    root_chain,
    name,
    uid,
    gid,
    authority_check=None,
):
    """Quarantine one validated snapshot before bounded, non-recursive removal.

    The deployment lock excludes cooperating controllers. Replacement before
    unlink is detected. POSIX has no atomic
    compare-and-unlink-by-inode operation, so a malicious same-UID process that
    ignores that lock remains outside this protocol's guarantee. Random
    no-replace quarantine plus held descriptors closes deterministic name-swap
    windows without treating unknown replacement material as managed data.
    """
    snapshot_descriptor = -1
    tombstone = None
    try:
        (
            snapshot_descriptor,
            directory_info,
            file_info,
            _manifest_sha256,
            _model,
        ) = _validated_snapshot_for_deletion(root_descriptor, name, uid, gid)
        if (
            not _same_exact_directory_path(root, root_info, root_chain)
            or not _same_directory_entry(root_descriptor, name, directory_info)
        ):
            raise DeploymentError("backup_retention_failed")

        tombstone = f"{RETENTION_TOMBSTONE_PREFIX}{os.urandom(16).hex()}"
        if authority_check is not None:
            authority_check(name)
        _rename_directory_noreplace_at(root_descriptor, name, tombstone)
        if (
            not _same_exact_directory_path(root, root_info, root_chain)
            or not _entry_absent_at(root_descriptor, name)
            or not _same_directory_entry(root_descriptor, tombstone, directory_info)
        ):
            # The no-replace rename may have quarantined an attacker-controlled
            # replacement. Preserve that entry verbatim and fail closed.
            raise DeploymentError("backup_retention_failed")
        if authority_check is not None:
            try:
                authority_check(name)
            except Exception:
                _restore_retention_tombstone(
                    root_descriptor,
                    name,
                    tombstone,
                    directory_info,
                )
                raise

        remaining = set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST}
        for filename in (*SNAPSHOT_FILES, SNAPSHOT_MANIFEST):
            file_descriptor = -1
            try:
                if authority_check is not None:
                    try:
                        authority_check(name)
                    except Exception:
                        if remaining == set(SNAPSHOT_FILES) | {SNAPSHOT_MANIFEST}:
                            _restore_retention_tombstone(
                                root_descriptor,
                                name,
                                tombstone,
                                directory_info,
                            )
                        raise
                file_descriptor, opened_info = _open_snapshot_file_at(
                    snapshot_descriptor,
                    filename,
                    SNAPSHOT_FILE_LIMITS.get(filename, 64 * 1024),
                    uid,
                    gid,
                )
                expected = file_info[filename]
                if (
                    opened_info.st_dev != expected.st_dev
                    or opened_info.st_ino != expected.st_ino
                    or set(os.listdir(snapshot_descriptor)) != remaining
                    or not _same_exact_directory_path(root, root_info, root_chain)
                    or not _entry_absent_at(root_descriptor, name)
                    or not _same_directory_entry(root_descriptor, tombstone, directory_info)
                    or not _same_file_entry(snapshot_descriptor, filename, expected)
                ):
                    raise DeploymentError("backup_retention_failed")
                os.unlink(filename, dir_fd=snapshot_descriptor)
                unlinked_info = os.fstat(file_descriptor)
                if (
                    unlinked_info.st_dev != expected.st_dev
                    or unlinked_info.st_ino != expected.st_ino
                    or unlinked_info.st_nlink != 0
                ):
                    raise DeploymentError("backup_retention_failed")
                if authority_check is not None:
                    authority_check(name)
                remaining.remove(filename)
                if (
                    not _entry_absent_at(snapshot_descriptor, filename)
                    or set(os.listdir(snapshot_descriptor)) != remaining
                    or not _same_exact_directory_path(root, root_info, root_chain)
                    or not _entry_absent_at(root_descriptor, name)
                    or not _same_directory_entry(root_descriptor, tombstone, directory_info)
                ):
                    raise DeploymentError("backup_retention_failed")
            finally:
                if file_descriptor >= 0:
                    os.close(file_descriptor)

        if (
            os.listdir(snapshot_descriptor)
            or not _same_exact_directory_path(root, root_info, root_chain)
            or not _entry_absent_at(root_descriptor, name)
            or not _same_directory_entry(root_descriptor, tombstone, directory_info)
        ):
            raise DeploymentError("backup_retention_failed")
        _fsync_directory_fd(snapshot_descriptor)
        if (
            os.listdir(snapshot_descriptor)
            or not _same_exact_directory_path(root, root_info, root_chain)
            or not _entry_absent_at(root_descriptor, name)
            or not _same_directory_entry(root_descriptor, tombstone, directory_info)
        ):
            raise DeploymentError("backup_retention_failed")
        if authority_check is not None:
            authority_check(name)
        os.rmdir(tombstone, dir_fd=root_descriptor)
        removed_info = os.fstat(snapshot_descriptor)
        if (
            removed_info.st_dev != directory_info.st_dev
            or removed_info.st_ino != directory_info.st_ino
            # Linux, the deployment target, reports zero links for the held
            # directory after rmdir. Darwin retains two on an otherwise
            # successfully removed open directory, so its local test runtime
            # cannot use this Linux kernel signal.
            or (sys.platform.startswith("linux") and removed_info.st_nlink != 0)
            or not _entry_absent_at(root_descriptor, tombstone)
            or not _same_exact_directory_path(root, root_info, root_chain)
        ):
            raise DeploymentError("backup_retention_failed")
        _fsync_directory_fd(root_descriptor)
        if not _same_exact_directory_path(root, root_info, root_chain):
            raise DeploymentError("backup_retention_failed")
        if authority_check is not None:
            authority_check(name)
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError("backup_retention_failed") from exc
    finally:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)


def _restore_retention_tombstone(
    root_descriptor,
    original_name,
    tombstone,
    directory_info,
):
    """Best-effort no-replace restoration; never removes either entry."""
    try:
        if (
            not _entry_absent_at(root_descriptor, original_name)
            or not _same_directory_entry(root_descriptor, tombstone, directory_info)
        ):
            return False
        _rename_directory_noreplace_at(root_descriptor, tombstone, original_name)
        if (
            not _same_directory_entry(root_descriptor, original_name, directory_info)
            or not _entry_absent_at(root_descriptor, tombstone)
        ):
            return False
        _fsync_directory_fd(root_descriptor)
        return True
    except (DeploymentError, OSError):
        return False


def _prune_release_snapshots(
    release_root,
    *,
    protected_names,
    uid,
    gid,
    keep=5,
    authority_check=None,
):
    """Delete only old, complete direct-child managed snapshots."""
    root_descriptor = -1
    try:
        if (
            type(uid) is not int
            or uid < 0
            or type(gid) is not int
            or gid < 0
            or type(keep) is not int
            or keep < 0
        ):
            raise DeploymentError("backup_retention_failed")
        protected = frozenset(protected_names)
        if any(type(name) is not str or not SNAPSHOT_NAME.fullmatch(name) for name in protected):
            raise DeploymentError("backup_retention_failed")
        root = _exact_absolute_path(release_root)
        root_descriptor, root_info, root_chain = _open_directory_path_chain(root)
        if not _private_directory_info(root_info, uid, gid):
            raise DeploymentError("backup_retention_failed")
        managed = []
        for name in os.listdir(root_descriptor):
            if type(name) is not str or not SNAPSHOT_NAME.fullmatch(name):
                continue
            try:
                model = load_snapshot_manifest(
                    root / name,
                    release_root=root,
                    uid=uid,
                    gid=gid,
                )
            except DeploymentError as exc:
                if exc.code == "snapshot_manifest_invalid":
                    continue
                raise DeploymentError("backup_retention_failed") from exc
            managed.append((model["created_at"], model["snapshot"]))
        managed.sort()
        newest = {name for _created_at, name in managed[-keep:]} if keep else set()
        removed = []
        for _created_at, name in managed:
            if name in newest or name in protected:
                continue
            _delete_managed_snapshot(
                root,
                root_descriptor,
                root_info,
                root_chain,
                name,
                uid,
                gid,
                authority_check=authority_check,
            )
            removed.append(name)
        return tuple(removed)
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise DeploymentError("backup_retention_failed") from exc
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)


def prune_release_snapshots(release_root, *, protected_names, uid, gid, keep=5):
    """Public retention interface without application-record authority."""
    return _prune_release_snapshots(
        release_root,
        protected_names=protected_names,
        uid=uid,
        gid=gid,
        keep=keep,
    )


def _require_bound_snapshot(release_root, record, uid, gid):
    root_descriptor = -1
    snapshot_descriptor = -1
    try:
        root = _exact_absolute_path(release_root)
        root_descriptor, root_info, root_chain = _open_directory_path_chain(root)
        if not _private_directory_info(root_info, uid, gid):
            raise DeploymentError("backup_retention_failed")
        snapshot_descriptor, directory_info, _file_info, manifest_sha256, manifest = (
            _validated_snapshot_for_deletion(
                root_descriptor,
                record["snapshot"],
                uid,
                gid,
            )
        )
        if (
            manifest_sha256 != record["snapshot_manifest_sha256"]
            or manifest["git_sha"] != record["git_sha"]
            or manifest["build_id"] != record["build_id"]
            or not _same_exact_directory_path(root, root_info, root_chain)
            or not _same_directory_entry(root_descriptor, record["snapshot"], directory_info)
        ):
            raise DeploymentError("backup_retention_failed")
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise DeploymentError("backup_retention_failed") from exc
    finally:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _load_retention_authority(uid, gid):
    release_raw, release_record = _load_private_record(
        RELEASE_PATH,
        kind="release",
        uid=uid,
        gid=gid,
        required=True,
    )
    transaction_raw, release_transaction = _load_private_record(
        TRANSACTION_PATH,
        kind="transaction",
        uid=uid,
        gid=gid,
        required=False,
    )
    return RetentionAuthority(
        release_raw=release_raw,
        release_sha256=hashlib.sha256(release_raw).hexdigest(),
        release_record=release_record,
        transaction_raw=transaction_raw,
        transaction_sha256=(
            hashlib.sha256(transaction_raw).hexdigest()
            if transaction_raw is not None
            else None
        ),
        transaction_record=release_transaction,
        protected_names=protected_snapshot_names(release_record, release_transaction),
    )


def _require_unchanged_retention_authority(expected, candidate, uid, gid):
    current = _load_retention_authority(uid, gid)
    if (
        current.release_raw != expected.release_raw
        or current.release_sha256 != expected.release_sha256
        or current.transaction_raw != expected.transaction_raw
        or current.transaction_sha256 != expected.transaction_sha256
        or current.protected_names != expected.protected_names
        or candidate in current.protected_names
    ):
        raise DeploymentError("backup_retention_failed")


def enforce_release_snapshot_retention(release_root, *, current_snapshot, uid, gid):
    """Apply retention only when every authority record is strict managed v2."""
    try:
        if type(current_snapshot) is not str or not SNAPSHOT_NAME.fullmatch(current_snapshot):
            raise DeploymentError("backup_retention_failed")
        authority = _load_retention_authority(uid, gid)
        release_record = authority.release_record
        release_transaction = authority.transaction_record
        if release_record["schema"] in {RELEASE_SCHEMA_V1, EMPTY_BASELINE_SCHEMA} or (
            release_transaction is not None
            and release_transaction["schema"] == TRANSACTION_SCHEMA_V1
        ):
            return None
        _require_bound_snapshot(release_root, release_record, uid, gid)
        if release_transaction is not None:
            _require_bound_snapshot(release_root, release_transaction, uid, gid)
        _prune_release_snapshots(
            release_root,
            protected_names=authority.protected_names | {current_snapshot},
            uid=uid,
            gid=gid,
            authority_check=lambda candidate: _require_unchanged_retention_authority(
                authority,
                candidate,
                uid,
                gid,
            ),
        )
        return None
    except DeploymentError as exc:
        if exc.code == "backup_retention_failed":
            raise
        raise DeploymentError("backup_retention_failed") from exc
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise DeploymentError("backup_retention_failed") from exc


def _preflight(env_text, images, candidate_compose, candidate_env):
    _directory(APP_DIR)
    env_info = _regular_file(ENV_PATH, 1024 * 1024, 0o600)
    if os.geteuid() != env_info.st_uid:
        raise DeploymentError("release_user_required")
    _regular_file(COMPOSE_PATH, 64 * 1024)
    _regular_file(DOCKER_CONFIG, 1024 * 1024, 0o600)
    for binary in (Path(DOCKER), Path(CURL)):
        _regular_file(binary, 128 * 1024 * 1024)
    _lines, values, _indexes = _parse_env(env_text)
    parse_test_database_url(values[POLICY["database"]["url_env"]])
    if POLICY.get("redis"):
        parse_test_redis_url(values[POLICY["redis"]["url_env"]])
        if "prefix_env" in POLICY["redis"]:
            validate_test_redis_prefix(values[POLICY["redis"]["prefix_env"]])
    for service in SERVICES:
        validate_image(service, images[service])
    _run(_docker_prefix() + ["info", "--format", "{{json .ServerVersion}}"])
    for network in POLICY["networks"]:
        _run(_docker_prefix() + ["network", "inspect", network])
    for container in ([POLICY["database"]["container"]] + ([POLICY["redis"]["container"]] if POLICY.get("redis") else [])):
        running = _run(_docker_prefix() + ["inspect", "--format", "{{json .State.Running}}", container]).strip()
        health = _run(
            _docker_prefix()
            + ["inspect", "--format", "{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}", container]
        ).strip()
        if running != b"true" or health != b'"healthy"':
            raise DeploymentError("shared_infra_unhealthy")
    if POLICY.get("proxy_container"):
        proxy_running = _run(_docker_prefix() + ["inspect", "--format", "{{json .State.Running}}", POLICY["proxy_container"]]).strip()
        if proxy_running != b"true":
            raise DeploymentError("shared_proxy_unavailable")
    try:
        compose_model = json.loads(
            _compose(candidate_compose, candidate_env, ["config", "--format", "json"], images).decode(
                "utf-8", "strict"
            )
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentError("compose_contract_invalid") from exc
    runtime_values = dict(values)
    runtime_values.update(_image_environment(images))
    validate_compose_model(compose_model, images, runtime_values)
    release_compressed_bytes = _release_manifest_bytes(images)
    try:
        database_size = int(
            _run(
                _docker_prefix()
                + [
                    "exec",
                    POLICY["database"]["container"],
                    "psql", "-U", POLICY["database"]["admin_user"], "-d", POLICY["database"]["name"],
                    "-Atc", "select pg_database_size(current_database())",
                ],
                timeout=30,
                max_output=128,
            ).decode("ascii", "strict").strip()
        )
        required_bytes = required_capacity_bytes(database_size, release_compressed_bytes)
    except (UnicodeError, ValueError) as exc:
        raise DeploymentError("capacity_check_failed") from exc
    for path in (APP_DIR, Path("/var/lib/docker")):
        usage = os.statvfs(path)
        if usage.f_bavail * usage.f_frsize < required_bytes or usage.f_favail < 10_000:
            raise DeploymentError("insufficient_host_capacity")


def _validate_database_dump(destination):
    descriptor = os.open(
        destination,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > SNAPSHOT_FILE_LIMITS["database.dump"]
        ):
            raise DeploymentError("database_backup_invalid")
        _validate_database_dump_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _backup_database(destination):
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            _run(
                _docker_prefix()
                + [
                    "exec",
                    POLICY["database"]["container"],
                    "pg_dump", "-U", POLICY["database"]["admin_user"],
                    "--format=custom", "--no-owner", "--no-privileges", POLICY["database"]["name"],
                ],
                output=stream,
                timeout=300,
            )
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    _validate_database_dump(destination)
    info = _regular_file(destination, SNAPSHOT_FILE_LIMITS["database.dump"], 0o600)
    descriptor = os.open(
        destination,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return _hash_descriptor_exact(descriptor, info.st_size, "database_backup_invalid")
    finally:
        os.close(descriptor)


def _backup_database_at(directory_fd, name, uid, gid):
    descriptor = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            _run(
                _docker_prefix()
                + [
                    "exec",
                    POLICY["database"]["container"],
                    "pg_dump", "-U", POLICY["database"]["admin_user"],
                    "--format=custom", "--no-owner", "--no-privileges", POLICY["database"]["name"],
                ],
                output=stream,
                timeout=300,
            )
            stream.flush()
            os.fsync(stream.fileno())
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > SNAPSHOT_FILE_LIMITS[name]
            or not _same_file_entry(directory_fd, name, info)
        ):
            raise DeploymentError("database_backup_invalid")
        _validate_database_dump_descriptor(descriptor)
        digest = _hash_descriptor_exact(
            descriptor,
            info.st_size,
            "database_backup_invalid",
        )
        if not _same_file_entry(directory_fd, name, info):
            raise DeploymentError("database_backup_invalid")
        return digest
    finally:
        os.close(descriptor)


def validate_runtime_loopback(service, ports):
    port = POLICY["services"][service]["loopback_port"]
    expected = {str(port["target"]) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port["published"])}]}
    # Docker may include unbound image EXPOSE entries with null values.
    if type(ports) is not dict or {key: value for key, value in ports.items() if value is not None} != expected:
        raise DeploymentError("runtime_loopback_mismatch")


def _wait_for_runtime(images):
    deadline = time.monotonic() + POLICY.get("startup_timeout_seconds", 300)
    while time.monotonic() < deadline:
        ready = True
        for service in SERVICES:
            container = CONTAINERS[service]
            try:
                running = _run(
                    _docker_prefix() + ["inspect", "--format", "{{json .State.Running}}", container],
                    timeout=5,
                ).strip()
                configured_image = _run(
                    _docker_prefix() + ["inspect", "--format", "{{json .Config.Image}}", container],
                    timeout=5,
                ).decode("utf-8", "strict").strip()
                if running != b"true" or json.loads(configured_image) != images[service]:
                    ready = False
                    break
                if "loopback_port" in POLICY["services"][service]:
                    ports = _run(_docker_prefix() + ["inspect", "--format", "{{json .NetworkSettings.Ports}}", container], timeout=5)
                    validate_runtime_loopback(service, json.loads(ports.decode("utf-8", "strict")))
                if POLICY["services"][service]["healthcheck"]:
                    health = _run(
                        _docker_prefix()
                        + ["inspect", "--format", "{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}", container],
                        timeout=5,
                    ).strip()
                    if health != b'"healthy"':
                        ready = False
                        break
            except (DeploymentError, UnicodeError, json.JSONDecodeError):
                ready = False
                break
        if ready:
            return
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    raise DeploymentError("runtime_unhealthy")


def _public_curl_arguments(url, *, discard):
    arguments = [
        CURL,
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
    ]
    if discard:
        arguments.extend(("--output", "/dev/null"))
    else:
        arguments.extend(("--max-filesize", str(MAX_PUBLIC_IDENTITY_BYTES)))
    arguments.append(url)
    return arguments


def _fetch_public_release_identity(url):
    """Read curl stdout incrementally, with two independent 4 KiB limits."""
    try:
        process = subprocess.Popen(
            _public_curl_arguments(url, discard=False),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=BASE_ENV,
        )
    except OSError as exc:
        raise DeploymentError("command_failed") from exc
    chunks = []
    total = 0
    deadline = time.monotonic() + 30
    try:
        while True:
            if time.monotonic() > deadline:
                process.kill()
                raise DeploymentError("public_probe_transport")
            block = process.stdout.read(min(1024, MAX_PUBLIC_IDENTITY_BYTES - total + 1))
            if not block:
                break
            total += len(block)
            if total > MAX_PUBLIC_IDENTITY_BYTES:
                process.kill()
                raise DeploymentError("release_identity_mismatch")
            chunks.append(block)
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        process.kill()
        raise DeploymentError("public_probe_transport") from exc
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if returncode != 0:
        if returncode in RETRIABLE_CURL_EXIT_CODES:
            raise DeploymentError("public_probe_transport")
        raise DeploymentError("release_identity_mismatch")
    return b"".join(chunks)


def _probe_public_urls(git_sha, build_id):
    requests = {
        url: (service, api_envelope)
        for url, service, api_envelope in IDENTITY_PROBES
    }
    for url in PUBLIC_PROBES:
        identity = requests.get(url)
        reached = False
        for attempt in range(5):
            try:
                if identity is None:
                    _run(
                        _public_curl_arguments(url, discard=True),
                        timeout=30,
                        classify_curl_transport=True,
                    )
                else:
                    service, api_envelope = identity
                    raw = _fetch_public_release_identity(url)
                    validate_public_release_identity(
                        service, raw, git_sha, build_id, api_envelope=api_envelope
                    )
                reached = True
                break
            except DeploymentError as error:
                if error.code == "release_identity_mismatch":
                    raise
                if error.code != "public_probe_transport":
                    if identity is not None:
                        raise
                    raise DeploymentError("public_probe_failed") from error
                if attempt < 4:
                    time.sleep(3)
        if not reached:
            raise DeploymentError("public_probe_failed")
    return PUBLIC_PROBES


def _arguments(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--tat-script", required=True)
    values = parser.parse_args(argv)
    script_path = Path(values.tat_script)
    _regular_file(script_path, 64 * 1024)
    release = parse_tat_release_script(script_path.read_bytes())
    values.git_sha = release["git_sha"]
    values.build_id = release["build_id"]
    values.controller_commit = release["controller_commit"]
    return values, release["images"], _read_controller_compose()


def deploy(argv=None):
    values, images, compose_bytes = _arguments(argv)
    controller_program_digest = controller_program_sha256()
    phase = "lock"
    transaction_active = False
    transaction = None
    candidate_env = None
    candidate_compose = None
    lock_descriptor = os.open(
        LOCK_PATH,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if not stat.S_ISREG(os.fstat(lock_descriptor).st_mode):
            raise DeploymentError("release_lock_invalid")
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentError("release_busy") from exc
        _assert_release_unblocked()

        phase = "preflight"
        env_info = _regular_file(ENV_PATH, 1024 * 1024, 0o600)
        compose_info = _regular_file(COMPOSE_PATH, 64 * 1024)
        env_bytes = ENV_PATH.read_bytes()
        compose_before = COMPOSE_PATH.read_bytes()
        try:
            env_text = env_bytes.decode("utf-8", "strict")
            candidate_env_bytes = update_env_text(env_text, images).encode("utf-8")
        except (UnicodeError, ValueError, KeyError) as exc:
            raise DeploymentError("environment_contract_invalid") from exc
        token = hashlib.sha256(values.build_id.encode("ascii")).hexdigest()[:16]
        candidate_env = APP_DIR / f".env.candidate.{token}"
        candidate_compose = APP_DIR / f".docker-compose.candidate.{token}.yml"
        for path in (candidate_env, candidate_compose):
            if path.exists() or path.is_symlink():
                raise DeploymentError("candidate_path_exists")
        _write_new(candidate_env, candidate_env_bytes, 0o600, env_info.st_uid, env_info.st_gid)
        _write_new(candidate_compose, compose_bytes, 0o600, compose_info.st_uid, compose_info.st_gid)
        _preflight(env_text, images, candidate_compose, candidate_env)
        _assert_empty_baseline_runtime(env_bytes, env_info.st_uid, env_info.st_gid)
        phase = "pull"
        _compose(candidate_compose, candidate_env, ["pull", *SERVICES], images, timeout=600)

        phase = "backup"
        backup_root = APP_DIR / "backups"
        if not backup_root.exists():
            _safe_mkdir(backup_root, 0o700, env_info.st_uid, env_info.st_gid)
        else:
            _require_private_directory(backup_root, env_info.st_uid, env_info.st_gid)
        release_root = backup_root / "releases"
        if not release_root.exists():
            _safe_mkdir(release_root, 0o700, env_info.st_uid, env_info.st_gid)
        else:
            _require_private_directory(release_root, env_info.st_uid, env_info.st_gid)
        snapshot_ref = create_release_snapshot(
            release_root,
            env_bytes=env_bytes,
            compose_bytes=compose_before,
            git_sha=values.git_sha,
            build_id=values.build_id,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            uid=env_info.st_uid,
            gid=env_info.st_gid,
        )
        snapshot = release_root / snapshot_ref.name
        snapshot_manifest = load_snapshot_manifest(
            snapshot,
            release_root=release_root,
            uid=env_info.st_uid,
            gid=env_info.st_gid,
        )
        database_sha256 = snapshot_manifest["files"]["database.dump"]["sha256"]
        previous_release_raw_before, _previous_release_before = _load_private_record(
            RELEASE_PATH,
            kind="release",
            uid=env_info.st_uid,
            gid=env_info.st_gid,
            required=True,
        )
        enforce_release_snapshot_retention(
            release_root,
            current_snapshot=snapshot_ref.name,
            uid=env_info.st_uid,
            gid=env_info.st_gid,
        )
        previous_release_raw, previous_release = _load_private_record(
            RELEASE_PATH,
            kind="release",
            uid=env_info.st_uid,
            gid=env_info.st_gid,
            required=True,
        )
        if previous_release_raw != previous_release_raw_before:
            raise DeploymentError("backup_retention_failed")

        transaction = {
            "schema": TRANSACTION_SCHEMA_V2,
            "status": "active",
            "phase": "prepared",
            "controller": CONTROLLER_ID,
            "controller_program_sha256": controller_program_digest,
            "controller_compose_sha256": CONTROLLER_COMPOSE_SHA256,
            "git_sha": values.git_sha,
            "build_id": values.build_id,
            "images": images,
            "previous_images": previous_release["images"],
            "previous_release_sha256": hashlib.sha256(previous_release_raw).hexdigest(),
            "snapshot": snapshot_ref.name,
            "snapshot_manifest_sha256": snapshot_ref.manifest_sha256,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        transaction_bytes = (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _write_new(
            TRANSACTION_PATH,
            transaction_bytes,
            0o600,
            env_info.st_uid,
            env_info.st_gid,
        )
        transaction_active = True

        phase = "migrate"
        transaction["phase"] = "migrating"
        transaction["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _atomic_write(
            TRANSACTION_PATH,
            (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600,
            env_info.st_uid,
            env_info.st_gid,
        )
        if POLICY["migration"] is not None:
            _compose(
                candidate_compose, candidate_env,
                ["run", "--rm", "--no-deps", POLICY["migration"]["service"], *POLICY["migration"]["argv"]],
                images, timeout=600,
            )
        transaction["phase"] = "migration_complete"
        transaction["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _atomic_write(
            TRANSACTION_PATH,
            (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600,
            env_info.st_uid,
            env_info.st_gid,
        )

        phase = "install"
        transaction["phase"] = "installing_runtime_config"
        transaction["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _atomic_write(
            TRANSACTION_PATH,
            (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600,
            env_info.st_uid,
            env_info.st_gid,
        )
        _atomic_write(COMPOSE_PATH, compose_bytes, 0o644, compose_info.st_uid, compose_info.st_gid)
        _atomic_write(ENV_PATH, candidate_env_bytes, 0o600, env_info.st_uid, env_info.st_gid)

        phase = "up"
        transaction["phase"] = "starting_runtime"
        transaction["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        _atomic_write(
            TRANSACTION_PATH,
            (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            0o600,
            env_info.st_uid,
            env_info.st_gid,
        )
        _compose(COMPOSE_PATH, ENV_PATH, ["up", "-d", *SERVICES], images, timeout=600)

        phase = "runtime"
        _wait_for_runtime(images)

        phase = "probe"
        _probe_public_urls(values.git_sha, values.build_id)

        phase = "record"
        record = {
            "schema": RELEASE_SCHEMA_V2,
            "status": "passed",
            "controller": CONTROLLER_ID,
            "controller_program_sha256": controller_program_digest,
            "controller_compose_sha256": CONTROLLER_COMPOSE_SHA256,
            "git_sha": values.git_sha,
            "build_id": values.build_id,
            "images": images,
            "snapshot": snapshot_ref.name,
            "snapshot_manifest_sha256": snapshot_ref.manifest_sha256,
            "deployed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "probes": list(PUBLIC_PROBES),
        }
        record_bytes = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _atomic_write(RELEASE_PATH, record_bytes, 0o600, env_info.st_uid, env_info.st_gid)
        TRANSACTION_PATH.unlink()
        _fsync_directory(APP_DIR)
        transaction_active = False
        result = {
            "schema": "cnb-deploy-result/v1", "status": "passed",
            "project": POLICY["project"], "environment": POLICY["environment"],
            "controller": CONTROLLER_ID, "git_sha": values.git_sha,
            "controller_commit": values.controller_commit, "build_id": values.build_id,
            "images": images, "controller_program_sha256": controller_program_digest,
            "controller_compose_sha256": CONTROLLER_COMPOSE_SHA256, "policy_sha256": POLICY_SHA256,
            "database_backup_sha256": database_sha256, "container_count": len(SERVICES),
            "probe_count": len(PUBLIC_PROBES), "probes": list(PUBLIC_PROBES),
        }
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except DeploymentError as exc:
        if transaction_active and transaction is not None:
            try:
                transaction["status"] = "failed"
                transaction["phase"] = phase
                transaction["reason"] = exc.code
                transaction["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                _atomic_write(
                    TRANSACTION_PATH,
                    (json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
                    0o600,
                    env_info.st_uid,
                    env_info.st_gid,
                )
            except Exception:
                pass
        result = {
            "schema": "cnb-deploy-result/v1",
            "status": "failed",
            "phase": phase,
            "reason": exc.code,
        }
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        return 1
    finally:
        for path in (candidate_env, candidate_compose):
            if path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
        os.close(lock_descriptor)


if __name__ == "__main__":
    try:
        install_policy()
        raise SystemExit(deploy())
    except (DeploymentError, ValueError, OSError):
        sys.stdout.write(
            '{"phase":"bootstrap","reason":"deployment_failed","schema":"cnb-deploy-result/v1","status":"failed"}\n'
        )
        raise SystemExit(1)
