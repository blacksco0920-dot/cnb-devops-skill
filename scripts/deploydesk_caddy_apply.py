#!/usr/bin/python3
"""Reference normal-release helper for shared-caddy-contract/v1.

The public CLI intentionally accepts only a deployment identity and an already
installed bundle identity.  All paths and commands are derived from a trusted
server contract.  Library injection exists for deterministic local tests; the
CLI always uses the fixed host layout, root ownership and fixed executables.
"""

import argparse
import contextlib
import errno
import fcntl
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


CONTRACT_VERSION = "shared-caddy-contract/v1"
HELPER_VERSION = "1.0.0"
ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ENVIRONMENT_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
DEPLOYMENT_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?--"
    r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SAFE_RUNTIME_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
SAFE_PROXY_HOST_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
HOSTNAME_PATTERN = (
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
SOURCE_REPO_RE = re.compile(
    r"https://(?=[^/]{1,253}/)" + HOSTNAME_PATTERN + r"(?:/[A-Za-z0-9._~-]+)+"
)
CONFIG_ROOT_RE = re.compile(r"/(?:[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+)*")
ARCHIVE_FILES = (
    "caddy/declaration.json", "caddy/site.caddy",
    "caddy/helper-requirement.json", "caddy/bundle-provenance.json",
    "runtime/compose.json",
)
SNAPSHOT_FILES = ("deploy-bundle.tar.gz", "server-manifest.json")
MAX_ARCHIVE_MEMBERS = len(ARCHIVE_FILES)
MAX_ARCHIVE_MEMBER_SIZE = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 16 * 1024 * 1024
MAX_ARCHIVE_STREAM_SIZE = MAX_ARCHIVE_TOTAL_SIZE + 64 * 1024
MAX_ARCHIVE_COMPRESSED_SIZE = 8 * 1024 * 1024


class ContractError(RuntimeError):
    pass


class SecurityError(ContractError):
    pass


class AttestationError(SecurityError):
    pass


class OwnershipError(ContractError):
    pass


class MaintenanceRequired(OwnershipError):
    pass


class TransactionError(RuntimeError):
    pass


class RecoveryRequired(TransactionError):
    pass


class Layout:
    def __init__(self, root, infra_root, state_root, lock_root, bundle_root, helper_path):
        self.root = Path(root)
        self.infra_root = Path(infra_root)
        self.state_root = Path(state_root)
        self.lock_root = Path(lock_root)
        self.bundle_root = Path(bundle_root)
        self.helper_path = Path(helper_path)

    @classmethod
    def for_host(cls):
        return cls(
            Path("/"),
            Path("/opt/infra/caddy"),
            Path("/var/lib/deploydesk/caddy"),
            Path("/var/lib/deploydesk/locks"),
            Path("/var/lib/deploydesk/bundles"),
            Path("/usr/local/sbin/deploydesk-caddy-apply"),
        )

    @classmethod
    def for_test_root(cls, root):
        root = Path(root)
        return cls(
            root,
            root / "opt" / "infra" / "caddy",
            root / "var" / "lib" / "deploydesk" / "caddy",
            root / "var" / "lib" / "deploydesk" / "locks",
            root / "var" / "lib" / "deploydesk" / "bundles",
            root / "usr" / "local" / "sbin" / "deploydesk-caddy-apply",
        )

    @property
    def managed_root(self):
        return self.infra_root / "managed"

    @property
    def generations_root(self):
        return self.managed_root / "generations"

    @property
    def current_link(self):
        return self.managed_root / "current"

    @property
    def contract_path(self):
        return self.infra_root / "contract.json"

    @property
    def transaction_path(self):
        return self.state_root / "transaction.json"

    @property
    def history_path(self):
        return self.state_root / "history.jsonl"

    @property
    def recovery_marker(self):
        return self.state_root / "caddy-recovery-required"

    @property
    def bootstrap_attestation_path(self):
        return self.infra_root / "bootstrap-attestation.json"

    @property
    def maintenance_transaction_path(self):
        return self.state_root / "maintenance-transaction.json"

    @property
    def maintenance_recovery_marker(self):
        return self.state_root / "maintenance-recovery-required"

    @property
    def maintenance_root(self):
        return self.state_root / "maintenance"

    @property
    def intake_root(self):
        return self.state_root / "intake"

    @property
    def receipts_root(self):
        return self.state_root / "receipts"

    @property
    def shared_lock(self):
        return self.lock_root / "shared-caddy.lock"

    @property
    def lock_manifest_path(self):
        return self.state_root / "lock-inodes.json"

    def project_lock(self, deployment_id):
        validate_deployment_id(deployment_id)
        return self.lock_root / "projects" / (deployment_id + ".caddy.lock")

    def release_lock(self, deployment_id):
        validate_deployment_id(deployment_id)
        return self.lock_root / "releases" / (deployment_id + ".release.lock")

    def bundle_dir(self, deployment_id, bundle_id):
        validate_deployment_id(deployment_id)
        validate_bundle_id(bundle_id)
        return self.bundle_root / deployment_id / bundle_id

    def receipt_path(self, transaction_id):
        if not re.fullmatch(r"tx-[0-9a-f]{32}", transaction_id):
            raise ContractError("invalid transaction id")
        return self.receipts_root / (transaction_id + ".json")

    def current_generation(self):
        target = os.readlink(self.current_link)
        if not re.fullmatch(r"generations/gen-[0-9a-f]{32}", target):
            raise SecurityError("managed/current target is outside generations")
        resolved = self.managed_root / target
        if not resolved.is_dir() or resolved.is_symlink():
            raise SecurityError("managed/current target is not a real generation")
        return resolved


class TrustPolicy:
    def __init__(self, owner_uid=0):
        self.owner_uid = owner_uid


def validate_deployment_id(value):
    if not isinstance(value, str) or not DEPLOYMENT_RE.fullmatch(value):
        raise ContractError("deployment-id must be normalized <project>--<environment>")
    return value


def validate_bundle_id(value):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractError("bundle-id must be 64 lowercase hexadecimal characters")
    return value


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "ctime_ns": info.st_ctime_ns,
    }


def _validate_lock_manifest(value):
    if set(value) != {"schema_version", "shared", "deployments"}:
        raise SecurityError("lock inode manifest fields are not exact")
    if (
        value["schema_version"] != "shared-caddy-lock-inodes/v1"
        or not isinstance(value["deployments"], dict)
    ):
        raise SecurityError("unknown or malformed lock inode manifest")
    identities = [value["shared"]]
    for deployment_id, deployment in value["deployments"].items():
        try:
            validate_deployment_id(deployment_id)
        except ContractError as exc:
            raise SecurityError("malformed deployment lock evidence") from exc
        if not isinstance(deployment, dict) or set(deployment) != {"project", "release"}:
            raise SecurityError("malformed deployment lock evidence")
        identities.extend((deployment["project"], deployment["release"]))
    for identity in identities:
        if (
            not isinstance(identity, dict)
            or set(identity) != {"device", "inode", "ctime_ns"}
            or not all(
                isinstance(identity[field], int)
                and not isinstance(identity[field], bool)
                and identity[field] >= 0
                for field in identity
            )
        ):
            raise SecurityError("malformed lock inode identity")
    return value


def read_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("invalid JSON: " + str(path)) from exc
    if not isinstance(value, dict):
        raise ContractError("JSON document must be an object: " + str(path))
    return value


def _lexists(path):
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def _json_type_matches(expected, value):
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate_json_schema_instance(schema, value, location="$", root_schema=None):
    """Validate the strict JSON-Schema subset used by this package."""
    if root_schema is None:
        root_schema = schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ContractError("unsupported external schema reference")
        target = root_schema["$defs"][ref.rsplit("/", 1)[1]]
        return validate_json_schema_instance(target, value, location, root_schema)
    if "const" in schema and value != schema["const"]:
        raise ContractError(location + " does not match const")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(location + " is not an allowed value")
    expected_type = schema.get("type")
    if expected_type:
        choices = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_json_type_matches(item, value) for item in choices):
            raise ContractError(location + " has wrong JSON type")
    if "oneOf" in schema:
        matches = 0
        for candidate in schema["oneOf"]:
            try:
                validate_json_schema_instance(candidate, value, location, root_schema)
                matches += 1
            except ContractError:
                pass
        if matches != 1:
            raise ContractError(location + " must match exactly one schema branch")
    for candidate in schema.get("allOf", []):
        validate_json_schema_instance(candidate, value, location, root_schema)
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise ContractError(location + " missing: " + ", ".join(missing))
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                raise ContractError(location + " unknown fields: " + ", ".join(sorted(unknown)))
        for key, child in value.items():
            if key in properties:
                validate_json_schema_instance(properties[key], child, location + "." + key, root_schema)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractError(location + " has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractError(location + " has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                raise ContractError(location + " contains duplicate items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_json_schema_instance(schema["items"], item, location + "[" + str(index) + "]", root_schema)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ContractError(location + " is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ContractError(location + " is too long")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ContractError(location + " does not match pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractError(location + " is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractError(location + " is above maximum")


def normalize_hostname(value):
    if not isinstance(value, str) or not value or value.startswith("*") or value.startswith(":"):
        raise ContractError("wildcard, catch-all and bare-listener hosts are forbidden")
    candidate = value[:-1] if value.endswith(".") else value
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ContractError("hostname is not valid IDNA") from exc
    if len(normalized) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in normalized.split(".")
    ):
        raise ContractError("invalid hostname")
    return normalized


def _normalize_hostname_for_display(value):
    candidate = value[:-1] if value.endswith(".") else value
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ContractError("hostname is not valid IDNA") from exc
    if len(normalized) > 253 or not normalized:
        raise ContractError("invalid hostname")
    return normalized


def _validate_source_repo(value):
    if not isinstance(value, str) or not SOURCE_REPO_RE.fullmatch(value):
        raise ContractError("source_repo must be a normalized credential-free HTTPS repository URL")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.netloc != parsed.hostname
        or parsed.query or parsed.fragment or parsed.path.endswith("/")
        or any(part in ("", ".", "..") for part in parsed.path.split("/")[1:])
    ):
        raise ContractError("source_repo must be normalized")
    return value


def validate_declaration(value):
    allowed = {
        "contract_version", "project_id", "environment", "deployment_id",
        "source_repo", "compose_path", "routes",
    }
    if not isinstance(value, dict) or set(value) != allowed:
        raise ContractError("declaration has missing or unknown fields")
    if value["contract_version"] != CONTRACT_VERSION:
        raise ContractError("unsupported contract version")
    if not ID_RE.fullmatch(value["project_id"] or "") or not ENVIRONMENT_RE.fullmatch(value["environment"] or ""):
        raise ContractError("project_id and environment must be normalized")
    expected = value["project_id"] + "--" + value["environment"]
    validate_deployment_id(value["deployment_id"])
    if value["deployment_id"] != expected:
        raise ContractError("deployment identity fields disagree")
    _validate_source_repo(value["source_repo"])
    if value["compose_path"] != "runtime/compose.json":
        raise ContractError("compose_path is fixed by v1")
    if not isinstance(value["routes"], list) or not value["routes"]:
        raise ContractError("routes must be a non-empty array")
    hosts = []
    for route in value["routes"]:
        if not isinstance(route, dict):
            raise ContractError("route must be an object")
        route_type = route.get("type")
        common = {"type", "host"}
        if route_type == "docker_proxy":
            expected_keys = common | {"service", "upstream", "port", "network"}
            if set(route) != expected_keys:
                raise ContractError("docker_proxy route fields are not exact")
            for key in ("service", "network"):
                if not SAFE_RUNTIME_NAME_RE.fullmatch(str(route[key])):
                    raise ContractError("unsafe docker route identifier")
            if (
                not SAFE_PROXY_HOST_RE.fullmatch(str(route["upstream"]))
                or len(route["upstream"]) > 253
            ):
                raise ContractError("unsafe docker proxy host")
            if not isinstance(route["port"], int) or isinstance(route["port"], bool) or not 1 <= route["port"] <= 65535:
                raise ContractError("invalid upstream port")
        elif route_type == "https_proxy":
            if set(route) != common | {"target_host"}:
                raise ContractError("https_proxy route fields are not exact")
            normalize_hostname(route["target_host"])
        elif route_type == "redirect":
            if set(route) != common | {"target_host", "preserve_uri", "redirect_code"}:
                raise ContractError("redirect route fields are not exact")
            normalize_hostname(route["target_host"])
            if route["preserve_uri"] is not True or route["redirect_code"] not in (301, 308):
                raise ContractError("v1 redirects preserve URI and are permanent")
        else:
            raise ContractError("unsupported route type")
        normalized_host = normalize_hostname(route["host"])
        if route["host"] != normalized_host:
            raise ContractError("hostname must already be normalized IDNA ASCII")
        hosts.append(normalized_host)
    if len(hosts) != len(set(hosts)):
        raise ContractError("duplicate normalized hostname")
    owned = set(hosts)
    for route in value["routes"]:
        if route["type"] in ("https_proxy", "redirect") and route["target_host"] not in owned:
            raise ContractError("proxy/redirect target must be owned by the same deployment")
    return value


def render_fragment(declaration):
    validate_declaration(declaration)
    blocks = []
    for route in declaration["routes"]:
        host = route["host"]
        if route["type"] == "docker_proxy":
            blocks.append(
                f"{host} {{\n"
                "    encode zstd gzip\n"
                f"    reverse_proxy {route['upstream']}:{route['port']}\n"
                "}"
            )
        elif route["type"] == "https_proxy":
            target = route["target_host"]
            blocks.append(
                f"{host} {{\n"
                "    encode zstd gzip\n"
                f"    reverse_proxy https://{target} {{\n"
                f"        header_up Host {target}\n"
                "        transport http {\n"
                f"            tls_server_name {target}\n"
                "        }\n"
                "    }\n"
                "}"
            )
        else:
            target = route["target_host"]
            blocks.append(
                f"{host} {{\n"
                f"    redir https://{target}{{uri}} {route['redirect_code']}\n"
                "}"
            )
    return "\n\n".join(blocks) + "\n"


def reconcile_fragment(declaration, fragment_bytes):
    try:
        actual = fragment_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise ContractError("fragment must be UTF-8") from exc
    expected = render_fragment(declaration)
    if actual != expected:
        raise ContractError("fragment is not the canonical declaration-derived v1 fragment")


def reconcile_compose(declaration, compose):
    if not isinstance(compose, dict) or set(compose) != {"services", "networks"}:
        raise ContractError("Compose facts must contain only services and networks")
    services = compose["services"]
    networks = compose["networks"]
    if not isinstance(services, dict) or not isinstance(networks, dict):
        raise ContractError("invalid Compose facts")
    for route in declaration["routes"]:
        if route["type"] != "docker_proxy":
            continue
        service = services.get(route["service"])
        if not isinstance(service, dict):
            raise ContractError("declared Compose service is missing")
        if route["network"] not in networks:
            raise ContractError("declared shared Docker network is missing")
        attached = service.get("networks", {})
        if route["network"] not in attached:
            raise ContractError("service is not attached to its declared network")
        aliases = attached[route["network"]].get("aliases", []) if isinstance(attached[route["network"]], dict) else []
        labels = service.get("labels", {})
        if not isinstance(labels, dict) or labels.get("com.deploydesk.deployment-id") != declaration["deployment_id"]:
            raise ContractError("Compose service lacks matching deployment ownership label")
        if service.get("container_name") != route["upstream"] or route["upstream"] not in aliases:
            raise ContractError("upstream is not derived from the declared Compose service")
        exposed = set()
        for item in service.get("expose", []):
            exposed.add(int(str(item).split("/", 1)[0]))
        for item in service.get("ports", []):
            if isinstance(item, str):
                exposed.add(int(item.split(":")[-1].split("/", 1)[0]))
            elif isinstance(item, dict) and "target" in item:
                exposed.add(int(item["target"]))
        if route["port"] not in exposed:
            raise ContractError("declared upstream port is absent from Compose")


def _ensure_exact_keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ContractError(name + " has missing or unknown fields")


def validate_requirement(value):
    _ensure_exact_keys(value, ("contract_version", "helper_version", "helper_sha256"), "helper requirement")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise AttestationError("helper requirement version mismatch")
    if not SHA256_RE.fullmatch(str(value["helper_sha256"])):
        raise ContractError("invalid required helper hash")


def validate_server_contract(value):
    _ensure_exact_keys(
        value,
        ("contract_version", "helper_version", "helper_sha256", "caddy_container", "container_config_root"),
        "server contract",
    )
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise AttestationError("server contract version mismatch")
    if not SHA256_RE.fullmatch(str(value["helper_sha256"])):
        raise ContractError("invalid server helper hash")
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(value["caddy_container"])):
        raise ContractError("invalid fixed Caddy container name")
    if not isinstance(value["container_config_root"], str) or not CONFIG_ROOT_RE.fullmatch(value["container_config_root"]):
        raise ContractError("invalid container config root")
    return value


def validate_bootstrap_attestation(value):
    expected = (
        "schema_version", "contract_version", "caddy_container", "container_config_root",
        "initial_generation", "initial_current_target", "root_config_sha256",
        "server_options_sha256", "shared_lock_device", "shared_lock_inode",
        "shared_lock_ctime_ns",
    )
    _ensure_exact_keys(value, expected, "bootstrap attestation")
    if value["schema_version"] != "shared-caddy-host-bootstrap/v1" or value["contract_version"] != CONTRACT_VERSION:
        raise AttestationError("bootstrap attestation version mismatch")
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(value["caddy_container"])):
        raise ContractError("invalid bootstrap Caddy container")
    if not isinstance(value["container_config_root"], str) or not CONFIG_ROOT_RE.fullmatch(value["container_config_root"]):
        raise ContractError("invalid bootstrap container config root")
    if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value["initial_generation"])):
        raise ContractError("invalid bootstrap generation")
    if value["initial_current_target"] != "generations/" + value["initial_generation"]:
        raise ContractError("bootstrap current target evidence disagrees")
    for field in ("root_config_sha256", "server_options_sha256"):
        if not SHA256_RE.fullmatch(str(value[field])):
            raise ContractError("invalid bootstrap hash")
    for field in ("shared_lock_device", "shared_lock_inode", "shared_lock_ctime_ns"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0:
            raise ContractError("invalid bootstrap lock identity")
    return value


def validate_internal_provenance(value):
    expected = (
        "schema_version", "contract_version", "helper_version", "helper_sha256",
        "project_id", "environment", "deployment_id", "source_repo", "hosts", "git_sha",
        "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "source",
    )
    _ensure_exact_keys(value, expected, "internal bundle provenance")
    if value["schema_version"] != "shared-caddy-bundle-provenance/v1":
        raise ContractError("internal provenance schema mismatch")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise AttestationError("internal provenance controller mismatch")
    if not ID_RE.fullmatch(str(value["project_id"])) or not ENVIRONMENT_RE.fullmatch(str(value["environment"])):
        raise ContractError("internal provenance identity is not normalized")
    if value["deployment_id"] != value["project_id"] + "--" + value["environment"]:
        raise ContractError("internal provenance identity fields disagree")
    validate_deployment_id(value["deployment_id"])
    _validate_source_repo(value["source_repo"])
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid internal provenance Git SHA")
    for field in (
        "helper_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256",
    ):
        if not SHA256_RE.fullmatch(str(value[field])):
            raise ContractError("invalid internal provenance hash: " + field)
    if not isinstance(value["hosts"], list) or not value["hosts"]:
        raise ContractError("internal provenance hosts must be non-empty")
    normalized = [normalize_hostname(host) for host in value["hosts"]]
    if normalized != value["hosts"] or len(normalized) != len(set(normalized)):
        raise ContractError("internal provenance hosts must be unique and normalized")
    if value["source"] != {"kind": "bundle"}:
        raise ContractError("internal provenance source must be exact bundle evidence")
    return value


def validate_manifest(value):
    expected = (
        "schema_version", "contract_version", "project_id", "environment",
        "deployment_id", "source_repo", "hosts", "git_sha",
        "deploy_bundle_sha256", "declaration_sha256", "fragment_sha256",
        "compose_sha256", "helper_requirement_sha256", "internal_provenance_sha256",
        "helper_version", "helper_sha256", "source",
    )
    _ensure_exact_keys(value, expected, "server manifest")
    if value["schema_version"] != "shared-caddy-server-manifest/v1" or value["contract_version"] != CONTRACT_VERSION:
        raise ContractError("server manifest version mismatch")
    if (
        not ID_RE.fullmatch(str(value["project_id"]))
        or not ENVIRONMENT_RE.fullmatch(str(value["environment"]))
        or value["deployment_id"] != value["project_id"] + "--" + value["environment"]
    ):
        raise ContractError("server manifest identity fields disagree")
    validate_deployment_id(value["deployment_id"])
    _validate_source_repo(value["source_repo"])
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid git SHA")
    for field in (
        "deploy_bundle_sha256", "declaration_sha256", "fragment_sha256",
        "compose_sha256", "helper_requirement_sha256", "internal_provenance_sha256",
        "helper_sha256",
    ):
        if not SHA256_RE.fullmatch(str(value[field])):
            raise ContractError("invalid manifest hash: " + field)
    if not isinstance(value["hosts"], list) or not value["hosts"]:
        raise ContractError("manifest hosts must be non-empty")
    normalized = [normalize_hostname(host) for host in value["hosts"]]
    if normalized != value["hosts"] or len(normalized) != len(set(normalized)):
        raise ContractError("manifest hosts must be unique and normalized")
    if value["helper_version"] != HELPER_VERSION:
        raise AttestationError("server manifest helper version mismatch")
    source = value["source"]
    if not isinstance(source, dict) or source.get("kind") not in ("bundle", "baseline_import", "legacy_opaque"):
        raise ContractError("invalid manifest source")
    if source["kind"] == "legacy_opaque":
        _ensure_exact_keys(source, ("kind", "legacy_fragment_sha256"), "legacy source")
        if not SHA256_RE.fullmatch(str(source["legacy_fragment_sha256"])):
            raise ContractError("invalid legacy fragment hash")
    else:
        _ensure_exact_keys(source, ("kind",), "manifest source")


def validate_transaction(value):
    expected = (
        "schema_version", "phase", "contract_version", "helper_version",
        "helper_sha256", "transaction_id", "deployment_id", "bundle_id",
        "project_id", "environment", "source_repo", "git_sha",
        "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "internal_provenance_sha256",
        "old_generation", "new_generation", "hosts", "network_attachment_intents",
    )
    _ensure_exact_keys(value, expected, "transaction")
    if value["schema_version"] != "shared-caddy-transaction/v1":
        raise RecoveryRequired("unknown transaction schema")
    if value["phase"] not in ("prepared", "current-switched", "reloaded", "verified", "committed"):
        raise RecoveryRequired("unknown transaction phase")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise RecoveryRequired("transaction controller version drift")
    if not re.fullmatch(r"tx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise RecoveryRequired("invalid transaction identity")
    validate_deployment_id(value["deployment_id"])
    if (
        not ID_RE.fullmatch(str(value["project_id"]))
        or not ENVIRONMENT_RE.fullmatch(str(value["environment"]))
        or value["deployment_id"] != value["project_id"] + "--" + value["environment"]
    ):
        raise RecoveryRequired("transaction identity fields disagree")
    _validate_source_repo(value["source_repo"])
    validate_bundle_id(value["bundle_id"])
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise RecoveryRequired("invalid transaction Git SHA")
    for field in (
        "helper_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "internal_provenance_sha256",
    ):
        if not SHA256_RE.fullmatch(str(value[field])):
            raise RecoveryRequired("invalid transaction evidence hash")
    for field in ("old_generation", "new_generation"):
        if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value[field])):
            raise RecoveryRequired("invalid transaction generation identity")
    if value["old_generation"] == value["new_generation"]:
        raise RecoveryRequired("transaction generations must differ")
    if not isinstance(value["hosts"], list) or not value["hosts"]:
        raise RecoveryRequired("invalid transaction hosts")
    normalized_hosts = [normalize_hostname(host) for host in value["hosts"]]
    if normalized_hosts != value["hosts"] or len(normalized_hosts) != len(set(normalized_hosts)):
        raise RecoveryRequired("transaction hosts must be unique and normalized")
    if not isinstance(value["network_attachment_intents"], list):
        raise RecoveryRequired("invalid transaction network attachment intents")
    intent_networks = []
    for intent in value["network_attachment_intents"]:
        if not isinstance(intent, dict) or set(intent) != {"network", "pre_transaction_state"}:
            raise RecoveryRequired("invalid transaction network attachment intent")
        if intent["pre_transaction_state"] != "absent":
            raise RecoveryRequired("network attachment intent did not record absent pre-state")
        network = intent["network"]
        if not SAFE_RUNTIME_NAME_RE.fullmatch(str(network)):
            raise RecoveryRequired("unsafe transaction network attachment intent")
        intent_networks.append(network)
    if len(intent_networks) != len(set(intent_networks)):
        raise RecoveryRequired("duplicate transaction network attachment intent")


def validate_receipt(value):
    expected = (
        "schema_version", "status", "contract_version", "helper_version",
        "helper_sha256", "transaction_id", "deployment_id", "bundle_id",
        "project_id", "environment", "source_repo", "git_sha",
        "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "internal_provenance_sha256",
        "old_generation", "generation_id", "hosts",
    )
    _ensure_exact_keys(value, expected, "receipt")
    if value["schema_version"] != "shared-caddy-receipt/v1" or value["status"] != "committed":
        raise RecoveryRequired("invalid receipt status/schema")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise RecoveryRequired("receipt controller drift")
    if not re.fullmatch(r"tx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise RecoveryRequired("invalid receipt transaction identity")
    validate_deployment_id(value["deployment_id"])
    if (
        not ID_RE.fullmatch(str(value["project_id"]))
        or not ENVIRONMENT_RE.fullmatch(str(value["environment"]))
        or value["deployment_id"] != value["project_id"] + "--" + value["environment"]
    ):
        raise RecoveryRequired("receipt identity fields disagree")
    _validate_source_repo(value["source_repo"])
    validate_bundle_id(value["bundle_id"])
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise RecoveryRequired("invalid receipt Git SHA")
    for field in (
        "helper_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "internal_provenance_sha256",
    ):
        if not SHA256_RE.fullmatch(str(value[field])):
            raise RecoveryRequired("invalid receipt hash")
    for field in ("old_generation", "generation_id"):
        if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value[field])):
            raise RecoveryRequired("invalid receipt generation")
    if value["old_generation"] == value["generation_id"]:
        raise RecoveryRequired("receipt generations must differ")
    if not isinstance(value["hosts"], list) or not value["hosts"]:
        raise RecoveryRequired("invalid receipt hosts")
    normalized_hosts = [normalize_hostname(host) for host in value["hosts"]]
    if normalized_hosts != value["hosts"] or len(normalized_hosts) != len(set(normalized_hosts)):
        raise RecoveryRequired("receipt hosts must be unique and normalized")


def _atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _atomic_json(path, value, mode=0o600):
    _atomic_write(path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(), mode)


def _fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_trusted(path, trust, kind, allow_symlink=False):
    path = Path(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        if allow_symlink:
            return info
        raise SecurityError("unexpected symlink: " + str(path))
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise SecurityError("trusted path is not a directory: " + str(path))
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise SecurityError("trusted path is not a regular file: " + str(path))
    if info.st_uid != trust.owner_uid:
        raise SecurityError("trusted path has wrong owner: " + str(path))
    if info.st_mode & 0o022:
        raise SecurityError("trusted path is group/other writable: " + str(path))
    if kind == "file" and info.st_nlink != 1:
        raise SecurityError("trusted file link count is not one: " + str(path))
    return info


def _verify_trusted_chain(path, root, trust, final_kind):
    path = Path(path)
    root = Path(root)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise SecurityError("trusted path escapes configured root") from exc
    current = root
    anchor_device = None
    if current == Path("/"):
        _verify_trusted(current, trust, "directory")
    for index, component in enumerate(relative.parts):
        current = current / component
        kind = final_kind if index == len(relative.parts) - 1 else "directory"
        info = _verify_trusted(current, trust, kind)
        if anchor_device is None:
            anchor_device = info.st_dev
        elif info.st_dev != anchor_device:
            raise SecurityError("trusted path crosses a device boundary: " + str(current))
    return current


def _open_fixed_lock(path, trust):
    before = _verify_trusted(path, trust, "file")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    after = os.fstat(descriptor)
    if _lock_identity(before) != _lock_identity(after):
        os.close(descriptor)
        raise SecurityError("lock identity changed while opening")
    return descriptor


@contextlib.contextmanager
def _locked(path, trust):
    descriptor = _open_fixed_lock(path, trust)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.lstat(path)
        opened = os.fstat(descriptor)
        if _lock_identity(current) != _lock_identity(opened):
            raise SecurityError("lock identity was replaced")
        yield descriptor
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _require_lock_held_elsewhere(path, trust):
    descriptor = _open_fixed_lock(path, trust)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            raise SecurityError("application release lock is not held by the caller")
    finally:
        os.close(descriptor)


def _safe_open_relative(anchor, relative):
    if not hasattr(os, "O_NOFOLLOW") or os.open not in getattr(os, "supports_dir_fd", set()):
        raise SecurityError("platform lacks required no-follow dirfd support")
    parts = relative.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise SecurityError("unsafe fixed bundle path")
    anchor_fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    opened = [anchor_fd]
    try:
        anchor_stat = os.fstat(anchor_fd)
        current = anchor_fd
        for part in parts[:-1]:
            try:
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            except OSError as exc:
                raise SecurityError("bundle parent failed beneath/no-follow open") from exc
            opened.append(descriptor)
            info = os.fstat(descriptor)
            if info.st_dev != anchor_stat.st_dev:
                raise SecurityError("bundle traversal crossed a mount boundary")
            current = descriptor
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        except OSError as exc:
            raise SecurityError("bundle leaf failed no-follow open") from exc
        opened.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_dev != anchor_stat.st_dev:
            raise SecurityError("bundle input is not a same-filesystem single-link regular file")
        opened.pop()
        return descriptor
    finally:
        for item in reversed(opened):
            os.close(item)


def _snapshot_file(anchor, relative, destination):
    descriptor = _safe_open_relative(anchor, relative)
    before = os.fstat(descriptor)
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        output = os.open(destination, flags, 0o600)
        try:
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > 8 * 1024 * 1024:
                    raise SecurityError("bundle input exceeds v1 snapshot limit")
                digest.update(block)
                os.write(output, block)
            os.fsync(output)
        finally:
            os.close(output)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields) or after.st_size != size:
        raise SecurityError("bundle input changed during snapshot")
    if sha256_file(destination) != digest.hexdigest():
        raise SecurityError("root-owned intake snapshot recheck failed")
    return digest.hexdigest()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class DockerRuntime:
    def __init__(self, contract, layout):
        container = contract.get("caddy_container")
        config_root = contract.get("container_config_root")
        if not SAFE_RUNTIME_NAME_RE.fullmatch(str(container)):
            raise ContractError("invalid fixed Caddy container name")
        if not isinstance(config_root, str) or not config_root.startswith("/") or ".." in config_root.split("/"):
            raise ContractError("invalid container config root")
        self.container = container
        self.config_root = config_root.rstrip("/")
        self.layout = layout

    def _run(self, arguments):
        result = subprocess.run(arguments, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            raise TransactionError("fixed Caddy operation failed: " + result.stdout[-1000:])

    def validate(self, generation):
        generation_id = Path(generation).name
        temporary = self.layout.infra_root / (".validate-" + generation_id + ".Caddyfile")
        content = (
            f"import {self.config_root}/server-options.caddy\n"
            f"import {self.config_root}/managed/generations/{generation_id}/sites/*.caddy\n"
        )
        _atomic_write(temporary, content.encode(), 0o600)
        try:
            self._run([
                "/usr/bin/docker", "exec", self.container, "caddy", "validate",
                "--config", self.config_root + "/" + temporary.name, "--adapter", "caddyfile",
            ])
        finally:
            temporary.unlink(missing_ok=True)

    def ensure_network(self, network, upstream, deployment_id, persist_intent):
        if not SAFE_RUNTIME_NAME_RE.fullmatch(network) or not SAFE_RUNTIME_NAME_RE.fullmatch(upstream):
            raise ContractError("unsafe derived Docker network identity")
        inspect = subprocess.run(
            ["/usr/bin/docker", "network", "inspect", network],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if inspect.returncode:
            raise TransactionError("declared project Docker network is absent")
        try:
            network_value = json.loads(inspect.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise TransactionError("Docker network inspection is malformed") from exc
        containers = network_value.get("Containers") or {}
        attached_names = {item.get("Name") for item in containers.values() if isinstance(item, dict)}
        if upstream not in attached_names:
            raise TransactionError("declared upstream is not live on its project network")
        container_inspect = subprocess.run(
            ["/usr/bin/docker", "inspect", upstream],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if container_inspect.returncode:
            raise TransactionError("declared upstream container inspection failed")
        try:
            labels = json.loads(container_inspect.stdout)[0]["Config"]["Labels"] or {}
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            raise TransactionError("upstream ownership inspection is malformed") from exc
        if labels.get("com.deploydesk.deployment-id") != deployment_id:
            raise OwnershipError("live upstream belongs to another deployment")
        connected_now = False
        if self.container not in attached_names:
            # Write-ahead ownership: failure or interruption here cannot mutate Docker.
            persist_intent(network)
            self._run(["/usr/bin/docker", "network", "connect", network, self.container])
            connected_now = True
            verify = subprocess.run(
                ["/usr/bin/docker", "network", "inspect", network],
                check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            if verify.returncode:
                raise TransactionError("Caddy network attachment verification failed")
            values = json.loads(verify.stdout)
            names = {
                item.get("Name")
                for item in (values[0].get("Containers") or {}).values()
                if isinstance(item, dict)
            }
            if self.container not in names:
                raise TransactionError("Caddy did not join the project network")
        return connected_now

    def verify_network(self, network, upstream, deployment_id):
        if not SAFE_RUNTIME_NAME_RE.fullmatch(network) or not SAFE_PROXY_HOST_RE.fullmatch(upstream):
            raise ContractError("unsafe derived Docker network identity")
        inspect = subprocess.run(
            ["/usr/bin/docker", "network", "inspect", network],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if inspect.returncode:
            raise TransactionError("declared project Docker network is absent during recovery")
        try:
            values = json.loads(inspect.stdout)
            names = {
                item.get("Name")
                for item in (values[0].get("Containers") or {}).values()
                if isinstance(item, dict)
            }
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise TransactionError("Docker network recovery inspection is malformed") from exc
        if upstream not in names or self.container not in names:
            raise TransactionError("committed runtime network membership drift")
        container_inspect = subprocess.run(
            ["/usr/bin/docker", "inspect", upstream],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if container_inspect.returncode:
            raise TransactionError("declared upstream recovery inspection failed")
        try:
            labels = json.loads(container_inspect.stdout)[0]["Config"]["Labels"] or {}
        except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
            raise TransactionError("upstream recovery ownership inspection is malformed") from exc
        if labels.get("com.deploydesk.deployment-id") != deployment_id:
            raise OwnershipError("live upstream ownership drift during recovery")

    def detach_network(self, network):
        inspect = subprocess.run(
            ["/usr/bin/docker", "network", "inspect", network],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if inspect.returncode:
            raise TransactionError("network inspection failed during rollback")
        try:
            values = json.loads(inspect.stdout)
            names = {
                item.get("Name")
                for item in (values[0].get("Containers") or {}).values()
                if isinstance(item, dict)
            }
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise TransactionError("network rollback inspection is malformed") from exc
        if self.container not in names:
            return
        self._run(["/usr/bin/docker", "network", "disconnect", network, self.container])
        verify = subprocess.run(
            ["/usr/bin/docker", "network", "inspect", network],
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if verify.returncode:
            raise TransactionError("network detach verification failed")
        try:
            values = json.loads(verify.stdout)
            names = {
                item.get("Name")
                for item in (values[0].get("Containers") or {}).values()
                if isinstance(item, dict)
            }
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise TransactionError("network detach verification is malformed") from exc
        if self.container in names:
            raise TransactionError("Caddy remained attached after rollback")

    def reload(self):
        self._run([
            "/usr/bin/docker", "exec", self.container, "caddy", "reload",
            "--config", self.config_root + "/Caddyfile", "--adapter", "caddyfile",
        ])

    def smoke(self, hosts):
        opener = urllib.request.build_opener(_NoRedirectHandler())
        for host in hosts:
            request = urllib.request.Request("https://" + host + "/", method="HEAD")
            try:
                with opener.open(request, timeout=10) as response:
                    if response.status >= 500:
                        raise TransactionError("public smoke returned server error")
            except urllib.error.HTTPError as exc:
                try:
                    if exc.code >= 500:
                        raise TransactionError("public smoke returned server error") from exc
                finally:
                    exc.close()
            except Exception as exc:
                raise TransactionError("public smoke failed for " + host) from exc


class SharedCaddyHelper:
    def __init__(
        self, layout, runtime=None, trust=None, executable_path=None,
        phase_hook=None, archive_validation_hook=None,
    ):
        self.layout = layout
        self.trust = trust or TrustPolicy()
        self.executable_path = Path(executable_path or layout.helper_path)
        self.phase_hook = phase_hook
        self.archive_validation_hook = archive_validation_hook
        self.runtime = runtime
        self.last_lock_order = []

    def _phase(self, transaction, phase):
        transaction["phase"] = phase
        _atomic_json(self.layout.transaction_path, transaction)
        if self.phase_hook:
            self.phase_hook(phase, dict(transaction))

    def _current_generation(self):
        before = os.lstat(self.layout.current_link)
        if not stat.S_ISLNK(before.st_mode) or before.st_uid != self.trust.owner_uid or before.st_nlink != 1:
            raise SecurityError("managed/current symlink attestation failed")
        target = os.readlink(self.layout.current_link)
        after = os.lstat(self.layout.current_link)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SecurityError("managed/current changed during inspection")
        if not re.fullmatch(r"generations/gen-[0-9a-f]{32}", target):
            raise SecurityError("managed/current target is outside generations")
        generation = self.layout.managed_root / target
        _verify_trusted_chain(generation, self.layout.root, self.trust, "directory")
        return generation

    def _verify_generation_tree(self, generation):
        if generation.is_symlink():
            raise SecurityError("generation root may not be a symlink")
        for path in (generation, *generation.rglob("*")):
            info = os.lstat(path)
            if info.st_uid != self.trust.owner_uid:
                raise SecurityError("generation owner drift")
            if stat.S_ISLNK(info.st_mode):
                raise SecurityError("generation may not contain symlinks")
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o500:
                    raise SecurityError("completed generation directory is not immutable")
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400:
                    raise SecurityError("completed generation file is not immutable")
            else:
                raise SecurityError("generation contains a special file")

    def _attest_server(self):
        for path in (
            self.layout.infra_root, self.layout.managed_root, self.layout.generations_root,
            self.layout.state_root, self.layout.intake_root, self.layout.receipts_root,
            self.layout.maintenance_root,
            self.layout.lock_root, self.layout.lock_root / "projects", self.layout.lock_root / "releases",
            self.layout.bundle_root, self.layout.helper_path.parent,
        ):
            _verify_trusted_chain(path, self.layout.root, self.trust, "directory")
        for path in (
            self.layout.contract_path, self.layout.helper_path, self.layout.shared_lock,
            self.layout.lock_manifest_path, self.layout.bootstrap_attestation_path,
            self.layout.infra_root / "Caddyfile", self.layout.infra_root / "server-options.caddy",
        ):
            _verify_trusted_chain(path, self.layout.root, self.trust, "file")
        contract = read_json(self.layout.contract_path)
        validate_server_contract(contract)
        bootstrap = read_json(self.layout.bootstrap_attestation_path)
        validate_bootstrap_attestation(bootstrap)
        if (
            bootstrap["caddy_container"] != contract["caddy_container"]
            or bootstrap["container_config_root"] != contract["container_config_root"]
            or bootstrap["server_options_sha256"] != sha256_file(self.layout.infra_root / "server-options.caddy")
        ):
            raise AttestationError("bootstrap and server contract evidence disagree")
        if bootstrap["root_config_sha256"] != sha256_file(self.layout.infra_root / "Caddyfile"):
            raise MaintenanceRequired("root Caddyfile differs from the bootstrapped baseline")
        shared_info = os.lstat(self.layout.shared_lock)
        if {
            "device": bootstrap["shared_lock_device"],
            "inode": bootstrap["shared_lock_inode"],
            "ctime_ns": bootstrap["shared_lock_ctime_ns"],
        } != _lock_identity(shared_info):
            raise AttestationError("bootstrap shared lock identity drift")
        actual_hash = sha256_file(self.executable_path)
        if (
            contract["contract_version"] != CONTRACT_VERSION
            or contract["helper_version"] != HELPER_VERSION
            or contract["helper_sha256"] != actual_hash
            or self.executable_path.resolve() != self.layout.helper_path.resolve()
        ):
            raise AttestationError("helper self-attestation failed")
        config_root = contract.get("container_config_root")
        canonical_root = (
            f"import {config_root}/server-options.caddy\n"
            f"import {config_root}/managed/current/sites/*.caddy\n"
        )
        if (self.layout.infra_root / "Caddyfile").read_text(encoding="utf-8") != canonical_root:
            raise MaintenanceRequired("root Caddyfile contains unmanaged or noncanonical content")
        if self.runtime is None:
            self.runtime = DockerRuntime(contract, self.layout)
        return contract, actual_hash

    def _attest_lock_inodes(self, deployment_id):
        value = _validate_lock_manifest(read_json(self.layout.lock_manifest_path))
        deployment = value["deployments"].get(deployment_id)
        if not isinstance(deployment, dict) or set(deployment) != {"project", "release"}:
            raise SecurityError("deployment lock inodes were not provisioned")
        checks = (
            (self.layout.shared_lock, value["shared"], 0o600),
            (self.layout.project_lock(deployment_id), deployment["project"], 0o600),
            (self.layout.release_lock(deployment_id), deployment["release"], 0o640),
        )
        for path, expected, expected_mode in checks:
            actual = os.lstat(path)
            if (
                not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
                or actual.st_uid != self.trust.owner_uid
                or stat.S_IMODE(actual.st_mode) != expected_mode
            ):
                raise SecurityError("pre-created lock metadata drift")
            if _lock_identity(actual) != expected:
                raise SecurityError("pre-created lock identity was replaced")

    def _snapshot(self, deployment_id, bundle_id, transaction_id):
        intake = self.layout.intake_root / transaction_id
        os.mkdir(intake, 0o700)
        hashes = {}
        try:
            if os.stat(intake).st_uid != self.trust.owner_uid:
                raise SecurityError("intake owner mismatch")
            for relative in SNAPSHOT_FILES:
                derived = deployment_id + "/" + bundle_id + "/" + relative
                hashes[relative] = _snapshot_file(self.layout.bundle_root, derived, intake / relative)
            if hashes["deploy-bundle.tar.gz"] != bundle_id:
                raise SecurityError("raw deployment archive hash differs from bundle-id")
            self._extract_archive(intake / "deploy-bundle.tar.gz", intake)
            for relative in ARCHIVE_FILES:
                hashes[relative] = sha256_file(intake / relative)
            _fsync_dir(intake)
            _fsync_dir(self.layout.intake_root)
        except BaseException:
            self._discard_pretransaction_artifacts(intake=intake)
            raise
        return intake, hashes

    def _extract_archive(self, archive_path, intake):
        archive_path = Path(archive_path)
        intake = Path(intake)
        stage = None
        published = []

        def cleanup():
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
            for path in reversed(published):
                shutil.rmtree(path, ignore_errors=True)
            with contextlib.suppress(OSError):
                _fsync_dir(intake)

        def consume_pass(tar_bytes, retain_payloads):
            seen = set()
            member_count = 0
            total_size = 0
            expected_header_offset = 0
            logical_end = 0
            records = []
            payloads = {}
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > MAX_ARCHIVE_MEMBERS:
                        raise SecurityError("deployment archive exceeds v1 member limit")
                    if member.offset != expected_header_offset:
                        raise SecurityError("deployment archive contains a hidden path/header override")
                    if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_SIZE:
                        raise SecurityError("deployment archive exceeds v1 member size limit")
                    total_size += member.size
                    if total_size > MAX_ARCHIVE_TOTAL_SIZE:
                        raise SecurityError("deployment archive exceeds v1 aggregate size limit")
                    if (
                        member.name not in ARCHIVE_FILES
                        or member.name in seen
                        or not member.isfile()
                        or member.islnk()
                        or member.issym()
                        or member.pax_headers
                    ):
                        raise SecurityError("deployment archive contains a forbidden member")
                    seen.add(member.name)
                    source = archive.extractfile(member)
                    if source is None:
                        raise SecurityError("deployment archive member cannot be read")
                    data = source.read(member.size + 1)
                    if len(data) != member.size:
                        raise SecurityError("deployment archive member size mismatch")
                    records.append((member.name, member.size, sha256_bytes(data)))
                    if retain_payloads:
                        payloads[member.name] = data
                    logical_end = member.offset_data + ((member.size + 511) // 512) * 512
                    expected_header_offset = logical_end
            if seen != set(ARCHIVE_FILES):
                raise SecurityError("deployment archive allowlist is incomplete")
            tail = tar_bytes[logical_end:]
            if len(tail) < 1024 or len(tar_bytes) % 512 or any(tail):
                raise SecurityError("deployment archive does not have a clean canonical EOF")
            return records, payloads

        try:
            descriptor = os.open(archive_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise SecurityError("deployment archive is not a pinned regular file")
                chunks = []
                size = 0
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_ARCHIVE_COMPRESSED_SIZE:
                        raise SecurityError("deployment archive exceeds compressed input limit")
                    chunks.append(block)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in stable) or size != after.st_size:
                raise SecurityError("deployment archive changed during pinned read")
            pinned_bytes = b"".join(chunks)
            with gzip.GzipFile(fileobj=io.BytesIO(pinned_bytes), mode="rb") as compressed:
                tar_bytes = compressed.read(MAX_ARCHIVE_STREAM_SIZE + 1)
                if len(tar_bytes) > MAX_ARCHIVE_STREAM_SIZE:
                    raise SecurityError("deployment archive stream exceeds v1 limit")

            first_records, _ = consume_pass(tar_bytes, False)
            if self.archive_validation_hook:
                self.archive_validation_hook()
            second_records, payloads = consume_pass(tar_bytes, True)
            if second_records != first_records:
                raise SecurityError("deployment archive changed between validation passes")

            stage = intake / (".archive-stage-" + uuid.uuid4().hex)
            os.mkdir(stage, 0o700)
            for relative in ARCHIVE_FILES:
                destination = stage / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write(destination, payloads[relative], 0o600)
            for directory in (stage / "caddy", stage / "runtime", stage):
                _fsync_dir(directory)
            targets = (intake / "caddy", intake / "runtime")
            if any(path.exists() or path.is_symlink() for path in targets):
                raise SecurityError("archive extraction destination is not empty")
            for name in ("caddy", "runtime"):
                target = intake / name
                os.replace(stage / name, target)
                published.append(target)
            stage.rmdir()
            stage = None
            _fsync_dir(intake)
        except SecurityError:
            cleanup()
            raise
        except (tarfile.TarError, OSError, EOFError) as exc:
            cleanup()
            raise SecurityError("deployment archive is malformed") from exc
        except BaseException:
            cleanup()
            raise

    def _load_snapshot(self, intake, hashes, deployment_id, bundle_id, helper_hash):
        declaration = read_json(intake / "caddy" / "declaration.json")
        validate_declaration(declaration)
        if declaration["deployment_id"] != deployment_id:
            raise ContractError("declaration deployment does not match invocation")
        fragment = (intake / "caddy" / "site.caddy").read_bytes()
        reconcile_fragment(declaration, fragment)
        compose = read_json(intake / "runtime" / "compose.json")
        reconcile_compose(declaration, compose)
        requirement = read_json(intake / "caddy" / "helper-requirement.json")
        validate_requirement(requirement)
        if requirement["helper_sha256"] != helper_hash:
            raise AttestationError("bundle helper requirement differs from installed helper")
        provenance = read_json(intake / "caddy" / "bundle-provenance.json")
        validate_internal_provenance(provenance)
        if provenance["deployment_id"] != deployment_id:
            raise ContractError("internal provenance deployment does not match invocation")
        if provenance["helper_version"] != requirement["helper_version"] or provenance["helper_sha256"] != requirement["helper_sha256"]:
            raise AttestationError("internal provenance and helper requirement disagree")
        manifest = read_json(intake / "server-manifest.json")
        validate_manifest(manifest)
        if manifest["source"] != {"kind": "bundle"}:
            raise MaintenanceRequired("normal release manifests must have bundle provenance")
        if manifest["deployment_id"] != deployment_id or manifest["deploy_bundle_sha256"] != bundle_id:
            raise ContractError("server manifest invocation evidence mismatch")
        expected_hashes = {
            "declaration_sha256": hashes["caddy/declaration.json"],
            "fragment_sha256": hashes["caddy/site.caddy"],
            "compose_sha256": hashes["runtime/compose.json"],
            "helper_requirement_sha256": hashes["caddy/helper-requirement.json"],
            "internal_provenance_sha256": hashes["caddy/bundle-provenance.json"],
        }
        for key, expected in expected_hashes.items():
            if manifest[key] != expected:
                raise SecurityError("manifest artifact hash mismatch: " + key)
            if key != "internal_provenance_sha256" and provenance[key] != expected:
                raise SecurityError("internal provenance artifact hash mismatch: " + key)
        identity_fields = ("project_id", "environment", "deployment_id", "source_repo")
        if any(manifest[key] != declaration[key] for key in identity_fields):
            raise ContractError("declaration and server manifest identities differ")
        if manifest["hosts"] != [route["host"] for route in declaration["routes"]]:
            raise ContractError("declaration and server manifest hosts differ")
        if provenance["hosts"] != [route["host"] for route in declaration["routes"]]:
            raise ContractError("declaration and internal provenance hosts differ")
        overlap = (
            "contract_version", "helper_version", "helper_sha256", "project_id",
            "environment", "deployment_id", "source_repo", "hosts", "git_sha",
            "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256", "source",
        )
        for field in overlap:
            if manifest[field] != provenance[field]:
                raise SecurityError("external manifest and internal provenance differ: " + field)
        return declaration, manifest, provenance

    def _scan_ownership(self, generation, deployment_id, incoming_manifest):
        seen = {}
        manifests = generation / "manifests"
        sites = generation / "sites"
        manifest_ids = {path.stem for path in manifests.glob("*.json")}
        site_ids = {path.stem for path in sites.glob("*.caddy")}
        if manifest_ids != site_ids:
            raise OwnershipError("every live site must have exactly one owner manifest")
        current_target = manifests / (deployment_id + ".json")
        if current_target.exists():
            existing = read_json(current_target)
            validate_manifest(existing)
            if existing["source"]["kind"] in ("legacy_opaque", "baseline_import"):
                raise MaintenanceRequired("baseline/legacy takeover requires separate maintenance authority")
            for field in ("project_id", "environment", "deployment_id", "source_repo"):
                if existing[field] != incoming_manifest[field]:
                    raise MaintenanceRequired("ownership identity change requires separate maintenance authority")
        for path in sorted(manifests.glob("*.json")):
            value = incoming_manifest if path == current_target else read_json(path)
            validate_manifest(value)
            if path.stem != value["deployment_id"]:
                raise OwnershipError("manifest filename and deployment identity differ")
            site_hash = sha256_file(sites / (value["deployment_id"] + ".caddy"))
            if site_hash != value["fragment_sha256"]:
                raise OwnershipError("live fragment differs from its owner manifest hash")
            if value["source"]["kind"] == "legacy_opaque" and site_hash != value["source"]["legacy_fragment_sha256"]:
                raise OwnershipError("legacy opaque fragment differs from its bound hash")
            for host in value["hosts"]:
                owner = seen.setdefault(normalize_hostname(host), value["deployment_id"])
                if owner != value["deployment_id"]:
                    raise OwnershipError("hostname is already owned by another deployment")
        for host in incoming_manifest["hosts"]:
            owner = seen.setdefault(normalize_hostname(host), deployment_id)
            if owner != deployment_id:
                raise OwnershipError("hostname is already owned by another deployment")

    def _new_generation(self, deployment_id, intake, manifest):
        old = self._current_generation()
        self._verify_generation_tree(old)
        old_manifest_path = old / "manifests" / (deployment_id + ".json")
        if old_manifest_path.exists():
            old_manifest = read_json(old_manifest_path)
            validate_manifest(old_manifest)
            if old_manifest["source"]["kind"] in ("legacy_opaque", "baseline_import"):
                raise MaintenanceRequired("baseline/legacy takeover requires separate maintenance authority")
            for field in ("project_id", "environment", "deployment_id", "source_repo"):
                if old_manifest[field] != manifest[field]:
                    raise MaintenanceRequired("ownership identity change requires separate maintenance authority")
            if not set(old_manifest["hosts"]).issubset(set(manifest["hosts"])):
                raise MaintenanceRequired("hostname deletion requires separate maintenance authority")
        generation_id = "gen-" + uuid.uuid4().hex
        staged = self.layout.generations_root / generation_id
        try:
            shutil.copytree(old, staged, symlinks=False)
            _fsync_dir(self.layout.generations_root)
            for directory in (staged, staged / "sites", staged / "manifests"):
                os.chmod(directory, 0o700)
            target_site = staged / "sites" / (deployment_id + ".caddy")
            target_manifest = staged / "manifests" / (deployment_id + ".json")
            target_site.unlink(missing_ok=True)
            target_manifest.unlink(missing_ok=True)
            shutil.copyfile(intake / "caddy" / "site.caddy", target_site)
            _atomic_json(target_manifest, manifest, 0o600)
            self._scan_ownership(staged, deployment_id, manifest)
        except BaseException:
            self._discard_pretransaction_artifacts(staged=staged)
            raise
        return old.name, generation_id, staged

    def _freeze_generation(self, generation):
        for path in generation.rglob("*"):
            if path.is_symlink():
                raise SecurityError("generation may not contain symlinks")
            if path.is_file():
                if os.stat(path).st_nlink != 1:
                    raise SecurityError("generation file has unexpected hardlink")
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.chmod(path, 0o400)
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for path in sorted((item for item in generation.rglob("*") if item.is_dir()), reverse=True):
            os.chmod(path, 0o500)
            _fsync_dir(path)
        os.chmod(generation, 0o500)
        _fsync_dir(generation)
        _fsync_dir(self.layout.generations_root)

    def _switch_current(self, generation_id):
        target = "generations/" + generation_id
        if not re.fullmatch(r"generations/gen-[0-9a-f]{32}", target):
            raise SecurityError("unsafe generation target")
        temporary = self.layout.managed_root / (".current-" + uuid.uuid4().hex)
        os.symlink(target, temporary)
        os.replace(temporary, self.layout.current_link)
        _fsync_dir(self.layout.managed_root)

    def _receipt_from_transaction(self, transaction):
        return {
            "schema_version": "shared-caddy-receipt/v1",
            "status": "committed",
            "contract_version": transaction["contract_version"],
            "helper_version": transaction["helper_version"],
            "helper_sha256": transaction["helper_sha256"],
            "transaction_id": transaction["transaction_id"],
            "project_id": transaction["project_id"],
            "environment": transaction["environment"],
            "deployment_id": transaction["deployment_id"],
            "source_repo": transaction["source_repo"],
            "bundle_id": transaction["bundle_id"],
            "git_sha": transaction["git_sha"],
            "declaration_sha256": transaction["declaration_sha256"],
            "fragment_sha256": transaction["fragment_sha256"],
            "compose_sha256": transaction["compose_sha256"],
            "helper_requirement_sha256": transaction["helper_requirement_sha256"],
            "internal_provenance_sha256": transaction["internal_provenance_sha256"],
            "old_generation": transaction["old_generation"],
            "generation_id": transaction["new_generation"],
            "hosts": transaction["hosts"],
        }

    def _finish_committed(self, transaction):
        validate_transaction(transaction)
        receipt = self._receipt_from_transaction(transaction)
        validate_receipt(receipt)
        receipt_path = self.layout.receipt_path(transaction["transaction_id"])
        if receipt_path.exists():
            existing_receipt = read_json(receipt_path)
            validate_receipt(existing_receipt)
            if existing_receipt != receipt:
                raise RecoveryRequired("existing receipt differs from committed transaction")
        else:
            _atomic_json(receipt_path, receipt, 0o600)
        history = []
        if self.layout.history_path.exists():
            for line in self.layout.history_path.read_text(encoding="utf-8").splitlines():
                if line:
                    item = json.loads(line)
                    validate_receipt(item)
                    history.append(item)
        history_ids = [item["transaction_id"] for item in history]
        if len(history_ids) != len(set(history_ids)):
            raise RecoveryRequired("history contains duplicate transaction identities")
        existing = [item for item in history if item.get("transaction_id") == transaction["transaction_id"]]
        if existing and existing != [receipt]:
            raise RecoveryRequired("history differs from committed transaction")
        if not existing:
            history.append(receipt)
            payload = "".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in history)
            _atomic_write(self.layout.history_path, payload.encode(), 0o600)
        self.layout.transaction_path.unlink(missing_ok=True)
        _fsync_dir(self.layout.state_root)
        shutil.rmtree(self.layout.intake_root / transaction["transaction_id"], ignore_errors=True)
        _fsync_dir(self.layout.intake_root)
        return receipt

    def _mark_recovery(self, message):
        _atomic_write(self.layout.recovery_marker, (message + "\n").encode(), 0o600)

    def _assert_no_maintenance_state(self):
        if (
            _lexists(self.layout.maintenance_transaction_path)
            or _lexists(self.layout.maintenance_recovery_marker)
        ):
            raise RecoveryRequired("helper maintenance state blocks normal releases")

    def _discard_pretransaction_artifacts(self, intake=None, staged=None):
        """Remove uncommitted derived state before any durable transaction exists."""
        try:
            if staged is not None and Path(staged).exists():
                for directory, _, _ in os.walk(staged, topdown=True, followlinks=False):
                    os.chmod(directory, 0o700)
                shutil.rmtree(staged)
                _fsync_dir(self.layout.generations_root)
            if intake is not None and Path(intake).exists():
                for directory, _, _ in os.walk(intake, topdown=True, followlinks=False):
                    os.chmod(directory, 0o700)
                shutil.rmtree(intake)
                _fsync_dir(self.layout.intake_root)
        except Exception as exc:
            self._mark_recovery("pre-transaction cleanup failed")
            raise RecoveryRequired("pre-transaction artifacts require administrator recovery") from exc

    def _block_committed_recovery_after_attestation_failure(self, deployment_id, cause):
        """Durably block a committed repair whose controller evidence drifted.

        A helper/contract attestation failure normally happens before the normal
        lock sequence.  If a committed transaction is retained, however, that
        failure is part of recovery and must leave an administrator-visible
        marker.  Acquire the same release -> project -> shared ordering before
        inspecting or changing recovery state; if the retained transaction is
        not committed, preserve the original fail-closed attestation result.
        """
        self._attest_lock_inodes(deployment_id)
        project_lock = self.layout.project_lock(deployment_id)
        release_lock = self.layout.release_lock(deployment_id)
        _verify_trusted_chain(project_lock, self.layout.root, self.trust, "file")
        _verify_trusted_chain(release_lock, self.layout.root, self.trust, "file")
        _verify_trusted_chain(self.layout.shared_lock, self.layout.root, self.trust, "file")
        with _locked(project_lock, self.trust):
            _require_lock_held_elsewhere(release_lock, self.trust)
            with _locked(self.layout.shared_lock, self.trust):
                if not _lexists(self.layout.transaction_path):
                    return
                try:
                    transaction = read_json(self.layout.transaction_path)
                    validate_transaction(transaction)
                except Exception as exc:
                    self._mark_recovery("malformed retained transaction during controller attestation")
                    raise RecoveryRequired("retained transaction failed strict validation") from exc
                if transaction["phase"] != "committed":
                    return
                self._mark_recovery("committed receipt recovery controller attestation failed")
                raise RecoveryRequired("committed transaction recovery failed") from cause

    def _revalidate_committed_evidence(self, transaction, contract, helper_hash):
        if contract is None or helper_hash is None:
            raise RecoveryRequired("committed recovery lacks current controller attestation")
        if (
            transaction["contract_version"] != contract["contract_version"]
            or transaction["helper_version"] != contract["helper_version"]
            or transaction["helper_sha256"] != helper_hash
        ):
            raise RecoveryRequired("committed transaction controller evidence drift")
        intake = self.layout.intake_root / transaction["transaction_id"]
        _verify_trusted_chain(intake, self.layout.root, self.trust, "directory")
        archive_path = intake / "deploy-bundle.tar.gz"
        manifest_path = intake / "server-manifest.json"
        _verify_trusted(archive_path, self.trust, "file")
        _verify_trusted(manifest_path, self.trust, "file")
        if sha256_file(archive_path) != transaction["bundle_id"]:
            raise SecurityError("retained archive differs from committed bundle")
        retained_member_hashes = {}
        for relative in ARCHIVE_FILES:
            retained_path = intake / relative
            _verify_trusted(retained_path, self.trust, "file")
            retained_member_hashes[relative] = sha256_file(retained_path)
        recheck = Path(tempfile.mkdtemp(prefix=".committed-recheck-", dir=self.layout.intake_root))
        try:
            self._extract_archive(archive_path, recheck)
            manifest_bytes = manifest_path.read_bytes()
            _atomic_write(recheck / "server-manifest.json", manifest_bytes, 0o600)
            hashes = {
                "deploy-bundle.tar.gz": transaction["bundle_id"],
                "server-manifest.json": sha256_bytes(manifest_bytes),
            }
            for relative in ARCHIVE_FILES:
                hashes[relative] = sha256_file(recheck / relative)
                if hashes[relative] != retained_member_hashes[relative]:
                    raise SecurityError("retained extracted member differs from raw archive: " + relative)
            declaration, manifest, provenance = self._load_snapshot(
                recheck, hashes, transaction["deployment_id"], transaction["bundle_id"], helper_hash
            )
        finally:
            shutil.rmtree(recheck, ignore_errors=True)
            _fsync_dir(self.layout.intake_root)
        evidence_fields = (
            "project_id", "environment", "deployment_id", "source_repo", "git_sha",
            "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256", "internal_provenance_sha256", "hosts",
        )
        for field in evidence_fields:
            if transaction[field] != manifest[field]:
                raise RecoveryRequired("committed transaction differs from retained evidence: " + field)
        generation = self.layout.generations_root / transaction["new_generation"]
        self._verify_generation_tree(generation)
        generation_manifest = read_json(
            generation / "manifests" / (transaction["deployment_id"] + ".json")
        )
        validate_manifest(generation_manifest)
        if generation_manifest != manifest:
            raise RecoveryRequired("committed generation manifest differs from retained evidence")
        self._scan_ownership(generation, transaction["deployment_id"], manifest)
        for route in declaration["routes"]:
            if route["type"] == "docker_proxy":
                self.runtime.verify_network(
                    route["network"], route["upstream"], declaration["deployment_id"]
                )
        return generation, manifest, provenance

    def _rollback(self, transaction):
        try:
            self._switch_current(transaction["old_generation"])
            for intent in transaction.get("network_attachment_intents", []):
                self.runtime.detach_network(intent["network"])
            self.runtime.reload()
            old_manifest_path = self._current_generation() / "manifests" / (transaction["deployment_id"] + ".json")
            hosts = []
            if old_manifest_path.exists():
                hosts = read_json(old_manifest_path).get("hosts", [])
            self.runtime.smoke(hosts)
            shutil.rmtree(self.layout.generations_root / transaction["new_generation"], ignore_errors=True)
            _fsync_dir(self.layout.generations_root)
            shutil.rmtree(self.layout.intake_root / transaction["transaction_id"], ignore_errors=True)
            _fsync_dir(self.layout.intake_root)
            self.layout.transaction_path.unlink(missing_ok=True)
            _fsync_dir(self.layout.state_root)
        except Exception as exc:
            self._mark_recovery("rollback failed; inspect retained transaction")
            raise RecoveryRequired("Caddy rollback failed") from exc

    def _recover_if_needed(self, contract=None, helper_hash=None):
        if _lexists(self.layout.recovery_marker):
            raise RecoveryRequired("caddy-recovery-required blocks normal releases")
        if not _lexists(self.layout.transaction_path):
            return
        try:
            transaction = read_json(self.layout.transaction_path)
            validate_transaction(transaction)
        except (ContractError, RecoveryRequired) as exc:
            self._mark_recovery("malformed retained transaction")
            raise RecoveryRequired("retained transaction failed strict validation") from exc
        phase = transaction.get("phase")
        current = self._current_generation().name
        old = transaction.get("old_generation")
        new = transaction.get("new_generation")
        if phase == "committed":
            if current != new:
                self._mark_recovery("committed transaction current pointer mismatch")
                raise RecoveryRequired("cannot finish inconsistent committed transaction")
            try:
                generation, manifest, provenance = self._revalidate_committed_evidence(
                    transaction, contract, helper_hash
                )
                if self._current_generation().name != new:
                    raise RecoveryRequired("committed current pointer changed during evidence validation")
                self.runtime.validate(generation)
                self.runtime.reload()
                self.runtime.smoke(manifest["hosts"])
                self._finish_committed(transaction)
                return
            except Exception as exc:
                self._mark_recovery("committed receipt recovery failed")
                raise RecoveryRequired("committed transaction recovery failed") from exc
        if phase == "prepared" and current == old:
            try:
                for intent in transaction["network_attachment_intents"]:
                    self.runtime.detach_network(intent["network"])
                shutil.rmtree(self.layout.generations_root / new, ignore_errors=True)
                _fsync_dir(self.layout.generations_root)
                shutil.rmtree(self.layout.intake_root / transaction["transaction_id"], ignore_errors=True)
                _fsync_dir(self.layout.intake_root)
                self.layout.transaction_path.unlink()
                _fsync_dir(self.layout.state_root)
                return
            except Exception as exc:
                self._mark_recovery("prepared rollback failed; inspect retained transaction")
                raise RecoveryRequired("prepared transaction rollback failed") from exc
        if phase in ("prepared", "current-switched", "reloaded", "verified") and current == new:
            self._rollback(transaction)
            return
        if phase in ("current-switched", "reloaded", "verified") and current == old:
            # A prior rollback was interrupted after restoring the pointer.
            self._rollback(transaction)
            return
        self._mark_recovery("transaction phase/current pointer mismatch")
        raise RecoveryRequired("transaction state requires administrator recovery")

    def apply(self, deployment_id, bundle_id):
        validate_deployment_id(deployment_id)
        validate_bundle_id(bundle_id)
        self._assert_no_maintenance_state()
        self.last_lock_order = []
        try:
            contract, helper_hash = self._attest_server()
        except ContractError as exc:
            self._block_committed_recovery_after_attestation_failure(deployment_id, exc)
            raise
        self._attest_lock_inodes(deployment_id)
        project_lock = self.layout.project_lock(deployment_id)
        release_lock = self.layout.release_lock(deployment_id)
        _verify_trusted_chain(project_lock, self.layout.root, self.trust, "file")
        _verify_trusted_chain(release_lock, self.layout.root, self.trust, "file")
        transaction_id = "tx-" + uuid.uuid4().hex
        intake = None
        with _locked(project_lock, self.trust):
            self.last_lock_order.append("project")
            _require_lock_held_elsewhere(release_lock, self.trust)
            intake, hashes = self._snapshot(deployment_id, bundle_id, transaction_id)
            staged = None
            own_transaction_durable = False
            try:
                declaration, manifest, provenance = self._load_snapshot(
                    intake, hashes, deployment_id, bundle_id, helper_hash
                )
                with _locked(self.layout.shared_lock, self.trust):
                    self._assert_no_maintenance_state()
                    self._attest_lock_inodes(deployment_id)
                    self.last_lock_order.append("shared")
                    current_contract, current_helper_hash = self._attest_server()
                    if current_contract != contract or current_helper_hash != helper_hash:
                        raise AttestationError(
                            "helper/contract changed while this apply waited for shared lock"
                        )
                    self._recover_if_needed(current_contract, current_helper_hash)
                    old_generation, new_generation, staged = self._new_generation(
                        deployment_id, intake, manifest
                    )
                    self.runtime.validate(staged)
                    self._freeze_generation(staged)
                    transaction = {
                        "schema_version": "shared-caddy-transaction/v1",
                        "phase": "prepared",
                        "contract_version": contract["contract_version"],
                        "helper_version": contract["helper_version"],
                        "helper_sha256": helper_hash,
                        "transaction_id": transaction_id,
                        "project_id": manifest["project_id"],
                        "environment": manifest["environment"],
                        "deployment_id": deployment_id,
                        "source_repo": manifest["source_repo"],
                        "bundle_id": bundle_id,
                        "git_sha": manifest["git_sha"],
                        "declaration_sha256": manifest["declaration_sha256"],
                        "fragment_sha256": manifest["fragment_sha256"],
                        "compose_sha256": manifest["compose_sha256"],
                        "helper_requirement_sha256": manifest["helper_requirement_sha256"],
                        "internal_provenance_sha256": manifest["internal_provenance_sha256"],
                        "old_generation": old_generation,
                        "new_generation": new_generation,
                        "hosts": manifest["hosts"],
                        "network_attachment_intents": [],
                    }
                    try:
                        self._phase(transaction, "prepared")
                    except BaseException:
                        if _lexists(self.layout.transaction_path):
                            try:
                                persisted = read_json(self.layout.transaction_path)
                                own_transaction_durable = (
                                    persisted.get("transaction_id") == transaction_id
                                )
                            except Exception:
                                own_transaction_durable = True
                                self._mark_recovery(
                                    "prepared transaction durability is ambiguous"
                                )
                        raise
                    own_transaction_durable = True
                    try:
                        def persist_attachment_intent(network):
                            existing_networks = {
                                intent["network"]
                                for intent in transaction["network_attachment_intents"]
                            }
                            if network not in existing_networks:
                                transaction["network_attachment_intents"].append({
                                    "network": network,
                                    "pre_transaction_state": "absent",
                                })
                                self._phase(transaction, "prepared")

                        for route in declaration["routes"]:
                            if route["type"] == "docker_proxy":
                                self.runtime.ensure_network(
                                    route["network"], route["upstream"],
                                    declaration["deployment_id"], persist_attachment_intent,
                                )
                        self._switch_current(new_generation)
                        self._phase(transaction, "current-switched")
                        self.runtime.reload()
                        self._phase(transaction, "reloaded")
                        self.runtime.smoke(manifest["hosts"])
                        self._phase(transaction, "verified")
                        self._phase(transaction, "committed")
                        return self._finish_committed(transaction)
                    except Exception as exc:
                        if _lexists(self.layout.transaction_path):
                            try:
                                self._recover_if_needed(current_contract, current_helper_hash)
                            except RecoveryRequired:
                                raise
                        raise TransactionError("shared Caddy transaction failed") from exc
            except BaseException:
                if not own_transaction_durable:
                    self._discard_pretransaction_artifacts(intake=intake, staged=staged)
                    intake = None
                    staged = None
                raise


def _deployment_argument(value):
    try:
        return validate_deployment_id(value)
    except ContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _bundle_argument(value):
    try:
        return validate_bundle_id(value)
    except ContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser():
    parser = argparse.ArgumentParser(prog="deploydesk-caddy-apply", allow_abbrev=False)
    parser.add_argument("--deployment-id", required=True, type=_deployment_argument)
    parser.add_argument("--bundle-id", required=True, type=_bundle_argument)
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        raise SecurityError("normal-release helper must run as root through the fixed sudo rule")
    receipt = SharedCaddyHelper(Layout.for_host()).apply(arguments.deployment_id, arguments.bundle_id)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, TransactionError) as error:
        print("deploydesk-caddy-apply: " + str(error), file=sys.stderr)
        raise SystemExit(1)
