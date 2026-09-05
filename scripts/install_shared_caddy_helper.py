#!/usr/bin/python3
"""Root host-maintenance actions for shared-caddy-contract/v1.

Baseline bootstrap, helper installation/recovery, and project provisioning are
separate authorities. Every mutation uses retained descriptor-relative
directory handles from one trusted walker.
"""

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import urllib.parse
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
CONFIG_ROOT_RE = re.compile(r"/(?:[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+)*")
HOSTNAME_PATTERN = (
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
SOURCE_REPO_RE = re.compile(
    r"https://(?=[^/]{1,253}/)" + HOSTNAME_PATTERN + r"(?:/[A-Za-z0-9._~-]+)+"
)
LEGACY_BASELINE_ARCHIVE_FILES = (
    "caddy/declaration.json", "caddy/site.caddy", "caddy/helper-requirement.json",
    "caddy/bundle-provenance.json", "runtime/compose.json",
)
LEGACY_BASELINE_MAX_ARCHIVE_MEMBER_SIZE = 8 * 1024 * 1024
LEGACY_BASELINE_MAX_ARCHIVE_TOTAL_SIZE = 16 * 1024 * 1024
LEGACY_BASELINE_MAX_ARCHIVE_COMPRESSED_SIZE = 8 * 1024 * 1024
SUDOERS_IDENTITY_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
SUDOERS_ALIAS_RE = re.compile(r"[A-Z][A-Z0-9_]{0,62}")
_REQUIRED_DIR_FD_OPERATIONS = (
    os.open, os.stat, os.mkdir, os.rename, os.symlink,
    os.unlink, os.readlink, os.rmdir,
)
_REQUIRED_NOFOLLOW_OPERATIONS = (os.stat,)
_REQUIRED_FD_PATH_OPERATIONS = (os.listdir,)


class ContractError(RuntimeError):
    pass


class SecurityError(ContractError):
    pass


def validate_deployment_id(value):
    if not isinstance(value, str) or not DEPLOYMENT_RE.fullmatch(value):
        raise ContractError("deployment-id must be normalized <project>--<environment>")
    return value


def validate_bundle_id(value):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractError("bundle-id must be 64 lowercase hexadecimal characters")
    return value


def render_deployment_sudoers(deployment_id, release_identity, alias):
    """Render the two exact sudoers grants for one provisioned deployment.

    This pure helper deliberately does not write a sudoers file: a host
    administrator reviews the generated text and validates its destination with
    visudo as a separate host-maintenance step.
    """
    try:
        validate_deployment_id(deployment_id)
    except ContractError as exc:
        raise InstallError("sudoers deployment-id must be normalized") from exc
    if not isinstance(release_identity, str) or not SUDOERS_IDENTITY_RE.fullmatch(release_identity):
        raise InstallError("release identity must be one normalized local account name")
    if not isinstance(alias, str) or not SUDOERS_ALIAS_RE.fullmatch(alias):
        raise InstallError("sudoers alias must be uppercase letters, digits, and underscores")
    return (
        f"Cmnd_Alias {alias}_CADDY_PREFLIGHT = "
        "/usr/local/sbin/deploydesk-caddy-apply ^--preflight "
        f"--deployment-id {deployment_id} --bundle-id [0-9a-f]{{64}}$\n"
        f"Cmnd_Alias {alias}_CADDY_APPLY = "
        "/usr/local/sbin/deploydesk-caddy-apply ^--deployment-id "
        f"{deployment_id} --bundle-id [0-9a-f]{{64}}$\n"
        f"{release_identity} ALL=(root) NOPASSWD: "
        f"{alias}_CADDY_PREFLIGHT, {alias}_CADDY_APPLY\n"
    )


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _lock_identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "ctime_ns": info.st_ctime_ns,
    }


def _ensure_exact_keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ContractError(name + " has missing or unknown fields")


def _normalize_hostname(value):
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


def _validate_baseline_identity(value, name):
    if not ID_RE.fullmatch(str(value["project_id"])) or not ENVIRONMENT_RE.fullmatch(str(value["environment"])):
        raise ContractError(name + " identity is not normalized")
    if value["deployment_id"] != value["project_id"] + "--" + value["environment"]:
        raise ContractError(name + " identity fields disagree")
    validate_deployment_id(value["deployment_id"])
    _validate_source_repo(value["source_repo"])


def _validate_baseline_hosts(hosts, name):
    if not isinstance(hosts, list) or not hosts:
        raise ContractError(name + " hosts must be a non-empty approved owner list")
    normalized = [_normalize_hostname(host) for host in hosts]
    if normalized != hosts or len(normalized) != len(set(normalized)):
        raise ContractError(name + " hosts must be unique and normalized")
    return normalized


def _validate_baseline_hashes(value, fields, name):
    for field in fields:
        if not SHA256_RE.fullmatch(str(value[field])):
            raise ContractError("invalid " + name + " hash: " + field)


def validate_legacy_baseline_declaration(value):
    """Validate the separately authorized, external-HTTPS legacy baseline shape."""
    expected = (
        "contract_version", "project_id", "environment", "deployment_id",
        "source_repo", "compose_path", "routes",
    )
    _ensure_exact_keys(value, expected, "legacy baseline declaration")
    if value["contract_version"] != CONTRACT_VERSION:
        raise ContractError("unsupported contract version")
    _validate_baseline_identity(value, "legacy baseline declaration")
    if value["compose_path"] != "runtime/compose.json":
        raise ContractError("compose_path is fixed by v1")
    if not isinstance(value["routes"], list) or not value["routes"]:
        raise ContractError("legacy baseline requires at least one HTTPS proxy route")
    hosts = []
    targets = []
    for route in value["routes"]:
        _ensure_exact_keys(route, ("type", "host", "target_host"), "legacy baseline route")
        if route["type"] != "https_proxy":
            raise ContractError("legacy baseline routes must be HTTPS proxies")
        host = _normalize_hostname(route["host"])
        target = _normalize_hostname(route["target_host"])
        if route["host"] != host or route["target_host"] != target:
            raise ContractError("legacy baseline hosts must already be normalized IDNA ASCII")
        hosts.append(host)
        targets.append(target)
    if len(hosts) != len(set(hosts)):
        raise ContractError("duplicate normalized hostname")
    if set(hosts) & set(targets):
        raise ContractError("legacy baseline HTTPS targets must not be owned on this host")
    return value


def render_legacy_baseline_fragment(value):
    """Render only the declaration-derived external HTTPS compatibility fragment."""
    validate_legacy_baseline_declaration(value)
    blocks = []
    for route in value["routes"]:
        blocks.append(
            f"{route['host']} {{\n"
            "    encode zstd gzip\n"
            f"    reverse_proxy https://{route['target_host']} {{\n"
            f"        header_up Host {route['target_host']}\n"
            "        transport http {\n"
            f"            tls_server_name {route['target_host']}\n"
            "        }\n"
            "    }\n"
            "}"
        )
    return ("\n\n".join(blocks) + "\n").encode("utf-8")


def reconcile_legacy_baseline_fragment(value, raw):
    if not isinstance(raw, bytes):
        raise ContractError("legacy baseline fragment must be bytes")
    expected = render_legacy_baseline_fragment(value)
    if raw != expected:
        raise ContractError("legacy baseline fragment is not the canonical declaration-derived bytes")


def validate_baseline_provenance(value):
    expected = (
        "schema_version", "contract_version", "helper_version", "helper_sha256",
        "project_id", "environment", "deployment_id", "source_repo", "hosts", "git_sha",
        "declaration_sha256", "fragment_sha256", "compose_facts", "compose_sha256",
        "helper_requirement_sha256", "source",
    )
    _ensure_exact_keys(value, expected, "legacy baseline provenance")
    if value["schema_version"] != "shared-caddy-baseline-provenance/v1":
        raise ContractError("baseline provenance schema mismatch")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("baseline provenance controller mismatch")
    _validate_baseline_identity(value, "baseline provenance")
    _validate_baseline_hosts(value["hosts"], "baseline provenance")
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid baseline provenance Git SHA")
    _validate_baseline_hashes(
        value,
        ("helper_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256", "helper_requirement_sha256"),
        "baseline provenance",
    )
    _ensure_exact_keys(value["compose_facts"], ("services", "networks"), "baseline Compose facts")
    if value["compose_facts"]["services"] != {} or value["compose_facts"]["networks"] != {}:
        raise ContractError("baseline Compose facts must be empty")
    if value["compose_sha256"] != sha256_bytes(_canonical_json(value["compose_facts"])):
        raise ContractError("baseline Compose facts hash mismatch")
    source = value["source"]
    _ensure_exact_keys(source, ("kind", "legacy_fragment_sha256"), "baseline manifest source")
    if source["kind"] != "legacy_opaque" or source["legacy_fragment_sha256"] != value["fragment_sha256"]:
        raise ContractError("baseline manifest source must bind the rendered legacy fragment")
    if not SHA256_RE.fullmatch(str(source["legacy_fragment_sha256"])):
        raise ContractError("invalid baseline legacy fragment hash")
    return value


def validate_baseline_transaction(value):
    expected = (
        "schema_version", "phase", "contract_version", "helper_version", "helper_sha256",
        "transaction_id", "project_id", "environment", "deployment_id", "source_repo",
        "archive_id", "git_sha", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "baseline_provenance_sha256", "server_manifest_sha256",
        "old_generation", "new_generation", "hosts",
    )
    _ensure_exact_keys(value, expected, "baseline transaction")
    if value["schema_version"] != "shared-caddy-baseline-transaction/v1":
        raise ContractError("unknown baseline transaction schema")
    if value["phase"] not in ("prepared", "current-switched", "reloaded", "smoked", "verified", "committed"):
        raise ContractError("unknown baseline transaction phase")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("baseline transaction controller version drift")
    if not re.fullmatch(r"tx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise ContractError("invalid baseline transaction identity")
    _validate_baseline_identity(value, "baseline transaction")
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid baseline transaction Git SHA")
    _validate_baseline_hashes(
        value,
        (
            "helper_sha256", "archive_id", "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256", "baseline_provenance_sha256", "server_manifest_sha256",
        ),
        "baseline transaction evidence",
    )
    for field in ("old_generation", "new_generation"):
        if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value[field])):
            raise ContractError("invalid baseline transaction generation identity")
    if value["old_generation"] == value["new_generation"]:
        raise ContractError("baseline transaction generations must differ")
    _validate_baseline_hosts(value["hosts"], "baseline transaction")
    return value


def validate_baseline_receipt(value):
    expected = (
        "schema_version", "status", "contract_version", "helper_version", "helper_sha256",
        "transaction_id", "project_id", "environment", "deployment_id", "source_repo",
        "archive_id", "git_sha", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "baseline_provenance_sha256", "server_manifest_sha256",
        "old_generation", "generation_id", "hosts",
    )
    _ensure_exact_keys(value, expected, "baseline receipt")
    if value["schema_version"] != "shared-caddy-baseline-receipt/v1" or value["status"] != "committed":
        raise ContractError("baseline receipt is not a committed baseline receipt")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("baseline receipt controller version drift")
    if not re.fullmatch(r"tx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise ContractError("invalid baseline receipt transaction identity")
    _validate_baseline_identity(value, "baseline receipt")
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid baseline receipt Git SHA")
    _validate_baseline_hashes(
        value,
        (
            "helper_sha256", "archive_id", "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256", "baseline_provenance_sha256", "server_manifest_sha256",
        ),
        "baseline receipt evidence",
    )
    for field in ("old_generation", "generation_id"):
        if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value[field])):
            raise ContractError("invalid baseline receipt generation identity")
    if value["old_generation"] == value["generation_id"]:
        raise ContractError("baseline receipt generations must differ")
    _validate_baseline_hosts(value["hosts"], "baseline receipt")
    return value


def _validate_legacy_baseline_requirement(value):
    _ensure_exact_keys(
        value, ("contract_version", "helper_version", "helper_sha256"),
        "legacy baseline helper requirement",
    )
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("baseline helper requirement controller mismatch")
    if not SHA256_RE.fullmatch(str(value["helper_sha256"])):
        raise ContractError("invalid baseline helper requirement hash")


def _validate_legacy_baseline_manifest(value):
    expected = (
        "schema_version", "contract_version", "helper_version", "helper_sha256",
        "project_id", "environment", "deployment_id", "source_repo", "hosts", "git_sha",
        "deploy_bundle_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256",
        "helper_requirement_sha256", "internal_provenance_sha256", "source",
    )
    _ensure_exact_keys(value, expected, "legacy baseline server manifest")
    if value["schema_version"] != "shared-caddy-server-manifest/v1":
        raise ContractError("baseline server manifest schema mismatch")
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("baseline server manifest controller mismatch")
    _validate_baseline_identity(value, "baseline server manifest")
    _validate_baseline_hosts(value["hosts"], "baseline server manifest")
    if not GIT_SHA_RE.fullmatch(str(value["git_sha"])):
        raise ContractError("invalid baseline server manifest Git SHA")
    _validate_baseline_hashes(
        value,
        (
            "helper_sha256", "deploy_bundle_sha256", "declaration_sha256", "fragment_sha256",
            "compose_sha256", "helper_requirement_sha256", "internal_provenance_sha256",
        ),
        "baseline server manifest",
    )
    source = value["source"]
    _ensure_exact_keys(source, ("kind", "legacy_fragment_sha256"), "baseline server manifest source")
    if source["kind"] != "legacy_opaque" or source["legacy_fragment_sha256"] != value["fragment_sha256"]:
        raise ContractError("baseline server manifest source must bind the rendered legacy fragment")


def _read_legacy_baseline_archive(raw_archive):
    if not isinstance(raw_archive, bytes):
        raise ContractError("legacy baseline archive must be bytes")
    if len(raw_archive) > LEGACY_BASELINE_MAX_ARCHIVE_COMPRESSED_SIZE:
        raise ContractError("legacy baseline archive exceeds compressed size limit")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r|gz") as archive:
            result = {}
            total_size = 0
            member_count = 0
            for member in archive:
                if member_count >= len(LEGACY_BASELINE_ARCHIVE_FILES):
                    raise ContractError("legacy baseline archive member set is not exact")
                if member.name != LEGACY_BASELINE_ARCHIVE_FILES[member_count]:
                    raise ContractError("legacy baseline archive member set is not exact")
                if not member.isfile() or member.issym() or member.islnk():
                    raise ContractError("legacy baseline archive member must be a regular file")
                if member.size > LEGACY_BASELINE_MAX_ARCHIVE_MEMBER_SIZE:
                    raise ContractError("legacy baseline archive member exceeds size limit")
                total_size += member.size
                if total_size > LEGACY_BASELINE_MAX_ARCHIVE_TOTAL_SIZE:
                    raise ContractError("legacy baseline archive exceeds total size limit")
                source = archive.extractfile(member)
                if source is None:
                    raise ContractError("legacy baseline archive member cannot be read")
                result[member.name] = source.read(member.size + 1)
                if len(result[member.name]) != member.size:
                    raise ContractError("legacy baseline archive member size changed while reading")
                member_count += 1
            if member_count != len(LEGACY_BASELINE_ARCHIVE_FILES):
                raise ContractError("legacy baseline archive member set is not exact")
    except (OSError, tarfile.TarError) as exc:
        raise ContractError("invalid legacy baseline archive") from exc
    return result


def validate_legacy_baseline_artifact_chain(
    declaration, raw_fragment, compose_facts, helper_requirement, provenance, manifest,
    raw_archive, transaction, receipt,
):
    """Bind the approved legacy-baseline archive and durable evidence as one chain."""
    validate_legacy_baseline_declaration(declaration)
    reconcile_legacy_baseline_fragment(declaration, raw_fragment)
    _validate_legacy_baseline_requirement(helper_requirement)
    validate_baseline_provenance(provenance)
    _validate_legacy_baseline_manifest(manifest)
    validate_baseline_transaction(transaction)
    validate_baseline_receipt(receipt)
    if transaction["phase"] != "committed":
        raise ContractError("committed baseline receipt requires a committed transaction")
    if compose_facts != {"services": {}, "networks": {}}:
        raise ContractError("legacy baseline Compose facts must be empty")
    declaration_hosts = [route["host"] for route in declaration["routes"]]
    for field in ("project_id", "environment", "deployment_id", "source_repo"):
        if provenance[field] != declaration[field]:
            raise ContractError("legacy baseline provenance identity disagrees with declaration: " + field)
    if provenance["hosts"] != declaration_hosts:
        raise ContractError("legacy baseline provenance hosts disagree with declaration")
    expected_members = {
        "caddy/declaration.json": _canonical_json(declaration),
        "caddy/site.caddy": raw_fragment,
        "caddy/helper-requirement.json": _canonical_json(helper_requirement),
        "caddy/bundle-provenance.json": _canonical_json(provenance),
        "runtime/compose.json": _canonical_json(compose_facts),
    }
    if _read_legacy_baseline_archive(raw_archive) != expected_members:
        raise ContractError("legacy baseline archive bytes disagree with declared artifacts")
    archive_id = sha256_bytes(raw_archive)
    provenance_hash = sha256_bytes(expected_members["caddy/bundle-provenance.json"])
    manifest_hash = sha256_bytes(_canonical_json(manifest))
    for field, expected in (
        ("helper_sha256", helper_requirement["helper_sha256"]),
        ("declaration_sha256", sha256_bytes(expected_members["caddy/declaration.json"])),
        ("fragment_sha256", sha256_bytes(raw_fragment)),
        ("compose_sha256", sha256_bytes(expected_members["runtime/compose.json"])),
        ("helper_requirement_sha256", sha256_bytes(expected_members["caddy/helper-requirement.json"])),
    ):
        if provenance[field] != expected:
            raise ContractError("legacy baseline provenance hash mismatch: " + field)
    if provenance["source"] != manifest["source"]:
        raise ContractError("legacy baseline provenance and manifest source disagree")
    for field in (
        "project_id", "environment", "deployment_id", "source_repo", "hosts", "git_sha",
        "declaration_sha256", "fragment_sha256", "compose_sha256", "helper_requirement_sha256",
    ):
        if manifest[field] != provenance[field]:
            raise ContractError("legacy baseline manifest evidence mismatch: " + field)
    if manifest["helper_sha256"] != provenance["helper_sha256"]:
        raise ContractError("legacy baseline manifest helper evidence mismatch")
    if manifest["deploy_bundle_sha256"] != archive_id or manifest["internal_provenance_sha256"] != provenance_hash:
        raise ContractError("legacy baseline manifest archive or provenance hash mismatch")
    for record, generation_field in ((transaction, "new_generation"), (receipt, "generation_id")):
        for field in (
            "project_id", "environment", "deployment_id", "source_repo", "hosts", "git_sha",
            "helper_sha256", "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256",
        ):
            if record[field] != provenance[field]:
                raise ContractError("legacy baseline durable evidence mismatch: " + field)
        if (
            record["archive_id"] != archive_id
            or record["baseline_provenance_sha256"] != provenance_hash
            or record["server_manifest_sha256"] != manifest_hash
        ):
            raise ContractError("legacy baseline durable archive or manifest evidence mismatch")
        if record["old_generation"] != transaction["old_generation"]:
            raise ContractError("legacy baseline durable old generation mismatch")
        if generation_field == "generation_id" and record[generation_field] != transaction["new_generation"]:
            raise ContractError("legacy baseline receipt generation mismatch")
    if receipt["transaction_id"] != transaction["transaction_id"]:
        raise ContractError("legacy baseline receipt transaction identity mismatch")
    return {
        "archive_id": archive_id,
        "baseline_provenance_sha256": provenance_hash,
        "server_manifest_sha256": manifest_hash,
    }


def validate_server_contract(value):
    _ensure_exact_keys(
        value,
        (
            "contract_version", "helper_version", "helper_sha256",
            "caddy_container", "container_config_root",
        ),
        "server contract",
    )
    if value["contract_version"] != CONTRACT_VERSION or value["helper_version"] != HELPER_VERSION:
        raise ContractError("server contract version mismatch")
    if not SHA256_RE.fullmatch(str(value["helper_sha256"])):
        raise ContractError("invalid server helper hash")
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(value["caddy_container"])):
        raise ContractError("invalid fixed Caddy container name")
    if (
        not isinstance(value["container_config_root"], str)
        or not CONFIG_ROOT_RE.fullmatch(value["container_config_root"])
    ):
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
    if (
        value["schema_version"] != "shared-caddy-host-bootstrap/v1"
        or value["contract_version"] != CONTRACT_VERSION
    ):
        raise ContractError("bootstrap attestation version mismatch")
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(value["caddy_container"])):
        raise ContractError("invalid bootstrap Caddy container")
    if (
        not isinstance(value["container_config_root"], str)
        or not CONFIG_ROOT_RE.fullmatch(value["container_config_root"])
    ):
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
    def baseline_input_root(self):
        return self.maintenance_root / "baseline-input"

    @property
    def baseline_receipt_path(self):
        return self.maintenance_root / "baseline-receipt.json"

    @property
    def baseline_rollback_path(self):
        return self.maintenance_root / "baseline-rollback.json"

    @property
    def baseline_rollback_receipt_path(self):
        return self.maintenance_root / "baseline-rollback-receipt.json"

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


class InstallError(RuntimeError):
    pass


class CrossedMaintenanceRecovery(InstallError):
    pass


def _require_security_primitives():
    for name in ("O_NOFOLLOW", "O_DIRECTORY"):
        value = getattr(os, name, None)
        if not isinstance(value, int) or isinstance(value, bool) or value == 0:
            raise InstallError("platform lacks required no-follow directory primitives")
    if not all(
        operation in getattr(os, "supports_dir_fd", set())
        for operation in _REQUIRED_DIR_FD_OPERATIONS
    ):
        raise InstallError("platform lacks required descriptor-relative filesystem support")
    if not all(
        operation in getattr(os, "supports_follow_symlinks", set())
        for operation in _REQUIRED_NOFOLLOW_OPERATIONS
    ):
        raise InstallError("platform lacks required no-follow stat support")
    if not all(
        operation in getattr(os, "supports_fd", set())
        for operation in _REQUIRED_FD_PATH_OPERATIONS
    ):
        raise InstallError("platform lacks required descriptor-path support")


def _fsync_descriptor(descriptor, evidence_path):
    """Durability barrier with an evidence label used by ordering tests."""
    os.fsync(descriptor)


def _canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_approved_helper(source, expected_sha256):
    _require_security_primitives()
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise InstallError("helper source failed no-follow open") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InstallError("helper source must be a single-link regular file")
        chunks = []
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise InstallError("helper source changed during approved read")
    if digest.hexdigest() != expected_sha256:
        raise InstallError("helper source hash does not match approved maintenance input")
    return b"".join(chunks)


class _DirectoryHandle:
    def __init__(self, logical, fd, info, parent=None, name=None):
        self.logical = logical
        self.fd = fd
        self.device = info.st_dev
        self.inode = info.st_ino
        self.parent = parent
        self.name = name


class TrustedInstallerWalker:
    """Descriptor-relative trusted walker retained for the whole action."""

    def __init__(self, root, owner_uid):
        _require_security_primitives()
        self.root = Path(root)
        self.owner_uid = owner_uid
        self.handles = {}
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            root_fd = os.open(self.root, flags)
        except OSError as exc:
            raise InstallError("fixed maintenance root failed no-follow open") from exc
        try:
            info = os.fstat(root_fd)
            self._check_directory(info, self.root)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(root_fd)
            raise
        self.root_device = info.st_dev
        self.handles[()] = _DirectoryHandle((), root_fd, info)

    def close(self):
        seen = set()
        for handle in reversed(list(self.handles.values())):
            if handle.fd not in seen:
                seen.add(handle.fd)
                with contextlib.suppress(OSError):
                    os.close(handle.fd)
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _relative(self, path):
        try:
            return Path(path).relative_to(self.root).parts
        except ValueError as exc:
            raise InstallError("maintenance path escapes fixed root") from exc

    def _check_directory(self, info, display):
        if not stat.S_ISDIR(info.st_mode):
            raise InstallError("maintenance component is not a directory: " + str(display))
        if info.st_uid != self.owner_uid:
            raise InstallError("maintenance component owner mismatch: " + str(display))
        if info.st_mode & 0o022:
            raise InstallError("maintenance component is group/world writable: " + str(display))
        if info.st_nlink < 1:
            raise InstallError("maintenance directory link count is invalid: " + str(display))

    def _check_file(self, info, display, parent_device):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InstallError("maintenance target is not a single-link regular file: " + str(display))
        if info.st_uid != self.owner_uid:
            raise InstallError("maintenance file owner mismatch: " + str(display))
        if info.st_mode & 0o022:
            raise InstallError("maintenance file is group/world writable: " + str(display))
        if info.st_dev != parent_device:
            raise InstallError("maintenance file crosses a device boundary: " + str(display))

    def _lstat(self, parent, name):
        return os.stat(name, dir_fd=parent.fd, follow_symlinks=False)

    def _open_component(self, parent, name, logical, create, mode, anchor_device):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent.fd)
        except FileNotFoundError:
            if not create:
                raise InstallError("required maintenance directory is absent: " + str(self.root.joinpath(*logical)))
            os.mkdir(name, mode, dir_fd=parent.fd)
            _fsync_descriptor(parent.fd, self.root.joinpath(*logical[:-1]))
            try:
                descriptor = os.open(name, flags, dir_fd=parent.fd)
            except OSError as exc:
                raise InstallError("maintenance path contains an unexpected symlink or non-directory") from exc
        except OSError as exc:
            raise InstallError("maintenance path contains an unexpected symlink or non-directory") from exc
        try:
            info = os.fstat(descriptor)
            self._check_directory(info, self.root.joinpath(*logical))
            if info.st_dev != anchor_device:
                raise InstallError(
                    "maintenance path crosses a device boundary: "
                    + str(self.root.joinpath(*logical))
                )
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            raise
        return _DirectoryHandle(logical, descriptor, info, parent, name)

    def ensure_dir(self, path, mode=0o755, create=False):
        parts = self._relative(path)
        self.attest()
        if parts in self.handles:
            return self.handles[parts]
        current = self.handles[()]
        anchor = self.root_device
        for index, name in enumerate(parts):
            logical = parts[: index + 1]
            if logical in self.handles:
                current = self.handles[logical]
                continue
            if create:
                self.attest()
            handle = self._open_component(
                current, name, logical, create,
                mode if index == len(parts) - 1 else 0o755, anchor,
            )
            self.handles[logical] = handle
            current = handle
        self.attest()
        if create:
            os.fchmod(current.fd, mode)
            _fsync_descriptor(current.fd, self.root.joinpath(*parts))
        return current

    def attest(self):
        for handle in list(self.handles.values()):
            info = os.fstat(handle.fd)
            self._check_directory(info, self.root.joinpath(*handle.logical))
            if (info.st_dev, info.st_ino) != (handle.device, handle.inode):
                raise InstallError("retained maintenance directory changed")
            if handle.parent is None:
                continue
            try:
                entry = self._lstat(handle.parent, handle.name)
            except OSError as exc:
                raise InstallError("retained maintenance ancestor was replaced") from exc
            if (entry.st_dev, entry.st_ino) != (handle.device, handle.inode):
                raise InstallError("retained maintenance ancestor was replaced")

    def _parent_and_name(self, path, create_parent=False):
        path = Path(path)
        return self.ensure_dir(path.parent, create=create_parent), path.name

    def exists(self, path):
        parent, name = self._parent_and_name(path)
        try:
            self._lstat(parent, name)
            return True
        except FileNotFoundError:
            return False

    def lstat(self, path):
        parent, name = self._parent_and_name(path)
        return self._lstat(parent, name)

    def read_file(self, path, required=True):
        self.attest()
        parent, name = self._parent_and_name(path)
        flags = os.O_RDONLY | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent.fd)
        except FileNotFoundError:
            if required:
                raise InstallError("required maintenance file is absent: " + str(path))
            return None
        except OSError as exc:
            raise InstallError("maintenance file failed no-follow open: " + str(path)) from exc
        try:
            before = os.fstat(descriptor)
            self._check_file(before, path, parent.device)
            chunks = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                chunks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise InstallError("maintenance file changed during read: " + str(path))
        return b"".join(chunks)

    def write_file(self, path, data, mode, preserve=False):
        self.attest()
        parent, name = self._parent_and_name(path)
        try:
            existing = self._lstat(parent, name)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            self._check_file(existing, path, parent.device)
            if preserve:
                return
        temporary = "." + name + "." + uuid.uuid4().hex
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, mode, dir_fd=parent.fd)
        try:
            os.fchmod(descriptor, mode)
            offset = 0
            while offset < len(data):
                offset += os.write(descriptor, data[offset:])
            _fsync_descriptor(descriptor, Path(path))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=parent.fd)
            raise
        finally:
            os.close(descriptor)
        os.rename(temporary, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        _fsync_descriptor(parent.fd, Path(path).parent)
        final_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent.fd)
        try:
            _fsync_descriptor(final_fd, Path(path))
        finally:
            os.close(final_fd)

    def write_json(self, path, value, mode=0o600):
        self.write_file(path, _canonical_json(value), mode)

    def remove_file(self, path, missing_ok=False):
        self.attest()
        parent, name = self._parent_and_name(path)
        try:
            info = self._lstat(parent, name)
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner_uid:
            raise InstallError("refusing unsafe maintenance file removal")
        os.unlink(name, dir_fd=parent.fd)
        _fsync_descriptor(parent.fd, Path(path).parent)

    def replace_symlink(self, path, target):
        self.attest()
        parent, name = self._parent_and_name(path)
        try:
            existing = self._lstat(parent, name)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISLNK(existing.st_mode) or existing.st_uid != self.owner_uid):
            raise InstallError("controlled current target is not a trusted symlink")
        temporary = "." + name + "." + uuid.uuid4().hex
        os.symlink(target, temporary, dir_fd=parent.fd)
        os.rename(temporary, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        _fsync_descriptor(parent.fd, Path(path).parent)

    def chmod_dir(self, path, mode):
        handle = self.ensure_dir(path)
        self.attest()
        os.fchmod(handle.fd, mode)
        _fsync_descriptor(handle.fd, Path(path))

    def handoff_directory(self, path, target_uid, target_gid, mode=0o700):
        """Create or resume one leaf-directory handoff without retaining its FD."""
        path = Path(path)
        self.attest()
        parent, name = self._parent_and_name(path)
        try:
            entry = self._lstat(parent, name)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode, dir_fd=parent.fd)
                _fsync_descriptor(parent.fd, path.parent)
                entry = self._lstat(parent, name)
            except OSError as exc:
                raise InstallError("controller directory creation failed") from exc
        if (
            not stat.S_ISDIR(entry.st_mode) or entry.st_nlink < 1
            or entry.st_dev != parent.device or entry.st_mode & 0o077
        ):
            raise InstallError("controller directory is not a safe private directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent.fd)
        except OSError as exc:
            raise InstallError("controller directory failed no-follow open") from exc
        try:
            opened = os.fstat(descriptor)
            identity = (entry.st_dev, entry.st_ino)
            if (
                not stat.S_ISDIR(opened.st_mode) or opened.st_nlink < 1
                or (opened.st_dev, opened.st_ino) != identity
            ):
                raise InstallError("controller directory changed before handoff")
            target_owner = (target_uid, target_gid)
            if (opened.st_uid, opened.st_gid) == target_owner:
                if stat.S_IMODE(opened.st_mode) != mode:
                    raise InstallError("controller directory mode differs from fixed handoff mode")
            elif opened.st_uid == self.owner_uid:
                try:
                    os.fchmod(descriptor, mode)
                    os.fchown(descriptor, target_uid, target_gid)
                    _fsync_descriptor(descriptor, path)
                    _fsync_descriptor(parent.fd, path.parent)
                except OSError as exc:
                    raise InstallError("controller directory handoff failed") from exc
            else:
                raise InstallError("controller directory owner differs from fixed release UID")
            final = os.fstat(descriptor)
            current = self._lstat(parent, name)
            if (
                not stat.S_ISDIR(final.st_mode) or final.st_nlink < 1
                or (final.st_dev, final.st_ino) != identity
                or (current.st_dev, current.st_ino) != identity
                or (final.st_uid, final.st_gid) != target_owner
                or (current.st_uid, current.st_gid) != target_owner
                or stat.S_IMODE(final.st_mode) != mode
                or stat.S_IMODE(current.st_mode) != mode
            ):
                raise InstallError("controller directory handoff postcondition failed")
        finally:
            os.close(descriptor)
        self.attest()
        return final

    def handoff_regular_file(self, path, target_uid, target_gid, mode):
        """Finalize one root-owned regular file through its opened descriptor."""
        if target_uid != self.owner_uid:
            raise InstallError("release lock must remain owned by the maintenance identity")
        path = Path(path)
        self.attest()
        parent, name = self._parent_and_name(path)
        entry = self._lstat(parent, name)
        self._check_file(entry, path, parent.device)
        flags = os.O_RDWR | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent.fd)
        except OSError as exc:
            raise InstallError("release lock failed no-follow open") from exc
        try:
            opened = os.fstat(descriptor)
            self._check_file(opened, path, parent.device)
            identity = (entry.st_dev, entry.st_ino)
            if (opened.st_dev, opened.st_ino) != identity:
                raise InstallError("release lock changed before handoff")
            target_owner = (target_uid, target_gid)
            if (opened.st_uid, opened.st_gid) != target_owner or stat.S_IMODE(opened.st_mode) != mode:
                try:
                    os.fchmod(descriptor, mode)
                    os.fchown(descriptor, target_uid, target_gid)
                    _fsync_descriptor(descriptor, path)
                    _fsync_descriptor(parent.fd, path.parent)
                except OSError as exc:
                    raise InstallError("release lock handoff failed") from exc
            final = os.fstat(descriptor)
            current = self._lstat(parent, name)
            if (
                not stat.S_ISREG(final.st_mode) or final.st_nlink != 1
                or final.st_dev != parent.device
                or (final.st_dev, final.st_ino) != identity
                or (current.st_dev, current.st_ino) != identity
                or (final.st_uid, final.st_gid) != target_owner
                or (current.st_uid, current.st_gid) != target_owner
                or stat.S_IMODE(final.st_mode) != mode
                or stat.S_IMODE(current.st_mode) != mode
            ):
                raise InstallError("release lock handoff postcondition failed")
        finally:
            os.close(descriptor)
        self.attest()
        return final

    def _clear_directory(self, descriptor, device, display):
        for name in os.listdir(descriptor):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            child_display = display / name
            if stat.S_ISDIR(info.st_mode):
                self._check_directory(info, child_display)
                if info.st_dev != device:
                    raise InstallError("maintenance staging tree crosses a device boundary")
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise InstallError("maintenance staging directory was replaced")
                    self._clear_directory(child, device, child_display)
                finally:
                    os.close(child)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise InstallError("maintenance staging directory was replaced")
                os.rmdir(name, dir_fd=descriptor)
            elif stat.S_ISREG(info.st_mode):
                self._check_file(info, child_display, device)
                os.unlink(name, dir_fd=descriptor)
            else:
                raise InstallError("maintenance staging tree contains a link or special file")
        _fsync_descriptor(descriptor, display)

    def remove_tree(self, path):
        self.attest()
        handle = self.ensure_dir(path)
        if handle.parent is None:
            raise InstallError("refusing to remove the maintenance root")
        info = self._lstat(handle.parent, handle.name)
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid
            or (info.st_dev, info.st_ino) != (handle.device, handle.inode)
        ):
            raise InstallError("unsafe maintenance staging tree")
        self._clear_directory(handle.fd, handle.device, Path(path))
        current = self._lstat(handle.parent, handle.name)
        if (current.st_dev, current.st_ino) != (handle.device, handle.inode):
            raise InstallError("maintenance staging tree was replaced")
        os.rmdir(handle.name, dir_fd=handle.parent.fd)
        _fsync_descriptor(handle.parent.fd, Path(path).parent)
        prefix = handle.logical
        removed = []
        for logical in sorted(
            [key for key in self.handles if key[:len(prefix)] == prefix],
            key=len, reverse=True,
        ):
            removed.append(self.handles.pop(logical).fd)
        retained = {item.fd for item in self.handles.values()}
        for descriptor in set(removed) - retained:
            os.close(descriptor)


def _parse_json(data, name):
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(name + " is malformed") from exc
    if not isinstance(value, dict):
        raise InstallError(name + " must be an object")
    return value


def _load_lock_manifest(walker, layout):
    value = _parse_json(walker.read_file(layout.lock_manifest_path), "lock inode manifest")
    if set(value) != {"schema_version", "shared", "deployments"}:
        raise InstallError("lock inode manifest fields are not exact")
    if value["schema_version"] != "shared-caddy-lock-inodes/v1" or not isinstance(value["deployments"], dict):
        raise InstallError("unknown or malformed lock inode manifest")
    pairs = [value["shared"]]
    for deployment_id, pair in value["deployments"].items():
        validate_deployment_id(deployment_id)
        if not isinstance(pair, dict) or set(pair) != {"project", "release"}:
            raise InstallError("malformed deployment lock evidence")
        pairs.extend((pair["project"], pair["release"]))
    for item in pairs:
        if (
            not isinstance(item, dict) or set(item) != {"device", "inode", "ctime_ns"}
            or not all(isinstance(item[key], int) and not isinstance(item[key], bool) and item[key] >= 0 for key in item)
        ):
            raise InstallError("malformed lock inode identity")
    return value


def _attest_bootstrap(walker, layout):
    for path in (
        layout.infra_root, layout.managed_root, layout.generations_root,
        layout.state_root, layout.intake_root, layout.receipts_root,
        layout.maintenance_root, layout.lock_root, layout.lock_root / "projects",
        layout.lock_root / "releases", layout.bundle_root, layout.helper_path.parent,
    ):
        walker.ensure_dir(path)
    evidence = _parse_json(walker.read_file(layout.bootstrap_attestation_path), "bootstrap attestation")
    try:
        validate_bootstrap_attestation(evidence)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    root_config = walker.read_file(layout.infra_root / "Caddyfile")
    server_options = walker.read_file(layout.infra_root / "server-options.caddy")
    shared_info = walker.lstat(layout.shared_lock)
    if (
        sha256_bytes(root_config) != evidence["root_config_sha256"]
        or sha256_bytes(server_options) != evidence["server_options_sha256"]
    ):
        raise InstallError("bootstrapped host evidence drift")
    lock_manifest = _load_lock_manifest(walker, layout)
    _assert_recorded_locks(walker, layout, lock_manifest)
    if _lock_identity(shared_info) != {
        "device": evidence["shared_lock_device"],
        "inode": evidence["shared_lock_inode"],
        "ctime_ns": evidence["shared_lock_ctime_ns"],
    }:
        raise InstallError("bootstrapped shared lock identity drift")
    if lock_manifest["shared"] != _lock_identity(shared_info):
        raise InstallError("bootstrap lock manifest disagrees with shared lock")
    return evidence, lock_manifest


def _assert_recorded_locks(walker, layout, manifest, release_gid=None):
    checks = [(layout.shared_lock, manifest["shared"], 0o600, None)]
    for deployment_id, pair in manifest["deployments"].items():
        checks.extend((
            (layout.project_lock(deployment_id), pair["project"], 0o600, None),
            (layout.release_lock(deployment_id), pair["release"], 0o640, release_gid),
        ))
    for path, expected, expected_mode, expected_gid in checks:
        try:
            parent, name = walker._parent_and_name(path)
            actual = walker._lstat(parent, name)
            walker._check_file(actual, path, parent.device)
            if (
                stat.S_IMODE(actual.st_mode) != expected_mode
                or (expected_gid is not None and actual.st_gid != expected_gid)
            ):
                raise InstallError("lock metadata differs from its fixed contract")
        except (InstallError, OSError) as exc:
            raise InstallError("recorded lock metadata drift: " + str(path)) from exc
        if _lock_identity(actual) != expected:
            raise InstallError("recorded lock identity was replaced: " + str(path))


def _open_shared_lock(walker, layout, manifest):
    _assert_recorded_locks(walker, layout, manifest)
    parent, name = walker._parent_and_name(layout.shared_lock)
    try:
        descriptor = os.open(
            name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent.fd,
        )
    except OSError as exc:
        raise InstallError("shared lock failed no-follow open") from exc
    try:
        info = os.fstat(descriptor)
        walker._check_file(info, layout.shared_lock, parent.device)
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError("shared lock mode differs from its fixed contract")
        if _lock_identity(info) != manifest["shared"]:
            raise InstallError("shared lock changed while opening")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _baseline_rollback_path(layout):
    return getattr(
        layout, "baseline_rollback_path", layout.maintenance_root / "baseline-rollback.json",
    )


def _baseline_rollback_receipt_path(layout):
    return getattr(
        layout, "baseline_rollback_receipt_path",
        layout.maintenance_root / "baseline-rollback-receipt.json",
    )


def _blocked_state(layout, include_maintenance=True):
    paths = [layout.transaction_path, layout.recovery_marker]
    if include_maintenance:
        paths.extend((
            layout.maintenance_transaction_path,
            layout.maintenance_recovery_marker,
            _baseline_rollback_path(layout),
        ))
    return paths


def bootstrap_host(
    layout, owner_uid=0, caddy_container="caddy", container_config_root="/etc/caddy",
    phase_hook=None,
):
    """Create only the host baseline layout, root config, and initial generation."""
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(caddy_container)):
        raise InstallError("approved Caddy container identity is invalid")
    if not isinstance(container_config_root, str) or not CONFIG_ROOT_RE.fullmatch(container_config_root):
        raise InstallError("approved container config root is invalid")
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        for path in (
            layout.bootstrap_attestation_path, layout.current_link,
            layout.infra_root / "Caddyfile", layout.shared_lock, layout.lock_manifest_path,
        ):
            if path.exists() or path.is_symlink():
                raise InstallError("host baseline already exists or is incomplete")
        for path, mode in (
            (layout.infra_root, 0o755), (layout.managed_root, 0o755),
            (layout.generations_root, 0o755), (layout.state_root, 0o755),
            (layout.intake_root, 0o700), (layout.receipts_root, 0o755),
            (layout.maintenance_root, 0o700), (layout.lock_root, 0o755),
            (layout.lock_root / "projects", 0o755), (layout.lock_root / "releases", 0o755),
            (layout.bundle_root, 0o755), (layout.helper_path.parent, 0o755),
        ):
            walker.ensure_dir(path, mode, create=True)
        walker.write_file(layout.shared_lock, b"", 0o600)
        server_options = b"# Host-global options are installed only by approved baseline maintenance.\n"
        root_config = (
            f"import {container_config_root}/server-options.caddy\n"
            f"import {container_config_root}/managed/current/sites/*.caddy\n"
        ).encode()
        walker.write_file(layout.infra_root / "server-options.caddy", server_options, 0o644)
        generation_id = "gen-" + "0" * 32
        generation = layout.generations_root / generation_id
        walker.ensure_dir(generation, 0o700, create=True)
        walker.ensure_dir(generation / "sites", 0o700, create=True)
        walker.ensure_dir(generation / "manifests", 0o700, create=True)
        walker.chmod_dir(generation / "sites", 0o500)
        walker.chmod_dir(generation / "manifests", 0o500)
        walker.chmod_dir(generation, 0o500)
        _fsync_descriptor(walker.ensure_dir(layout.generations_root).fd, layout.generations_root)
        walker.write_file(layout.infra_root / "Caddyfile", root_config, 0o644)
        walker.replace_symlink(layout.current_link, "generations/" + generation_id)
        shared = walker.lstat(layout.shared_lock)
        lock_manifest = {
            "schema_version": "shared-caddy-lock-inodes/v1",
            "shared": _lock_identity(shared),
            "deployments": {},
        }
        walker.write_json(layout.lock_manifest_path, lock_manifest, 0o600)
        evidence = {
            "schema_version": "shared-caddy-host-bootstrap/v1",
            "contract_version": CONTRACT_VERSION,
            "caddy_container": caddy_container,
            "container_config_root": container_config_root,
            "initial_generation": generation_id,
            "initial_current_target": "generations/" + generation_id,
            "root_config_sha256": sha256_bytes(root_config),
            "server_options_sha256": sha256_bytes(server_options),
            "shared_lock_device": shared.st_dev,
            "shared_lock_inode": shared.st_ino,
            "shared_lock_ctime_ns": shared.st_ctime_ns,
        }
        walker.write_json(layout.bootstrap_attestation_path, evidence, 0o644)
        walker.attest()
        if phase_hook:
            phase_hook("published", dict(evidence))
        return evidence


def _validate_maintenance_transaction(value):
    expected = {
        "schema_version", "phase", "transaction_id", "contract_version",
        "old_helper_sha256", "old_contract_sha256", "new_helper_sha256",
        "new_contract_sha256", "caddy_container", "container_config_root",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise InstallError("maintenance transaction fields are not exact")
    if value["schema_version"] != "shared-caddy-helper-maintenance/v1":
        raise InstallError("unknown maintenance transaction schema")
    if value["phase"] not in ("staged", "helper-installed", "contract-installed", "committed"):
        raise InstallError("unknown maintenance transaction phase")
    if not re.fullmatch(r"mtx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise InstallError("invalid maintenance transaction identity")
    if value["contract_version"] != CONTRACT_VERSION:
        raise InstallError("maintenance transaction contract drift")
    try:
        for field in ("new_helper_sha256", "new_contract_sha256"):
            validate_bundle_id(value[field])
        for field in ("old_helper_sha256", "old_contract_sha256"):
            if value[field] is not None:
                validate_bundle_id(value[field])
    except ContractError as exc:
        raise InstallError("invalid maintenance transaction hash") from exc
    if (value["old_helper_sha256"] is None) != (value["old_contract_sha256"] is None):
        raise InstallError("old helper and contract evidence must be an atomic pair")
    if not SAFE_RUNTIME_NAME_RE.fullmatch(str(value["caddy_container"])):
        raise InstallError("invalid maintenance Caddy container")
    if not isinstance(value["container_config_root"], str) or not CONFIG_ROOT_RE.fullmatch(value["container_config_root"]):
        raise InstallError("invalid maintenance config root")
    return value


def _phase_maintenance(walker, layout, transaction, phase, phase_hook):
    transaction["phase"] = phase
    walker.write_json(layout.maintenance_transaction_path, transaction, 0o600)
    if phase_hook:
        phase_hook(phase, dict(transaction))


def _current_pair(walker, layout):
    helper_data = walker.read_file(layout.helper_path, required=False)
    contract_data = walker.read_file(layout.contract_path, required=False)
    if (helper_data is None) != (contract_data is None):
        raise InstallError("helper and contract are already mismatched")
    if helper_data is None:
        return None, None, None
    if (
        stat.S_IMODE(walker.lstat(layout.helper_path).st_mode) != 0o755
        or stat.S_IMODE(walker.lstat(layout.contract_path).st_mode) != 0o644
    ):
        raise InstallError("existing helper or contract mode differs from its fixed contract")
    contract = _parse_json(contract_data, "existing server contract")
    try:
        validate_server_contract(contract)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    if contract["helper_sha256"] != sha256_bytes(helper_data):
        raise InstallError("existing helper and contract attestation disagree")
    return helper_data, contract_data, contract


def _validate_staged_contract(data, expected_helper_sha256, bootstrap, label):
    contract = _parse_json(data, label)
    try:
        validate_server_contract(contract)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    if contract["helper_sha256"] != expected_helper_sha256:
        raise InstallError(label + " helper attestation mismatch")
    if (
        contract["caddy_container"] != bootstrap["caddy_container"]
        or contract["container_config_root"] != bootstrap["container_config_root"]
    ):
        raise InstallError(label + " runtime identity differs from bootstrap")
    return contract


def _validate_maintenance_live_phase(
    walker, layout, transaction, old_helper, old_contract, new_helper, new_contract,
):
    live_helper = walker.read_file(layout.helper_path, required=False)
    live_contract = walker.read_file(layout.contract_path, required=False)
    for path, data, mode in (
        (layout.helper_path, live_helper, 0o755),
        (layout.contract_path, live_contract, 0o644),
    ):
        if data is not None and stat.S_IMODE(walker.lstat(path).st_mode) != mode:
            raise InstallError("live helper maintenance pair mode drift")
    old_pair = (old_helper, old_contract)
    helper_installed = (new_helper, old_contract)
    new_pair = (new_helper, new_contract)
    allowed = {
        "staged": (old_pair, helper_installed),
        "helper-installed": (helper_installed, new_pair),
        "contract-installed": (new_pair,),
        "committed": (new_pair,),
    }[transaction["phase"]]
    if (live_helper, live_contract) not in allowed:
        raise InstallError("maintenance transaction phase disagrees with the live pair")


def install_helper(layout, helper_source, expected_sha256, owner_uid=0, phase_hook=None):
    """Install/upgrade only an already bootstrapped and attested host."""
    validate_bundle_id(expected_sha256)
    helper_data = _read_approved_helper(Path(helper_source), expected_sha256)
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
        _assert_recorded_locks(walker, layout, lock_manifest)
        lock_fd = _open_shared_lock(walker, layout, lock_manifest)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if phase_hook:
                phase_hook("locked", {})
            walker.attest()
            _assert_recorded_locks(walker, layout, lock_manifest)
            if any(walker.exists(path) for path in _blocked_state(layout)):
                raise InstallError("helper maintenance blocked by app, Caddy, or maintenance state")
            old_helper, old_contract_data, old_contract = _current_pair(walker, layout)
            if old_contract is not None and (
                old_contract["caddy_container"] != bootstrap["caddy_container"]
                or old_contract["container_config_root"] != bootstrap["container_config_root"]
            ):
                raise InstallError("Caddy runtime identity change requires separate baseline maintenance")
            new_contract = {
                "contract_version": CONTRACT_VERSION,
                "helper_version": HELPER_VERSION,
                "helper_sha256": expected_sha256,
                "caddy_container": bootstrap["caddy_container"],
                "container_config_root": bootstrap["container_config_root"],
            }
            new_contract_data = _canonical_json(new_contract)
            transaction_id = "mtx-" + uuid.uuid4().hex
            stage = layout.maintenance_root / transaction_id
            walker.ensure_dir(stage, 0o700, create=True)
            walker.write_file(stage / "new-helper", helper_data, 0o600)
            walker.write_file(stage / "new-contract.json", new_contract_data, 0o600)
            if old_helper is not None:
                walker.write_file(stage / "old-helper", old_helper, 0o600)
                walker.write_file(stage / "old-contract.json", old_contract_data, 0o600)
            _fsync_descriptor(walker.ensure_dir(stage).fd, stage)
            _fsync_descriptor(walker.ensure_dir(layout.maintenance_root).fd, layout.maintenance_root)
            transaction = {
                "schema_version": "shared-caddy-helper-maintenance/v1",
                "phase": "staged",
                "transaction_id": transaction_id,
                "contract_version": CONTRACT_VERSION,
                "old_helper_sha256": sha256_bytes(old_helper) if old_helper is not None else None,
                "old_contract_sha256": sha256_bytes(old_contract_data) if old_contract_data is not None else None,
                "new_helper_sha256": expected_sha256,
                "new_contract_sha256": sha256_bytes(new_contract_data),
                "caddy_container": bootstrap["caddy_container"],
                "container_config_root": bootstrap["container_config_root"],
            }
            _phase_maintenance(walker, layout, transaction, "staged", phase_hook)
            walker.write_file(layout.helper_path, helper_data, 0o755)
            _phase_maintenance(walker, layout, transaction, "helper-installed", phase_hook)
            walker.write_file(layout.contract_path, new_contract_data, 0o644)
            _phase_maintenance(walker, layout, transaction, "contract-installed", phase_hook)
            current_helper, current_contract_data, current_contract = _current_pair(walker, layout)
            if current_helper != helper_data or current_contract_data != new_contract_data:
                raise InstallError("new helper/contract pair failed post-install attestation")
            _phase_maintenance(walker, layout, transaction, "committed", phase_hook)
            walker.remove_file(layout.maintenance_transaction_path)
            walker.remove_tree(stage)
            return current_contract
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def recover_helper_maintenance(layout, owner_uid=0):
    """Explicitly recover one valid retained helper+contract transaction."""
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
        lock_fd = _open_shared_lock(walker, layout, lock_manifest)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            walker.attest()
            _assert_recorded_locks(walker, layout, lock_manifest)
            if walker.exists(layout.maintenance_recovery_marker):
                raise InstallError("maintenance recovery marker requires administrator repair")
            if walker.exists(_baseline_rollback_path(layout)):
                raise CrossedMaintenanceRecovery(
                    "baseline rollback requires the baseline recovery action"
                )
            if walker.exists(layout.transaction_path) or walker.exists(layout.recovery_marker):
                raise InstallError("application/Caddy state blocks helper maintenance recovery")
            try:
                transaction = _parse_json(
                    walker.read_file(layout.maintenance_transaction_path), "maintenance transaction"
                )
                if transaction.get("schema_version") == "shared-caddy-baseline-transaction/v1":
                    raise CrossedMaintenanceRecovery(
                        "baseline transaction requires the baseline recovery action"
                    )
                _validate_maintenance_transaction(transaction)
                if (
                    transaction["caddy_container"] != bootstrap["caddy_container"]
                    or transaction["container_config_root"] != bootstrap["container_config_root"]
                ):
                    raise InstallError("maintenance transaction runtime identity differs from bootstrap")
                stage = layout.maintenance_root / transaction["transaction_id"]
                walker.ensure_dir(stage)
                new_helper = walker.read_file(stage / "new-helper")
                new_contract = walker.read_file(stage / "new-contract.json")
                if (
                    sha256_bytes(new_helper) != transaction["new_helper_sha256"]
                    or sha256_bytes(new_contract) != transaction["new_contract_sha256"]
                ):
                    raise InstallError("staged new maintenance pair hash mismatch")
                _validate_staged_contract(
                    new_contract, transaction["new_helper_sha256"], bootstrap,
                    "staged new server contract",
                )
                old_helper = None
                old_contract = None
                if transaction["old_helper_sha256"] is None:
                    if (
                        walker.exists(stage / "old-helper")
                        or walker.exists(stage / "old-contract.json")
                    ):
                        raise InstallError("unexpected staged old maintenance pair")
                else:
                    old_helper = walker.read_file(stage / "old-helper")
                    old_contract = walker.read_file(stage / "old-contract.json")
                    if (
                        sha256_bytes(old_helper) != transaction["old_helper_sha256"]
                        or sha256_bytes(old_contract) != transaction["old_contract_sha256"]
                    ):
                        raise InstallError("staged old maintenance pair hash mismatch")
                    _validate_staged_contract(
                        old_contract, transaction["old_helper_sha256"], bootstrap,
                        "staged old server contract",
                    )
                _validate_maintenance_live_phase(
                    walker, layout, transaction, old_helper, old_contract,
                    new_helper, new_contract,
                )
                if transaction["phase"] == "staged":
                    if transaction["old_helper_sha256"] is None:
                        walker.remove_file(layout.helper_path, missing_ok=True)
                        walker.remove_file(layout.contract_path, missing_ok=True)
                    else:
                        walker.write_file(layout.helper_path, old_helper, 0o755)
                        walker.write_file(layout.contract_path, old_contract, 0o644)
                else:
                    walker.write_file(layout.helper_path, new_helper, 0o755)
                    walker.write_file(layout.contract_path, new_contract, 0o644)
                helper_data, contract_data, contract = _current_pair(walker, layout)
                if contract is not None and (
                    contract["caddy_container"] != bootstrap["caddy_container"]
                    or contract["container_config_root"] != bootstrap["container_config_root"]
                ):
                    raise InstallError("recovered maintenance pair runtime identity mismatch")
                if transaction["phase"] != "staged" and (
                    sha256_bytes(helper_data) != transaction["new_helper_sha256"]
                    or sha256_bytes(contract_data) != transaction["new_contract_sha256"]
                ):
                    raise InstallError("recovered maintenance pair attestation mismatch")
                walker.remove_file(layout.maintenance_transaction_path)
                walker.remove_tree(stage)
                return contract
            except CrossedMaintenanceRecovery:
                raise
            except InstallError:
                if not walker.exists(layout.maintenance_recovery_marker):
                    walker.write_file(
                        layout.maintenance_recovery_marker,
                        b"helper maintenance recovery requires administrator review\n", 0o600,
                    )
                raise
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


class _NoBaselineRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


BASELINE_DOCKER_TIMEOUT_SECONDS = 30


class BaselineDockerRuntime:
    """Fixed Caddy operations derived only from the attested server contract."""

    def __init__(self, contract, layout, walker=None):
        validate_server_contract(contract)
        self.container = contract["caddy_container"]
        self.config_root = contract["container_config_root"].rstrip("/")
        self.layout = layout
        self.walker = walker

    def _run(self, arguments):
        try:
            result = subprocess.run(
                arguments, check=False, text=True, timeout=BASELINE_DOCKER_TIMEOUT_SECONDS,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
        except subprocess.TimeoutExpired as exc:
            raise InstallError("fixed baseline Caddy operation timed out") from exc
        if result.returncode:
            raise InstallError("fixed baseline Caddy operation failed: " + result.stdout[-1000:])

    def validate(self, generation):
        generation_id = Path(generation).name
        if not re.fullmatch(r"gen-[0-9a-f]{32}", generation_id):
            raise InstallError("invalid baseline generation identity")
        if self.walker is None:
            raise InstallError("baseline candidate validation requires the retained trusted walker")
        self.walker.attest()
        parent = self.walker.ensure_dir(self.layout.infra_root)
        temporary_name = ".baseline-validate-" + uuid.uuid4().hex + ".Caddyfile"
        temporary = self.layout.infra_root / temporary_name
        payload = (
            f"import {self.config_root}/server-options.caddy\n"
            f"import {self.config_root}/managed/generations/{generation_id}/sites/*.caddy\n"
        ).encode()
        descriptor = os.open(
            temporary_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent.fd,
        )
        created = os.fstat(descriptor)
        try:
            self.walker._check_file(created, temporary, parent.device)
            if stat.S_IMODE(created.st_mode) != 0o600:
                raise InstallError("baseline candidate temporary mode drift")
            entry = self.walker._lstat(parent, temporary_name)
            if (entry.st_dev, entry.st_ino) != (created.st_dev, created.st_ino):
                raise InstallError("baseline candidate temporary entry changed during create")
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            _fsync_descriptor(descriptor, temporary)
            stable = os.fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(created, field) != getattr(stable, field) for field in fields[:2]):
                raise InstallError("baseline candidate temporary descriptor changed")
            self.walker.attest()
            entry = self.walker._lstat(parent, temporary_name)
            if (entry.st_dev, entry.st_ino) != (stable.st_dev, stable.st_ino):
                raise InstallError("baseline candidate temporary entry changed before validation")
            self._run([
                "/usr/bin/docker", "exec", self.container, "caddy", "validate",
                "--config", self.config_root + "/" + temporary_name,
                "--adapter", "caddyfile",
            ])
            self.walker.attest()
            after = os.fstat(descriptor)
            entry = self.walker._lstat(parent, temporary_name)
            if (
                (after.st_dev, after.st_ino) != (stable.st_dev, stable.st_ino)
                or (entry.st_dev, entry.st_ino) != (stable.st_dev, stable.st_ino)
            ):
                raise InstallError("baseline candidate temporary entry changed during validation")
        finally:
            try:
                entry = self.walker._lstat(parent, temporary_name)
                if (entry.st_dev, entry.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(temporary_name, dir_fd=parent.fd)
                    _fsync_descriptor(parent.fd, self.layout.infra_root)
            except FileNotFoundError:
                pass
            finally:
                os.close(descriptor)

    def reload(self):
        self._run([
            "/usr/bin/docker", "exec", self.container, "caddy", "reload",
            "--config", self.config_root + "/Caddyfile", "--adapter", "caddyfile",
        ])

    def smoke(self, hosts):
        opener = urllib.request.build_opener(_NoBaselineRedirectHandler())
        for host in hosts:
            request = urllib.request.Request("https://" + host + "/", method="HEAD")
            try:
                with opener.open(request, timeout=10) as response:
                    if response.status >= 500:
                        raise InstallError("baseline compatibility smoke returned server error")
            except urllib.error.HTTPError as exc:
                try:
                    if exc.code >= 500:
                        raise InstallError("baseline compatibility smoke returned server error") from exc
                finally:
                    exc.close()
            except InstallError:
                raise
            except Exception as exc:
                raise InstallError("baseline compatibility smoke failed for " + host) from exc


def _require_root_baseline_caller():
    if os.geteuid() != 0:
        raise InstallError("baseline host maintenance must run as root")


def _baseline_current_target(walker, layout):
    walker.attest()
    parent, name = walker._parent_and_name(layout.current_link)
    try:
        before = walker._lstat(parent, name)
        if (
            not stat.S_ISLNK(before.st_mode) or before.st_uid != walker.owner_uid
            or before.st_nlink != 1
        ):
            raise InstallError("managed current pointer is not a trusted root-owned symlink")
        target = os.readlink(name, dir_fd=parent.fd)
        after = walker._lstat(parent, name)
    except OSError as exc:
        raise InstallError("managed current pointer failed stable read") from exc
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise InstallError("managed current pointer changed during stable read")
    if not re.fullmatch(r"generations/gen-[0-9a-f]{32}", target):
        raise InstallError("managed current pointer escapes fixed generations")
    return target


def _baseline_generation_id(bundle_id):
    try:
        validate_bundle_id(bundle_id)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    identity = sha256_bytes(
        b"shared-caddy-baseline-generation/v1\0" + bundle_id.encode("ascii")
    )
    return "gen-" + identity[:32]


def _baseline_input_members(input_dir):
    try:
        return set(os.listdir(input_dir.fd))
    except OSError as exc:
        raise InstallError("baseline input directory failed stable listing") from exc


def _read_baseline_input_member(walker, input_dir, input_dir_path, name, expected_names):
    if _baseline_input_members(input_dir) != expected_names:
        raise InstallError("baseline input directory file set is not exact")
    path = input_dir_path / name
    try:
        entry_before = walker._lstat(input_dir, name)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=input_dir.fd)
    except OSError as exc:
        raise InstallError("baseline input member failed descriptor-relative no-follow open") from exc
    try:
        before = os.fstat(descriptor)
        if (entry_before.st_dev, entry_before.st_ino) != (before.st_dev, before.st_ino):
            raise InstallError("baseline input entry changed while opening")
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != walker.owner_uid or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_dev != input_dir.device
        ):
            raise InstallError(
                "baseline input files must be same-filesystem root-owned mode 0600 single-link files"
            )
        chunks = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        fingerprint = tuple(getattr(before, field) for field in fields)
        if fingerprint != tuple(getattr(after, field) for field in fields):
            raise InstallError("baseline input changed during descriptor-bound stable read")
        entry_after = walker._lstat(input_dir, name)
        if fingerprint != tuple(getattr(entry_after, field) for field in fields):
            raise InstallError("baseline input directory entry changed during stable read")
        if _baseline_input_members(input_dir) != expected_names:
            raise InstallError("baseline input directory member set changed during stable read")
        return b"".join(chunks), fingerprint
    finally:
        os.close(descriptor)


def _baseline_input_snapshot(walker, layout, bundle_id):
    try:
        validate_bundle_id(bundle_id)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    input_root = walker.ensure_dir(layout.baseline_input_root)
    input_dir_path = layout.baseline_input_root / bundle_id
    input_dir = walker.ensure_dir(input_dir_path)
    for handle, display in ((input_root, layout.baseline_input_root), (input_dir, input_dir_path)):
        info = os.fstat(handle.fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != walker.owner_uid:
            raise InstallError("baseline input directories must be root-owned mode 0700: " + str(display))
    expected_names = {"deploy-bundle.tar.gz", "server-manifest.json"}
    if _baseline_input_members(input_dir) != expected_names:
        raise InstallError("baseline input directory file set is not exact")
    values = {}
    fingerprints = {}
    for name in sorted(expected_names):
        values[name], fingerprints[name] = _read_baseline_input_member(
            walker, input_dir, input_dir_path, name, expected_names,
        )
    walker.attest()
    if _baseline_input_members(input_dir) != expected_names:
        raise InstallError("baseline input directory member set changed after stable read")
    if sha256_bytes(values["deploy-bundle.tar.gz"]) != bundle_id:
        raise InstallError("baseline archive bytes differ from baseline-bundle-id")
    manifest = _parse_json(values["server-manifest.json"], "baseline server manifest")
    if values["server-manifest.json"] != _canonical_json(manifest):
        raise InstallError("baseline server manifest is not canonical JSON")
    try:
        _validate_legacy_baseline_manifest(manifest)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    return {
        "archive": values["deploy-bundle.tar.gz"],
        "manifest": manifest,
        "manifest_bytes": values["server-manifest.json"],
        "fingerprints": fingerprints,
    }


def _baseline_archive_artifacts(snapshot):
    try:
        members = _read_legacy_baseline_archive(snapshot["archive"])
        declaration = _parse_json(members["caddy/declaration.json"], "baseline declaration")
        helper_requirement = _parse_json(
            members["caddy/helper-requirement.json"], "baseline helper requirement",
        )
        provenance = _parse_json(
            members["caddy/bundle-provenance.json"], "baseline provenance",
        )
        compose_facts = _parse_json(members["runtime/compose.json"], "baseline Compose facts")
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    for name, value in (
        ("caddy/declaration.json", declaration),
        ("caddy/helper-requirement.json", helper_requirement),
        ("caddy/bundle-provenance.json", provenance),
        ("runtime/compose.json", compose_facts),
    ):
        if members[name] != _canonical_json(value):
            raise InstallError("baseline archive JSON member is not canonical: " + name)
    return {
        "declaration": declaration,
        "fragment": members["caddy/site.caddy"],
        "helper_requirement": helper_requirement,
        "provenance": provenance,
        "compose_facts": compose_facts,
    }


def _attest_baseline_controller(walker, layout, bootstrap):
    helper_data, contract_data, contract = _current_pair(walker, layout)
    if contract is None:
        raise InstallError("baseline import requires an installed attested helper")
    if (
        contract["caddy_container"] != bootstrap["caddy_container"]
        or contract["container_config_root"] != bootstrap["container_config_root"]
    ):
        raise InstallError("installed helper contract differs from bootstrapped Caddy runtime")
    return helper_data, contract_data, contract


def _verify_empty_initial_generation(walker, layout, bootstrap):
    generation = layout.generations_root / bootstrap["initial_generation"]
    generation_handle = walker.ensure_dir(generation)
    if set(os.listdir(generation_handle.fd)) != {"sites", "manifests"}:
        raise InstallError("initial generation is not empty")
    for child in (generation, generation / "sites", generation / "manifests"):
        handle = walker.ensure_dir(child)
        info = os.fstat(handle.fd)
        if stat.S_IMODE(info.st_mode) != 0o500 or info.st_uid != walker.owner_uid:
            raise InstallError("initial generation immutable mode or owner drift")
        if child != generation and os.listdir(handle.fd):
            raise InstallError("initial generation is not empty")
    return bootstrap["initial_generation"]


def _require_untouched_initial_generation(walker, layout, bootstrap, lock_manifest):
    if lock_manifest["deployments"]:
        raise InstallError("baseline import is forbidden after deployment provisioning")
    if _baseline_current_target(walker, layout) != bootstrap["initial_current_target"]:
        raise InstallError("baseline import requires the initial current generation")
    generations = walker.ensure_dir(layout.generations_root)
    if set(os.listdir(generations.fd)) != {bootstrap["initial_generation"]}:
        raise InstallError("baseline import requires an untouched initial generation set")
    return _verify_empty_initial_generation(walker, layout, bootstrap)


def _baseline_transaction_from_artifacts(artifacts, snapshot, transaction_id, old_generation,
                                         new_generation, phase="prepared"):
    provenance = artifacts["provenance"]
    manifest = snapshot["manifest"]
    return {
        "schema_version": "shared-caddy-baseline-transaction/v1",
        "phase": phase,
        "contract_version": CONTRACT_VERSION,
        "helper_version": HELPER_VERSION,
        "helper_sha256": provenance["helper_sha256"],
        "transaction_id": transaction_id,
        "project_id": provenance["project_id"],
        "environment": provenance["environment"],
        "deployment_id": provenance["deployment_id"],
        "source_repo": provenance["source_repo"],
        "archive_id": sha256_bytes(snapshot["archive"]),
        "git_sha": provenance["git_sha"],
        "declaration_sha256": provenance["declaration_sha256"],
        "fragment_sha256": provenance["fragment_sha256"],
        "compose_sha256": provenance["compose_sha256"],
        "helper_requirement_sha256": provenance["helper_requirement_sha256"],
        "baseline_provenance_sha256": sha256_bytes(_canonical_json(provenance)),
        "server_manifest_sha256": sha256_bytes(_canonical_json(manifest)),
        "old_generation": old_generation,
        "new_generation": new_generation,
        "hosts": list(provenance["hosts"]),
    }


def _baseline_receipt_from_transaction(transaction):
    return {
        "schema_version": "shared-caddy-baseline-receipt/v1",
        "status": "committed",
        "contract_version": transaction["contract_version"],
        "helper_version": transaction["helper_version"],
        "helper_sha256": transaction["helper_sha256"],
        "transaction_id": transaction["transaction_id"],
        "project_id": transaction["project_id"],
        "environment": transaction["environment"],
        "deployment_id": transaction["deployment_id"],
        "source_repo": transaction["source_repo"],
        "archive_id": transaction["archive_id"],
        "git_sha": transaction["git_sha"],
        "declaration_sha256": transaction["declaration_sha256"],
        "fragment_sha256": transaction["fragment_sha256"],
        "compose_sha256": transaction["compose_sha256"],
        "helper_requirement_sha256": transaction["helper_requirement_sha256"],
        "baseline_provenance_sha256": transaction["baseline_provenance_sha256"],
        "server_manifest_sha256": transaction["server_manifest_sha256"],
        "old_generation": transaction["old_generation"],
        "generation_id": transaction["new_generation"],
        "hosts": list(transaction["hosts"]),
    }


def _validate_baseline_snapshot_chain(artifacts, snapshot, transaction):
    committed = dict(transaction, phase="committed")
    receipt = _baseline_receipt_from_transaction(committed)
    try:
        validate_legacy_baseline_artifact_chain(
            artifacts["declaration"], artifacts["fragment"], artifacts["compose_facts"],
            artifacts["helper_requirement"], artifacts["provenance"], snapshot["manifest"],
            snapshot["archive"], committed, receipt,
        )
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    return receipt


def _freeze_baseline_generation(walker, generation):
    sites = generation / "sites"
    manifests = generation / "manifests"
    for directory in (sites, manifests):
        handle = walker.ensure_dir(directory)
        for name in os.listdir(handle.fd):
            path = directory / name
            info = walker.lstat(path)
            walker._check_file(info, path, handle.device)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=handle.fd)
            try:
                _fsync_descriptor(descriptor, path)
                os.fchmod(descriptor, 0o400)
                _fsync_descriptor(descriptor, path)
            finally:
                os.close(descriptor)
    for directory in (sites, manifests, generation):
        walker.chmod_dir(directory, 0o500)
    generations_root = generation.parent
    _fsync_descriptor(walker.ensure_dir(generations_root).fd, generations_root)


def _verify_baseline_generation(walker, layout, transaction, snapshot, artifacts):
    generation = layout.generations_root / transaction["new_generation"]
    root_handle = walker.ensure_dir(generation)
    if set(os.listdir(root_handle.fd)) != {"sites", "manifests"}:
        raise InstallError("baseline generation directory set is not exact")
    expected = {
        generation / "sites": {
            transaction["deployment_id"] + ".caddy": artifacts["fragment"],
        },
        generation / "manifests": {
            transaction["deployment_id"] + ".json": _canonical_json(snapshot["manifest"]),
        },
    }
    for directory, files in expected.items():
        handle = walker.ensure_dir(directory)
        if stat.S_IMODE(os.fstat(handle.fd).st_mode) != 0o500:
            raise InstallError("baseline generation directory is not immutable")
        if set(os.listdir(handle.fd)) != set(files):
            raise InstallError("baseline generation file set is not exact")
        for name, content in files.items():
            path = directory / name
            if stat.S_IMODE(walker.lstat(path).st_mode) != 0o400:
                raise InstallError("baseline generation file is not immutable")
            if walker.read_file(path) != content:
                raise InstallError("baseline generation differs from retained input evidence")
    if stat.S_IMODE(os.fstat(root_handle.fd).st_mode) != 0o500:
        raise InstallError("baseline generation root is not immutable")
    return generation


def _phase_baseline(walker, layout, transaction, phase, phase_hook):
    transaction["phase"] = phase
    walker.write_json(layout.maintenance_transaction_path, transaction, 0o600)
    if phase_hook:
        phase_hook(phase, dict(transaction))


def _thaw_and_remove_baseline_generation(walker, generation):
    if not walker.exists(generation):
        return
    for directory in (generation, generation / "sites", generation / "manifests"):
        if walker.exists(directory):
            walker.chmod_dir(directory, 0o700)
    walker.remove_tree(generation)


BASELINE_ROLLBACK_STEPS = (
    "intent", "pointer-restored", "reloaded", "smoked", "candidate-removed",
    "transaction-removed", "receipt-written",
)
BASELINE_RECOVERY_REASONS = {
    "automatic-recovery-result-ambiguous",
    "automatic-rollback-ambiguous",
    "pre-prepared-orphan-ambiguous",
    "pre-transaction-cleanup-ambiguous",
    "retained-state-unproven",
    "rollback-in-progress",
    "runtime-or-evidence-unproven",
}


def _baseline_recovery_binding(value):
    if value is None:
        return {
            "transaction_id": None, "archive_id": None,
            "old_generation": None, "new_generation": None,
        }
    return {
        "transaction_id": value["transaction_id"],
        "archive_id": value["archive_id"],
        "old_generation": value["old_generation"],
        "new_generation": value["new_generation"],
    }


def _baseline_rollback_from_transaction(transaction, step="intent"):
    return {
        "schema_version": "shared-caddy-baseline-rollback/v1",
        "step": step,
        **_baseline_recovery_binding(transaction),
    }


def _validate_baseline_rollback(value, transaction=None):
    _ensure_exact_keys(
        value,
        (
            "schema_version", "step", "transaction_id", "archive_id",
            "old_generation", "new_generation",
        ),
        "baseline rollback",
    )
    if value["schema_version"] != "shared-caddy-baseline-rollback/v1":
        raise InstallError("unknown baseline rollback schema")
    if value["step"] not in BASELINE_ROLLBACK_STEPS:
        raise InstallError("unknown baseline rollback step")
    if not re.fullmatch(r"tx-[0-9a-f]{32}", str(value["transaction_id"])):
        raise InstallError("invalid baseline rollback transaction identity")
    if not SHA256_RE.fullmatch(str(value["archive_id"])):
        raise InstallError("invalid baseline rollback archive identity")
    for field in ("old_generation", "new_generation"):
        if not re.fullmatch(r"gen-[0-9a-f]{32}", str(value[field])):
            raise InstallError("invalid baseline rollback generation identity")
    if value["old_generation"] == value["new_generation"]:
        raise InstallError("baseline rollback generations must differ")
    if transaction is not None and _baseline_recovery_binding(value) != _baseline_recovery_binding(transaction):
        raise InstallError("baseline rollback does not match retained transaction")
    return value


def _baseline_rollback_receipt_from_rollback(rollback):
    _validate_baseline_rollback(rollback)
    return {
        "schema_version": "shared-caddy-baseline-rollback-receipt/v1",
        "status": "rolled-back",
        **_baseline_recovery_binding(rollback),
    }


def _validate_baseline_rollback_receipt(value, rollback=None):
    _ensure_exact_keys(
        value,
        (
            "schema_version", "status", "transaction_id", "archive_id",
            "old_generation", "new_generation",
        ),
        "baseline rollback receipt",
    )
    if value["schema_version"] != "shared-caddy-baseline-rollback-receipt/v1":
        raise InstallError("unknown baseline rollback receipt schema")
    if value["status"] != "rolled-back":
        raise InstallError("invalid baseline rollback receipt status")
    _validate_baseline_rollback({
        "schema_version": "shared-caddy-baseline-rollback/v1",
        "step": "receipt-written",
        **_baseline_recovery_binding(value),
    })
    if rollback is not None and _baseline_recovery_binding(value) != _baseline_recovery_binding(rollback):
        raise InstallError("baseline rollback receipt does not match live rollback")
    return value


def _load_baseline_rollback_receipt(walker, layout, rollback=None):
    raw = walker.read_file(_baseline_rollback_receipt_path(layout))
    value = _parse_json(raw, "baseline rollback receipt")
    if raw != _canonical_json(value):
        raise InstallError("baseline rollback receipt is not canonical JSON")
    return _validate_baseline_rollback_receipt(value, rollback)


def _load_baseline_rollback(walker, layout):
    raw = walker.read_file(_baseline_rollback_path(layout))
    value = _parse_json(raw, "baseline rollback")
    if raw != _canonical_json(value):
        raise InstallError("baseline rollback is not canonical JSON")
    return _validate_baseline_rollback(value)


def _phase_baseline_rollback(walker, layout, rollback, step):
    rollback["step"] = step
    _validate_baseline_rollback(rollback)
    walker.write_json(_baseline_rollback_path(layout), rollback, 0o600)


def _baseline_marker_value(reason, binding=None):
    return {
        "schema_version": "shared-caddy-baseline-recovery-required/v1",
        "reason": reason,
        **_baseline_recovery_binding(binding),
    }


def _validate_baseline_recovery_marker(value, binding=None):
    _ensure_exact_keys(
        value,
        (
            "schema_version", "reason", "transaction_id", "archive_id",
            "old_generation", "new_generation",
        ),
        "baseline recovery marker",
    )
    if value["schema_version"] != "shared-caddy-baseline-recovery-required/v1":
        raise InstallError("maintenance recovery marker is not baseline recovery state")
    if value["reason"] not in BASELINE_RECOVERY_REASONS:
        raise InstallError("invalid baseline recovery marker reason")
    fields = ("transaction_id", "archive_id", "old_generation", "new_generation")
    populated = [value[field] is not None for field in fields]
    if any(populated) and not all(populated):
        raise InstallError("baseline recovery marker binding is partial")
    if all(populated):
        _validate_baseline_rollback({
            "schema_version": "shared-caddy-baseline-rollback/v1",
            "step": "intent",
            **{field: value[field] for field in fields},
        })
    if binding is not None:
        if not all(populated):
            raise InstallError("baseline recovery marker is not bound to retained state")
        if _baseline_recovery_binding(value) != _baseline_recovery_binding(binding):
            raise InstallError("baseline recovery marker does not match retained state")
    return value


def _load_baseline_recovery_marker(walker, layout, binding=None):
    raw = walker.read_file(layout.maintenance_recovery_marker)
    value = _parse_json(raw, "baseline recovery marker")
    if raw != _canonical_json(value):
        raise InstallError("baseline recovery marker is not canonical JSON")
    return _validate_baseline_recovery_marker(value, binding)


def _mark_baseline_recovery(walker, layout, reason, binding=None):
    if walker.exists(layout.maintenance_recovery_marker):
        existing = _load_baseline_recovery_marker(walker, layout)
        if binding is not None and existing["transaction_id"] is None:
            marker = _baseline_marker_value(existing["reason"], binding)
            _validate_baseline_recovery_marker(marker, binding)
            walker.write_json(layout.maintenance_recovery_marker, marker, 0o600)
            return marker
        return _validate_baseline_recovery_marker(existing, binding)
    marker = _baseline_marker_value(reason, binding)
    _validate_baseline_recovery_marker(marker, binding)
    walker.write_json(layout.maintenance_recovery_marker, marker, 0o600)
    return marker


def _baseline_binding_from_retained_state(walker, layout):
    if walker.exists(_baseline_rollback_path(layout)):
        with contextlib.suppress(InstallError, ContractError, KeyError, TypeError):
            return _load_baseline_rollback(walker, layout)
    if walker.exists(layout.maintenance_transaction_path):
        with contextlib.suppress(InstallError, ContractError, KeyError, TypeError):
            transaction = _parse_json(
                walker.read_file(layout.maintenance_transaction_path),
                "baseline maintenance transaction",
            )
            validate_baseline_transaction(transaction)
            return transaction
    return None


def _finish_baseline_commit(walker, layout, transaction, snapshot, artifacts):
    if transaction["phase"] != "committed":
        raise InstallError("baseline receipt is forbidden before committed evidence")
    receipt = _validate_baseline_snapshot_chain(artifacts, snapshot, transaction)
    if walker.exists(layout.baseline_receipt_path):
        existing = _parse_json(
            walker.read_file(layout.baseline_receipt_path), "baseline receipt",
        )
        try:
            validate_baseline_receipt(existing)
        except ContractError as exc:
            raise InstallError(str(exc)) from exc
        if existing != receipt:
            raise InstallError("existing baseline receipt differs from committed transaction")
    else:
        walker.write_json(layout.baseline_receipt_path, receipt, 0o600)
    walker.remove_file(layout.maintenance_transaction_path, missing_ok=True)
    if walker.exists(layout.maintenance_recovery_marker):
        _load_baseline_recovery_marker(walker, layout, transaction)
        walker.remove_file(layout.maintenance_recovery_marker)
    if walker.exists(_baseline_rollback_receipt_path(layout)):
        _load_baseline_rollback_receipt(walker, layout)
        walker.remove_file(_baseline_rollback_receipt_path(layout))
    return receipt


def _rollback_baseline(walker, layout, transaction, runtime, bootstrap):
    if walker.exists(_baseline_rollback_path(layout)):
        rollback = _load_baseline_rollback(walker, layout)
        _validate_baseline_rollback(rollback, transaction)
    else:
        _mark_baseline_recovery(walker, layout, "rollback-in-progress", transaction)
        rollback = _baseline_rollback_from_transaction(transaction)
        walker.write_json(_baseline_rollback_path(layout), rollback, 0o600)
    return _resume_baseline_rollback(walker, layout, rollback, runtime, bootstrap)


def _resume_baseline_rollback(walker, layout, rollback, runtime, bootstrap):
    _validate_baseline_rollback(rollback)
    if not walker.exists(layout.maintenance_recovery_marker):
        raise InstallError("live baseline rollback lost its recovery marker")
    _load_baseline_recovery_marker(walker, layout, rollback)
    old_target = "generations/" + rollback["old_generation"]
    new_target = "generations/" + rollback["new_generation"]
    step = rollback["step"]
    if step != "intent" and _baseline_current_target(walker, layout) != old_target:
        raise InstallError("durable baseline rollback disagrees with current pointer")
    if step == "intent":
        target = _baseline_current_target(walker, layout)
        if target == new_target:
            walker.replace_symlink(layout.current_link, old_target)
        elif target != old_target:
            raise InstallError("baseline rollback pointer state is ambiguous")
        _phase_baseline_rollback(walker, layout, rollback, "pointer-restored")
        step = rollback["step"]
    if step == "pointer-restored":
        runtime.reload()
        _phase_baseline_rollback(walker, layout, rollback, "reloaded")
        step = rollback["step"]
    if step == "reloaded":
        runtime.smoke(())
        _phase_baseline_rollback(walker, layout, rollback, "smoked")
        step = rollback["step"]
    if step == "smoked":
        _thaw_and_remove_baseline_generation(
            walker, layout.generations_root / rollback["new_generation"],
        )
        _phase_baseline_rollback(walker, layout, rollback, "candidate-removed")
        step = rollback["step"]
    if step == "candidate-removed":
        if walker.exists(layout.maintenance_transaction_path):
            retained = _parse_json(
                walker.read_file(layout.maintenance_transaction_path),
                "baseline maintenance transaction",
            )
            try:
                validate_baseline_transaction(retained)
            except ContractError as exc:
                raise InstallError(str(exc)) from exc
            _validate_baseline_rollback(rollback, retained)
            walker.remove_file(layout.maintenance_transaction_path)
        _phase_baseline_rollback(walker, layout, rollback, "transaction-removed")
        step = rollback["step"]
    if step == "transaction-removed":
        receipt = _baseline_rollback_receipt_from_rollback(rollback)
        if walker.exists(_baseline_rollback_receipt_path(layout)):
            retained_receipt = _load_baseline_rollback_receipt(walker, layout, rollback)
            if retained_receipt != receipt:
                raise InstallError("existing baseline rollback receipt differs from live rollback")
        else:
            walker.write_json(_baseline_rollback_receipt_path(layout), receipt, 0o600)
        _phase_baseline_rollback(walker, layout, rollback, "receipt-written")
        step = rollback["step"]
    if step != "receipt-written":
        raise InstallError("baseline rollback could not reach its terminal evidence step")
    _load_baseline_rollback_receipt(walker, layout, rollback)
    walker.remove_file(_baseline_rollback_path(layout))
    return _finish_terminal_baseline_rollback(walker, layout, bootstrap)


def _load_retained_baseline(walker, layout, transaction, helper_hash):
    snapshot = _baseline_input_snapshot(walker, layout, transaction["archive_id"])
    artifacts = _baseline_archive_artifacts(snapshot)
    if artifacts["helper_requirement"]["helper_sha256"] != helper_hash:
        raise InstallError("retained baseline helper requirement differs from installed helper")
    expected = _baseline_transaction_from_artifacts(
        artifacts, snapshot, transaction["transaction_id"], transaction["old_generation"],
        transaction["new_generation"], transaction["phase"],
    )
    if expected != transaction:
        raise InstallError("baseline transaction differs from retained input evidence")
    _validate_baseline_snapshot_chain(artifacts, snapshot, transaction)
    return snapshot, artifacts


def _finish_terminal_baseline_rollback(walker, layout, bootstrap):
    if walker.exists(_baseline_rollback_path(layout)):
        raise InstallError("terminal baseline rollback still has a live rollback ledger")
    receipt = _load_baseline_rollback_receipt(walker, layout)
    if receipt["old_generation"] != bootstrap["initial_generation"]:
        raise InstallError("baseline rollback receipt initial-generation evidence drift")
    if receipt["new_generation"] != _baseline_generation_id(receipt["archive_id"]):
        raise InstallError("baseline rollback receipt generation identity drift")
    if walker.exists(layout.maintenance_recovery_marker):
        _load_baseline_recovery_marker(walker, layout, receipt)
    _verify_empty_initial_generation(walker, layout, bootstrap)
    if _baseline_current_target(walker, layout) != "generations/" + receipt["old_generation"]:
        raise InstallError("baseline rollback receipt current pointer mismatch")
    if walker.exists(layout.generations_root / receipt["new_generation"]):
        raise InstallError("baseline rollback receipt candidate still exists")
    snapshot = _baseline_input_snapshot(walker, layout, receipt["archive_id"])
    _baseline_archive_artifacts(snapshot)
    if walker.exists(layout.maintenance_recovery_marker):
        _load_baseline_recovery_marker(walker, layout, receipt)
        walker.remove_file(layout.maintenance_recovery_marker)
    return {"status": "rolled-back", "transaction_id": receipt["transaction_id"]}


def _recover_prepared_baseline_orphan(walker, layout, bootstrap, helper_hash, runtime):
    generations = walker.ensure_dir(layout.generations_root)
    generation_names = set(os.listdir(generations.fd))
    extras = generation_names - {bootstrap["initial_generation"]}
    if not extras:
        raise InstallError("no baseline maintenance transaction exists")
    try:
        input_root = walker.ensure_dir(layout.baseline_input_root)
        candidates = {}
        for bundle_id in os.listdir(input_root.fd):
            if not SHA256_RE.fullmatch(str(bundle_id)):
                continue
            generation_id = _baseline_generation_id(bundle_id)
            if generation_id in extras:
                candidates.setdefault(generation_id, []).append(bundle_id)
        if any(len(bundle_ids) != 1 for bundle_ids in candidates.values()):
            raise InstallError("pre-prepared baseline orphan generation key collides")
        matches = [
            (generation_id, bundle_ids[0])
            for generation_id, bundle_ids in candidates.items()
        ]
        if len(matches) != 1:
            raise InstallError("pre-prepared baseline orphan full-evidence match is ambiguous")
        new_generation, bundle_id = matches[0]
        if new_generation == bootstrap["initial_generation"]:
            raise InstallError("pre-prepared baseline orphan identity collides with initial state")
        lock_manifest = _load_lock_manifest(walker, layout)
        if lock_manifest["deployments"]:
            raise InstallError("pre-prepared baseline orphan coexists with provisioned deployments")
        if _baseline_current_target(walker, layout) != bootstrap["initial_current_target"]:
            raise InstallError("pre-prepared baseline orphan current pointer is ambiguous")
        _verify_empty_initial_generation(walker, layout, bootstrap)
        snapshot = _baseline_input_snapshot(walker, layout, bundle_id)
        artifacts = _baseline_archive_artifacts(snapshot)
        if artifacts["helper_requirement"]["helper_sha256"] != helper_hash:
            raise InstallError("pre-prepared baseline orphan helper evidence drift")
        transaction_id = "tx-" + sha256_bytes(
            b"shared-caddy-baseline-orphan-recovery/v1\0" + bundle_id.encode("ascii")
        )[:32]
        hypothetical = _baseline_transaction_from_artifacts(
            artifacts, snapshot, transaction_id,
            bootstrap["initial_generation"], new_generation,
        )
        _validate_baseline_snapshot_chain(artifacts, snapshot, hypothetical)
        _verify_baseline_generation(walker, layout, hypothetical, snapshot, artifacts)
        _mark_baseline_recovery(walker, layout, "rollback-in-progress", hypothetical)
        walker.write_json(layout.maintenance_transaction_path, hypothetical, 0o600)
        return _rollback_baseline(walker, layout, hypothetical, runtime, bootstrap)
    except Exception:
        _mark_baseline_recovery(walker, layout, "pre-prepared-orphan-ambiguous")
        raise


def _recover_baseline_locked(walker, layout, bootstrap, contract, helper_hash,
                             runtime, phase_hook):
    if walker.exists(_baseline_rollback_path(layout)):
        rollback = _load_baseline_rollback(walker, layout)
        if rollback["old_generation"] != bootstrap["initial_generation"]:
            raise InstallError("baseline rollback initial-generation evidence drift")
        _verify_empty_initial_generation(walker, layout, bootstrap)
        if walker.exists(layout.maintenance_recovery_marker):
            _load_baseline_recovery_marker(walker, layout, rollback)
        if walker.exists(layout.maintenance_transaction_path):
            transaction = _parse_json(
                walker.read_file(layout.maintenance_transaction_path),
                "baseline maintenance transaction",
            )
            try:
                validate_baseline_transaction(transaction)
            except ContractError as exc:
                raise InstallError(str(exc)) from exc
            if (
                transaction["contract_version"] != contract["contract_version"]
                or transaction["helper_version"] != contract["helper_version"]
                or transaction["helper_sha256"] != helper_hash
            ):
                raise InstallError("baseline rollback controller evidence drift")
            _validate_baseline_rollback(rollback, transaction)
            _load_retained_baseline(walker, layout, transaction, helper_hash)
        elif rollback["step"] not in (
            "candidate-removed", "transaction-removed", "receipt-written",
        ):
            raise InstallError("baseline rollback lost its retained transaction too early")
        return _resume_baseline_rollback(walker, layout, rollback, runtime, bootstrap)

    if not walker.exists(layout.maintenance_transaction_path):
        if (
            not walker.exists(layout.baseline_receipt_path)
            and walker.exists(_baseline_rollback_receipt_path(layout))
        ):
            return _finish_terminal_baseline_rollback(walker, layout, bootstrap)
        if not walker.exists(layout.baseline_receipt_path):
            return _recover_prepared_baseline_orphan(
                walker, layout, bootstrap, helper_hash, runtime,
            )
        receipt = _parse_json(walker.read_file(layout.baseline_receipt_path), "baseline receipt")
        try:
            validate_baseline_receipt(receipt)
        except ContractError as exc:
            raise InstallError(str(exc)) from exc
        transaction = dict(receipt)
        transaction.pop("status")
        transaction["schema_version"] = "shared-caddy-baseline-transaction/v1"
        transaction["phase"] = "committed"
        transaction["new_generation"] = transaction.pop("generation_id")
        if walker.exists(layout.maintenance_recovery_marker):
            _load_baseline_recovery_marker(walker, layout, transaction)
        snapshot, artifacts = _load_retained_baseline(
            walker, layout, transaction, helper_hash,
        )
        if _baseline_current_target(walker, layout) != "generations/" + transaction["new_generation"]:
            raise InstallError("committed baseline receipt current pointer mismatch")
        _verify_baseline_generation(walker, layout, transaction, snapshot, artifacts)
        return _finish_baseline_commit(walker, layout, transaction, snapshot, artifacts)

    transaction = _parse_json(
        walker.read_file(layout.maintenance_transaction_path), "baseline maintenance transaction",
    )
    if transaction.get("schema_version") == "shared-caddy-helper-maintenance/v1":
        raise CrossedMaintenanceRecovery(
            "helper transaction requires the helper recovery action"
        )
    try:
        validate_baseline_transaction(transaction)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    if (
        transaction["contract_version"] != contract["contract_version"]
        or transaction["helper_version"] != contract["helper_version"]
        or transaction["helper_sha256"] != helper_hash
        or transaction["old_generation"] != bootstrap["initial_generation"]
    ):
        raise InstallError("baseline transaction controller or initial-generation evidence drift")
    if walker.exists(layout.maintenance_recovery_marker):
        _load_baseline_recovery_marker(walker, layout, transaction)
    _verify_empty_initial_generation(walker, layout, bootstrap)
    snapshot, artifacts = _load_retained_baseline(walker, layout, transaction, helper_hash)
    target = _baseline_current_target(walker, layout)
    old_target = "generations/" + transaction["old_generation"]
    new_target = "generations/" + transaction["new_generation"]
    if target not in (old_target, new_target):
        raise InstallError("baseline transaction pointer state is ambiguous")
    if transaction["phase"] in ("prepared", "current-switched", "reloaded"):
        return _rollback_baseline(walker, layout, transaction, runtime, bootstrap)
    if target != new_target:
        raise InstallError("successful baseline evidence disagrees with current pointer")
    try:
        generation = _verify_baseline_generation(
            walker, layout, transaction, snapshot, artifacts,
        )
        runtime.validate(generation)
        runtime.reload()
        runtime.smoke(transaction["hosts"])
    except Exception:
        if transaction["phase"] in ("smoked", "verified"):
            return _rollback_baseline(walker, layout, transaction, runtime, bootstrap)
        raise
    if transaction["phase"] == "smoked":
        _phase_baseline(walker, layout, transaction, "smoked", phase_hook)
        _phase_baseline(walker, layout, transaction, "verified", phase_hook)
        _phase_baseline(walker, layout, transaction, "committed", phase_hook)
    elif transaction["phase"] == "verified":
        _phase_baseline(walker, layout, transaction, "verified", phase_hook)
        _phase_baseline(walker, layout, transaction, "committed", phase_hook)
    return _finish_baseline_commit(walker, layout, transaction, snapshot, artifacts)


def import_baseline(layout, bundle_id, owner_uid=0, runtime=None, phase_hook=None):
    """Import the one approved legacy baseline under root-only host maintenance."""
    _require_root_baseline_caller()
    try:
        validate_bundle_id(bundle_id)
    except ContractError as exc:
        raise InstallError(str(exc)) from exc
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
        helper_data, contract_data, contract = _attest_baseline_controller(
            walker, layout, bootstrap,
        )
        if any(walker.exists(path) for path in _blocked_state(layout)):
            raise InstallError("baseline import blocked by app, helper, Caddy, or maintenance state")
        if walker.exists(layout.baseline_receipt_path):
            raise InstallError("legacy baseline was already imported")
        initial_snapshot = _baseline_input_snapshot(walker, layout, bundle_id)
        initial_artifacts = _baseline_archive_artifacts(initial_snapshot)
        lock_fd = _open_shared_lock(walker, layout, lock_manifest)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            walker.attest()
            locked_bootstrap, locked_manifest = _attest_bootstrap(walker, layout)
            locked_helper, locked_contract_data, locked_contract = _attest_baseline_controller(
                walker, layout, locked_bootstrap,
            )
            if (
                locked_bootstrap != bootstrap or locked_manifest != lock_manifest
                or locked_helper != helper_data or locked_contract_data != contract_data
                or locked_contract != contract
            ):
                raise InstallError("baseline controller evidence changed while waiting for shared lock")
            if any(walker.exists(path) for path in _blocked_state(layout)):
                raise InstallError("baseline import blocked by app, helper, Caddy, or maintenance state")
            if walker.exists(layout.baseline_receipt_path):
                raise InstallError("legacy baseline was already imported")
            old_generation = _require_untouched_initial_generation(
                walker, layout, locked_bootstrap, locked_manifest,
            )
            snapshot = _baseline_input_snapshot(walker, layout, bundle_id)
            if snapshot != initial_snapshot:
                raise InstallError("baseline input changed while waiting for shared lock")
            artifacts = _baseline_archive_artifacts(snapshot)
            if artifacts != initial_artifacts:
                raise InstallError("baseline archive interpretation changed while waiting for shared lock")
            helper_hash = sha256_bytes(locked_helper)
            if artifacts["helper_requirement"]["helper_sha256"] != helper_hash:
                raise InstallError("baseline helper requirement differs from installed helper")
            transaction_id = "tx-" + uuid.uuid4().hex
            new_generation = _baseline_generation_id(bundle_id)
            transaction = _baseline_transaction_from_artifacts(
                artifacts, snapshot, transaction_id, old_generation, new_generation,
            )
            _validate_baseline_snapshot_chain(artifacts, snapshot, transaction)
            deployment_id = transaction["deployment_id"]
            if walker.exists(_baseline_rollback_receipt_path(layout)):
                _load_baseline_rollback_receipt(walker, layout)
                walker.remove_file(_baseline_rollback_receipt_path(layout))
            generation = layout.generations_root / new_generation
            transaction_durable = False
            try:
                walker.ensure_dir(generation, 0o700, create=True)
                walker.ensure_dir(generation / "sites", 0o700, create=True)
                walker.ensure_dir(generation / "manifests", 0o700, create=True)
                walker.write_file(
                    generation / "sites" / (deployment_id + ".caddy"),
                    artifacts["fragment"], 0o600,
                )
                walker.write_file(
                    generation / "manifests" / (deployment_id + ".json"),
                    _canonical_json(snapshot["manifest"]), 0o600,
                )
                _freeze_baseline_generation(walker, generation)
                runtime = runtime or BaselineDockerRuntime(locked_contract, layout, walker)
                runtime.validate(generation)
                _verify_baseline_generation(walker, layout, transaction, snapshot, artifacts)
                _phase_baseline(walker, layout, transaction, "prepared", phase_hook)
                transaction_durable = True
                walker.replace_symlink(layout.current_link, "generations/" + new_generation)
                _phase_baseline(walker, layout, transaction, "current-switched", phase_hook)
                runtime.reload()
                _phase_baseline(walker, layout, transaction, "reloaded", phase_hook)
                runtime.smoke(transaction["hosts"])
                _phase_baseline(walker, layout, transaction, "smoked", phase_hook)
                _verify_baseline_generation(walker, layout, transaction, snapshot, artifacts)
                if _baseline_current_target(walker, layout) != "generations/" + new_generation:
                    raise InstallError("baseline current pointer changed before verification")
                _phase_baseline(walker, layout, transaction, "verified", phase_hook)
                _phase_baseline(walker, layout, transaction, "committed", phase_hook)
                return _finish_baseline_commit(walker, layout, transaction, snapshot, artifacts)
            except Exception as exc:
                if transaction_durable:
                    try:
                        recovery = _recover_baseline_locked(
                            walker, layout, locked_bootstrap, locked_contract, helper_hash,
                            runtime, None,
                        )
                    except Exception as recovery_exc:
                        _mark_baseline_recovery(
                            walker, layout, "automatic-rollback-ambiguous", transaction,
                        )
                        raise InstallError("baseline import requires maintenance recovery") from recovery_exc
                    if recovery.get("status") == "committed":
                        return recovery
                    if recovery.get("status") != "rolled-back":
                        _mark_baseline_recovery(
                            walker, layout, "automatic-recovery-result-ambiguous", transaction,
                        )
                        raise InstallError("baseline import recovery returned ambiguous state")
                    raise InstallError("baseline import failed and was rolled back") from exc
                try:
                    _thaw_and_remove_baseline_generation(walker, generation)
                except Exception as cleanup_exc:
                    _mark_baseline_recovery(
                        walker, layout, "pre-transaction-cleanup-ambiguous",
                    )
                    raise InstallError("baseline staging cleanup requires maintenance recovery") from cleanup_exc
                raise
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def recover_baseline_maintenance(layout, owner_uid=0, runtime=None, phase_hook=None):
    """Recover or finish the single retained baseline-maintenance transaction."""
    _require_root_baseline_caller()
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
        lock_fd = _open_shared_lock(walker, layout, lock_manifest)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            walker.attest()
            bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
            _assert_recorded_locks(walker, layout, lock_manifest)
            if walker.exists(layout.transaction_path) or walker.exists(layout.recovery_marker):
                raise InstallError("application/Caddy recovery state blocks baseline maintenance")
            try:
                helper_data, contract_data, contract = _attest_baseline_controller(
                    walker, layout, bootstrap,
                )
                runtime = runtime or BaselineDockerRuntime(contract, layout, walker)
                return _recover_baseline_locked(
                    walker, layout, bootstrap, contract, sha256_bytes(helper_data),
                    runtime, phase_hook,
                )
            except CrossedMaintenanceRecovery:
                raise
            except InstallError:
                if (
                    walker.exists(layout.maintenance_transaction_path)
                    or walker.exists(_baseline_rollback_path(layout))
                    or walker.exists(layout.maintenance_recovery_marker)
                ):
                    _mark_baseline_recovery(
                        walker, layout, "retained-state-unproven",
                        _baseline_binding_from_retained_state(walker, layout),
                    )
                raise
            except Exception as exc:
                if (
                    walker.exists(layout.maintenance_transaction_path)
                    or walker.exists(_baseline_rollback_path(layout))
                    or walker.exists(layout.maintenance_recovery_marker)
                ):
                    _mark_baseline_recovery(
                        walker, layout, "runtime-or-evidence-unproven",
                        _baseline_binding_from_retained_state(walker, layout),
                    )
                raise InstallError("baseline maintenance recovery failed closed") from exc
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def provision_deployments(layout, deployment_ids, owner_uid=0, release_uid=None, release_gid=None):
    if not deployment_ids or release_uid is None or release_gid is None:
        raise InstallError("deployment provisioning requires IDs and fixed release UID/GID")
    with TrustedInstallerWalker(layout.root, owner_uid) as walker:
        bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
        lock_fd = _open_shared_lock(walker, layout, lock_manifest)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            bootstrap, lock_manifest = _attest_bootstrap(walker, layout)
            helper_data, contract_data, contract = _current_pair(walker, layout)
            if contract is None:
                raise InstallError("deployment provisioning requires an installed attested helper")
            if (
                contract["caddy_container"] != bootstrap["caddy_container"]
                or contract["container_config_root"] != bootstrap["container_config_root"]
            ):
                raise InstallError("installed helper contract differs from baseline")
            walker.attest()
            _assert_recorded_locks(walker, layout, lock_manifest, release_gid=release_gid)
            if any(walker.exists(path) for path in _blocked_state(layout)):
                raise InstallError("deployment provisioning blocked by transaction or recovery state")
            updated = json.loads(json.dumps(lock_manifest))
            for deployment_id in deployment_ids:
                validate_deployment_id(deployment_id)
                project_path = layout.project_lock(deployment_id)
                release_path = layout.release_lock(deployment_id)
                if deployment_id not in updated["deployments"]:
                    if walker.exists(project_path) or walker.exists(release_path):
                        raise InstallError("new deployment lock paths already exist without evidence")
                    walker.write_file(project_path, b"", 0o600)
                    walker.write_file(release_path, b"", 0o640)
                    walker.handoff_regular_file(release_path, owner_uid, release_gid, 0o640)
                    project_info = walker.lstat(project_path)
                    release_info = walker.lstat(release_path)
                    updated["deployments"][deployment_id] = {
                        "project": _lock_identity(project_info),
                        "release": _lock_identity(release_info),
                    }
            walker.write_json(layout.lock_manifest_path, updated, 0o600)
            _assert_recorded_locks(walker, layout, updated, release_gid=release_gid)
            for deployment_id in deployment_ids:
                controller_dir = layout.bundle_root / deployment_id
                walker.handoff_directory(controller_dir, release_uid, release_gid, 0o700)
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def install(layout, helper_source, expected_sha256, owner_uid=0, **kwargs):
    """Compatibility name for helper-only maintenance; never bootstraps."""
    forbidden = {key for key, value in kwargs.items() if value not in (None, (), [])}
    if forbidden:
        raise InstallError("helper installation and other maintenance authorities are separate")
    return install_helper(layout, helper_source, expected_sha256, owner_uid=owner_uid)


def _deployment_argument(value):
    try:
        return validate_deployment_id(value)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _hash_argument(value):
    try:
        return validate_bundle_id(value)
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _maintenance_arguments_are_exact(arguments):
    common_empty = (
        not arguments.deployment_id
        and arguments.release_uid is None and arguments.release_gid is None
        and arguments.caddy_container is None and arguments.container_config_root is None
    )
    action = arguments.maintenance_action
    if action == "bootstrap-host":
        return (
            arguments.expected_helper_sha256 is None
            and arguments.baseline_bundle_id is None
            and not arguments.deployment_id
            and arguments.release_uid is None and arguments.release_gid is None
            and bool(arguments.caddy_container) == bool(arguments.container_config_root)
        )
    if action == "install-helper":
        return (
            arguments.expected_helper_sha256 is not None
            and arguments.baseline_bundle_id is None and common_empty
        )
    if action in ("recover-helper-maintenance", "recover-baseline-maintenance"):
        return (
            arguments.expected_helper_sha256 is None
            and arguments.baseline_bundle_id is None and common_empty
        )
    if action == "import-baseline":
        return (
            arguments.expected_helper_sha256 is None
            and arguments.baseline_bundle_id is not None and common_empty
        )
    return (
        arguments.expected_helper_sha256 is None
        and arguments.baseline_bundle_id is None
        and bool(arguments.deployment_id)
        and arguments.release_uid is not None and arguments.release_gid is not None
        and arguments.caddy_container is None and arguments.container_config_root is None
    )


class _MaintenanceArgumentParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        raw_arguments = list(sys.argv[1:] if args is None else args)
        for option in ("--maintenance-action", "--baseline-bundle-id"):
            occurrences = sum(
                token == option or token.startswith(option + "=")
                for token in raw_arguments
            )
            if occurrences > 1:
                self.error(option + " must appear at most once")
        arguments = super().parse_args(args, namespace)
        if not _maintenance_arguments_are_exact(arguments):
            self.error(arguments.maintenance_action + " received missing, crossed, or extra arguments")
        return arguments


def build_parser():
    parser = _MaintenanceArgumentParser(prog="install-shared-caddy-helper", allow_abbrev=False)
    parser.add_argument(
        "--maintenance-action", required=True,
        choices=(
            "bootstrap-host", "install-helper", "recover-helper-maintenance",
            "provision-deployment", "import-baseline", "recover-baseline-maintenance",
        ),
    )
    parser.add_argument("--expected-helper-sha256", type=_hash_argument)
    parser.add_argument("--baseline-bundle-id", type=_hash_argument)
    parser.add_argument("--deployment-id", action="append", default=[], type=_deployment_argument)
    parser.add_argument("--release-uid", type=int)
    parser.add_argument("--release-gid", type=int)
    parser.add_argument("--caddy-container")
    parser.add_argument("--container-config-root")
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        raise InstallError("host-maintenance installer must run as root")
    layout = Layout.for_host()
    source = Path(__file__).with_name("deploydesk_caddy_apply.py")
    action = arguments.maintenance_action
    if action == "bootstrap-host":
        if (
            arguments.expected_helper_sha256 is not None or arguments.deployment_id
            or arguments.release_uid is not None or arguments.release_gid is not None
            or bool(arguments.caddy_container) != bool(arguments.container_config_root)
        ):
            raise InstallError("bootstrap-host accepts only both fixed Caddy runtime fields")
        bootstrap_host(
            layout, owner_uid=0,
            caddy_container=arguments.caddy_container or "caddy",
            container_config_root=arguments.container_config_root or "/etc/caddy",
        )
    elif action == "install-helper":
        if (
            arguments.expected_helper_sha256 is None or arguments.deployment_id
            or arguments.release_uid is not None or arguments.release_gid is not None
            or arguments.caddy_container is not None or arguments.container_config_root is not None
        ):
            raise InstallError("install-helper requires only the independently approved helper hash")
        install_helper(layout, source, arguments.expected_helper_sha256, owner_uid=0)
    elif action == "recover-helper-maintenance":
        if any((
            arguments.expected_helper_sha256 is not None, bool(arguments.deployment_id),
            arguments.release_uid is not None, arguments.release_gid is not None,
            arguments.caddy_container is not None, arguments.container_config_root is not None,
        )):
            raise InstallError("recover-helper-maintenance accepts no mutation parameters")
        recover_helper_maintenance(layout, owner_uid=0)
    elif action == "import-baseline":
        import_baseline(layout, arguments.baseline_bundle_id, owner_uid=0)
    elif action == "recover-baseline-maintenance":
        recover_baseline_maintenance(layout, owner_uid=0)
    else:
        if (
            arguments.expected_helper_sha256 is not None or not arguments.deployment_id
            or arguments.release_uid is None or arguments.release_gid is None
            or arguments.caddy_container is not None or arguments.container_config_root is not None
        ):
            raise InstallError("provision-deployment requires deployment IDs and fixed release UID/GID only")
        provision_deployments(
            layout, arguments.deployment_id, 0, arguments.release_uid, arguments.release_gid
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InstallError, OSError, ValueError, ContractError) as error:
        print("install-shared-caddy-helper: " + str(error), file=sys.stderr)
        raise SystemExit(1)
