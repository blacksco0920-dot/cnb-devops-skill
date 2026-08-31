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
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


CONTRACT_VERSION = "shared-caddy-contract/v1"
HELPER_VERSION = "1.0.0"
DEPLOYMENT_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?--"
    r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_RUNTIME_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
CONFIG_ROOT_RE = re.compile(r"/(?:[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+)*")
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


def _blocked_state(layout, include_maintenance=True):
    paths = [layout.transaction_path, layout.recovery_marker]
    if include_maintenance:
        paths.extend((layout.maintenance_transaction_path, layout.maintenance_recovery_marker))
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
            if walker.exists(layout.transaction_path) or walker.exists(layout.recovery_marker):
                raise InstallError("application/Caddy state blocks helper maintenance recovery")
            try:
                transaction = _parse_json(
                    walker.read_file(layout.maintenance_transaction_path), "maintenance transaction"
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


def build_parser():
    parser = argparse.ArgumentParser(prog="install-shared-caddy-helper", allow_abbrev=False)
    parser.add_argument(
        "--maintenance-action", required=True,
        choices=("bootstrap-host", "install-helper", "recover-helper-maintenance", "provision-deployment"),
    )
    parser.add_argument("--expected-helper-sha256", type=_hash_argument)
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
