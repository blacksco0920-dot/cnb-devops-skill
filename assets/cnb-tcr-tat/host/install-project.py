#!/usr/bin/env python3
"""Preview or root-install one fixed environment controller on a provisioned Ubuntu host.

No dependency downloads, database creation, cloud calls, recovery or production activation.
Runtime values enter only from an administrator's protected local file; output is metadata.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import sys
from types import ModuleType
from datetime import datetime, timezone


class InstallError(Exception):
    pass


PRODUCTION_FILES = {"production-release.py": ("host/production-release.py", 0o555),
                    "production-authority.json": ("production-authority.json", 0o444),
                    "approval-ed25519.pub": ("approval-ed25519.pub", 0o444)}


def canonical(model):
    return (json.dumps(model, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, maximum=8 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise InstallError("unsafe_input_file")
        raw = b""
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw += part
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise InstallError("input_changed")
        return raw
    finally:
        os.close(fd)


def strict_json(raw):
    def unique(pairs):
        model = {}
        for key, value in pairs:
            if key in model:
                raise InstallError("duplicate_json_key")
            model[key] = value
        return model
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=lambda _v: (_ for _ in ()).throw(InstallError("invalid_json")))


def verify_bundle(bundle_dir, lock_sha256=None, *, require_trusted=False):
    bundle_dir = bundle_dir.resolve(strict=True)
    if require_trusted and lock_sha256 is None:
        # An explicit reviewed digest permits a transfer directory; without it all authority
        # ancestors and the lock itself must be an administrator-controlled local copy.
        for path in [bundle_dir / "artifact-lock.json", bundle_dir, *bundle_dir.parents]:
            info = path.lstat()
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise InstallError("reviewed_artifact_lock_sha256_required")
    raw_lock = read_file(bundle_dir / "artifact-lock.json")
    if lock_sha256 is not None and (not re.fullmatch(r"[0-9a-f]{64}", lock_sha256) or digest(raw_lock) != lock_sha256):
        raise InstallError("artifact_lock_mismatch")
    lock = strict_json(raw_lock)
    if (type(lock) is not dict or set(lock) != {"schema", "version", "files"}
        or lock["schema"] != "cnb-devops-artifacts/v1" or type(lock["files"]) is not dict
        or not 1 <= len(lock["files"]) <= 512):
        raise InstallError("artifact_lock_invalid")
    files = {}
    for name, expected in lock["files"].items():
        relative = PurePosixPath(name)
        if (type(name) is not str or relative.is_absolute() or str(relative) != name
            or ".." in relative.parts or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
            or type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise InstallError("artifact_path_invalid")
        current = bundle_dir
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise InstallError("artifact_symlink")
        files[name] = read_file(current)
        if digest(files[name]) != expected:
            raise InstallError("artifact_digest_mismatch")
    required = {"host/tat-deploy-test.py", "host-policy.json", "docker-compose.yml", "tat-command.sh", "bundle.json"}
    if not required <= files.keys():
        raise InstallError("artifact_files_missing")
    # Execute the captured, verified bytes; do not reopen a mutable transfer-path program.
    host = ModuleType("installed_release_controller")
    host.__file__ = str(bundle_dir / "host/tat-deploy-test.py")
    exec(compile(files["host/tat-deploy-test.py"], host.__file__, "exec"), host.__dict__)
    policy = host.validate_host_policy(strict_json(files["host-policy.json"]))
    policy_sha = digest(files["host-policy.json"])
    if digest(files["docker-compose.yml"]) != policy["compose_sha256"]:
        raise InstallError("compose_identity_mismatch")
    if policy["environment"] == "production":
        if not {source for source, _mode in PRODUCTION_FILES.values()} <= files.keys():
            raise InstallError("production_authority_files_missing")
        wrapper = ModuleType("installed_production_authorization")
        wrapper.__file__ = str(bundle_dir / "host/production-release.py")
        exec(compile(files["host/production-release.py"], wrapper.__file__, "exec"), wrapper.__dict__)
        try:
            authority = wrapper.validate_authority(strict_json(files["production-authority.json"]))
        except Exception as error:
            raise InstallError("production_authority_invalid") from error
        expected = {"schema": "cnb-production-authority/v1", "project": policy["project"], "environment": "production",
                    "controller_program_sha256": digest(files["host/tat-deploy-test.py"]),
                    "host_policy_sha256": policy_sha, "controller_compose_sha256": digest(files["docker-compose.yml"]),
                    "approval_public_key_sha256": digest(files["approval-ed25519.pub"])}
        if authority != expected:
            raise InstallError("production_authority_mismatch")
        public = files["approval-ed25519.pub"]
        match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/]{59}=)\n-----END PUBLIC KEY-----\n", public)
        der = base64.b64decode(match[1], validate=True) if match else b""
        if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100") or base64.b64encode(der) != match[1]:
            raise InstallError("approval_ed25519_spki_required")
        template = wrapper.render_tat_template(policy, digest(files["host/production-release.py"]), digest(files["production-authority.json"]))
    else:
        template = host.render_tat_template(policy, digest(files["host/tat-deploy-test.py"]), policy_sha)
    if files["tat-command.sh"] != template:
        raise InstallError("tat_shim_mismatch")
    if "recovery-policy.json" in files:
        if "host/recover-project.py" not in files:
            raise InstallError("recovery_program_missing")
        recovery = ModuleType("installed_project_recovery")
        recovery.__file__ = str(bundle_dir / "host/recover-project.py")
        exec(compile(files["host/recover-project.py"], recovery.__file__, "exec"), recovery.__dict__)
        try:
            recovery.validate_recovery_policy(strict_json(files["recovery-policy.json"]), policy, policy_sha)
        except Exception as error:
            raise InstallError("recovery_policy_invalid") from error
    host.configure_policy(policy, policy_sha256=policy_sha)
    return {"host": host, "policy": policy, "files": files, "raw_lock": raw_lock,
            "lock_sha256": digest(raw_lock), "version": lock["version"]}


def ensure_directory(path, mode, uid, gid):
    if path.is_symlink():
        raise InstallError("directory_symlink")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            raise InstallError("directory_metadata_mismatch")
        return
    os.mkdir(path, mode)
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def verify_file(path, raw, mode, uid, gid):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode)
        or read_file(path) != raw):
        raise InstallError("existing_file_mismatch")


def install_file(path, raw, mode, uid, gid):
    if path.exists() or path.is_symlink():
        verify_file(path, raw, mode, uid, gid)
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def prepare_runtime_env(host, raw):
    text = raw.decode("utf-8", "strict")
    if not text.endswith("\n"):
        text += "\n"
    keys = set()
    for line in text.splitlines():
        if line.strip() and not line.strip().startswith("#"):
            match = host.ENV_LINE.fullmatch(line)
            if match is None or match[1] in keys:
                raise InstallError("runtime_environment_invalid")
            keys.add(match[1])
            if match[1] in host.IMAGE_KEYS.values() and match[2] != "uninitialized":
                raise InstallError("bootstrap_image_value_forbidden")
    for image_key in sorted(set(host.IMAGE_KEYS.values()) - keys):
        text += image_key + "=uninitialized\n"
    _lines, values, _indexes = host._parse_env(text)
    host.parse_test_database_url(values[host.POLICY["database"]["url_env"]])
    if host.POLICY.get("redis"):
        host.parse_test_redis_url(values[host.POLICY["redis"]["url_env"]])
        if "prefix_env" in host.POLICY["redis"]:
            host.validate_test_redis_prefix(values[host.POLICY["redis"]["prefix_env"]])
    return text.encode("utf-8")


def check_dependencies(host, release_account):
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise InstallError("ubuntu_24_04_required")
    if sys.version_info < (3, 12):
        raise InstallError("python_3_12_required")
    binaries = (host.DOCKER, host.CURL) + (("/usr/bin/openssl",) if host.POLICY["environment"] == "production" else ())
    for binary in binaries:
        host._regular_file(Path(binary), 128 * 1024 * 1024)
    info = host._regular_file(host.DOCKER_CONFIG, 1024 * 1024, 0o600)
    if (info.st_uid, info.st_gid) != (release_account.pw_uid, release_account.pw_gid):
        raise InstallError("pull_credential_ownership")
    host._run(host._docker_prefix() + ["info", "--format", "{{json .ServerVersion}}"])
    host._run(["/usr/sbin/runuser", "-u", host.POLICY["release_user"], "--", *host._docker_prefix(),
               "info", "--format", "{{json .ServerVersion}}"])
    if not re.fullmatch(rb"v?2\.[0-9]+\.[0-9]+(?:[^\s]*)?", host._run(host._docker_prefix() + ["compose", "version", "--short"]).strip()):
        raise InstallError("compose_v2_required")
    for network in host.POLICY["networks"]:
        host._run(host._docker_prefix() + ["network", "inspect", network])
    database = host.POLICY["database"]
    prefix = host._docker_prefix() + ["exec", database["container"]]
    server = host._run(prefix + ["psql", "--no-psqlrc", "-U", database["admin_user"], "-d", database["name"], "-Atc", "SHOW server_version_num"], max_output=128)
    major = int(server.strip()) // 10000
    for tool in ("pg_dump", "pg_restore"):
        version = host._run(prefix + [tool, "--version"], max_output=128)
        if re.search(rb"PostgreSQL\) " + str(major).encode() + rb"\.", version) is None:
            raise InstallError("postgresql_client_version_mismatch")


def assert_new_or_matching_install(plan, env_raw, account, fixed):
    """Classify app ownership before creating any new installation authority or paths."""
    host = plan["host"]
    names = host._run(host._docker_prefix() + ["ps", "--all", "--format", "{{.Names}}"],
                      timeout=30, max_output=256 * 1024).decode("utf-8", "strict").splitlines()
    if set(names) & set(host.CONTAINERS.values()):
        raise InstallError("existing_application_container")
    app = host.APP_DIR
    if not app.exists() and not app.is_symlink():
        return
    info = app.lstat()
    if (not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (account.pw_uid, account.pw_gid, 0o750)):
        raise InstallError("existing_application_unrecognized")
    if not any(app.iterdir()):
        return
    # Database emptiness alone is not proof that an existing application is ours.
    # A nonempty directory may resume only an exact root-attested partial installation.
    try:
        install = Path(plan["policy"]["install_dir"])
        for name, (raw, mode) in fixed.items():
            verify_file(install / name, raw, mode, 0, 0)
        baseline, _sha = host._installed_empty_baseline()
        if baseline["runtime_env_sha256"] != digest(env_raw):
            raise InstallError("bootstrap_environment_changed")
        expected_files = {
            host.ENV_PATH: (env_raw, 0o600),
            host.COMPOSE_PATH: (plan["files"]["docker-compose.yml"], 0o644),
            host.RELEASE_PATH: (canonical(baseline), 0o600),
        }
        allowed_dirs = set()
        for service in host.POLICY["services"].values():
            for mount in service["mounts"]:
                directory = Path(mount["source"])
                if not directory.is_relative_to(app) or directory == app:
                    raise InstallError("existing_application_unrecognized")
                while directory != app:
                    allowed_dirs.add(directory)
                    directory = directory.parent
        pending = [app]
        while pending:
            for path in pending.pop().iterdir():
                if path in expected_files:
                    raw, mode = expected_files[path]
                    verify_file(path, raw, mode, account.pw_uid, account.pw_gid)
                elif path in allowed_dirs:
                    info = path.lstat()
                    if (not stat.S_ISDIR(info.st_mode)
                        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (account.pw_uid, account.pw_gid, 0o750)):
                        raise InstallError("existing_application_unrecognized")
                    pending.append(path)
                else:
                    raise InstallError("existing_application_unrecognized")
    except Exception as exc:
        if isinstance(exc, InstallError):
            raise
        raise InstallError("existing_application_unrecognized") from exc


def apply_install(plan, runtime_env, *, installed_lock_sha256=None):
    if os.geteuid() != 0:
        raise InstallError("root_administrator_required")
    if installed_lock_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", installed_lock_sha256):
        raise InstallError("reviewed_installed_lock_invalid")
    host, policy = plan["host"], plan["policy"]
    account = pwd.getpwnam(policy["release_user"])
    if account.pw_dir != policy["release_home"]:
        raise InstallError("release_home_mismatch")
    install = Path(policy["install_dir"])
    fixed = {"tat-deploy-test.py": (plan["files"]["host/tat-deploy-test.py"], 0o555),
             "host-policy.json": (plan["files"]["host-policy.json"], 0o444),
             "docker-compose.yml": (plan["files"]["docker-compose.yml"], 0o444),
             "tat-command.sh": (plan["files"]["tat-command.sh"], 0o444),
             "artifact-lock.json": (plan["raw_lock"], 0o444)}
    if policy["environment"] == "production":
        fixed.update({name: (plan["files"][source], mode) for name, (source, mode) in PRODUCTION_FILES.items()})
    if "recovery-policy.json" in plan["files"]:
        fixed.update({"recovery-policy.json": (plan["files"]["recovery-policy.json"], 0o444),
                      "recover-project.py": (plan["files"]["host/recover-project.py"], 0o555)})
    # Completed installation is read-only even after ordinary release changes its runtime env.
    receipt_path = install / "installation.json"
    if receipt_path.exists():
        receipt, _sha = host.read_root_owned_json(receipt_path)
        if installed_lock_sha256 is not None and receipt != {"schema": "cnb-test-installation/v1", "lock_sha256": installed_lock_sha256}:
            raise InstallError("reviewed_installed_lock_mismatch")
        if receipt != {"schema": "cnb-test-installation/v1", "lock_sha256": plan["lock_sha256"]}:
            if installed_lock_sha256 is None:
                raise InstallError("installed_version_mismatch")
            old_raw = read_file(install / "artifact-lock.json")
            verify_file(install / "artifact-lock.json", old_raw, 0o444, 0, 0)
            old, new = strict_json(old_raw), strict_json(plan["raw_lock"])
            helpers = {"bundle.json", "host/bootstrap-host.py", "host/install-project.py",
                       "host/setup-project.py", "host/configure-native-caddy.py"}
            if (digest(old_raw) != installed_lock_sha256 or type(old) is not dict
                or set(old) != {"schema", "version", "files"} or old["schema"] != new["schema"]
                or old["version"] != new["version"] or type(old["files"]) is not dict
                or old["files"].keys() != new["files"].keys()
                or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in old["files"].values())
                or any(old["files"][name] != value and name not in helpers for name, value in new["files"].items())):
                raise InstallError("administrator_helper_only_resume_required")
            # The installed authority and its original receipt remain byte-for-byte intact.
            fixed["artifact-lock.json"] = (old_raw, 0o444)
        for name, (raw, mode) in fixed.items():
            if not (install / name).exists():
                raise InstallError("installed_file_missing")
            install_file(install / name, raw, mode, 0, 0)
        host._installed_empty_baseline()
        plan["installed_lock_sha256"] = receipt["lock_sha256"]
        return "unchanged"
    if installed_lock_sha256 is not None:
        raise InstallError("reviewed_installation_missing")
    check_dependencies(host, account)
    info = runtime_env.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
        raise InstallError("protected_runtime_env_required")
    env_raw = prepare_runtime_env(host, read_file(runtime_env, 1024 * 1024))
    assert_new_or_matching_install(plan, env_raw, account, fixed)
    # Only an empty pre-existing scoped database can establish this first-install authority.
    host._assert_database_empty()
    for parent in reversed(install.parents):
        if parent == Path("/"):
            continue
        ensure_directory(parent, 0o755, 0, 0)
    ensure_directory(install, 0o755, 0, 0)
    ensure_directory(host.APP_DIR.parent, 0o755, 0, 0)
    lock_fd = os.open(host.LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
            raise InstallError("release_lock_unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchown(lock_fd, account.pw_uid, account.pw_gid)
        os.fchmod(lock_fd, 0o600)
        # Recheck under the shared lock before any authority files are installed.
        assert_new_or_matching_install(plan, env_raw, account, fixed)
        # Reject existing projects; interrupted installs may resume only exact matching files.
        if host.TRANSACTION_PATH.exists() or host.TRANSACTION_PATH.is_symlink():
            raise InstallError("recovery_required")
        if host.RELEASE_PATH.exists():
            record = strict_json(read_file(host.RELEASE_PATH))
            if record.get("schema") != host.EMPTY_BASELINE_SCHEMA:
                raise InstallError("existing_project_requires_adoption")
        for name, (raw, mode) in fixed.items():
            install_file(install / name, raw, mode, 0, 0)
        baseline_path = install / "empty-baseline.json"
        baseline = {
            "schema": host.EMPTY_BASELINE_SCHEMA, "status": "empty", "images": {},
            "project": policy["project"], "environment": policy["environment"], "controller": host.CONTROLLER_ID,
            "policy_sha256": host.POLICY_SHA256, "database": policy["database"],
            "runtime_env_sha256": digest(env_raw), "controller_compose_sha256": policy["compose_sha256"],
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        if baseline_path.exists():
            previous, _sha = host.read_root_owned_json(baseline_path)
            baseline["created_at"] = previous.get("created_at")
        install_file(baseline_path, canonical(baseline), 0o444, 0, 0)
        ensure_directory(host.APP_DIR, 0o750, account.pw_uid, account.pw_gid)
        install_file(host.ENV_PATH, env_raw, 0o600, account.pw_uid, account.pw_gid)
        install_file(host.COMPOSE_PATH, plan["files"]["docker-compose.yml"], 0o644, account.pw_uid, account.pw_gid)
        for service in policy["services"].values():
            for mount in service["mounts"]:
                ensure_directory(Path(mount["source"]), 0o750, account.pw_uid, account.pw_gid)
        install_file(host.RELEASE_PATH, canonical(baseline), 0o600, account.pw_uid, account.pw_gid)
        # Receipt is last; absent receipt permits only exact-content interrupted-install resumption.
        install_file(receipt_path, canonical({"schema": "cnb-test-installation/v1", "lock_sha256": plan["lock_sha256"]}), 0o444, 0, 0)
        plan["installed_lock_sha256"] = plan["lock_sha256"]
        return "installed"
    finally:
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--runtime-env", type=Path, required=True)
    parser.add_argument("--lock-sha256")
    parser.add_argument("--apply", action="store_true")
    values = parser.parse_args(argv)
    plan = verify_bundle(values.bundle_dir, values.lock_sha256, require_trusted=values.apply)
    status = apply_install(plan, values.runtime_env) if values.apply else "preview"
    print(json.dumps({"schema": "cnb-install-result/v1", "status": status,
                      "project": plan["policy"]["project"], "environment": plan["policy"]["environment"], "version": plan["version"],
                      "artifact_lock_sha256": plan["lock_sha256"],
                      "requires": ["Ubuntu 24.04", "Docker Compose v2", "pre-existing empty PostgreSQL database",
                                   "release user Docker access", "private TCR pull credentials", "approved external networks"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc) if isinstance(exc, InstallError) and re.fullmatch(r"[a-z0-9_]+", str(exc)) else "installation_failed"
        print(json.dumps({"schema": "cnb-install-result/v1", "status": "failed", "reason": code}, sort_keys=True))
        raise SystemExit(1)
