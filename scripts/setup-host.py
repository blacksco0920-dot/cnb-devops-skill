#!/usr/bin/env python3
"""Preview or explicitly perform one reviewed administrator setup over strict SSH.

No SDK, password prompt, listener, or persistent SSH configuration is created.
The archive is streamed through SSH stdin; private values never enter argv/output.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import ModuleType


class SetupError(ValueError):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_safe(path, modes=None, limit=8 * 1024 * 1024):
    path = Path(os.path.abspath(path))
    try:
        for parent in path.parents:
            info = parent.lstat()
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky):
                raise SetupError("SETUP_INPUT_PATH_UNSAFE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid not in (0, os.getuid())
                or before.st_mode & 0o022 or (modes and stat.S_IMODE(before.st_mode) not in modes)
                or not 0 < before.st_size <= limit):
                raise SetupError("SETUP_INPUT_FILE_UNSAFE")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in fields) or len(raw) != before.st_size:
            raise SetupError("SETUP_INPUT_CHANGED")
        return raw
    except OSError as error:
        raise SetupError("SETUP_INPUT_FILE_UNSAFE") from error


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SetupError("SETUP_JSON_INVALID")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as error:
        raise SetupError("SETUP_JSON_INVALID") from error


def native_shared_input(directory, plan, target_path):
    """Bind reviewed local maintenance evidence; only value-free input travels."""
    directory = Path(directory)
    validate_output_path(directory / "native-caddy-shared-input.json")
    names = ("native-caddy-shared-input.json", "inventory.json", "maintenance-authorization.json",
             "gateway-recovery-receipt.json", "credential-review-receipt.json")
    try:
        raw = {name: read_safe(directory / name, {0o600}, 1024 * 1024) for name in names}
        model = {name: strict_json(value) for name, value in raw.items()}
        shared = model[names[0]]
        fields = {"schema", "inventory_sha256", "maintenance_authorization_sha256",
                  "gateway_recovery_receipt_sha256", "credential_review_receipt_sha256"}
        if (type(shared) is not dict or set(shared) != fields
                or shared["schema"] != "cnb-native-caddy-shared-input/v1"
                or any(type(shared[key]) is not str or not re.fullmatch('[a-f0-9]{64}', shared[key]) for key in fields - {"schema"})):
            raise ValueError()
        inventory = model["inventory.json"]
        inventory_sha = sha(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        if inventory.get("schema") != "cnb-native-caddy-inventory/v1" or inventory.get("status") != "verified" or shared["inventory_sha256"] != inventory_sha:
            raise ValueError()
        for field, name in (("maintenance_authorization_sha256", "maintenance-authorization.json"),
                            ("gateway_recovery_receipt_sha256", "gateway-recovery-receipt.json"),
                            ("credential_review_receipt_sha256", "credential-review-receipt.json")):
            if shared[field] != sha(raw[name]):
                raise ValueError()
        target_sha = sha(read_safe(target_path, {0o600}))
        authorization = model["maintenance-authorization.json"]
        if (authorization.get("schema") != "cnb-native-caddy-maintenance-authorization/v1"
                or authorization.get("status") != "authorized"
                or authorization.get("project") != plan["policy"]["project"]
                or authorization.get("environment") != plan["policy"]["environment"]
                or authorization.get("source_target_sha256") != target_sha
                or authorization.get("inventory_sha256") != inventory_sha
                or authorization.get("scope") != ["preserve-existing", "add-project-static-routes"]
                or type(authorization.get("authorization_source")) is not str
                or not 1 <= len(authorization["authorization_source"]) <= 4096):
            raise ValueError()
        recovery = model["gateway-recovery-receipt.json"]
        if (recovery.get("schema") != "cnb-native-caddy-recovery/v1" or recovery.get("status") != "verified"
                or recovery.get("source_inventory_sha256") != inventory_sha
                or recovery.get("source_target_sha256") != target_sha
                or any(recovery.get(key) is not True for key in ("source_unchanged", "config_restored", "tls_restored", "isolated"))):
            raise ValueError()
        credentials = model["credential-review-receipt.json"]
        if (credentials.get("schema") != "cnb-native-caddy-credential-review/v1"
                or credentials.get("status") != "reviewed"
                or credentials.get("source_target_sha256") != target_sha
                or credentials.get("inventory_sha256") != inventory_sha
                or type(credentials.get("unresolved")) is not list or credentials["unresolved"]
                or type(credentials.get("evidence")) is not list or not credentials["evidence"]):
            raise ValueError()
        return raw[names[0]]
    except (KeyError, TypeError, ValueError, SetupError) as error:
        raise SetupError("SETUP_NATIVE_SHARED_EVIDENCE_INVALID") from error


def prepare(args):
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", args.lock_sha256):
            raise SetupError("SETUP_LOCK_INVALID")
        raw_lock = read_safe(args.bundle_dir / "artifact-lock.json")
        if sha(raw_lock) != args.lock_sha256:
            raise SetupError("SETUP_LOCK_MISMATCH")
        lock = strict_json(raw_lock)
        source = read_safe(args.bundle_dir / "host/install-project.py")
        if sha(source) != lock["files"]["host/install-project.py"]:
            raise SetupError("SETUP_INSTALLER_MISMATCH")
        installer = ModuleType("setup_local_installer")
        installer.__file__ = str(args.bundle_dir / "host/install-project.py")
        exec(compile(source, installer.__file__, "exec"), installer.__dict__)
        plan = installer.verify_bundle(args.bundle_dir, args.lock_sha256)
        files = {"bundle/" + name: raw for name, raw in plan["files"].items()}
        files["bundle/artifact-lock.json"] = raw_lock
        files["bootstrap-spec.json"] = read_safe(args.bootstrap_spec, {0o600})
        files["docker-config.json"] = read_safe(args.tcr_docker_config, {0o600})
        expected = {"lock_sha256": args.lock_sha256, "spec_sha256": sha(files["bootstrap-spec.json"]),
                    "docker_config_sha256": sha(files["docker-config.json"]), "caddy_baseline_sha256": args.caddy_baseline_sha256,
                    "installed_lock_sha256": getattr(args, "installed_lock_sha256", None)}
        driver = ModuleType("setup_local_driver")
        driver.__file__ = str(args.bundle_dir / "host/setup-project.py")
        driver_raw = files["bundle/host/setup-project.py"]
        exec(compile(driver_raw, driver.__file__, "exec"), driver.__dict__)
        target = strict_json(read_safe(args.target, {0o600}))
        if (type(target) is not dict or set(target) != {"host", "port", "user", "identity_file", "known_hosts_file"}
            or type(target["host"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target["host"])
            or type(target["port"]) is not int or not 1 <= target["port"] <= 65535
            or target["user"] not in ("root", plan["policy"]["release_user"])):
            raise SetupError("SETUP_TARGET_INVALID")
        for key, modes in [("identity_file", {0o400, 0o600}), ("known_hosts_file", {0o400, 0o600, 0o644})]:
            if type(target[key]) is not str or not Path(target[key]).is_absolute():
                raise SetupError("SETUP_TARGET_INVALID")
            read_safe(target[key], modes, 1024 * 1024)
        if getattr(args, "native_caddy_shared_dir", None):
            shared = native_shared_input(args.native_caddy_shared_dir, plan, args.target)
            files["native-caddy-shared-input.json"] = shared
            expected["native_caddy_shared_sha256"] = sha(shared)
        if getattr(args, "runtime_import", None):
            runtime_import = read_safe(args.runtime_import, {0o600}, 1024 * 1024)
            files["runtime-import.env"] = runtime_import
            expected["runtime_import_sha256"] = sha(runtime_import)
        driver.validate_inputs(files, expected)
        return plan, files, expected, target
    except SetupError:
        raise
    except Exception as error:
        raise SetupError("SETUP_BUNDLE_INVALID") from error


ROOT_GATE = r'''
import hashlib, io, json, re, sys, tarfile
try:
    archive = sys.stdin.buffer.read(128 * 1024 * 1024 + 1)
    if len(archive) > 128 * 1024 * 1024: raise ValueError()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        item = stream.getmember('bundle/host/setup-project.py')
        if not item.isfile() or item.size > 1024 * 1024: raise ValueError()
        source = stream.extractfile(item).read()
    if hashlib.sha256(source).hexdigest() != sys.argv[1]: raise ValueError()
    namespace = {'__name__': 'verified_setup_driver', '__file__': '/verified/setup-project.py'}
    exec(compile(source, namespace['__file__'], 'exec'), namespace)
    print(json.dumps(namespace['setup_archive'](archive, json.loads(sys.argv[2])), sort_keys=True))
except Exception as error:
    code = str(error)
    if re.fullmatch('CADDY_[A-Z_]+', code): code = 'SETUP_' + code
    print(json.dumps({'schema':'cnb-host-setup/v1','status':'failed','code':code if re.fullmatch('SETUP_[A-Z0-9_]+', code) else 'SETUP_REMOTE_FAILED'}))
    sys.exit(1)
'''


def archive_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(raw), 0o600
            archive.addfile(item, io.BytesIO(raw))
    if output.tell() > 128 * 1024 * 1024:
        raise SetupError("SETUP_BUNDLE_TOO_LARGE")
    return output.getvalue()


INSTALLATION_GATE = r'''
import base64, json, os, stat, sys
try:
    install = sys.argv[1]
    if not install.startswith('/opt/cnb-devops/') or not install.endswith('/v1'): raise ValueError()
    result = {}
    for name in ('installation.json', 'artifact-lock.json', 'host-policy.json', 'tat-deploy-test.py'):
        path = os.path.join(install, name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in (0o444, 0o555) or info.st_size > 8 * 1024 * 1024: raise ValueError()
            raw = stream.read(8 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
        fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if len(raw) != info.st_size or any(getattr(info, key) != getattr(after, key) for key in fields): raise ValueError()
        result[name] = base64.b64encode(raw).decode('ascii')
    print(json.dumps({'schema':'cnb-installation-capture/v1','files':result}, sort_keys=True))
except Exception:
    print(json.dumps({'schema':'cnb-installation-capture/v1','status':'failed'}))
    sys.exit(1)
'''


def ssh_command(target, remote):
    command = ["/usr/bin/ssh", "-F", "/dev/null", "-p", str(target["port"]), "-i", target["identity_file"]]
    for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
                   "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                   "GlobalKnownHostsFile=/dev/null", "UserKnownHostsFile=" + target["known_hosts_file"],
                   "ConnectTimeout=15", "ConnectionAttempts=1", "ServerAliveInterval=15", "ServerAliveCountMax=3"):
        command += ["-o", option]
    return command + [target["user"] + "@" + target["host"], shlex.join(remote)]


def validate_output_path(path):
    path = Path(os.path.abspath(path))
    try:
        for parent in path.parents:
            info = parent.lstat()
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not sticky)):
                raise SetupError("SETUP_INSTALLATION_OUTPUT_UNSAFE")
        info = path.parent.lstat()
        if info.st_mode & 0o077:
            raise SetupError("SETUP_INSTALLATION_OUTPUT_UNSAFE")
        if path.exists() or path.is_symlink():
            read_safe(path, {0o600}, 1024 * 1024)
        return path
    except (OSError, SetupError) as error:
        if isinstance(error, SetupError) and str(error) == "SETUP_INSTALLATION_OUTPUT_UNSAFE":
            raise
        raise SetupError("SETUP_INSTALLATION_OUTPUT_UNSAFE") from error


def decode_installation_capture(raw, plan, installed_lock_sha256):
    try:
        capture = strict_json(raw)
        if type(capture) is not dict or set(capture) != {"schema", "files"} or capture["schema"] != "cnb-installation-capture/v1":
            raise ValueError()
        names = {"installation.json", "artifact-lock.json", "host-policy.json", "tat-deploy-test.py"}
        if type(capture["files"]) is not dict or set(capture["files"]) != names:
            raise ValueError()
        files = {name: base64.b64decode(capture["files"][name], validate=True) for name in names}
        receipt = strict_json(files["installation.json"])
        if receipt != {"schema": "cnb-test-installation/v1", "lock_sha256": installed_lock_sha256}:
            raise ValueError()
        lock = strict_json(files["artifact-lock.json"])
        if (sha(files["artifact-lock.json"]) != installed_lock_sha256 or type(lock) is not dict
            or set(lock) != {"schema", "version", "files"} or lock["schema"] != "cnb-devops-artifacts/v1"
            or type(lock["files"]) is not dict):
            raise ValueError()
        for installed_name, lock_name in (("host-policy.json", "host-policy.json"), ("tat-deploy-test.py", "host/tat-deploy-test.py")):
            if lock["files"].get(lock_name) != sha(files[installed_name]):
                raise ValueError()
        if files["host-policy.json"] != plan["files"]["host-policy.json"] or files["tat-deploy-test.py"] != plan["files"]["host/tat-deploy-test.py"]:
            raise ValueError()
        policy = strict_json(files["host-policy.json"])
        if policy.get("project") != plan["policy"]["project"] or policy.get("environment") != plan["policy"]["environment"] or policy.get("install_dir") != plan["policy"]["install_dir"]:
            raise ValueError()
        return files["installation.json"]
    except Exception as error:
        raise SetupError("SETUP_READY_INSTALLATION_READBACK_INVALID") from error


def save_installation(path, raw):
    temporary = None
    try:
        if path.exists() or path.is_symlink():
            if read_safe(path, {0o600}, 1024 * 1024) != raw:
                raise SetupError("SETUP_READY_INSTALLATION_OUTPUT_CONFLICT")
            return
        fd, name = tempfile.mkstemp(prefix=".installation-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if read_safe(path, {0o600}, 1024 * 1024) != raw:
                raise SetupError("SETUP_READY_INSTALLATION_OUTPUT_CONFLICT")
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except SetupError as error:
        if str(error) == "SETUP_READY_INSTALLATION_OUTPUT_CONFLICT":
            raise
        raise SetupError("SETUP_READY_INSTALLATION_OUTPUT_UNSAFE") from error
    except OSError as error:
        raise SetupError("SETUP_READY_INSTALLATION_OUTPUT_UNSAFE") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle-dir", "target", "bootstrap-spec", "tcr-docker-config"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--caddy-baseline-sha256")
    parser.add_argument("--installed-lock-sha256", help="explicit reviewed prior lock; permits only administrator helper compatibility changes")
    parser.add_argument("--installation-output", type=Path, help="protected local destination for the verified original installation receipt")
    parser.add_argument("--native-caddy-shared-dir", type=Path, help="protected directory of reviewed native shared-host inventory and maintenance evidence")
    parser.add_argument("--runtime-import", type=Path, help="protected first-install runtime values validated against the reviewed policy")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    plan, files, expected, target = prepare(args)
    installation_output = validate_output_path(args.installation_output) if args.installation_output else None
    result = {"schema": "cnb-host-setup/v1", "status": "preview", "project": plan["policy"]["project"],
              "environment": plan["policy"]["environment"], **expected,
              "actions": ["strict SSH root gate", "protected reviewed inputs", "pinned infrastructure bootstrap",
                          "fixed controller installation", "reviewed native Caddy sites"], "release_executed": False}
    if args.apply:
        remote = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8",
                  "/usr/bin/python3", "-I", "-c", ROOT_GATE, sha(files["bundle/host/setup-project.py"]), json.dumps(expected, separators=(",", ":"))]
        if target["user"] != "root":
            remote = ["/usr/bin/sudo", "-n", "--", *remote]
        command = ssh_command(target, remote)
        try:
            completed = subprocess.run(command, input=archive_bytes(files), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600, check=False)
            response = strict_json(completed.stdout) if len(completed.stdout) <= 65536 else {}
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SetupError("SETUP_SSH_INCOMPLETE") from error
        if completed.returncode or type(response) is not dict or any(response.get(k) != result[k] for k in ("schema", "project", "environment", "lock_sha256")) or response.get("status") != "ready":
            if type(response) is dict and type(response.get("code")) is str and re.fullmatch(r"SETUP_[A-Z0-9_]+", response["code"]):
                raise SetupError(response["code"])
            raise SetupError("SETUP_REMOTE_NOT_VERIFIED")
        # Only selected non-secret receipt fields cross the process boundary.
        actual_installed = response.get("installed_lock_sha256")
        if actual_installed != (args.installed_lock_sha256 or args.lock_sha256):
            raise SetupError("SETUP_INSTALLED_LOCK_MISMATCH")
        result = {key: response[key] for key in ("schema", "status", "project", "environment", "lock_sha256")}
        result.update(installed_lock_sha256=actual_installed, release_executed=False, receipt_path=response.get("receipt_path"), caddy_baseline_sha256=response.get("caddy_baseline_sha256"))
        if installation_output:
            read_remote = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8",
                           "/usr/bin/python3", "-I", "-c", INSTALLATION_GATE, plan["policy"]["install_dir"]]
            if target["user"] != "root":
                read_remote = ["/usr/bin/sudo", "-n", "--", *read_remote]
            try:
                captured = subprocess.run(ssh_command(target, read_remote), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise SetupError("SETUP_READY_INSTALLATION_READBACK_INCOMPLETE") from error
            if captured.returncode or len(captured.stdout) > 16 * 1024 * 1024:
                raise SetupError("SETUP_READY_INSTALLATION_READBACK_INCOMPLETE")
            installation_raw = decode_installation_capture(captured.stdout, plan, actual_installed)
            save_installation(installation_output, installation_raw)
            result.update(installation_path=str(installation_output), installation_sha256=sha(installation_raw))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if isinstance(error, SetupError) else "SETUP_FAILED"
        print(json.dumps({"schema": "cnb-host-setup/v1", "status": "failed", "code": code}))
        raise SystemExit(1)
