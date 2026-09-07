#!/usr/bin/env python3
"""Preview or explicitly perform one reviewed administrator setup over strict SSH.

No SDK, password prompt, listener, or persistent SSH configuration is created.
The archive is streamed through SSH stdin; private values never enter argv/output.
"""
import argparse
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
        driver.validate_inputs(files, expected)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle-dir", "target", "bootstrap-spec", "tcr-docker-config"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--caddy-baseline-sha256")
    parser.add_argument("--installed-lock-sha256", help="explicit reviewed prior lock; permits only administrator helper compatibility changes")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    plan, files, expected, target = prepare(args)
    result = {"schema": "cnb-host-setup/v1", "status": "preview", "project": plan["policy"]["project"],
              "environment": plan["policy"]["environment"], **expected,
              "actions": ["strict SSH root gate", "protected reviewed inputs", "pinned infrastructure bootstrap",
                          "fixed controller installation", "reviewed native Caddy sites"], "release_executed": False}
    if args.apply:
        remote = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8",
                  "/usr/bin/python3", "-I", "-c", ROOT_GATE, sha(files["bundle/host/setup-project.py"]), json.dumps(expected, separators=(",", ":"))]
        if target["user"] != "root":
            remote = ["/usr/bin/sudo", "-n", "--", *remote]
        command = ["/usr/bin/ssh", "-F", "/dev/null", "-p", str(target["port"]), "-i", target["identity_file"]]
        for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
                       "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                       "GlobalKnownHostsFile=/dev/null", "UserKnownHostsFile=" + target["known_hosts_file"],
                       "ConnectTimeout=15", "ConnectionAttempts=1", "ServerAliveInterval=15", "ServerAliveCountMax=3"):
            command += ["-o", option]
        command += [target["user"] + "@" + target["host"], shlex.join(remote)]
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
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if isinstance(error, SetupError) else "SETUP_FAILED"
        print(json.dumps({"schema": "cnb-host-setup/v1", "status": "failed", "code": code}))
        raise SystemExit(1)
