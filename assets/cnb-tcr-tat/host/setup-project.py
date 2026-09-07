#!/usr/bin/env python3
"""Administrator-only sequencing of the existing bootstrap, installer and Caddy helper.

Called from the SSH gate with captured, reviewed bytes. Never used by ordinary TAT.
Only the Docker login file reaches this host; no cloud API or signing key is accepted.
"""
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import tarfile
from types import ModuleType


class SetupError(ValueError):
    pass


def require(value, code):
    if not value:
        raise SetupError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "SETUP_DUPLICATE_JSON")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(SetupError("SETUP_JSON_INVALID")))


def module(files, name):
    result = ModuleType("verified_setup_" + name.replace("-", "_"))
    result.__file__ = "/verified/" + name
    exec(compile(files["bundle/host/" + name], result.__file__, "exec"), result.__dict__)
    return result


def validate_inputs(files, expected):
    require(type(expected) is dict and set(expected) == {"lock_sha256", "spec_sha256", "docker_config_sha256", "caddy_baseline_sha256"}, "SETUP_EXPECTATION_INVALID")
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
                for key, value in expected.items() if key != "caddy_baseline_sha256" or value is not None), "SETUP_EXPECTATION_INVALID")
    require(sha(files["bundle/artifact-lock.json"]) == expected["lock_sha256"], "SETUP_LOCK_MISMATCH")
    lock = strict_json(files["bundle/artifact-lock.json"])
    require(type(lock) is dict and set(lock) == {"schema", "version", "files"} and lock["schema"] == "cnb-devops-artifacts/v1"
            and type(lock["files"]) is dict and 1 <= len(lock["files"]) <= 512, "SETUP_LOCK_INVALID")
    require(set(files) == {"bundle/" + name for name in lock["files"]} | {"bundle/artifact-lock.json", "bootstrap-spec.json", "docker-config.json"}, "SETUP_ARCHIVE_FILES_INVALID")
    for name, digest in lock["files"].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and str(path) == name and ".." not in path.parts
                and re.fullmatch(r"[A-Za-z0-9_./-]+", name) and sha(files["bundle/" + name]) == digest, "SETUP_BUNDLE_DRIFT")
    require(sha(files["bootstrap-spec.json"]) == expected["spec_sha256"]
            and sha(files["docker-config.json"]) == expected["docker_config_sha256"], "SETUP_PRIVATE_INPUT_DRIFT")
    installer = module(files, "install-project.py")
    core = module(files, "tat-deploy-test.py")
    policy = core.validate_host_policy(strict_json(files["bundle/host-policy.json"]))
    bootstrap, caddy = module(files, "bootstrap-host.py"), module(files, "configure-native-caddy.py")
    caddy.render_sites(policy, policy["project"], sha(files["bundle/host-policy.json"]), policy["environment"])
    spec = bootstrap.validate_spec(strict_json(files["bootstrap-spec.json"]), policy, sha(files["bundle/host-policy.json"]), apply=True)
    config = strict_json(files["docker-config.json"])
    registries = {s["image_repository"].split("/", 1)[0] for s in policy["services"].values()}
    registries |= {image.split("/", 1)[0] for image in spec["images"].values()}
    require(type(config) is dict and set(config) == {"auths"} and type(config["auths"]) is dict
            and set(config["auths"]) == registries, "SETUP_DOCKER_AUTH_SCOPE")
    for entry in config["auths"].values():
        require(type(entry) is dict and set(entry) == {"auth"} and type(entry["auth"]) is str, "SETUP_DOCKER_AUTH_INVALID")
        decoded = base64.b64decode(entry["auth"], validate=True)
        require(base64.b64encode(decoded).decode() == entry["auth"] and b":" in decoded
                and all(part for part in decoded.split(b":", 1)) and all(32 < c < 127 for c in decoded), "SETUP_DOCKER_AUTH_INVALID")
    return policy, spec, installer, bootstrap, caddy


def archive_members(raw):
    require(0 < len(raw) <= 128 * 1024 * 1024, "SETUP_ARCHIVE_SIZE")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for item in archive:
            require(item.isfile() and item.name not in result and 0 < item.size <= 8 * 1024 * 1024
                    and len(result) < 516, "SETUP_ARCHIVE_INVALID")
            result[item.name] = archive.extractfile(item).read()
    return result


def existing_private(path, installer):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600, "SETUP_STATE_UNSAFE")
    return installer.read_file(path)


def materialize(task, files, installer):
    allowed = set(files) | {"caddy-baseline.json", "setup-receipt.json"}
    directories = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}
    installer.ensure_directory(task, 0o700, 0, 0)
    if task.exists():
        for path in task.rglob("*"):
            relative = path.relative_to(task).as_posix()
            require(not path.is_symlink(), "SETUP_STATE_UNSAFE")
            if path.is_dir():
                require(relative in directories, "SETUP_UNKNOWN_STATE")
                installer.ensure_directory(path, 0o700, 0, 0)
            else:
                require(relative in allowed, "SETUP_UNKNOWN_STATE")
                prior = existing_private(path, installer)
                require(relative not in files or prior == files[relative], "SETUP_STAGED_INPUT_DRIFT")
    for relative, raw in sorted(files.items()):
        path = task / relative
        for parent in reversed(path.parents):
            if parent != task and task in parent.parents:
                installer.ensure_directory(parent, 0o700, 0, 0)
        installer.install_file(path, raw, 0o600, 0, 0)


def ensure_caddy(spec, baseline_sha, task, installer, bootstrap, caddy):
    """An existing proxy always needs a reviewed baseline; only our new install records one."""
    binary, config = Path("/usr/bin/caddy"), Path("/etc/caddy/Caddyfile")
    receipt = task / "caddy-baseline.json"
    if receipt.exists():
        record = strict_json(existing_private(receipt, installer))
        require(set(record) == {"schema", "package_version", "baseline_sha256"}
                and record["schema"] == "cnb-new-caddy-baseline/v1"
                and record["package_version"] == spec["docker_packages"].get("caddy"), "SETUP_CADDY_STATE_DRIFT")
        require(baseline_sha in (None, record["baseline_sha256"]), "SETUP_CADDY_BASELINE_DRIFT")
        baseline_sha = record["baseline_sha256"]
    if binary.exists() or binary.is_symlink():
        require(baseline_sha is not None, "SETUP_EXISTING_CADDY_BASELINE_REQUIRED")
        caddy.check_system()
        return baseline_sha
    require(not config.exists() and not config.is_symlink() and not receipt.exists(), "SETUP_EXISTING_CADDY_CONFIG")
    version = spec["docker_packages"].get("caddy")
    require(type(version) is str and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", version), "SETUP_PINNED_CADDY_REQUIRED")
    bootstrap.run(["/usr/bin/apt-get", "update"], timeout=300)
    bootstrap.run(["/usr/bin/apt-get", "install", "--yes", "--no-install-recommends", "caddy=" + version], timeout=600)
    require(bootstrap.run(["/usr/bin/dpkg-query", "--show", "--showformat=${Version}", "caddy"]).decode().strip() == version, "SETUP_CADDY_PACKAGE_MISMATCH")
    bootstrap.run(["/usr/bin/systemctl", "enable", "--now", "caddy"])
    caddy.check_system()
    actual = sha(caddy.read_safe(config)[0])
    require(baseline_sha in (None, actual), "SETUP_CADDY_BASELINE_DRIFT")
    installer.install_file(receipt, canonical({"schema": "cnb-new-caddy-baseline/v1", "package_version": version,
                                               "baseline_sha256": actual}), 0o600, 0, 0)
    return actual


def setup_archive(raw, expected):
    require(os.geteuid() == 0, "SETUP_ROOT_REQUIRED")
    files = archive_members(raw)
    policy, spec, installer, bootstrap, caddy = validate_inputs(files, expected)
    release = Path("/etc/os-release").read_text()
    require(re.search(r"^ID=ubuntu$", release, re.M) and re.search(r'^VERSION_ID="24\.04"$', release, re.M), "SETUP_UBUNTU_REQUIRED")
    scope = policy["project"] + "-" + policy["environment"]
    lock_dir = Path("/run/lock")
    info = lock_dir.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, "SETUP_LOCK_UNSAFE")
    fd = os.open(lock_dir / ("cnb-devops-" + scope + "-setup.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "SETUP_LOCK_UNSAFE")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = Path("/var/lib/cnb-devops") / policy["project"] / policy["environment"]
        for parent in [*reversed(state.parents), state]:
            if parent != Path("/"):
                installer.ensure_directory(parent, 0o755, 0, 0)
        installer.ensure_directory(state / "setup", 0o700, 0, 0)
        task = state / "setup" / sha(canonical(expected))[:24]
        materialize(task, files, installer)
        plan = installer.verify_bundle(task / "bundle", expected["lock_sha256"], require_trusted=True)
        installed = Path(policy["install_dir"]) / "installation.json"
        app = Path(policy["app_dir"])
        require(installed.exists() or not app.exists() or not any(app.iterdir()), "SETUP_EXISTING_APPLICATION")
        baseline_sha = ensure_caddy(spec, expected["caddy_baseline_sha256"], task, installer, bootstrap, caddy)
        # Preflight the reviewed existing proxy before infrastructure or account changes.
        config, site, _policy_path = caddy.paths(policy["project"], policy["environment"])
        original = caddy.read_safe(config)[0]
        suffix = ("\nimport " + str(site) + "\n").encode()
        baseline = original[:-len(suffix)] if original.endswith(suffix) else original
        require(sha(baseline) == baseline_sha and not re.search(rb"\bimport\b|\{\$", baseline), "SETUP_CADDY_BASELINE_DRIFT")
        try:
            account = pwd.getpwnam(policy["release_user"])
        except KeyError:
            bootstrap.run(["/usr/sbin/useradd", "--create-home", "--shell", "/bin/bash", policy["release_user"]])
            account = pwd.getpwnam(policy["release_user"])
        require(account.pw_dir == policy["release_home"], "SETUP_RELEASE_HOME_MISMATCH")
        docker_config = Path(policy["docker_config"])
        installer.ensure_directory(docker_config.parent, 0o700, account.pw_uid, account.pw_gid)
        installer.install_file(docker_config, files["docker-config.json"], 0o600, account.pw_uid, account.pw_gid)
        runtime = state / "bootstrap/runtime.env"
        if not installed.exists():
            with bootstrap.bootstrap_lock(policy["project"], policy["environment"]):
                runtime = bootstrap.apply_bootstrap(installer, plan, spec, expected["spec_sha256"])
        installer.apply_install(plan, runtime)
        with caddy.locked():
            result = caddy.configure(policy["project"], sha(files["bundle/host-policy.json"]), baseline_sha, apply=True, environment=policy["environment"])
        receipt_path = task / "setup-receipt.json"
        receipt = {"schema": "cnb-host-setup/v1", "status": "ready", "project": policy["project"], "environment": policy["environment"],
                   "lock_sha256": expected["lock_sha256"], "spec_sha256": expected["spec_sha256"], "docker_config_sha256": expected["docker_config_sha256"],
                   "caddy_baseline_sha256": baseline_sha, "site_sha256": result["site_sha256"], "receipt_path": str(receipt_path),
                   "release_executed": False, "https_verified": False}
        installer.install_file(receipt_path, canonical(receipt), 0o600, 0, 0)
        return receipt
    finally:
        os.close(fd)
