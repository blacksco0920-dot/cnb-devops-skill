#!/usr/bin/env python3
"""First-host preset: Ubuntu 24.04, project PostgreSQL 16 and optional Redis 7.

Default is an offline plan. Apply requires reviewed artifact-lock/spec SHA-256 values.
Input bootstrap-spec.json: {schema:'cnb-first-host/v1', policy_sha256, images:
{postgres: TCR_REPOSITORY@sha256:DIGEST, redis: OPTIONAL_DIGEST}, docker_packages:
{'docker.io': EXACT_APT_VERSION, 'docker-compose-v2': EXACT_APT_VERSION,
'curl': EXACT_APT_VERSION}, generate_env:['AUTH_TOKEN_SECRET']}.
Missing image pins may be null for planning; missing package versions block installation
only when that package is needed. Existing apt repositories are never changed.

Generated private values stay in root-only host state and Docker runtime configuration.
No secret is printed, passed in host command arguments, or embedded in a TAT command.
No existing Caddy, application, database or unrelated Docker object is adopted/replaced.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
from types import ModuleType
from urllib.parse import quote


class BootstrapError(Exception):
    pass


# Only these fixed program-defined reasons may leave administrator setup.
SAFE_ERROR_CODES = frozenset({
    'apt_caddy_install_failed', 'apt_caddy_update_failed', 'apt_docker_install_failed',
    'apt_docker_update_failed', 'artifact_lock_mismatch', 'base_image_version_check_failed',
    'base_image_version_mismatch', 'bootstrap_busy', 'bootstrap_lock_unsafe',
    'bootstrap_receipt_mismatch', 'bootstrap_scope_invalid', 'bootstrap_spec_mismatch',
    'bootstrap_state_mismatch', 'caddy_package_query_failed', 'caddy_service_start_failed',
    'compose_v2_required', 'credential_state_invalid', 'database_authentication_failed',
    'database_provision_failed', 'database_role_check_failed', 'database_role_mismatch',
    'docker_compose_check_failed', 'docker_engine_check_failed', 'docker_group_assign_failed',
    'docker_service_start_failed', 'exact_apt_package_versions_required', 'existing_compose_incompatible',
    'existing_container_incompatible', 'existing_network_incompatible', 'existing_resource_not_owned',
    'existing_volume_incompatible', 'external_runtime_values_required', 'host_command_failed',
    'infrastructure_health_check_failed', 'infrastructure_start_failed', 'infrastructure_unhealthy',
    'installer_identity_mismatch', 'network_create_failed', 'postgres_image_pull_failed',
    'protected_runtime_import_required', 'redis_image_pull_failed', 'release_home_mismatch',
    'release_user_create_failed', 'resource_inventory_invalid', 'resource_state_missing',
    'root_administrator_required', 'runtime_import_invalid', 'ubuntu_24_04_required',
    'unknown_bootstrap_state', 'unsupported_bootstrap_spec', 'volume_create_failed',
})


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run(command, *, input=None, timeout=180, failure_code="host_command_failed"):
    failure_code = failure_code if failure_code in SAFE_ERROR_CODES else "host_command_failed"
    try:
        result = subprocess.run(command, input=input, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                "HOME": "/root", "LANG": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive"})
        if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
            raise BootstrapError(failure_code)
        return result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(failure_code) from exc


def binary_exists(name):
    return Path("/usr/bin", name).is_file()


def docker(policy):
    return ["/usr/bin/docker", "--config", str(Path(policy["docker_config"]).parent)]


def validate_spec(spec, policy, policy_sha256, *, apply=False):
    def require(condition):
        if not condition:
            raise ValueError("invalid bootstrap input")
    try:
        scope = policy["project"] + "-" + policy["environment"]
        fields = {"schema", "policy_sha256", "images", "docker_packages", "generate_env"}
        require(fields <= set(spec) <= fields | {"resource_limits", "postgres_extensions"})
        require(spec.get("postgres_extensions", []) in ([], ["vector"]))
        require(spec["schema"] == "cnb-first-host/v1" and spec["policy_sha256"] == policy_sha256)
        require(policy["environment"] in ("test", "production") and policy["networks"] == [scope])
        db = policy["database"]
        require(db["container"] == db["host"] == scope + "-postgres" and db["port"] == 5432)
        require(db["admin_user"] == "postgres" and db["user"] != "postgres")
        require(all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", db[k]) for k in ("name", "user")))
        roles = {"postgres"}
        if policy.get("redis"):
            redis = policy["redis"]
            require(redis["container"] == redis["host"] == scope + "-redis")
            require(redis["port"] == 6379 and redis["database"] == 0)
            roles.add("redis")
        require(set(spec["images"]) == roles)
        if "resource_limits" in spec:
            require(type(spec["resource_limits"]) is dict and set(spec["resource_limits"]) == roles)
            for limits in spec["resource_limits"].values():
                require(type(limits) is dict and set(limits) == {"memory_bytes", "cpu_millis"}
                        and type(limits["memory_bytes"]) is int and 32 * 1024 ** 2 <= limits["memory_bytes"] <= 64 * 1024 ** 3
                        and type(limits["cpu_millis"]) is int and 50 <= limits["cpu_millis"] <= 64000)
        for image in spec["images"].values():
            if image is None and not apply:
                continue
            require(type(image) is str and re.fullmatch(
                r"(?:ccr\.ccs\.tencentyun\.com|[a-z0-9.-]+\.tencentcloudcr\.com)/[a-z0-9._/-]+@sha256:[0-9a-f]{64}", image))
            require(".." not in image and "//" not in image)
        require(type(spec["docker_packages"]) is dict)
        require(set(spec["docker_packages"]) <= {"docker.io", "docker-compose-v2", "curl", "ca-certificates", "caddy"})
        require(all(type(v) is str and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,127}", v)
                   for v in spec["docker_packages"].values()))
        generated = spec["generate_env"]
        require(type(generated) is list and len(generated) == len(set(generated)))
        reserved = {db["url_env"]} | ({policy["redis"]["url_env"]} if policy.get("redis") else set())
        reserved |= {s["image_env"] for s in policy["services"].values()}
        require(set(generated) <= set(policy["required_env"]) - reserved)
        require(all(re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key) for key in generated))
    except (AssertionError, KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("unsupported_bootstrap_spec") from exc
    return spec


def ensure_docker(spec):
    missing = []
    if not binary_exists("docker"):
        missing += ["docker.io", "docker-compose-v2"]
    else:
        run(["/usr/bin/docker", "version", "--format", "{{.Server.Version}}"], failure_code="docker_engine_check_failed")
        try:
            compose = run(["/usr/bin/docker", "compose", "version", "--short"], failure_code="docker_compose_check_failed").strip()
        except BootstrapError:
            missing.append("docker-compose-v2")
        else:
            if not re.fullmatch(rb"v?2\.[0-9]+\.[0-9]+[^\s]*", compose):
                raise BootstrapError("existing_compose_incompatible")
    if not binary_exists("curl"):
        missing.append("curl")
    if missing:
        if any(name not in spec["docker_packages"] for name in missing):
            raise BootstrapError("exact_apt_package_versions_required")
        run(["/usr/bin/apt-get", "update"], timeout=300, failure_code="apt_docker_update_failed")
        # APT 2.7.14 debSystem::Lock waits on dpkg locks; this does not cover apt lists locks.
        # https://github.com/Debian/apt/blob/2.7.14/apt-pkg/deb/debsystem.cc
        run(["/usr/bin/apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "--yes", "--no-install-recommends",
             *[name + "=" + spec["docker_packages"][name] for name in missing]], timeout=720,
            failure_code="apt_docker_install_failed")
        if "docker.io" in missing:
            run(["/usr/bin/systemctl", "enable", "--now", "docker"], failure_code="docker_service_start_failed")
        run(["/usr/bin/docker", "version", "--format", "{{.Server.Version}}"], failure_code="docker_engine_check_failed")
        version = run(["/usr/bin/docker", "compose", "version", "--short"], failure_code="docker_compose_check_failed").strip()
        if not re.fullmatch(rb"v?2\.[0-9]+\.[0-9]+[^\s]*", version):
            raise BootstrapError("compose_v2_required")


def labels(policy, spec_sha256):
    return {"io.cnb-devops.project": policy["project"], "io.cnb-devops.environment": policy["environment"],
            "io.cnb-devops.bootstrap-spec": spec_sha256}


def compose_model(policy, spec, spec_sha256):
    scope = policy["project"] + "-" + policy["environment"]
    services = {}
    owned = labels(policy, spec_sha256)
    for role, image in spec["images"].items():
        service = {"image": image, "container_name": scope + "-" + role, "restart": "unless-stopped",
                   "labels": owned, "networks": [scope],
                   "volumes": [{"type": "volume", "source": role + "-data",
                                "target": "/var/lib/postgresql/data" if role == "postgres" else "/data"}]}
        if "resource_limits" in spec:
            limits = spec["resource_limits"][role]
            service.update(mem_limit=limits["memory_bytes"], cpus=limits["cpu_millis"] / 1000)
        if role == "postgres":
            service["environment"] = {"POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres",
                                      "POSTGRES_PASSWORD": "${BOOTSTRAP_PG_ADMIN_PASSWORD:?required}"}
            test = ["CMD", "pg_isready", "-U", "postgres", "-d", "postgres"]
        else:
            service["environment"] = {"BOOTSTRAP_REDIS_PASSWORD": "${BOOTSTRAP_REDIS_PASSWORD:?required}"}
            service["command"] = ["redis-server", "--appendonly", "yes", "--requirepass", "${BOOTSTRAP_REDIS_PASSWORD:?required}"]
            test = ["CMD-SHELL", 'test "$(redis-cli --no-auth-warning -a "$$BOOTSTRAP_REDIS_PASSWORD" ping)" = PONG']
        service["healthcheck"] = {"test": test, "interval": "5s", "timeout": "5s", "retries": 30}
        services[role] = service
    return {"name": scope + "-data", "services": services,
            "networks": {scope: {"external": True, "name": scope}},
            "volumes": {role + "-data": {"external": True, "name": scope + "-" + role + "-data"}
                        for role in spec["images"]}}


def inventory_resources(policy, spec, execute=run):
    scope = policy["project"] + "-" + policy["environment"]
    wanted = {"network": [scope], "volume": [scope + "-" + r + "-data" for r in spec["images"]],
              "container": [scope + "-" + r for r in spec["images"]]}
    result = {kind: {} for kind in wanted}
    for kind, requested in wanted.items():
        command = docker(policy) + [kind, "ls"] + (["--all"] if kind == "container" else [])
        names = execute(command + ["--format", "{{.Names}}" if kind == "container" else "{{.Name}}"])
        available = set(names.decode("utf-8", "strict").splitlines())
        for name in set(requested) & available:
            inspected = json.loads(execute(docker(policy) + [kind, "inspect", name]))
            if type(inspected) is not list or len(inspected) != 1:
                raise BootstrapError("resource_inventory_invalid")
            result[kind][name] = inspected[0]
    return result


def validate_resources(policy, spec, spec_sha256, inventory):
    scope, owned = policy["project"] + "-" + policy["environment"], labels(policy, spec_sha256)
    for kind, resources in inventory.items():
        for name, resource in resources.items():
            actual_labels = resource.get("Config", {}).get("Labels", {}) if kind == "container" else resource.get("Labels", {})
            if any(actual_labels.get(key) != value for key, value in owned.items()):
                raise BootstrapError("existing_resource_not_owned")
            if kind == "network" and resource.get("Driver") != "bridge":
                raise BootstrapError("existing_network_incompatible")
            if kind == "volume" and (resource.get("Driver") != "local" or resource.get("Options") not in (None, {})):
                raise BootstrapError("existing_volume_incompatible")
            if kind == "container":
                role = name[len(scope) + 1:]
                if "resource_limits" in spec:
                    expected = spec["resource_limits"].get(role, {})
                    actual = resource.get("HostConfig", {})
                    if (actual.get("Memory") != expected.get("memory_bytes")
                            or actual.get("NanoCpus") != expected.get("cpu_millis", 0) * 1000000):
                        raise BootstrapError("existing_container_incompatible")
                if (resource.get("Config", {}).get("Image") != spec["images"].get(role)
                    or resource.get("HostConfig", {}).get("Privileged") is not False
                    or resource.get("HostConfig", {}).get("PortBindings") not in (None, {})
                    or set(resource.get("NetworkSettings", {}).get("Networks", {})) != {scope}
                    or [(m.get("Type"), m.get("Name"), m.get("Destination")) for m in resource.get("Mounts", [])]
                       != [("volume", scope + "-" + role + "-data", "/var/lib/postgresql/data" if role == "postgres" else "/data")]):
                    raise BootstrapError("existing_container_incompatible")


def credential_keys(spec):
    keys = {"BOOTSTRAP_PG_ADMIN_PASSWORD", "BOOTSTRAP_PG_APP_PASSWORD"} | set(spec["generate_env"])
    if "redis" in spec["images"]:
        keys.add("BOOTSTRAP_REDIS_PASSWORD")
    return keys


def generate_credentials(spec):
    return {key: secrets.token_urlsafe(48) for key in sorted(credential_keys(spec))}


def runtime_environment(policy, spec, credentials, imported=b""):
    db = policy["database"]
    values = {db["url_env"]: "postgresql://" + db["user"] + ":" + quote(credentials["BOOTSTRAP_PG_APP_PASSWORD"], safe="")
              + "@" + db["host"] + ":5432/" + db["name"]}
    if policy.get("redis"):
        redis = policy["redis"]
        values[redis["url_env"]] = "redis://:" + quote(credentials["BOOTSTRAP_REDIS_PASSWORD"], safe="") + "@" + redis["host"] + ":6379/0"
        if "prefix_env" in redis:
            values[redis["prefix_env"]] = redis["prefix"]
    values.update({key: credentials[key] for key in spec["generate_env"]})
    for line in imported.decode("utf-8", "strict").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\r\n\0]*)", line)
        if not match or match[1] in values or match[1] in {s["image_env"] for s in policy["services"].values()}:
            raise BootstrapError("runtime_import_invalid")
        values[match[1]] = match[2]
    if not set(policy["required_env"]) <= values.keys():
        raise BootstrapError("external_runtime_values_required")
    return "".join(key + "=" + values[key] + "\n" for key in sorted(values)).encode()


def provision_database(policy, credentials, execute=run, *, create=True, extensions=()):
    if list(extensions) not in ([], ["vector"]):
        raise BootstrapError("unsupported_bootstrap_spec")
    db, password = policy["database"], credentials["BOOTSTRAP_PG_APP_PASSWORD"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password):
        raise BootstrapError("credential_state_invalid")
    sql = (f"SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', '{db['user']}') "
           f"WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{db['user']}') \\gexec\n"
           f"SELECT format('CREATE DATABASE %I OWNER %I', '{db['name']}', '{db['user']}') "
           f"WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='{db['name']}') \\gexec\n")
    admin = docker(policy) + ["exec", "-i", db["container"], "psql", "--no-psqlrc", "-U", "postgres", "-d", "postgres", "--set", "ON_ERROR_STOP=1"]
    if create:
        execute(admin, input=sql.encode(), failure_code="database_provision_failed")
        # psql encrypts the password client-side, keeping plaintext out of server logs.
        # https://www.postgresql.org/docs/16/app-psql.html (\password)
        execute(admin + ["--command", "\\password " + db["user"]], input=((password + "\n") * 2).encode(), failure_code="database_provision_failed")
    privilege_check = ("SELECT 'bootstrap_role_verified' FROM pg_roles r JOIN pg_database d ON d.datdba=r.oid "
                       f"WHERE r.rolname='{db['user']}' AND d.datname='{db['name']}' AND r.rolcanlogin "
                       "AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication")
    if execute(admin + ["-Atc", privilege_check], failure_code="database_role_check_failed").strip() != b"bootstrap_role_verified":
        raise BootstrapError("database_role_mismatch")
    if extensions:
        # Install the reviewed extension as the existing administrator, never by
        # granting the application role additional privileges. Resume only reads.
        database_admin = docker(policy) + ["exec", "-i", db["container"], "psql", "--no-psqlrc",
                                          "-U", "postgres", "-d", db["name"], "--set", "ON_ERROR_STOP=1"]
        if create:
            execute(database_admin + ["-c", "CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public"],
                    failure_code="database_provision_failed")
        check = "SELECT extname FROM pg_extension WHERE extname='vector' AND extnamespace='public'::regnamespace"
        if execute(database_admin + ["-Atc", check], failure_code="database_role_check_failed").strip() != b"vector":
            raise BootstrapError("database_role_mismatch")
    # 官方 PostgreSQL 镜像的 loopback 规则可能是 trust；使用应用实际访问的项目网络。
    auth = 'IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql --no-psqlrc -h "$1" -U "$2" -d "$3" -Atc "SELECT current_user"'
    result = execute(docker(policy) + ["exec", "-i", db["container"], "sh", "-ceu", auth, "sh", db["host"], db["user"], db["name"]], input=(password + "\n").encode(), failure_code="database_authentication_failed")
    if result.strip() != db["user"].encode():
        raise BootstrapError("database_authentication_failed")


def load_bundle(path, expected_lock):
    # Bootstrap uses the existing installer contract, executing only captured verified bytes.
    raw_lock = (path / "artifact-lock.json").read_bytes()
    if sha(raw_lock) != expected_lock:
        raise BootstrapError("artifact_lock_mismatch")
    lock = json.loads(raw_lock)
    source = (path / "host/install-project.py").read_bytes()
    if sha(source) != lock["files"]["host/install-project.py"]:
        raise BootstrapError("installer_identity_mismatch")
    module = ModuleType("bootstrap_installer")
    module.__file__ = str(path / "host/install-project.py")
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, module.verify_bundle(path, expected_lock)


def apply_bootstrap(installer, bundle, spec, spec_sha256, runtime_import=None):
    if os.geteuid() != 0:
        raise BootstrapError("root_administrator_required")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise BootstrapError("ubuntu_24_04_required")
    policy = bundle["policy"]
    validate_spec(spec, policy, bundle["host"].POLICY_SHA256, apply=True)
    ensure_docker(spec)
    existing = inventory_resources(policy, spec)
    validate_resources(policy, spec, spec_sha256, existing)
    scope = policy["project"] + "-" + policy["environment"]
    state = Path("/var/lib/cnb-devops") / policy["project"] / policy["environment"] / "bootstrap"
    identity = {"schema": "cnb-first-host-state/v1", "policy_sha256": spec["policy_sha256"], "spec_sha256": spec_sha256}
    if state.exists() and any(state.iterdir()):
        recorded, _digest = bundle["host"].read_root_owned_json(state / "identity.json")
        if recorded != identity or (not (state / "credentials.env").exists() and any(existing[k] for k in existing)):
            raise BootstrapError("bootstrap_state_mismatch")
        if {p.name for p in state.iterdir()} - {"identity.json", "credentials.env", "runtime.env", "compose.json", "receipt.json"}:
            raise BootstrapError("unknown_bootstrap_state")
    elif any(existing[kind] for kind in existing):
        raise BootstrapError("resource_state_missing")
    for parent in reversed(state.parents):
        if parent != Path("/"):
            installer.ensure_directory(parent, 0o755, 0, 0)
    installer.ensure_directory(state, 0o700, 0, 0)
    installer.install_file(state / "identity.json", canonical(identity), 0o444, 0, 0)
    credential_path = state / "credentials.env"
    if credential_path.exists():
        info = bundle["host"]._regular_file(credential_path, 64 * 1024, 0o600)
        if info.st_uid != 0 or info.st_gid != 0:
            raise BootstrapError("credential_state_invalid")
        credentials = dict(line.split("=", 1) for line in installer.read_file(credential_path).decode().splitlines())
        if set(credentials) != credential_keys(spec) or any(not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value) for value in credentials.values()):
            raise BootstrapError("credential_state_invalid")
    else:
        credentials = generate_credentials(spec)
        installer.install_file(credential_path, "".join(k + "=" + v + "\n" for k, v in credentials.items()).encode(), 0o600, 0, 0)
    imported = b""
    if runtime_import:
        info = bundle["host"]._regular_file(runtime_import, 1024 * 1024, 0o600)
        if info.st_uid != 0:
            raise BootstrapError("protected_runtime_import_required")
        imported = installer.read_file(runtime_import)
    elif (state / "runtime.env").exists():
        generated = {policy["database"]["url_env"]} | set(spec["generate_env"])
        if policy.get("redis"):
            generated.add(policy["redis"]["url_env"])
            if "prefix_env" in policy["redis"]:
                generated.add(policy["redis"]["prefix_env"])
        imported = b"\n".join(line for line in installer.read_file(state / "runtime.env").splitlines()
                               if line.split(b"=", 1)[0].decode("ascii", "strict") not in generated) + b"\n"
    runtime = runtime_environment(policy, spec, credentials, imported)
    installer.install_file(state / "runtime.env", runtime, 0o600, 0, 0)
    composed = canonical(compose_model(policy, spec, spec_sha256))
    installer.install_file(state / "compose.json", composed, 0o444, 0, 0)
    try:
        account = pwd.getpwnam(policy["release_user"])
        if account.pw_dir != policy["release_home"]:
            raise BootstrapError("release_home_mismatch")
    except KeyError:
        run(["/usr/sbin/useradd", "--create-home", "--shell", "/bin/bash", policy["release_user"]], failure_code="release_user_create_failed")
    run(["/usr/sbin/usermod", "--append", "--groups", "docker", policy["release_user"]], failure_code="docker_group_assign_failed")
    for role, image in spec["images"].items():
        run(docker(policy) + ["pull", image], timeout=600, failure_code=role + "_image_pull_failed")
        version = run(docker(policy) + ["run", "--rm", "--network", "none", "--entrypoint",
                                     "postgres" if role == "postgres" else "redis-server", image, "--version"], failure_code="base_image_version_check_failed")
        if (role == "postgres" and re.search(rb"PostgreSQL\) 16\.", version) is None
            or role == "redis" and re.search(rb"v=7\.", version) is None):
            raise BootstrapError("base_image_version_mismatch")
    label_args = [item for key, value in labels(policy, spec_sha256).items() for item in ("--label", key + "=" + value)]
    if scope not in existing["network"]:
        run(docker(policy) + ["network", "create", "--driver", "bridge", *label_args, scope], failure_code="network_create_failed")
    for role in spec["images"]:
        volume = scope + "-" + role + "-data"
        if volume not in existing["volume"]:
            run(docker(policy) + ["volume", "create", *label_args, volume], failure_code="volume_create_failed")
    compose = docker(policy) + ["compose", "--project-name", scope + "-data", "--env-file", str(credential_path), "-f", str(state / "compose.json")]
    # Existing compatible containers are only started; never recreated or removed.
    run(compose + ["up", "-d", "--no-recreate", *spec["images"]], timeout=300, failure_code="infrastructure_start_failed")
    deadline = time.monotonic() + 180
    while True:
        states = [run(docker(policy) + ["inspect", "--format", "{{.State.Health.Status}}", scope + "-" + role], failure_code="infrastructure_health_check_failed").strip()
                  for role in spec["images"]]
        if all(value == b"healthy" for value in states):
            break
        if time.monotonic() >= deadline:
            raise BootstrapError("infrastructure_unhealthy")
        time.sleep(3)
    completed = state / "receipt.json"
    if completed.exists():
        previous, _sha = bundle["host"].read_root_owned_json(completed)
        if previous != {**identity, "status": "ready"}:
            raise BootstrapError("bootstrap_receipt_mismatch")
    provision_database(policy, credentials, create=not completed.exists(), extensions=spec.get("postgres_extensions", []))
    validate_resources(policy, spec, spec_sha256, inventory_resources(policy, spec))
    installer.install_file(state / "receipt.json", canonical({**identity, "status": "ready"}), 0o444, 0, 0)
    return state / "runtime.env"


@contextlib.contextmanager
def bootstrap_lock(project, environment="test"):
    if os.geteuid() != 0:
        raise BootstrapError("root_administrator_required")
    if not isinstance(project, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", project) or environment not in ("test", "production"):
        raise BootstrapError("bootstrap_scope_invalid")
    path = Path("/run/lock") / ("cnb-devops-" + project + "-" + environment + "-bootstrap.lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
            raise BootstrapError("bootstrap_lock_unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BootstrapError("bootstrap_busy") from exc
        yield
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--lock-sha256", required=True)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--runtime-import", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    installer, bundle = load_bundle(args.bundle_dir, args.lock_sha256)
    spec_raw = installer.read_file(args.spec)
    if sha(spec_raw) != args.spec_sha256:
        raise BootstrapError("bootstrap_spec_mismatch")
    spec = installer.strict_json(spec_raw)
    validate_spec(spec, bundle["policy"], bundle["host"].POLICY_SHA256, apply=args.apply)
    runtime = None
    if args.apply:
        with bootstrap_lock(bundle["policy"]["project"], bundle["policy"]["environment"]):
            runtime = apply_bootstrap(installer, bundle, spec, args.spec_sha256, args.runtime_import)
    print(json.dumps({"schema": "cnb-first-host-result/v1", "status": "ready" if args.apply else "preview",
                      "project": bundle["policy"]["project"], "environment": bundle["policy"]["environment"], "spec_sha256": args.spec_sha256,
                      "missing_image_pins": sorted(key for key, value in spec["images"].items() if value is None),
                      "runtime_env_path": str(runtime) if runtime else None,
                      "remaining": ["private TCR pull credential import", "approved proxy routes", "install-project.py",
                                    bundle["policy"]["environment"] + " release verification"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        reason = str(exc) if isinstance(exc, BootstrapError) and str(exc) in SAFE_ERROR_CODES else "bootstrap_failed"
        print(json.dumps({"schema": "cnb-first-host-result/v1", "status": "failed", "reason": reason}, sort_keys=True))
        raise SystemExit(1)
