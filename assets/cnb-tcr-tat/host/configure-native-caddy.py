#!/usr/bin/env python3
"""Administrator-only first HTTPS routes for an inventoried native Caddy host.

Fixed installed policy and output paths; no release-controller authority. Preview
is read-only. This bounded preset accepts a baseline without imports or environment
substitution. It preserves that baseline verbatim and adds one explicit import.
See https://caddyserver.com/docs/command-line and /docs/caddyfile/directives/import.
"""
import argparse
import contextlib
import fcntl
import fnmatch
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse


ROOT = Path('/')
OWNER = 0
GROUP = 0
CADDY = '/usr/bin/caddy'
LIMIT = 1024 * 1024


class CaddyError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise CaddyError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'CADDY_JSON_DUPLICATE')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def paths(project):
    require(isinstance(project, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', project), 'CADDY_PROJECT_INVALID')
    return (ROOT / 'etc/caddy/Caddyfile', ROOT / f'etc/caddy/cnb-devops/{project}-test.caddy',
            ROOT / f'opt/cnb-devops/{project}/test/v1/host-policy.json')


def safe_directory(path):
    for parent in [path, *path.parents]:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and not info.st_mode & 0o022,
                'CADDY_PATH_UNSAFE')
        if parent == ROOT:
            break


def read_safe(path):
    safe_directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise CaddyError('CADDY_FILE_UNSAFE') from error
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= LIMIT, 'CADDY_FILE_UNSAFE')
        return stream.read(LIMIT + 1), info


def render_sites(policy, project, policy_sha):
    require(policy.get('schema') == 'cnb-devops-host-policy/v1' and policy.get('project') == project
            and policy.get('environment') == 'test', 'CADDY_POLICY_INVALID')
    routes = {}
    seen = set()
    try:
        for probe in policy['identity_probes']:
            role = probe['service']
            port = policy['services'][role]['loopback_port']
            url = urllib.parse.urlsplit(probe['url'])
            host = url.hostname
            require(url.scheme == 'https' and not url.username and not url.password and url.port in (None, 443)
                    and host and len(host) <= 253 and re.fullmatch(
                        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', host), 'CADDY_DOMAIN_INVALID')
            require(port['host_ip'] == '127.0.0.1' and port['protocol'] == 'tcp'
                    and type(port['published']) is int and 1024 <= port['published'] <= 65535, 'CADDY_LOOPBACK_INVALID')
            require(host not in routes or routes[host] == (role, port['published']), 'CADDY_DOMAIN_CONFLICT')
            routes[host] = (role, port['published'])
            seen.add(role)
        require(1 <= len(routes) <= 16 and seen == set(policy['services']), 'CADDY_SERVICE_MAPPING_INCOMPLETE')
    except (KeyError, TypeError, ValueError) as error:
        raise CaddyError('CADDY_POLICY_INVALID') from error
    text = f'# cnb-devops {project}/test policy_sha256={policy_sha}\n'
    for host, (_role, port) in sorted(routes.items()):
        text += f'\nhttps://{host} {{\n\treverse_proxy 127.0.0.1:{port}\n}}\n'
    return text.encode(), sorted(routes)


def command(args, data=None):
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=True, cwd=ROOT / 'etc/caddy',
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'})
    except (OSError, subprocess.SubprocessError) as error:
        raise CaddyError('CADDY_COMMAND_FAILED') from error
    require(len(result.stdout) <= LIMIT, 'CADDY_OUTPUT_TOO_LARGE')
    return result.stdout


def check_system():
    require(os.geteuid() == 0, 'CADDY_ROOT_REQUIRED')
    os_release = (ROOT / 'etc/os-release').read_text()
    require(re.search(r'^ID=ubuntu$', os_release, re.M) and re.search(r'^VERSION_ID="24\.04"$', os_release, re.M),
            'CADDY_UBUNTU_24_REQUIRED')
    command(['/usr/bin/systemctl', 'is-active', '--quiet', 'caddy'])
    pid = command(['/usr/bin/systemctl', 'show', 'caddy', '--property=MainPID', '--value']).decode().strip()
    require(pid.isdigit() and int(pid) > 1, 'CADDY_SERVICE_MISMATCH')
    argv = (ROOT / f'proc/{pid}/cmdline').read_bytes().split(b'\0')
    expected = [CADDY.encode(), b'run', b'--config', b'/etc/caddy/Caddyfile']
    argv = [arg for arg in argv if arg and arg != b'--environ']
    if argv[-2:] == [b'--adapter', b'caddyfile']:
        argv = argv[:-2]
    require(argv == expected, 'CADDY_SERVICE_MISMATCH')


def running_config():
    # No proxy environment, redirects, credentials or caller-selected endpoint.
    connection = http.client.HTTPConnection('127.0.0.1', 2019, timeout=10)
    try:
        connection.request('GET', '/config/')
        response = connection.getresponse()
        raw = response.read(LIMIT + 1)
        require(response.status == 200 and len(raw) <= LIMIT, 'CADDY_ADMIN_INVALID')
        return strict_json(raw)
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise CaddyError('CADDY_ADMIN_UNAVAILABLE') from error
    finally:
        connection.close()


def adapt(raw):
    model = strict_json(command([CADDY, 'adapt', '--config', '-', '--adapter', 'caddyfile'], raw))
    def filename(value):
        if isinstance(value, dict):
            # Caddy 自动隐藏配置文件；stdin 的虚拟文件名须对应已固定的实际主配置。
            hides = value.get('hide')
            if value.get('handler') == 'file_server' and isinstance(hides, list) and './-' in hides:
                hides[hides.index('./-')] = str(ROOT / 'etc/caddy/Caddyfile')
            for item in value.values():
                filename(item)
        elif isinstance(value, list):
            for item in value:
                filename(item)
    filename(model)
    return model


def check_conflicts(config, domains):
    def walk(value):
        if isinstance(value, dict):
            require(not ({'host_regexp', 'expression'} & set(value)), 'CADDY_ROUTE_CONFLICT')
            if 'host' in value:
                require(isinstance(value['host'], list), 'CADDY_ROUTE_CONFLICT')
                for host in value['host']:
                    require(isinstance(host, str) and not any(fnmatch.fnmatchcase(d, host.lower()) for d in domains),
                            'CADDY_DOMAIN_CONFLICT')
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(config)
    for server in config.get('apps', {}).get('http', {}).get('servers', {}).values():
        if any(endpoint.endswith(':443') for endpoint in server.get('listen', [])):
            require(all(route.get('match') and all(match.get('host') for match in route['match'])
                        for route in server.get('routes', [])), 'CADDY_HTTPS_CATCHALL_CONFLICT')


def atomic_write(path, raw, mode, uid, gid):
    fd, tmp = tempfile.mkstemp(prefix='.cnb-caddy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def locked():
    directory = ROOT / 'run/lock'
    # /run/lock is often root-owned 1777; use its fixed root-only lock safely.
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER, 'CADDY_LOCK_UNSAFE')
    fd = os.open(directory / 'cnb-devops-native-caddy.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'CADDY_LOCK_UNSAFE')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def configure(project, policy_sha, baseline_sha, apply=False):
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in (policy_sha, baseline_sha)),
            'CADDY_HASH_INVALID')
    config_path, site_path, policy_path = paths(project)
    check_system()
    policy_raw, _ = read_safe(policy_path)
    require(sha(policy_raw) == policy_sha, 'CADDY_POLICY_DRIFT')
    site, domains = render_sites(strict_json(policy_raw), project, policy_sha)
    original, info = read_safe(config_path)
    suffix = ('\nimport ' + str(site_path) + '\n').encode()
    existing = site_path.exists() or site_path.is_symlink()
    baseline = original[:-len(suffix)] if original.endswith(suffix) else original
    require(sha(baseline) == baseline_sha, 'CADDY_BASELINE_DRIFT')
    require(not re.search(rb'\bimport\b|\{\$', baseline), 'CADDY_BASELINE_SCOPE')
    if existing:
        prior_site, _ = read_safe(site_path)
        require(original.endswith(suffix) and prior_site == site, 'CADDY_PROJECT_FILE_UNKNOWN')
    else:
        require(not original.endswith(suffix), 'CADDY_PROJECT_FILE_MISSING')
    before = adapt(baseline)
    check_conflicts(before, domains)
    candidate = adapt(baseline + b'\n' + site)
    require(running_config() == (candidate if existing else before), 'CADDY_RUNNING_CONFIG_DRIFT')
    result = {'schema': 'cnb-native-caddy/v1', 'project': project, 'environment': 'test',
              'status': 'unchanged' if existing else 'planned', 'policy_sha256': policy_sha,
              'baseline_sha256': baseline_sha, 'site_sha256': sha(site), 'domains': domains,
              'site_path': str(site_path), 'site': site.decode(), 'https_verified': False}
    if not apply or existing:
        return result
    # Validate the exact expanded candidate before either configuration file changes.
    command([CADDY, 'validate', '--config', '-'], json.dumps(candidate).encode())
    require(read_safe(config_path)[0] == original and read_safe(policy_path)[0] == policy_raw
            and running_config() == before, 'CADDY_PREWRITE_DRIFT')
    created_dir = not site_path.parent.exists()
    if created_dir:
        site_path.parent.mkdir(mode=0o755)
    safe_directory(site_path.parent)
    require(not site_path.exists() and not site_path.is_symlink(), 'CADDY_PROJECT_FILE_UNKNOWN')
    main_changed = site_changed = False
    try:
        site_changed = True
        atomic_write(site_path, site, 0o644, OWNER, GROUP)
        main_changed = True
        atomic_write(config_path, original + suffix, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        command([CADDY, 'reload', '--config', str(config_path), '--adapter', 'caddyfile', '--address', '127.0.0.1:2019'])
        require(running_config() == candidate, 'CADDY_RELOAD_READBACK_FAILED')
    except Exception as error:
        try:
            if main_changed:
                require(read_safe(config_path)[0] in (original, original + suffix), 'CADDY_ROLLBACK_CONCURRENT_CHANGE')
                atomic_write(config_path, original, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
            if site_changed and site_path.exists():
                require(read_safe(site_path)[0] == site, 'CADDY_ROLLBACK_CONCURRENT_CHANGE')
                site_path.unlink()
            if created_dir:
                site_path.parent.rmdir()
            if main_changed:
                command([CADDY, 'reload', '--config', str(config_path), '--adapter', 'caddyfile', '--address', '127.0.0.1:2019'])
                require(running_config() == before, 'CADDY_ROLLBACK_READBACK_FAILED')
        except Exception as rollback_error:
            raise CaddyError('CADDY_ROLLBACK_INCOMPLETE') from rollback_error
        raise CaddyError('CADDY_APPLY_FAILED_ROLLED_BACK') from error
    result['status'] = 'installed'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'CADDY_ROOT_REQUIRED')
    with locked() if args.apply else contextlib.nullcontext():
        result = configure(args.project, args.policy_sha256, args.baseline_sha256, args.apply)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, CaddyError) else 'CADDY_CONFIGURATION_FAILED', file=sys.stderr)
        sys.exit(1)
