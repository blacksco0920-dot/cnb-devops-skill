#!/usr/bin/env python3
"""Administrator-only static HTTPS routes for an inventoried native Caddy host.

Fixed installed policy and output paths; no release-controller authority. Preview
is read-only. This bounded preset accepts only exact generated project imports and
a base without other imports or environment substitution. It preserves existing
bytes, journals an added import, and requires explicit recovery after uncertain state.
See https://caddyserver.com/docs/command-line and /docs/caddyfile/directives/import.
"""
import argparse
import base64
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


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'CADDY_JSON_DUPLICATE')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def paths(project, environment='test'):
    require(isinstance(project, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,39}', project), 'CADDY_PROJECT_INVALID')
    require(environment in ('test', 'production'), 'CADDY_ENVIRONMENT_INVALID')
    return (ROOT / 'etc/caddy/Caddyfile', ROOT / f'etc/caddy/cnb-devops/{project}-{environment}.caddy',
            ROOT / f'opt/cnb-devops/{project}/{environment}/v1/host-policy.json')


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


def render_sites(policy, project, policy_sha, environment='test'):
    require(policy.get('schema') == 'cnb-devops-host-policy/v1' and policy.get('project') == project
            and environment in ('test', 'production') and policy.get('environment') == environment, 'CADDY_POLICY_INVALID')
    routes = {}
    seen = set()
    try:
        gateway = policy.get('native_caddy_gateway')
        require(gateway is None or gateway in policy['services'], 'CADDY_GATEWAY_INVALID')
        for probe in policy['identity_probes']:
            role = probe['service']
            port = policy['services'][gateway or role]['loopback_port']
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
    text = f'# cnb-devops {project}/{environment} policy_sha256={policy_sha}\n'
    for host, (_role, port) in sorted(routes.items()):
        text += f'\nhttps://{host} {{\n\treverse_proxy 127.0.0.1:{port}\n}}\n'
    return text.encode(), sorted(routes)


IMPORT_PATTERN = re.compile(rb'\nimport ([^\n]+)\n')


def expand_imports(raw, overrides=None):
    overrides = overrides or {}
    def replace(match):
        try:
            name = match.group(1).decode('ascii')
        except UnicodeError as error:
            raise CaddyError('CADDY_IMPORT_SCOPE') from error
        site = overrides.get(name)
        if site is None:
            site, _ = read_safe(Path(name))
        return b'\n' + site
    return IMPORT_PATTERN.sub(replace, raw)


def _inventory_parts():
    check_system()
    config_path = ROOT / 'etc/caddy/Caddyfile'
    original, _ = read_safe(config_path)
    matches = list(IMPORT_PATTERN.finditer(original))
    require(len(matches) <= 16, 'CADDY_IMPORT_SCOPE')
    base = IMPORT_PATTERN.sub(b'', original)
    require(not re.search(rb'\bimport\b|\{\$', base), 'CADDY_IMPORT_SCOPE')
    records, all_domains, all_ports, seen_paths = [], set(), set(), set()
    expected_prefix = str(ROOT / 'etc/caddy/cnb-devops') + '/'
    for match in matches:
        try:
            imported = match.group(1).decode('ascii')
        except UnicodeError as error:
            raise CaddyError('CADDY_IMPORT_SCOPE') from error
        require(imported.startswith(expected_prefix), 'CADDY_IMPORT_SCOPE')
        filename = imported[len(expected_prefix):]
        found = re.fullmatch(r'([a-z][a-z0-9-]{0,39})-(test|production)\.caddy', filename)
        require(found is not None and imported not in seen_paths, 'CADDY_IMPORT_SCOPE')
        seen_paths.add(imported)
        project, environment = found.groups()
        _config, site_path, policy_path = paths(project, environment)
        require(str(site_path) == imported, 'CADDY_IMPORT_SCOPE')
        site_raw, _ = read_safe(site_path)
        policy_raw, _ = read_safe(policy_path)
        policy_sha = sha(policy_raw)
        policy = strict_json(policy_raw)
        rendered, site_domains = render_sites(policy, project, policy_sha, environment)
        require(site_raw == rendered, 'CADDY_PROJECT_FILE_UNKNOWN')
        gateway = policy.get('native_caddy_gateway')
        site_ports = sorted({policy['services'][gateway or probe['service']]['loopback_port']['published']
                             for probe in policy['identity_probes']})
        require(not all_domains.intersection(site_domains), 'CADDY_DOMAIN_CONFLICT')
        require(not all_ports.intersection(site_ports), 'CADDY_LOOPBACK_CONFLICT')
        all_domains.update(site_domains)
        all_ports.update(site_ports)
        records.append({'project': project, 'environment': environment, 'path': imported,
                        'site_sha256': sha(site_raw), 'policy_sha256': policy_sha,
                        'domains': site_domains, 'loopback_ports': site_ports})
    model = adapt(expand_imports(original))
    require(model == running_config(), 'CADDY_RUNNING_CONFIG_DRIFT')
    value = {'schema': 'cnb-native-caddy-inventory/v1', 'status': 'verified',
             'main_sha256': sha(original), 'base_sha256': sha(base),
             'running_sha256': sha(canonical(model)),
             'sites': sorted(records, key=lambda item: (item['project'], item['environment']))}
    return value, original, base


def inventory():
    active = state_paths()['active']
    require(not active.exists() and not active.is_symlink(), 'CADDY_RECOVERY_REQUIRED')
    return _inventory_parts()[0]


def validate_shared_input(raw):
    try:
        value = strict_json(raw)
        keys = {'schema', 'inventory_sha256', 'maintenance_authorization_sha256',
                'gateway_recovery_receipt_sha256', 'credential_review_receipt_sha256'}
        require(type(value) is dict and set(value) == keys
                and value['schema'] == 'cnb-native-caddy-shared-input/v1'
                and all(type(value[key]) is str and re.fullmatch(r'[0-9a-f]{64}', value[key])
                        for key in keys - {'schema'}), 'CADDY_SHARED_INPUT_INVALID')
        return value
    except (TypeError, ValueError, KeyError) as error:
        raise CaddyError('CADDY_SHARED_INPUT_INVALID') from error


def preflight(policy, policy_sha, baseline_sha, shared_input_raw=None):
    require(all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                for value in (policy_sha, baseline_sha)), 'CADDY_HASH_INVALID')
    site, domains = render_sites(policy, policy['project'], policy_sha, policy['environment'])
    current, _original, base = _inventory_parts()
    require(sha(base) == baseline_sha, 'CADDY_BASELINE_DRIFT')
    same = [item for item in current['sites']
            if (item['project'], item['environment']) == (policy['project'], policy['environment'])]
    others = [item for item in current['sites'] if item not in same]
    if others:
        require(shared_input_raw is not None, 'CADDY_SHARED_INPUT_REQUIRED')
        shared = validate_shared_input(shared_input_raw)
        current_sha = sha(canonical(current))
        if shared['inventory_sha256'] != current_sha:
            prior = receipt_for(policy['project'], policy['environment'], sha(shared_input_raw))
            require(prior is not None and prior.get('after_inventory_sha256') == current_sha and same,
                    'CADDY_SHARED_INVENTORY_DRIFT')
    else:
        require(shared_input_raw is None, 'CADDY_SHARED_INPUT_UNNECESSARY')
    if same:
        require(len(same) == 1 and same[0]['site_sha256'] == sha(site), 'CADDY_PROJECT_FILE_UNKNOWN')
    require(len(current['sites']) + (0 if same else 1) <= 16, 'CADDY_IMPORT_SCOPE')
    gateway = policy.get('native_caddy_gateway')
    ports = {policy['services'][gateway or probe['service']]['loopback_port']['published']
             for probe in policy['identity_probes']}
    for item in others:
        require(not set(domains).intersection(item['domains']), 'CADDY_DOMAIN_CONFLICT')
        require(not ports.intersection(item['loopback_ports']), 'CADDY_LOOPBACK_CONFLICT')
    without_current = base + b''.join(('\nimport ' + item['path'] + '\n').encode() for item in others)
    check_conflicts(adapt(expand_imports(without_current)), domains)
    return current


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
    model = strict_json(command([CADDY, 'adapt', '--config', '/dev/stdin', '--adapter', 'caddyfile'], raw))
    def filename(value):
        if isinstance(value, dict):
            # Caddy 自动隐藏配置文件；stdin 的虚拟文件名须对应已固定的实际主配置。
            hides = value.get('hide')
            if value.get('handler') == 'file_server' and isinstance(hides, list) and '/dev/stdin' in hides:
                hides[hides.index('/dev/stdin')] = str(ROOT / 'etc/caddy/Caddyfile')
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


def state_paths(transaction_id=None):
    root = ROOT / 'var/lib/cnb-devops/native-caddy'
    transaction = root / 'transactions' / transaction_id if transaction_id else None
    return {'root': root, 'active': root / 'active-transaction.json',
            'lock': root / 'transaction.lock',
            'journal': transaction / 'journal.json' if transaction else None,
            'receipt': root / 'receipts' / (transaction_id + '.json') if transaction_id else None}


def ensure_state():
    paths_value = state_paths()
    for path, mode in ((ROOT / 'var', 0o755), (ROOT / 'var/lib', 0o755),
                       (ROOT / 'var/lib/cnb-devops', 0o755), (paths_value['root'], 0o700),
                       (paths_value['root'] / 'transactions', 0o700),
                       (paths_value['root'] / 'receipts', 0o700)):
        if not path.exists():
            path.mkdir(mode=mode)
        safe_directory(path)
    return paths_value


def write_state(path, value):
    atomic_write(path, canonical(value), 0o600, OWNER, GROUP)


def read_state(path):
    raw, _ = read_safe(path)
    return strict_json(raw)


def receipt_for(project, environment, shared_sha):
    root = state_paths()['root'] / 'receipts'
    if not root.exists():
        return None
    for path in sorted(root.iterdir()):
        if not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
            raise CaddyError('CADDY_STATE_UNKNOWN')
        value = read_state(path)
        keys = {'schema', 'status', 'transaction_id', 'project', 'environment', 'before_main_sha256',
                'after_main_sha256', 'site_sha256', 'shared_input_sha256', 'after_inventory_sha256'}
        recovery_keys = {'schema', 'status', 'transaction_id', 'main_sha256', 'site_sha256'}
        require(type(value) is dict and (set(value) == keys or
                (set(value) == recovery_keys and value.get('schema') == 'cnb-native-caddy-recovery-receipt/v1')),
                'CADDY_STATE_UNKNOWN')
        if (value.get('schema') == 'cnb-native-caddy-receipt/v1' and value.get('status') == 'installed'
            and value.get('project') == project
            and value.get('environment') == environment and value.get('shared_input_sha256') == shared_sha):
            return value
    return None


@contextlib.contextmanager
def locked():
    directory = ROOT / 'run/lock'
    # /run/lock is often root-owned 1777; use its fixed root-only lock safely.
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER, 'CADDY_LOCK_UNSAFE')
    fd = os.open(directory / 'cnb-devops-native-caddy.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    persistent_fd = None
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'CADDY_LOCK_UNSAFE')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = ensure_state()
        persistent_fd = os.open(state['lock'], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        persistent_info = os.fstat(persistent_fd)
        require(stat.S_ISREG(persistent_info.st_mode) and persistent_info.st_uid == OWNER
                and persistent_info.st_nlink == 1 and stat.S_IMODE(persistent_info.st_mode) == 0o600,
                'CADDY_LOCK_UNSAFE')
        fcntl.flock(persistent_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if persistent_fd is not None:
            os.close(persistent_fd)
        os.close(fd)


def configure(project, policy_sha, baseline_sha, apply=False, environment='test', shared_input_raw=None):
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in (policy_sha, baseline_sha)),
            'CADDY_HASH_INVALID')
    config_path, site_path, policy_path = paths(project, environment)
    active_path = state_paths()['active']
    require(not active_path.exists() and not active_path.is_symlink(), 'CADDY_RECOVERY_REQUIRED')
    policy_raw, _ = read_safe(policy_path)
    require(sha(policy_raw) == policy_sha, 'CADDY_POLICY_DRIFT')
    site, domains = render_sites(strict_json(policy_raw), project, policy_sha, environment)
    original, info = read_safe(config_path)
    suffix = ('\nimport ' + str(site_path) + '\n').encode()
    existing = site_path.exists() or site_path.is_symlink()
    current_inventory = preflight(strict_json(policy_raw), policy_sha, baseline_sha, shared_input_raw)
    inventoried_main, _ = read_safe(config_path)
    baseline = IMPORT_PATTERN.sub(b'', inventoried_main)
    require(inventoried_main == original, 'CADDY_PREWRITE_DRIFT')
    require(sha(baseline) == baseline_sha, 'CADDY_BASELINE_DRIFT')
    if existing:
        prior_site, _ = read_safe(site_path)
        require(prior_site == site and any(item['path'] == str(site_path) for item in current_inventory['sites']),
                'CADDY_PROJECT_FILE_UNKNOWN')
    else:
        require(not any(item['path'] == str(site_path) for item in current_inventory['sites']), 'CADDY_PROJECT_FILE_MISSING')
    before = adapt(expand_imports(original))
    candidate_raw = original if existing else original + suffix
    candidate = adapt(expand_imports(candidate_raw, {str(site_path): site}))
    require(running_config() == before, 'CADDY_RUNNING_CONFIG_DRIFT')
    result = {'schema': 'cnb-native-caddy/v1', 'project': project, 'environment': environment,
              'status': 'unchanged' if existing else 'planned', 'policy_sha256': policy_sha,
              'baseline_sha256': baseline_sha, 'site_sha256': sha(site), 'domains': domains,
              'site_path': str(site_path), 'site': site.decode(), 'https_verified': False}
    if not apply or existing:
        return result
    # Validate the exact expanded candidate before either configuration file changes.
    command([CADDY, 'validate', '--config', '/dev/stdin'], json.dumps(candidate).encode())
    require(read_safe(config_path)[0] == original and read_safe(policy_path)[0] == policy_raw
            and running_config() == before, 'CADDY_PREWRITE_DRIFT')
    created_dir = not site_path.parent.exists()
    if created_dir:
        site_path.parent.mkdir(mode=0o755)
    safe_directory(site_path.parent)
    require(not site_path.exists() and not site_path.is_symlink(), 'CADDY_PROJECT_FILE_UNKNOWN')
    main_changed = site_changed = False
    state = ensure_state()
    transaction_id = os.urandom(16).hex()
    transaction = state_paths(transaction_id)
    require(not transaction['journal'].exists() and not transaction['receipt'].exists(), 'CADDY_TRANSACTION_EXISTS')
    transaction['journal'].parent.mkdir(mode=0o700)
    journal = {'schema': 'cnb-native-caddy-transaction/v1', 'transaction_id': transaction_id,
               'project': project, 'environment': environment, 'site_path': str(site_path),
               'before_main': base64.b64encode(original).decode(), 'after_main': base64.b64encode(candidate_raw).decode(),
               'before_site': None, 'after_site': base64.b64encode(site).decode(),
               'main_mode': stat.S_IMODE(info.st_mode), 'main_uid': info.st_uid, 'main_gid': info.st_gid,
               'shared_input_sha256': sha(shared_input_raw) if shared_input_raw else None,
               'retained_sites': [item for item in current_inventory['sites']
                                  if (item['project'], item['environment']) != (project, environment)],
               'phase': 'prepared'}
    write_state(transaction['journal'], journal)
    write_state(state['active'], {'schema': 'cnb-native-caddy-active/v1', 'transaction_id': transaction_id})
    try:
        site_changed = True
        atomic_write(site_path, site, 0o644, OWNER, GROUP)
        main_changed = True
        atomic_write(config_path, candidate_raw, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
        command([CADDY, 'reload', '--config', str(config_path), '--adapter', 'caddyfile', '--address', '127.0.0.1:2019'])
        require(running_config() == candidate, 'CADDY_RELOAD_READBACK_FAILED')
        after_inventory = _inventory_parts()[0]
        receipt = {'schema': 'cnb-native-caddy-receipt/v1', 'status': 'installed',
                   'transaction_id': transaction_id, 'project': project, 'environment': environment,
                   'before_main_sha256': sha(original), 'after_main_sha256': sha(candidate_raw),
                   'site_sha256': sha(site), 'shared_input_sha256': journal['shared_input_sha256'],
                   'after_inventory_sha256': sha(canonical(after_inventory))}
        write_state(transaction['receipt'], receipt)
        require(read_state(transaction['receipt']) == receipt, 'CADDY_RECEIPT_READBACK_FAILED')
        state['active'].unlink()
    except Exception as error:
        try:
            if main_changed:
                require(read_safe(config_path)[0] in (original, candidate_raw), 'CADDY_ROLLBACK_CONCURRENT_CHANGE')
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
        rollback = {'schema': 'cnb-native-caddy-receipt/v1', 'status': 'rolled-back',
                    'transaction_id': transaction_id, 'project': project, 'environment': environment,
                    'before_main_sha256': sha(original), 'after_main_sha256': sha(candidate_raw),
                    'site_sha256': sha(site), 'shared_input_sha256': journal['shared_input_sha256'],
                    'after_inventory_sha256': sha(canonical(_inventory_parts()[0]))}
        write_state(transaction['receipt'], rollback)
        state['active'].unlink()
        raise CaddyError('CADDY_APPLY_FAILED_ROLLED_BACK') from error
    result['status'] = 'installed'
    result['transaction_id'] = transaction_id
    result['receipt_path'] = str(transaction['receipt'])
    return result


def recover(transaction_id):
    require(isinstance(transaction_id, str) and re.fullmatch(r'[0-9a-f]{32}', transaction_id),
            'CADDY_TRANSACTION_INVALID')
    state = state_paths()
    transaction = state_paths(transaction_id)
    require(state['active'].exists() and transaction['journal'].exists(), 'CADDY_RECOVERY_RECORD_MISSING')
    active = read_state(state['active'])
    require(active == {'schema': 'cnb-native-caddy-active/v1', 'transaction_id': transaction_id},
            'CADDY_RECOVERY_RECORD_INVALID')
    journal = read_state(transaction['journal'])
    require(journal.get('schema') == 'cnb-native-caddy-transaction/v1'
            and journal.get('transaction_id') == transaction_id, 'CADDY_RECOVERY_RECORD_INVALID')
    try:
        before_main = base64.b64decode(journal['before_main'], validate=True)
        after_main = base64.b64decode(journal['after_main'], validate=True)
        after_site = base64.b64decode(journal['after_site'], validate=True)
    except (KeyError, ValueError, TypeError) as error:
        raise CaddyError('CADDY_RECOVERY_RECORD_INVALID') from error
    config_path = ROOT / 'etc/caddy/Caddyfile'
    site_path = Path(journal['site_path'])
    expected_site = ROOT / f"etc/caddy/cnb-devops/{journal['project']}-{journal['environment']}.caddy"
    require(site_path == expected_site, 'CADDY_RECOVERY_RECORD_INVALID')
    for retained in journal.get('retained_sites', []):
        require(type(retained) is dict and set(retained) == {'project', 'environment', 'path', 'site_sha256',
                                                             'policy_sha256', 'domains', 'loopback_ports'},
                'CADDY_RECOVERY_RECORD_INVALID')
        retained_path = Path(retained['path'])
        _main, expected_path, policy_path = paths(retained['project'], retained['environment'])
        require(retained_path == expected_path and sha(read_safe(retained_path)[0]) == retained['site_sha256']
                and sha(read_safe(policy_path)[0]) == retained['policy_sha256'], 'CADDY_RECOVERY_RETAINED_DRIFT')
    current_main, _ = read_safe(config_path)
    current_site = read_safe(site_path)[0] if site_path.exists() and not site_path.is_symlink() else None
    require(current_main in (before_main, after_main) and current_site in (None, after_site),
            'CADDY_RECOVERY_UNKNOWN_STATE')
    after_model = adapt(expand_imports(after_main, {str(site_path): after_site}))
    before_model = adapt(expand_imports(before_main))
    running = running_config()
    require(running in (before_model, after_model), 'CADDY_RECOVERY_UNKNOWN_STATE')
    if current_main == after_main and current_site == after_site:
        if running != after_model:
            command([CADDY, 'reload', '--config', str(config_path), '--adapter', 'caddyfile', '--address', '127.0.0.1:2019'])
            require(running_config() == after_model, 'CADDY_RECOVERY_READBACK_FAILED')
        status = 'installed'
    else:
        atomic_write(config_path, before_main, journal['main_mode'], journal['main_uid'], journal['main_gid'])
        if current_site == after_site:
            site_path.unlink()
        command([CADDY, 'reload', '--config', str(config_path), '--adapter', 'caddyfile', '--address', '127.0.0.1:2019'])
        require(running_config() == before_model, 'CADDY_RECOVERY_READBACK_FAILED')
        status = 'rolled-back'
    if status == 'installed':
        recovered_inventory = _inventory_parts()[0]
        receipt = {'schema': 'cnb-native-caddy-receipt/v1', 'status': status,
                   'transaction_id': transaction_id, 'project': journal['project'],
                   'environment': journal['environment'], 'before_main_sha256': sha(before_main),
                   'after_main_sha256': sha(after_main), 'site_sha256': sha(after_site),
                   'shared_input_sha256': journal['shared_input_sha256'],
                   'after_inventory_sha256': sha(canonical(recovered_inventory))}
    else:
        receipt = {'schema': 'cnb-native-caddy-recovery-receipt/v1', 'status': status,
                   'transaction_id': transaction_id, 'main_sha256': sha(before_main), 'site_sha256': None}
    write_state(transaction['receipt'], receipt)
    require(read_state(transaction['receipt']) == receipt, 'CADDY_RECEIPT_READBACK_FAILED')
    state['active'].unlink()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project')
    parser.add_argument('--environment', choices=('test', 'production'), default='test')
    parser.add_argument('--policy-sha256')
    parser.add_argument('--baseline-sha256')
    parser.add_argument('--shared-input', type=Path)
    parser.add_argument('--inventory', action='store_true')
    parser.add_argument('--recover')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'CADDY_ROOT_REQUIRED')
    if args.inventory:
        require(not args.apply and not args.recover and args.project is None, 'CADDY_ARGUMENTS_INVALID')
        result = inventory()
    elif args.recover:
        require(args.apply and args.project is None and args.shared_input is None, 'CADDY_ARGUMENTS_INVALID')
        with locked():
            result = recover(args.recover)
    else:
        require(args.project and args.policy_sha256 and args.baseline_sha256, 'CADDY_ARGUMENTS_INVALID')
        if args.shared_input:
            shared_raw, shared_info = read_safe(args.shared_input)
            require(stat.S_IMODE(shared_info.st_mode) == 0o600, 'CADDY_SHARED_INPUT_UNSAFE')
        else:
            shared_raw = None
        with locked() if args.apply else contextlib.nullcontext():
            result = configure(args.project, args.policy_sha256, args.baseline_sha256, args.apply,
                               args.environment, shared_raw)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, CaddyError) else 'CADDY_CONFIGURATION_FAILED', file=sys.stderr)
        sys.exit(1)
