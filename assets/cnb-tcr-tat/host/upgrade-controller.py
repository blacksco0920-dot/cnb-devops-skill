#!/usr/bin/env python3
"""Reviewed TEST controller-only upgrade. Called by the fixed administrator SSH gate."""
import base64
import contextlib
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
import tempfile
from types import ModuleType

ROOT_IDS = (0, 0)
FIXED = {'tat-deploy-test.py': ('host/tat-deploy-test.py', 0o555),
         'host-policy.json': ('host-policy.json', 0o444),
         'docker-compose.yml': ('docker-compose.yml', 0o444),
         'tat-command.sh': ('tat-command.sh', 0o444),
         'recover-project.py': ('host/recover-project.py', 0o555),
         'recovery-policy.json': ('recovery-policy.json', 0o444)}
REPAIR = ('host/repair-test-release.py', 0o555)


class UpgradeError(ValueError):
    pass


def require(value, code):
    if not value:
        raise UpgradeError('UPGRADE_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_JSON')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(UpgradeError('UPGRADE_JSON_INVALID')))


def module(raw, name):
    result = ModuleType(name)
    result.__file__ = '/verified/' + name + '.py'
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    return result


def fixed_files(plan, installation):
    result = {name: (plan['files'][source], mode) for name, (source, mode) in FIXED.items()}
    if REPAIR[0] in plan['files']:
        result['repair-test-release.py'] = (plan['files'][REPAIR[0]], REPAIR[1])
    result.update({'artifact-lock.json': (plan['raw_lock'], 0o444), 'installation.json': (installation, 0o444)})
    return result


def verify_pair(old, new, accepted, expected):
    keys = {'old_lock_sha256', 'lock_sha256', 'accepted_installation_sha256', 'failed_transaction_sha256', 'target_sha256'}
    require(type(expected) is dict and set(expected) == keys and all(type(x) is str and re.fullmatch('[a-f0-9]{64}', x) for x in expected.values()), 'PINS_INVALID')
    require(old['lock_sha256'] == expected['old_lock_sha256'] and new['lock_sha256'] == expected['lock_sha256']
            and sha(accepted) == expected['accepted_installation_sha256'], 'BUNDLE_PIN_MISMATCH')
    require(strict_json(accepted) == {'schema': 'cnb-test-installation/v1', 'lock_sha256': old['lock_sha256']}, 'ACCEPTED_INSTALLATION_INVALID')
    require(old['policy']['environment'] == new['policy']['environment'] == 'test', 'TEST_ONLY')
    for name in ('host-policy.json', 'docker-compose.yml', 'recovery-policy.json'):
        require(old['files'].get(name) == new['files'].get(name) and name in old['files'], 'POLICY_CHANGE')
    require(old['policy'] == new['policy'], 'POLICY_CHANGE')
    require(all(source in p['files'] for p in (old, new) for source, _ in FIXED.values()), 'FIXED_FILES_MISSING')
    require(REPAIR[0] in new['files'], 'REPAIR_HELPER_MISSING')
    require(old['lock_sha256'] != new['lock_sha256'], 'SAME_INSTALLATION')
    return {'schema': 'cnb-test-installation/v1', 'lock_sha256': new['lock_sha256']}


def installation_directory(plan):
    return Path(plan['policy']['install_dir'])


def state_directory(plan):
    return Path('/var/lib/cnb-devops') / plan['policy']['project'] / 'test' / 'controller-upgrade'


@contextlib.contextmanager
def parent_directory(host, path, owner=None):
    """No-follow ancestors, owner checks and a path/inode binding across the operation."""
    require(path.is_absolute() and path == Path(os.path.abspath(path)), 'PATH_INVALID')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    chain = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino)]
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            allowed = {0, ROOT_IDS[0]} | ({owner[0]} if owner else set())
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            require(info.st_uid in allowed and (not info.st_mode & 0o022 or sticky), 'ANCESTOR_UNSAFE')
            chain.append((info.st_dev, info.st_ino))
        info = os.fstat(fd)
        yield fd
        require(host._same_exact_directory_path(path.parent, info, tuple(chain)), 'DIRECTORY_CHANGED')
    finally:
        os.close(fd)


def read_checked(host, path, mode, owner=None, maximum=8 * 1024 * 1024):
    owner = ROOT_IDS if owner is None else owner
    with parent_directory(host, path, owner) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum
                    and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (*owner, mode), 'FILE_UNSAFE')
            raw = stream.read(maximum + 1)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            identity = lambda value: tuple(getattr(value, name) for name in fields)
            require(len(raw) == info.st_size and identity(info) == identity(os.fstat(stream.fileno()))
                    == identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False)), 'FILE_CHANGED')
            return raw


def maybe_read(host, path, mode):
    try:
        return read_checked(host, path, mode)
    except FileNotFoundError:
        return None


def root_directory(host, path, mode=0o700):
    if not path.exists() and not path.is_symlink():
        if not path.parent.exists():
            root_directory(host, path.parent, 0o755)
        with parent_directory(host, path) as directory:
            os.mkdir(path.name, mode, dir_fd=directory)
            os.fsync(directory)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (*ROOT_IDS, mode), 'STATE_DIRECTORY_UNSAFE')


def replace_known(host, path, old, new, mode):
    current = maybe_read(host, path, mode)
    require(current in (old, new), 'INSTALLED_DRIFT')
    if current == new:
        return
    temporary = path.with_name('.' + path.name + '.upgrade-' + sha(new)[:24])
    with parent_directory(host, path) as directory:
        staged = maybe_read(host, temporary, mode)
        if staged is None:
            fd = os.open(temporary.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), *ROOT_IDS); os.fchmod(stream.fileno(), mode)
                stream.write(new); stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        else:
            require(staged == new, 'STAGED_DRIFT')
        require(maybe_read(host, path, mode) == current, 'INSTALLED_DRIFT')
        os.replace(temporary.name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    require(read_checked(host, path, mode) == new, 'READBACK_MISMATCH')


def runtime_docker(host, recovery):
    return recovery.Docker(host._docker_prefix(), host.BASE_ENV)


def capture_source(old, new, expected, account):
    host = old['host']; owner = (account.pw_uid, account.pw_gid)
    try:
        require(not os.path.lexists(host.RECOVERY_TRANSACTION_PATH), 'RECOVERY_ACTIVE')
        raw, tx = host._load_private_record(host.TRANSACTION_PATH, kind='transaction', uid=owner[0], gid=owner[1], required=True)
        require(sha(raw) == expected['failed_transaction_sha256'] and tx['schema'] == host.TRANSACTION_SCHEMA_V2
                and tx['status'] == 'failed' and tx['phase'] == 'probe'
                and tx['controller_program_sha256'] == sha(old['files']['host/tat-deploy-test.py']), 'FAILED_TRANSACTION')
        host._require_bound_snapshot(host.APP_DIR / 'backups/releases', tx, *owner)
        release_raw, release = host._load_private_record(host.RELEASE_PATH, kind='release', uid=owner[0], gid=owner[1], required=True)
        require(sha(release_raw) == tx['previous_release_sha256'] and release['images'] == tx['previous_images'], 'PREVIOUS_RELEASE_DRIFT')
        baseline = read_checked(host, installation_directory(old) / 'empty-baseline.json', 0o444)
        host._installed_empty_baseline(); new['host']._installed_empty_baseline()
        env = read_checked(host, host.ENV_PATH, 0o600, owner, 1024 * 1024)
        compose = read_checked(host, host.COMPOSE_PATH, 0o644, owner, 64 * 1024)
        require(compose == old['files']['docker-compose.yml'], 'APP_COMPOSE_DRIFT')
        values = dict(line.split('=', 1) for line in env.decode('utf-8').splitlines() if line and not line.startswith('#'))
        require(all(values.get(host.IMAGE_KEYS[role]) == image for role, image in tx['images'].items()), 'RUNTIME_IMAGE_DRIFT')
        recovery = module(old['files']['host/recover-project.py'], 'upgrade_old_recovery')
        docker = runtime_docker(host, recovery)
        containers = [docker.inspect(host.CONTAINERS[role]) for role in host.SERVICES]
        for role, item in zip(host.SERVICES, containers):
            require(item['name'] == '/' + host.CONTAINERS[role] and item['image'] == tx['images'][role]
                    and item['running'] and not item['auto_remove']
                    and (item['health'] == 'healthy' if host.POLICY['services'][role]['healthcheck']
                         else item['health'] in (None, 'healthy')), 'RUNTIME_UNHEALTHY')
        return {'app': {'env_sha256': sha(env), 'compose_sha256': sha(compose), 'release_sha256': sha(release_raw),
                        'transaction_sha256': sha(raw)}, 'empty_baseline_sha256': sha(baseline),
                'containers': containers, 'snapshot': tx['snapshot'], 'snapshot_manifest_sha256': tx['snapshot_manifest_sha256']}, baseline
    except UpgradeError:
        raise
    except Exception as error:
        raise UpgradeError('UPGRADE_FAILED_SOURCE_INVALID') from error


def apply_upgrade(old, new, accepted, expected):
    installation = canonical(verify_pair(old, new, accepted, expected))
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    host = old['host']; install = installation_directory(old)
    account = pwd.getpwnam(old['policy']['release_user'])
    require(account.pw_dir == old['policy']['release_home'], 'RELEASE_ACCOUNT_CHANGED')
    lock_fd = os.open(host.LOCK_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        lock = os.fstat(lock_fd)
        require(stat.S_ISREG(lock.st_mode) and lock.st_nlink == 1 and (lock.st_uid, lock.st_gid, stat.S_IMODE(lock.st_mode)) == (account.pw_uid, account.pw_gid, 0o600), 'LOCK_UNSAFE')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def lock_unchanged():
            info = host.LOCK_PATH.lstat()
            require((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
                    == (lock.st_dev, lock.st_ino, lock.st_uid, lock.st_gid, lock.st_mode, lock.st_nlink), 'LOCK_CHANGED')
        source, baseline = capture_source(old, new, expected, account)
        before, after = fixed_files(old, accepted), fixed_files(new, installation)
        state = state_directory(old); journal_path = state / 'journal.json'
        journal_raw = maybe_read(host, journal_path, 0o600)
        journal = strict_json(journal_raw) if journal_raw else None
        identity = {'schema': 'cnb-controller-upgrade-journal/v1', 'project': old['policy']['project'], 'environment': 'test',
                    'expected': expected, 'source': source, 'before': {name: sha(raw) for name, (raw, _mode) in before.items()},
                    'after': {name: sha(raw) for name, (raw, _mode) in after.items()}}
        if journal:
            require(journal_raw == canonical(journal) and set(journal) == set(identity) | {'phase'}
                    and all(journal[key] == value for key, value in identity.items())
                    and journal['phase'] in ('backing_up', 'prepared', 'verified'), 'JOURNAL_MISMATCH')
        else:
            initial = canonical({**identity, 'phase': 'backing_up'})
            initial_stage = '.journal.json.upgrade-' + sha(initial)[:24]
            if state.exists():
                require(set(os.listdir(state)) <= {initial_stage}, 'JOURNAL_MISSING')
                if (state / initial_stage).exists():
                    require(read_checked(host, state / initial_stage, 0o600) == initial, 'STAGED_DRIFT')
        for name, (new_raw, mode) in after.items():
            current = maybe_read(host, install / name, mode)
            old_raw = before[name][0] if name in before else None
            allowed = (old_raw, new_raw) if journal and journal['phase'] != 'backing_up' else (old_raw,)
            require(current in allowed, 'INSTALLED_DRIFT')
        allowed_installed = set(before) | set(after) | {'empty-baseline.json'}
        for name, (raw, mode) in after.items():
            staged_name = '.' + name + '.upgrade-' + sha(raw)[:24]
            if os.path.lexists(install / staged_name):
                require(journal is not None and journal['phase'] == 'prepared'
                        and read_checked(host, install / staged_name, mode) == raw, 'STAGED_DRIFT')
                allowed_installed.add(staged_name)
        require(set(os.listdir(install)) <= allowed_installed, 'UNKNOWN_INSTALLED_FILE')
        lock_unchanged()
        root_directory(host, state)
        if not journal:
            journal = {**identity, 'phase': 'backing_up'}
            replace_known(host, journal_path, None, canonical(journal), 0o600)
        backup = state / 'before'; root_directory(host, backup)
        allowed_state = {'before', 'journal.json'}
        for phase in ('prepared', 'verified'):
            staged_raw = canonical({**identity, 'phase': phase})
            name = '.journal.json.upgrade-' + sha(staged_raw)[:24]
            if os.path.lexists(state / name):
                require(read_checked(host, state / name, 0o600) == staged_raw, 'STAGED_DRIFT')
                allowed_state.add(name)
        require(set(os.listdir(state)) <= allowed_state, 'UNKNOWN_STATE')
        backup_files = {**before, 'empty-baseline.json': (baseline, 0o444)}
        allowed_backup = set(backup_files)
        for name, (raw, _mode) in backup_files.items():
            staged_name = '.' + name + '.upgrade-' + sha(raw)[:24]
            if os.path.lexists(backup / staged_name):
                require(journal['phase'] == 'backing_up' and read_checked(host, backup / staged_name, 0o600) == raw, 'STAGED_DRIFT')
                allowed_backup.add(staged_name)
        require(set(os.listdir(backup)) <= allowed_backup, 'UNKNOWN_BACKUP')
        for name, (raw, _mode) in backup_files.items():
            if journal['phase'] != 'backing_up':
                require(read_checked(host, backup / name, 0o600) == raw, 'BACKUP_DRIFT')
            else:
                replace_known(host, backup / name, None, raw, 0o600)
        if journal['phase'] == 'backing_up':
            prepared = {**identity, 'phase': 'prepared'}
            replace_known(host, journal_path, canonical(journal), canonical(prepared), 0o600)
            journal = prepared
        require(capture_source(old, new, expected, account)[0] == source, 'SOURCE_CHANGED')
        for name in [*sorted(set(after) - {'installation.json'}), 'installation.json']:
            lock_unchanged()
            raw, mode = after[name]
            replace_known(host, install / name, before[name][0] if name in before else None, raw, mode)
        readback = {name: read_checked(host, install / name, mode) for name, (_raw, mode) in after.items()}
        require(all(readback[name] == raw for name, (raw, _mode) in after.items()), 'READBACK_MISMATCH')
        require(read_checked(host, install / 'empty-baseline.json', 0o444) == baseline
                and capture_source(old, new, expected, account)[0] == source, 'SOURCE_CHANGED')
        verified = {**identity, 'phase': 'verified'}
        replace_known(host, journal_path, canonical(journal), canonical(verified), 0o600)
        lock_unchanged()
        receipt = {'schema': 'cnb-controller-upgrade/v1', 'status': 'verified', 'project': old['policy']['project'], 'environment': 'test',
                   **expected, 'source': source, 'old_fixed_sha256': identity['before'], 'fixed_sha256': identity['after'],
                   'installation_sha256': sha(installation), 'journal_sha256': sha(canonical(verified)),
                   'application_changed': False, 'release_executed': False, 'failed_transaction_retained': True}
        readback['empty-baseline.json'] = baseline
        return {'receipt': receipt, 'readback': {name: base64.b64encode(raw).decode('ascii') for name, raw in readback.items()}}
    finally:
        os.close(lock_fd)


def upgrade_archive(raw, expected):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(0 < len(raw) <= 128 * 1024 * 1024, 'ARCHIVE_SIZE')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            require(item.isfile() and item.name not in files and not path.is_absolute() and '..' not in path.parts
                    and str(path) == item.name and 0 < item.size <= 8 * 1024 * 1024 and len(files) < 1030, 'ARCHIVE_INVALID')
            files[item.name] = archive.extractfile(item).read()
    plans = []
    with tempfile.TemporaryDirectory(prefix='cnb-reviewed-upgrade-') as temporary:
        for scope, digest in (('old', expected['old_lock_sha256']), ('new', expected['lock_sha256'])):
            raw_lock = files[scope + '/artifact-lock.json']
            require(sha(raw_lock) == digest, 'LOCK_MISMATCH')
            lock = strict_json(raw_lock)
            require(type(lock) is dict and set(lock) == {'schema', 'version', 'files'} and lock['schema'] == 'cnb-devops-artifacts/v1', 'LOCK_INVALID')
            directory = Path(temporary) / scope; directory.mkdir(mode=0o700)
            for name, pinned in {**lock['files'], 'artifact-lock.json': digest}.items():
                relative = PurePosixPath(name)
                require(not relative.is_absolute() and '..' not in relative.parts and str(relative) == name, 'ARCHIVE_INVALID')
                source = files[scope + '/' + name]
                require(sha(source) == pinned, 'ARTIFACT_MISMATCH')
                destination = directory / name; destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination.write_bytes(source); destination.chmod(0o600)
            installer = module(files[scope + '/host/install-project.py'], 'upgrade_' + scope + '_installer')
            plans.append(installer.verify_bundle(directory, digest))
        allowed = {'accepted-installation.json'}
        for scope, plan in zip(('old', 'new'), plans):
            allowed |= {scope + '/' + name for name in plan['files']} | {scope + '/artifact-lock.json'}
        require(set(files) == allowed, 'ARCHIVE_FILES_INVALID')
        return apply_upgrade(*plans, files['accepted-installation.json'], expected)
