#!/usr/bin/env python3
"""Preview offline or rehearse one approved environment with the installed recovery tool.

Re-run identical inputs to resume transfer. An uncertain export is inspected first;
source resumption and failed isolated restores remain explicit review actions.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace


class SessionError(ValueError):
    pass


def require(value, code):
    if not value:
        raise SessionError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(model):
    return (json.dumps(model, sort_keys=True, separators=(',', ':')) + '\n').encode()


def module_from_bytes(raw, filename):
    module = ModuleType('verified_recovery_session_dependency')
    module.__file__ = str(filename)
    exec(compile(raw, str(filename), 'exec'), module.__dict__)
    return module


_setup_path = Path(__file__).with_name('setup-host.py')
_setup = module_from_bytes(_setup_path.read_bytes(), _setup_path)
read_safe, strict_json = _setup.read_safe, _setup.strict_json


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle-dir', 'target', 'accepted-installation', 'evidence-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('lock-sha256', 'git-sha', 'build-id', 'export-id'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--pull-docker-config', type=Path, help='optional protected Docker config for a missing pinned image')
    parser.add_argument('--apply', action='store_true')
    return parser.parse_args(argv)


def safe_directory_ancestors(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and (not info.st_mode & 0o022 or sticky), 'PRIVATE_DIRECTORY_INVALID')


def prepare(args):
    require(sys.version_info >= (3, 11), 'PYTHON_311_REQUIRED')
    raw_lock = read_safe(args.bundle_dir / 'artifact-lock.json')
    require(re.fullmatch('[0-9a-f]{64}', args.lock_sha256) and sha(raw_lock) == args.lock_sha256, 'BUNDLE_LOCK_MISMATCH')
    lock = strict_json(raw_lock)
    installer_raw = read_safe(args.bundle_dir / 'host/install-project.py')
    require(sha(installer_raw) == lock['files'].get('host/install-project.py'), 'INSTALLER_PIN_MISMATCH')
    installer = module_from_bytes(installer_raw, args.bundle_dir / 'host/install-project.py')
    bundle = installer.verify_bundle(args.bundle_dir, args.lock_sha256)
    for name, raw in bundle['files'].items():
        require(read_safe(args.bundle_dir / name) == raw, 'BUNDLE_CHANGED')
    require({'host/recover-project.py', 'recovery-policy.json'} <= bundle['files'].keys(), 'RECOVERY_FILES_REQUIRED')
    policy, host = bundle['policy'], bundle['host']
    require(host.GIT_SHA.fullmatch(args.git_sha) and host.BUILD_ID.fullmatch(args.build_id), 'RELEASE_IDENTITY_INVALID')
    recovery = module_from_bytes(bundle['files']['host/recover-project.py'], args.bundle_dir / 'host/recover-project.py')
    require(recovery.NAME.fullmatch(args.export_id), 'EXPORT_ID_INVALID')
    accepted_raw = read_safe(args.accepted_installation, {0o600})
    accepted = strict_json(accepted_raw)
    require(type(accepted) is dict and set(accepted) == {'schema', 'lock_sha256'}
            and accepted['schema'] == 'cnb-test-installation/v1'
            and type(accepted['lock_sha256']) is str and recovery.HASH.fullmatch(accepted['lock_sha256']), 'ACCEPTED_INSTALLATION_INVALID')
    target_raw = read_safe(args.target, {0o600})
    target = strict_json(target_raw)
    require(type(target) is dict and set(target) == {'host', 'port', 'user', 'identity_file', 'known_hosts_file'}
            and type(target['host']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{0,252}', target['host'])
            and type(target['port']) is int and 1 <= target['port'] <= 65535
            and type(target['user']) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', target['user']), 'TARGET_INVALID')
    target_pins = {}
    for name, modes in [('identity_file', {0o400, 0o600}), ('known_hosts_file', {0o400, 0o600, 0o644})]:
        require(type(target[name]) is str and Path(target[name]).is_absolute(), 'TARGET_INVALID')
        target_pins[name] = sha(read_safe(target[name], modes))
    pull_raw = read_safe(args.pull_docker_config, {0o600}) if args.pull_docker_config else None
    if pull_raw is not None:
        require(type(strict_json(pull_raw)) is dict, 'DOCKER_CONFIG_INVALID')
    args.evidence_dir = args.evidence_dir.absolute()
    require(args.evidence_dir.parent.resolve(strict=True) == args.evidence_dir.parent, 'PRIVATE_DIRECTORY_INVALID')
    safe_directory_ancestors(args.evidence_dir.parent)
    if os.path.lexists(args.evidence_dir):
        safe_directory_ancestors(args.evidence_dir)
        info = args.evidence_dir.lstat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_INVALID')
    # These are the installed controller files, not every CI or installer artifact.
    fixed = {'tat-deploy-test.py': ('host/tat-deploy-test.py', 0o555),
             'host-policy.json': ('host-policy.json', 0o444), 'docker-compose.yml': ('docker-compose.yml', 0o444),
             'tat-command.sh': ('tat-command.sh', 0o444), 'recover-project.py': ('host/recover-project.py', 0o555),
             'recovery-policy.json': ('recovery-policy.json', 0o444)}
    if policy['environment'] == 'production':
        fixed.update(installer.PRODUCTION_FILES)
    runtime = {name: {'source': source, 'sha256': sha(bundle['files'][source]), 'mode': mode}
               for name, (source, mode) in fixed.items()}
    scope = {'project': policy['project'], 'environment': policy['environment'], 'export_id': args.export_id,
             'host_policy_sha256': runtime['host-policy.json']['sha256'],
             'controller_sha256': runtime['tat-deploy-test.py']['sha256'],
             'recovery_policy_sha256': runtime['recovery-policy.json']['sha256']}
    binding = {'bundle_lock_sha256': args.lock_sha256, 'accepted_installation_sha256': sha(accepted_raw),
               'target_sha256': sha(target_raw), 'target_files': target_pins, 'scope': scope,
               'git_sha': args.git_sha, 'build_id': args.build_id,
               'pull_config_sha256': sha(pull_raw) if pull_raw else None}
    request = {'scope': scope, 'git_sha': args.git_sha, 'build_id': args.build_id,
               'installed_lock_sha256': accepted['lock_sha256'], 'runtime': runtime, 'install_dir': policy['install_dir']}
    return SimpleNamespace(args=args, bundle=bundle, recovery=recovery, target=target, request=request,
                           scope=scope, binding=sha(canonical(binding)), pull_raw=pull_raw)


def remote_main():
    """Fixed root collector/dispatcher, transported verbatim; never supplied by CI."""
    import contextlib, hashlib, json, os, re, shutil, stat, sys
    from pathlib import Path
    from types import ModuleType, SimpleNamespace

    def check(value):
        if not value:
            raise ValueError('RECOVERY_REMOTE_INVALID')

    @contextlib.contextmanager
    def opened(path, mode, maximum):
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
                info = os.fstat(directory)
                check((info.st_uid, info.st_gid) == (0, 0) and not info.st_mode & 0o022)
            handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(handle, 'rb') as stream:
                before = os.fstat(stream.fileno())
                check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (before.st_uid, before.st_gid) == (0, 0)
                      and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= maximum)
                yield stream
                after = os.fstat(stream.fileno())
                check(all(getattr(before, key) == getattr(after, key) for key in
                          ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
        finally:
            os.close(directory)

    def read(path, mode=0o444):
        with opened(path, mode, 8 * 1024 ** 2) as stream:
            return stream.read()

    try:
        check(os.geteuid() == 0 and sys.platform == 'linux')
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        check(len(raw) <= 1024 * 1024)
        request = json.loads(raw)
        scope = request['scope']
        check(re.fullmatch('[a-z][a-z0-9-]{0,47}', scope['project']) and scope['environment'] in ('test', 'production'))
        install = Path('/opt/cnb-devops') / scope['project'] / scope['environment'] / 'v1'
        check(str(install) == request['install_dir'])
        accepted = {'schema': 'cnb-test-installation/v1', 'lock_sha256': request['installed_lock_sha256']}
        check(json.loads(read(install / 'installation.json')) == accepted)
        old_raw = read(install / 'artifact-lock.json')
        check(hashlib.sha256(old_raw).hexdigest() == accepted['lock_sha256'])
        old_lock = json.loads(old_raw)
        check(old_lock['schema'] == 'cnb-devops-artifacts/v1')
        captured = {}
        for name, record in request['runtime'].items():
            check(re.fullmatch('[A-Za-z0-9_.-]+', name))
            captured[name] = read(install / name, record['mode'])
            check(hashlib.sha256(captured[name]).hexdigest() == record['sha256']
                  and old_lock['files'].get(record['source']) == record['sha256'])
        recovery = ModuleType('verified_installed_recovery')
        recovery.__file__ = str(install / 'recover-project.py')
        exec(compile(captured['recover-project.py'], recovery.__file__, 'exec'), recovery.__dict__)
        args = SimpleNamespace(project=scope['project'], environment=scope['environment'], export_id=scope['export_id'],
                               policy_sha256=scope['host_policy_sha256'], controller_sha256=scope['controller_sha256'],
                               recovery_policy_sha256=scope['recovery_policy_sha256'], apply=False)
        host, policy, docker = recovery.load_source(args)
        with recovery.release_lock(host) as account:
            release_raw, release = recovery.source_release(host, account)
            check(release['git_sha'] == request['git_sha'] and release['build_id'] == request['build_id'])
            output = recovery.export_directory(args)
            pending = os.path.lexists(host.RECOVERY_TRANSACTION_PATH)
            def optional(name):
                path = output / name
                return recovery.strict_json(recovery.root_read(path, 0o600)) if os.path.lexists(path) else None
            exported = None
            if os.path.lexists(output):
                journal = optional('journal.json')
                check(type(journal) is dict)
                check(journal == recovery.journal_identity(args, recovery.sha(release_raw), journal['containers']))
                if pending:
                    check(recovery.root_read(host.RECOVERY_TRANSACTION_PATH, 0o600) == recovery.canonical(journal))
                exported = {'journal': journal, 'receipt': optional('export-receipt.json'), 'resumed': optional('source-resumed.json')}
            if not pending:
                host._assert_release_unblocked()
            if request['action'] == 'download':
                check(not pending and exported and exported['receipt'] and exported['resumed'])
                check(request['name'] in ('export.tar', 'export-receipt.json', 'source-resumed.json', 'journal.json'))
                with opened(output / request['name'], 0o600, recovery.MAX_BYTES) as stream:
                    shutil.copyfileobj(stream, sys.stdout.buffer)
                return
            containers = [docker.inspect(host.CONTAINERS[role]) for role in host.SERVICES]
            db = docker.inspect(host.POLICY['database']['container'])
            pg = recovery.Postgres(docker, db['id'], host.POLICY['database']['admin_user'], host.POLICY['database']['name'])
            if not pending:
                for role, item in zip(host.SERVICES, containers):
                    check(item['name'] == '/' + host.CONTAINERS[role] and item['image'] == release['images'][role]
                          and item['running'] and item['health'] in (None, 'healthy') and not item['auto_remove'])
                host._probe_public_urls(request['git_sha'], request['build_id'])
            state = {'schema': 'cnb-recovery-source-state/v1', 'project': args.project, 'environment': args.environment,
                     'git_sha': release['git_sha'], 'build_id': release['build_id'],
                     'installed_lock_sha256': accepted['lock_sha256'], 'source_release_sha256': recovery.sha(release_raw),
                     'containers': containers, 'postgres': {'image': db['image'], 'version_num': pg.version(), 'database': pg.database},
                     'source_docker_id_sha256': docker.identity(), 'public_identity_verified': not pending,
                     'pending': pending, 'export': exported}
            if request['action'] == 'export':
                check(not pending and exported is None and request['before'] == state)
                recovery.export_source(args, host, policy, docker, account)  # standard preview before mutation
                args.apply = True
                state = recovery.export_source(args, host, policy, docker, account)
            else:
                check(request['action'] == 'inspect')
            print(json.dumps(state, sort_keys=True))
    except Exception:
        # The installed tool may have touched writers. Never guess or print subprocess values.
        print('{"status":"stopped_review_required","code":"RECOVERY_REMOTE_INCOMPLETE"}')
        sys.exit(1)


class SSHTransport:
    def __init__(self, plan):
        self.plan = plan

    def call(self, action, *, destination=None, **extra):
        target = self.plan.target
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-p', str(target['port']), '-i', target['identity_file']]
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
                       'PreferredAuthentications=publickey', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                       'GlobalKnownHostsFile=/dev/null', 'UserKnownHostsFile=' + target['known_hosts_file'],
                       'ConnectTimeout=15', 'ConnectionAttempts=1', 'ServerAliveInterval=15', 'ServerAliveCountMax=3'):
            command += ['-o', option]
        remote = ['/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8',
                  '/usr/bin/python3', '-I', '-c', inspect.getsource(remote_main) + '\nremote_main()\n']
        if target['user'] != 'root':
            remote = ['/usr/bin/sudo', '-n', '--', *remote]
        command += [target['user'] + '@' + target['host'], shlex.join(remote)]
        with tempfile.TemporaryFile() as captured:
            result = subprocess.run(command, input=canonical({**self.plan.request, 'action': action, **extra}),
                                    stdout=destination or captured, stderr=subprocess.DEVNULL, timeout=1800, check=False)
            require(result.returncode == 0, 'SSH_INCOMPLETE')
            if destination is not None:
                require(destination.tell() <= self.plan.recovery.MAX_BYTES, 'TRANSFER_TOO_LARGE')
                return
            require(captured.tell() <= 1024 * 1024, 'SSH_OUTPUT_TOO_LARGE')
            captured.seek(0)
            return strict_json(captured.read())

    def inspect(self):
        return self.call('inspect')

    def export(self, before):
        return self.call('export', before=before)

    def download(self, name, destination):
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            self.call('download', destination=stream, name=name)
            stream.flush()
            os.fsync(stream.fileno())


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, raw):
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


class Session:
    def __init__(self, plan):
        self.plan, self.root = plan, plan.args.evidence_dir

    def __enter__(self):
        safe_directory_ancestors(self.root.parent)
        if not os.path.lexists(self.root):
            self.root.mkdir(mode=0o700)
            sync_directory(self.root.parent)
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'PRIVATE_DIRECTORY_INVALID')
        self.fd = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(self.fd)
        try:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600, 'SESSION_LOCK_INVALID')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root / 'state.json'
            if os.path.lexists(path):
                self.state = strict_json(read_safe(path, {0o600}))
                require(self.state.get('schema') == 'cnb-recovery-session/v1' and self.state.get('binding') == self.plan.binding, 'SESSION_INPUT_CHANGED')
                for name, expected in self.state['evidence'].items():
                    require(re.fullmatch('[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?', name)
                            and '..' not in Path(name).parts, 'EVIDENCE_PATH_INVALID')
                    require(self.record(self.root / name) == expected, 'EVIDENCE_CHANGED')
            else:
                require(set(p.name for p in self.root.iterdir()) == {'.lock'}, 'NEW_SESSION_DIRECTORY_REQUIRED')
                self.state = {'schema': 'cnb-recovery-session/v1', 'binding': self.plan.binding, 'created_at': now(),
                              'events': [], 'evidence': {}, 'export_started': False, 'restore_started': False,
                              'status': 'prepared', 'resume_stage': 'inspect-source'}
                self.save()
            return self
        except BaseException:
            os.close(self.fd)
            raise

    def __exit__(self, _kind, error, _traceback):
        try:
            if error is not None:
                self.state.update(status='stopped_review_required', failed_at=now())
                self.save()
                error.resume_stage = self.state['resume_stage']
        finally:
            os.close(self.fd)

    def save(self):
        atomic_write(self.root / 'state.json', canonical(self.state))

    def record(self, path):
        # The bundled descriptor-safe reader enforces size, single links and stable bytes.
        safe_directory_ancestors(path.parent)
        info = path.lstat()
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_EVIDENCE_INVALID')
        with self.plan.recovery.regular(path) as stream:
            return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'bytes': os.fstat(stream.fileno()).st_size}

    def retain(self, name):
        self.state['evidence'][name] = self.record(self.root / name)
        self.save()

    def evidence(self, name, model):
        raw = canonical(model)
        path = self.root / name
        if os.path.lexists(path):
            require(read_safe(path, {0o600}) == raw, 'EVIDENCE_CHANGED')
        else:
            atomic_write(path, raw)
        self.retain(name)

    def stage(self, name, action):
        event = {'stage': name, 'started_at': now(), 'status': 'running'}
        self.state['events'].append(event)
        self.state.update(resume_stage=name, status='running')
        self.save()
        try:
            result = action()
            event['status'] = 'passed'
            return result
        except BaseException as error:
            event.update(status='stopped_review_required', code=str(error) if isinstance(error, SessionError) else 'STAGE_INCOMPLETE')
            raise
        finally:
            event['finished_at'] = now()
            self.save()


def validate_source(plan, source):
    require(type(source) is dict and source.get('schema') == 'cnb-recovery-source-state/v1', 'SOURCE_STATE_INVALID')
    require(all(source.get(key) == value for key, value in
                {'project': plan.scope['project'], 'environment': plan.scope['environment'], 'git_sha': plan.args.git_sha,
                 'build_id': plan.args.build_id, 'installed_lock_sha256': plan.request['installed_lock_sha256']}.items()), 'SOURCE_IDENTITY_MISMATCH')
    require(source.get('pending') is False, 'SOURCE_RESUME_REQUIRED')
    require(source.get('public_identity_verified') is True and type(source.get('containers')) is list and source['containers'], 'SOURCE_STATE_INVALID')
    names = ['/' + plan.bundle['host'].CONTAINERS[role] for role in plan.bundle['host'].SERVICES]
    require([item.get('name') for item in source['containers']] == names, 'SOURCE_SERVICE_SET_MISMATCH')
    for item in source['containers']:
        require(type(item.get('id')) is str and plan.recovery.HASH.fullmatch(item['id'])
                and type(item.get('image')) is str and plan.recovery.IMAGE.fullmatch(item['image']), 'SOURCE_CONTAINER_INVALID')
        require(item['running'] is True and item['health'] in (None, 'healthy') and not item['paused']
                and not item['restarting'] and not item['auto_remove'], 'SOURCE_UNHEALTHY')
    return source


def stable_source(source):
    return {key: value for key, value in source.items() if key not in ('export', 'pending')}


def verify_export(plan, before, after):
    require(stable_source(before) == stable_source(after), 'SOURCE_CHANGED')
    exported = after.get('export')
    require(type(exported) is dict and exported.get('resumed') is not None, 'SOURCE_RESUME_REQUIRED')
    journal = {'schema': 'cnb-recovery-export-journal/v1', **plan.scope,
               'source_release_sha256': before['source_release_sha256'], 'containers': before['containers']}
    require(exported['journal'] == journal, 'EXPORT_JOURNAL_MISMATCH')
    require(exported['resumed'] == {'schema': 'cnb-recovery-source-resume/v1', 'status': 'resumed',
                                   'journal_sha256': sha(plan.recovery.canonical(journal))}, 'SOURCE_RESUME_REQUIRED')
    receipt = exported['receipt']
    require(type(receipt) is dict and set(receipt) == {'schema', 'status', 'archive_sha256', 'manifest_sha256', 'external_restore_verified'}
            and receipt['schema'] == 'cnb-recovery-export-receipt/v1' and receipt['status'] == 'exported'
            and receipt['external_restore_verified'] is False
            and all(type(receipt[k]) is str and plan.recovery.HASH.fullmatch(receipt[k]) for k in ('archive_sha256', 'manifest_sha256')), 'EXPORT_RECEIPT_INVALID')
    return exported


def prepare_local(plan, source, directory):
    recovery = plan.recovery
    docker = recovery.local_docker()
    target_id = docker.identity()
    require(target_id != source['source_docker_id_sha256'], 'DIFFERENT_DOCKER_REQUIRED')
    # Pin the observed socket, so a later personal context change cannot redirect restore.
    endpoint = docker.run(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], maximum=4096, timeout=30).decode().strip()
    require(endpoint.startswith('unix:///'), 'LOCAL_UNIX_DOCKER_REQUIRED')
    docker.prefix = [docker.prefix[0], '--host', endpoint]
    image = source['postgres']['image']
    require(recovery.IMAGE.fullmatch(image), 'POSTGRES_IMAGE_INVALID')
    try:
        info = strict_json(docker.run(['image', 'inspect', '--format', '{"os":{{json .Os}},"architecture":{{json .Architecture}}}', image]))
    except Exception:
        require(plan.pull_raw is not None, 'CACHED_POSTGRES_OR_PULL_CONFIG_REQUIRED')
        with tempfile.TemporaryDirectory(prefix='pull-auth-', dir=directory) as temporary:
            auth = Path(temporary) / 'config.json'
            atomic_write(auth, plan.pull_raw)
            pull = recovery.Docker([*docker.prefix, '--config', temporary], docker.environment)
            pull.run(['pull', '--platform=linux/amd64', image], timeout=900)
        info = strict_json(docker.run(['image', 'inspect', '--format', '{"os":{{json .Os}},"architecture":{{json .Architecture}}}', image]))
    require(info.get('os') == 'linux' and info.get('architecture') == 'amd64', 'CACHED_POSTGRES_PLATFORM_INVALID')
    return docker, target_id


def verify_restore(plan, receipt, manifest, transfer, target_id):
    require(type(receipt) is dict and receipt.get('schema') == 'cnb-recovery-restore-receipt/v1'
            and receipt.get('status') == 'verified', 'RESTORE_RECEIPT_INVALID')
    expected = {'external_restore_verified': True, 'schema_equal': True, 'all_table_data_equal': True,
                'sequences_equal': True, 'business_files_equal': True, 'file_ownership_remapped_to_local_user': True,
                'archive_sha256': transfer['archive_sha256'], 'manifest_sha256': transfer['manifest_sha256'],
                'source_release_sha256': manifest['source_release_sha256'], 'source_docker_id_sha256': manifest['source_docker_id_sha256'],
                'target_docker_id_sha256': target_id, 'postgres_image': manifest['postgres']['image'],
                'postgres_version_num': manifest['postgres']['version_num'], 'scope': manifest['scope']}
    require(all(receipt.get(key) == value and type(receipt.get(key)) is type(value) for key, value in expected.items()), 'RESTORE_RECEIPT_MISMATCH')
    require(type(receipt.get('target_container_id')) is str and plan.recovery.HASH.fullmatch(receipt['target_container_id'])
            and type(receipt.get('target_volume')) is str and re.fullmatch('cnb-recovery-[0-9a-f]{24}', receipt['target_volume']), 'RESTORE_TARGET_INVALID')


def verify_target(docker, receipt):
    container = docker.inspect(receipt['target_container_id'])
    require(container['id'] == receipt['target_container_id'] and container['running'] is False, 'RESTORE_TARGET_RUNNING')
    template = ('{"network_mode":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
                '"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}}}')
    actual = strict_json(docker.run(['inspect', '--type', 'container', '--format', template, receipt['target_container_id']]))
    require(actual['network_mode'] == 'none' and actual['ports'] in ({}, None)
            and type(actual['networks']) is dict and set(actual['networks']) == {'none'}
            and len(actual['mounts']) == 1
            and all(actual['mounts'][0].get(key) == value for key, value in
                    {'Type': 'volume', 'Name': receipt['target_volume'], 'Destination': '/var/lib/postgresql/data'}.items()),
            'RESTORE_TARGET_ISOLATION_MISMATCH')


def execute(plan, transport=None):
    transport = transport or SSHTransport(plan)
    with Session(plan) as session:
        current = session.stage('inspect-source', lambda: validate_source(plan, transport.inspect()))
        before_path = session.root / 'source-before.json'
        if 'source-before.json' in session.state['evidence']:
            before = strict_json(read_safe(before_path, {0o600}))
            require(stable_source(before) == stable_source(current), 'SOURCE_CHANGED')
        else:
            require(current['export'] is None and not session.state['export_started'], 'EXPORT_ALREADY_EXISTS')
            before = current
            session.evidence('source-before.json', before)
        docker, target_id = session.stage('prepare-local', lambda: prepare_local(plan, current, session.root))
        if current['export'] is None:
            require(not session.state['export_started'], 'EXPORT_RESULT_UNKNOWN_REVIEW_REQUIRED')
            session.state['export_started'] = True
            session.save()  # durable before the first request that can pause writers
            session.stage('export', lambda: transport.export(before))
            current = session.stage('inspect-source-after-export', lambda: validate_source(plan, transport.inspect()))
        exported = session.stage('verify-source-resumed', lambda: verify_export(plan, before, current))
        session.evidence('source-after.json', current)
        session.evidence('export-result.json', exported['receipt'])
        for name, expected in [('journal.json', exported['journal']), ('export-receipt.json', exported['receipt']),
                               ('source-resumed.json', exported['resumed']), ('export.tar', None)]:
            if name not in session.state['evidence']:
                temporary = session.root / ('.download-' + secrets.token_hex(8))
                def download():
                    transport.download(name, temporary)
                    if expected is not None:
                        require(read_safe(temporary, {0o600}) == plan.recovery.canonical(expected), 'TRANSFER_RECEIPT_MISMATCH')
                    session.record(temporary)
                    os.replace(temporary, session.root / name)
                    sync_directory(session.root)
                    session.retain(name)
                session.stage('download-' + name, download)
        transfer = exported['receipt']
        def validate_archive():
            with plan.recovery.verified_archive(session.root / 'export.tar', transfer['archive_sha256'], transfer['manifest_sha256']) as (_tar, model):
                require(all(model[key] == value for key, value in plan.scope.items()), 'ARCHIVE_SCOPE_MISMATCH')
                require(model['source_release_sha256'] == before['source_release_sha256']
                        and model['source_release']['git_sha'] == plan.args.git_sha and model['source_release']['build_id'] == plan.args.build_id
                        and model['source_docker_id_sha256'] == before['source_docker_id_sha256']
                        and model['postgres'] == before['postgres'], 'ARCHIVE_SOURCE_MISMATCH')
                return model
        manifest = session.stage('verify-archive', validate_archive)
        destination = session.root / 'restore'
        receipt_path = destination / 'restore-receipt.json'
        local_args = SimpleNamespace(archive=str(session.root / 'export.tar'), archive_sha256=transfer['archive_sha256'],
                                     manifest_sha256=transfer['manifest_sha256'], destination=str(destination), apply=False)
        if session.state['restore_started']:
            require('restore/restore-receipt.json' in session.state['evidence'], 'RESTORE_REVIEW_REQUIRED')
            receipt = strict_json(read_safe(receipt_path, {0o600}))
        else:
            original_local = plan.recovery.local_docker
            plan.recovery.local_docker = lambda: docker
            try:
                session.stage('restore-preview', lambda: plan.recovery.restore_local(local_args))
                session.state['restore_started'] = True
                session.save()
                local_args.apply = True
                receipt = session.stage('restore', lambda: plan.recovery.restore_local(local_args))
                require(read_safe(receipt_path, {0o600}) == plan.recovery.canonical(receipt), 'RESTORE_RECEIPT_MISMATCH')
                verify_restore(plan, receipt, manifest, transfer, target_id)
                session.retain('restore/restore-receipt.json')
            finally:
                plan.recovery.local_docker = original_local
        session.stage('verify-restore-receipt', lambda: verify_restore(plan, receipt, manifest, transfer, target_id))
        session.stage('verify-restore-target', lambda: verify_target(docker, receipt))
        final_source = session.stage('inspect-source-final', lambda: validate_source(plan, transport.inspect()))
        verify_export(plan, before, final_source)
        session.evidence('source-final.json', final_source)
        result = {'schema': 'cnb-recovery-session-result/v1', 'status': 'verified', 'project': plan.scope['project'],
                  'environment': plan.scope['environment'], 'git_sha': plan.args.git_sha, 'build_id': plan.args.build_id,
                  'export_id': plan.args.export_id, 'bundle_lock_sha256': plan.args.lock_sha256,
                  'installed_lock_sha256': plan.request['installed_lock_sha256'], 'external_restore_verified': True,
                  'restore_receipt_sha256': session.state['evidence']['restore/restore-receipt.json']['sha256'],
                  'source_unchanged': True, 'scope': receipt['scope']}
        session.evidence('result.json', result)
        session.state.update(status='verified', resume_stage='complete', verified_at=now())
        session.save()
        return result


def main(argv=None):
    os.umask(0o077)
    plan = prepare(parse_args(argv))
    result = execute(plan) if plan.args.apply else {
        'schema': 'cnb-recovery-session-result/v1', 'status': 'preview', 'project': plan.scope['project'],
        'environment': plan.scope['environment'], 'git_sha': plan.args.git_sha, 'build_id': plan.args.build_id,
        'export_id': plan.args.export_id, 'bundle_lock_sha256': plan.args.lock_sha256,
        'installed_lock_sha256': plan.request['installed_lock_sha256'], 'external_restore_verified': False,
        'actions': ['inspect-source', 'prepare-local', 'export-once', 'verify-source-resumed', 'download', 'restore-local', 'compare-source']}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error) if isinstance(error, SessionError) else 'RECOVERY_SESSION_INCOMPLETE'
        print(json.dumps({'schema': 'cnb-recovery-session-result/v1', 'status': 'stopped_review_required',
                          'code': code, 'resume_stage': getattr(error, 'resume_stage', 'prepare')}))
        raise SystemExit(1)
