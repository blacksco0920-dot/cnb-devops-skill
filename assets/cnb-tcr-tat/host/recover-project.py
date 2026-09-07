#!/usr/bin/env python3
"""Root export and isolated local PostgreSQL/business-file recovery. Preview is default.

No application credentials, runtime environment, or cluster roles are exported.
Source applications pause under their installed release lock; a durable recovery
marker blocks deployment until their exact original containers have resumed.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from types import ModuleType

MAX_BYTES = 8 * 1024 ** 3
MAX_FILES = 100000
HASH = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[a-z][a-z0-9-]{0,47}')
MOUNT = re.compile(r'[a-z][a-z0-9_-]{0,62}')
IMAGE = re.compile(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}')
CLEAN = {'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8'}


class RecoveryError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise RecoveryError(code)


def canonical(model):
    return (json.dumps(model, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(RecoveryError('nonfinite_json')))
    except (ValueError, UnicodeError) as exc:
        raise RecoveryError('invalid_json') from exc


def stable(info):
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                                'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


@contextlib.contextmanager
def regular(path, maximum=MAX_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'unsafe_file')
        yield stream
        require(stable(before) == stable(os.fstat(stream.fileno())) == stable(path.lstat()), 'file_changed')


def file_record(path):
    with regular(path) as stream:
        return {'bytes': os.fstat(stream.fileno()).st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def read_file(path, maximum=1024 * 1024):
    with regular(path, maximum) as stream:
        return stream.read(maximum + 1)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)


def safe_relative(value):
    require(type(value) is str and value and '\\' not in value and '\x00' not in value, 'unsafe_archive_path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and '..' not in path.parts and value != '.', 'unsafe_archive_path')
    return path


def tree_entries(root, tar=None):
    """Walk opened directory descriptors; never follow links or cross filesystems."""
    result, total = [], 0
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_info = os.fstat(root_fd)

    def visit(fd, prefix):
        nonlocal total
        before = os.fstat(fd)
        names = sorted(os.listdir(fd))
        for name in names:
            relative = '/'.join(prefix + [name])
            safe_relative(relative)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_dev == root_info.st_dev and not info.st_mode & 0o7000, 'unsupported_business_file')
            record = {'path': relative, 'mode': stat.S_IMODE(info.st_mode)}
            member = tarfile.TarInfo(relative)
            member.mode = record['mode']
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(stable(info) == stable(os.fstat(child)), 'business_directory_changed')
                    record['kind'] = 'directory'
                    result.append(record)
                    if tar:
                        member.type = tarfile.DIRTYPE
                        tar.addfile(member)
                    visit(child, prefix + [name])
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsupported_business_file')
                total += info.st_size
                require(total <= MAX_BYTES, 'business_data_too_large')
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(child, 'rb') as stream:
                    require(stable(info) == stable(os.fstat(stream.fileno())), 'business_file_changed')
                    record.update(kind='file', bytes=info.st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
                    result.append(record)
                    if tar:
                        stream.seek(0)
                        member.size = info.st_size
                        tar.addfile(member, stream)
                    require(stable(info) == stable(os.fstat(stream.fileno())), 'business_file_changed')
            require(stable(info) == stable(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'business_entry_changed')
            require(len(result) <= MAX_FILES, 'too_many_business_files')
        require(names == sorted(os.listdir(fd)) and stable(before) == stable(os.fstat(fd)), 'business_directory_changed')
    try:
        visit(root_fd, [])
        require(stable(root_info) == stable(root.lstat()), 'business_root_changed')
    finally:
        os.close(root_fd)
    return result


def tree_fingerprint(root):
    entries = tree_entries(root)
    return {'tree_sha256': sha(canonical(entries)), 'files': sum(r['kind'] == 'file' for r in entries),
            'bytes': sum(r.get('bytes', 0) for r in entries)}


def pack_tree(root, destination):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as tar:
            entries = tree_entries(root, tar)
        stream.flush()
        os.fsync(stream.fileno())
    result = {'tree_sha256': sha(canonical(entries)), 'files': sum(r['kind'] == 'file' for r in entries),
              'bytes': sum(r.get('bytes', 0) for r in entries)}
    require(tree_fingerprint(root) == result, 'business_tree_changed')
    return result


def restore_tree(archive, destination):
    with regular(archive) as stream, tarfile.open(fileobj=stream, mode='r:') as tar:
        members = []
        for member in tar:
            require(len(members) < MAX_FILES, 'too_many_tree_members')
            members.append(member)
        require(len(members) <= MAX_FILES and len({m.name for m in members}) == len(members), 'invalid_tree_archive')
        total = 0
        kinds = {}
        for member in members:
            relative = safe_relative(member.name)
            require(member.isdir() or member.isfile(), 'unsupported_tree_member')
            require(not member.mode & ~0o777 and member.size >= 0, 'unsupported_tree_mode')
            require(all(kinds.get(str(p)) == 'directory' for p in relative.parents if str(p) != '.'), 'tree_parent_missing')
            total += member.size
            require(total <= MAX_BYTES, 'business_data_too_large')
            kinds[member.name] = 'directory' if member.isdir() else 'file'
        destination.mkdir(mode=0o700)
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(mode=0o700)
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as out:
                    shutil.copyfileobj(tar.extractfile(member), out)
                    out.flush()
                    os.fchmod(out.fileno(), member.mode)
                    os.fsync(out.fileno())
        for member in reversed(members):
            if member.isdir():
                (destination / member.name).chmod(member.mode)
        sync_dir(destination)


def validate_recovery_policy(model, host, host_sha):
    require(type(model) is dict and set(model) == {'schema', 'project', 'environment', 'host_policy_sha256',
                                                'mounts', 'required_nonempty_tables'}, 'recovery_policy_invalid')
    require(model['schema'] == 'cnb-recovery-policy/v1' and model['project'] == host['project']
            and model['environment'] == host['environment'] and model['host_policy_sha256'] == host_sha, 'recovery_scope_mismatch')
    sources = {Path(m['source']).name for s in host['services'].values() for m in s['mounts']}
    require(type(model['mounts']) is dict and len(model['mounts']) <= 256 and set(model['mounts']) == sources
            and all(MOUNT.fullmatch(k) for k in model['mounts'])
            and all(v in ('backup', 'rebuild') for v in model['mounts'].values()), 'mount_classification_incomplete')
    for service in host['services'].values():
        for mount in service['mounts']:
            require(Path(mount['source']).parent == Path(host['app_dir']), 'mount_scope_invalid')
    tables = model['required_nonempty_tables']
    require(type(tables) is list and 1 <= len(tables) <= 256, 'business_tables_required')
    seen = set()
    for table in tables:
        require(type(table) is dict and set(table) == {'schema', 'name', 'minimum_rows'}, 'table_requirement_invalid')
        require(all(type(table[k]) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]{0,62}', table[k]) for k in ('schema', 'name'))
                and type(table['minimum_rows']) is int and table['minimum_rows'] > 0, 'table_requirement_invalid')
        key = (table['schema'], table['name'])
        require(key not in seen, 'duplicate_table_requirement')
        seen.add(key)
    return model


class Docker:
    def __init__(self, prefix, environment):
        self.prefix, self.environment = prefix, environment

    def run(self, args, *, data=None, source=None, output=None, maximum=8 * 1024 ** 2, timeout=900):
        with tempfile.TemporaryFile() as captured:
            options = {'input': data} if data is not None else {'stdin': source or subprocess.DEVNULL}
            result = subprocess.run(self.prefix + args, stdout=output or captured, stderr=subprocess.DEVNULL,
                                    env=self.environment, timeout=timeout, check=False, **options)
            require(result.returncode == 0, 'docker_operation_failed')
            if output is None:
                require(captured.tell() <= maximum, 'command_output_too_large')
                captured.seek(0)
                return captured.read()

    def identity(self):
        raw = self.run(['info', '--format', '{{.ID}}'], maximum=1024, timeout=30).strip()
        require(bool(raw), 'docker_identity_missing')
        return sha(raw)

    def inspect(self, reference):
        template = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},'
                    '"running":{{json .State.Running}},"paused":{{json .State.Paused}},'
                    '"restarting":{{json .State.Restarting}},"auto_remove":{{json .HostConfig.AutoRemove}},'
                    '"health":{{if index .State "Health"}}{{json .State.Health.Status}}{{else}}null{{end}}}')
        model = strict_json(self.run(['inspect', '--type', 'container', '--format', template, reference], maximum=8192, timeout=30))
        require(type(model) is dict and HASH.fullmatch(model.get('id', '')), 'container_identity_invalid')
        require(not model['paused'] and not model['restarting'], 'container_transition_in_progress')
        return model


def identifier(value):
    require(type(value) is str and '\x00' not in value, 'database_identifier_invalid')
    return '"' + value.replace('"', '""') + '"'


class Postgres:
    def __init__(self, docker, container, user, database):
        self.docker, self.container, self.user, self.database = docker, container, user, database

    def argv(self, tool, *options):
        return ['exec', '-i', '--env', 'PGOPTIONS=-c timezone=UTC -c datestyle=ISO,YMD -c extra_float_digits=3',
                self.container, tool, '-U', self.user, '-d', self.database, *options]

    def sql(self, query, output=None):
        return self.docker.run(self.argv('psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'), data=query, output=output)

    def version(self):
        value = int(self.sql(b'SHOW server_version_num;').strip())
        require(160000 <= value < 170000, 'postgresql_16_required')
        return value

    def fingerprint(self):
        self.version()
        unsupported = self.sql(b"SELECT (SELECT count(*) FROM pg_foreign_table)+(SELECT count(*) FROM pg_largeobject_metadata);")
        require(unsupported.strip() == b'0', 'unsupported_external_or_large_object_store')
        schema = self.docker.run(self.argv('pg_dump', '--schema-only', '--no-owner', '--no-privileges',
                                          '--restrict-key=CnbRecoverySchemaV1'), maximum=32 * 1024 ** 2)
        catalog = self.sql(b"SELECT COALESCE(json_agg(json_build_object('schema',n.nspname,'name',c.relname,'kind',c.relkind) ORDER BY n.nspname COLLATE \"C\",c.relname COLLATE \"C\"),'[]') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','m','S') AND n.nspname <> 'information_schema' AND n.nspname !~ '^pg_';")
        tables, sequences = [], []
        for relation in strict_json(catalog):
            qualified = identifier(relation['schema']) + '.' + identifier(relation['name'])
            if relation['kind'] == 'S':
                state = strict_json(self.sql(('SELECT row_to_json(s) FROM (SELECT last_value,is_called FROM ' + qualified + ') s;').encode()))
                sequences.append({'schema': relation['schema'], 'name': relation['name'], **state})
                continue
            query = ('COPY (SELECT h FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,\'UTF8\')),\'hex\') h FROM ONLY '
                     + qualified + ' t) rows ORDER BY h COLLATE "C") TO STDOUT;').encode()
            with tempfile.TemporaryFile() as hashes:
                self.sql(query, output=hashes)
                require(hashes.tell() <= MAX_BYTES, 'table_fingerprint_too_large')
                hashes.seek(0)
                count, digest = 0, hashlib.sha256()
                for line in hashes:
                    require(re.fullmatch(rb'[0-9a-f]{64}\n', line) is not None, 'row_fingerprint_invalid')
                    count += 1
                    digest.update(line)
            tables.append({'schema': relation['schema'], 'name': relation['name'], 'rows': count, 'sha256': digest.hexdigest()})
        return {'schema_sha256': sha(schema), 'tables': tables, 'sequences_sha256': sha(canonical(sequences))}

    def dump(self, path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            self.docker.run(self.argv('pg_dump', '--format=custom', '--no-owner', '--no-privileges'), output=stream)
            stream.flush()
            os.fsync(stream.fileno())
        with regular(path) as stream:
            require(stream.read(5) == b'PGDMP', 'database_dump_invalid')

    def restore(self, path):
        self.version()
        empty = self.sql(b"SELECT (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_')+(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_')+(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_')+(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_');")
        require(empty.strip() == b'0', 'restore_target_not_empty')
        with regular(path) as source:
            self.docker.run(self.argv('pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges'), source=source)


def require_business_rows(fingerprint, requirements):
    observed = {(t['schema'], t['name']): t['rows'] for t in fingerprint['tables']}
    require(all(observed.get((t['schema'], t['name']), -1) >= t['minimum_rows'] for t in requirements), 'representative_business_data_missing')


def observe_original_containers(docker, originals):
    current = []
    for original in originals:
        require(original.get('auto_remove') is False, 'auto_removed_container_cannot_resume')
        item = docker.inspect(original['id'])
        require(all(item[key] == original[key] for key in ('id', 'name', 'image')), 'source_container_changed')
        require(original['running'] or not item['running'], 'originally_stopped_container_started')
        current.append(item)
    return current


def resume_containers(docker, originals, timeout=900):
    current = observe_original_containers(docker, originals)  # Check the entire set before starting any.
    stopped = [old['id'] for old, now in zip(originals, current) if old['running'] and not now['running']]
    if stopped:
        docker.run(['start', *stopped], timeout=120)
    deadline = time.monotonic() + timeout
    while True:
        current = observe_original_containers(docker, originals)
        if all(not old['running'] or now['running'] and now['health'] in (None, 'healthy') for old, now in zip(originals, current)):
            return
        require(time.monotonic() < deadline, 'source_resume_timeout')
        time.sleep(2)


def root_read(path, mode):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require((info.st_uid, info.st_gid) == (0, 0) and not info.st_mode & 0o022, 'untrusted_root_ancestor')
        handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(handle, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024 ** 2
                    and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, 0, mode), 'untrusted_root_file')
            raw = stream.read()
            require(stable(before) == stable(os.fstat(stream.fileno()))
                    == stable(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'root_file_changed')
            return raw
    finally:
        os.close(fd)


def root_directory(path, mode=0o755):
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        wanted = mode if current == path else 0o755
        if not current.exists() and not current.is_symlink():
            current.mkdir(mode=wanted)
            current.chmod(wanted)
            sync_dir(current.parent)
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
                and not info.st_mode & 0o022, 'unsafe_root_directory')
        if current == path:
            require(stat.S_IMODE(info.st_mode) == mode, 'root_directory_mode_mismatch')


def load_source(args):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'source_requires_linux_root')
    require(NAME.fullmatch(args.project) and args.environment in ('test', 'production')
            and NAME.fullmatch(args.export_id), 'source_scope_invalid')
    for value in (args.policy_sha256, args.controller_sha256, args.recovery_policy_sha256):
        require(HASH.fullmatch(value), 'source_pin_invalid')
    install = Path('/opt/cnb-devops') / args.project / args.environment / 'v1'
    code = root_read(install / 'tat-deploy-test.py', 0o555)
    policy_raw = root_read(install / 'host-policy.json', 0o444)
    recovery_raw = root_read(install / 'recovery-policy.json', 0o444)
    require((sha(code), sha(policy_raw), sha(recovery_raw)) == (args.controller_sha256, args.policy_sha256,
                                                             args.recovery_policy_sha256), 'installed_pin_mismatch')
    host = ModuleType('verified_recovery_host')
    host.__file__ = str(install / 'tat-deploy-test.py')
    exec(compile(code, host.__file__, 'exec'), host.__dict__)
    host.configure_policy(strict_json(policy_raw), policy_sha256=args.policy_sha256)
    require(host.POLICY['project'] == args.project and host.POLICY['environment'] == args.environment
            and host.POLICY['install_dir'] == str(install), 'installed_scope_mismatch')
    recovery = validate_recovery_policy(strict_json(recovery_raw), host.POLICY, args.policy_sha256)
    docker = Docker(host._docker_prefix(), host.BASE_ENV)
    return host, recovery, docker


@contextlib.contextmanager
def release_lock(host):
    fd = os.open(host.LOCK_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        account = pwd.getpwnam(host.POLICY['release_user'])
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (account.pw_uid, account.pw_gid, 0o600), 'release_lock_invalid')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield account
    finally:
        os.close(fd)


def source_release(host, account):
    raw, release = host._load_private_record(host.RELEASE_PATH, kind='release', uid=account.pw_uid,
                                            gid=account.pw_gid, required=True)
    require(release.get('status') == 'passed' and set(release['images']) == set(host.SERVICES), 'accepted_source_release_required')
    return raw, release


def export_directory(args):
    return Path('/var/lib/cnb-devops') / args.project / args.environment / 'exports' / args.export_id


def journal_identity(args, release_sha, containers):
    return {'schema': 'cnb-recovery-export-journal/v1', 'project': args.project, 'environment': args.environment,
            'export_id': args.export_id, 'host_policy_sha256': args.policy_sha256,
            'controller_sha256': args.controller_sha256, 'recovery_policy_sha256': args.recovery_policy_sha256,
            'source_release_sha256': release_sha, 'containers': containers}


def resume_source(args, host, docker, account, *, apply=True):
    marker = root_read(host.RECOVERY_TRANSACTION_PATH, 0o600)
    journal = strict_json(marker)
    require(type(journal) is dict and type(journal.get('containers')) is list
            and len(journal['containers']) == len(host.SERVICES), 'export_journal_invalid')
    release_raw, release = source_release(host, account)
    expected = journal_identity(args, sha(release_raw), journal['containers'])
    require(marker == canonical(expected), 'export_journal_identity_mismatch')
    require(not os.path.lexists(host.TRANSACTION_PATH), 'release_transaction_present')
    by_name = {item.get('name'): item for item in journal['containers']}
    require(set(by_name) == {'/' + n for n in host.CONTAINERS.values()}, 'journal_container_set_mismatch')
    for role, name in host.CONTAINERS.items():
        item = by_name['/' + name]
        require(set(item) == {'id', 'name', 'image', 'running', 'paused', 'restarting', 'health', 'auto_remove'}
                and HASH.fullmatch(item['id']) and item['image'] == release['images'][role]
                and type(item['running']) is bool and item['paused'] is False and item['restarting'] is False and item['auto_remove'] is False
                and item['health'] in (None, 'healthy', 'unhealthy', 'starting'), 'journal_container_invalid')
    output = export_directory(args)
    require(root_read(output / 'journal.json', 0o600) == marker, 'export_audit_journal_mismatch')
    if not apply:
        observe_original_containers(docker, journal['containers'])
        return {'status': 'preview', 'action': 'resume_exact_original_containers', 'journal_sha256': sha(marker)}
    resume_containers(docker, journal['containers'], timeout=host.POLICY.get('startup_timeout_seconds', 900))
    require(source_release(host, account)[0] == release_raw and root_read(host.RECOVERY_TRANSACTION_PATH, 0o600) == marker,
            'source_changed_during_resume')
    receipt = {'schema': 'cnb-recovery-source-resume/v1', 'status': 'resumed', 'journal_sha256': sha(marker)}
    receipt_path = output / 'source-resumed.json'
    if receipt_path.exists():
        require(root_read(receipt_path, 0o600) == canonical(receipt), 'resume_receipt_mismatch')
    else:
        write_new(receipt_path, canonical(receipt))
    os.unlink(host.RECOVERY_TRANSACTION_PATH)
    sync_dir(host.RECOVERY_STATE_DIR)
    return receipt


def export_source(args, host, recovery, docker, account):
    host._assert_release_unblocked()
    release_raw, release = source_release(host, account)
    containers = [docker.inspect(host.CONTAINERS[role]) for role in host.SERVICES]
    for role, item in zip(host.SERVICES, containers):
        require(item['name'] == '/' + host.CONTAINERS[role] and item['image'] == release['images'][role]
                and item['auto_remove'] is False, 'source_container_mismatch')
        actual = strict_json(docker.run(['inspect', '--type', 'container', '--format', '{{json .Mounts}}', item['id']]))
        persistent = sorted((m['Type'], m['Source'], m['Destination']) for m in actual if m['Type'] != 'tmpfs')
        declared = sorted(('bind', m['source'], m['target']) for m in host.POLICY['services'][role]['mounts'])
        require(persistent == declared, 'unclassified_or_changed_runtime_mount')
    database = host.POLICY['database']
    db_container = docker.inspect(database['container'])
    require(db_container['running'] and IMAGE.fullmatch(db_container['image']), 'pinned_running_postgres_required')
    pg = Postgres(docker, db_container['id'], database['admin_user'], database['name'])
    version, docker_sha = pg.version(), docker.identity()
    if not args.apply:
        return {'status': 'preview', 'action': 'pause_export_resume', 'project': args.project, 'environment': args.environment,
                'export_id': args.export_id, 'source_release_sha256': sha(release_raw), 'scope': recovery['mounts']}
    output = export_directory(args)
    root_directory(output.parent, 0o700)
    output.mkdir(mode=0o700)
    sync_dir(output.parent)
    root_directory(host.RECOVERY_ROOT)
    root_directory(host.RECOVERY_STATE_DIR)
    marker = canonical(journal_identity(args, sha(release_raw), containers))
    write_new(output / 'journal.json', marker)
    write_new(host.RECOVERY_TRANSACTION_PATH, marker)
    try:
        running = [item['id'] for item in containers if item['running']]
        if running:
            docker.run(['stop', '--time', '30', *running], timeout=180)
        require(all(not docker.inspect(item['id'])['running'] for item in containers), 'source_writers_not_stopped')
        require(pg.sql(b"SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid();").strip() == b'0', 'other_database_clients_present')
        before = pg.fingerprint()
        require_business_rows(before, recovery['required_nonempty_tables'])
        payload = output / 'payload'
        payload.mkdir(mode=0o700)
        (payload / 'mounts').mkdir(mode=0o700)
        pg.dump(payload / 'database.dump')
        files, mounts = {'database.dump': file_record(payload / 'database.dump')}, {}
        for source, classification in sorted(recovery['mounts'].items()):
            mounts[source] = {'classification': classification}
            if classification == 'backup':
                name = 'mounts/' + source + '.tar'
                mounts[source].update(archive=name, **pack_tree(host.APP_DIR / source, payload / name))
                files[name] = file_record(payload / name)
        require(pg.fingerprint() == before and source_release(host, account)[0] == release_raw, 'source_changed_during_export')
        require(all(not docker.inspect(item['id'])['running'] for item in containers), 'source_writers_restarted')
        for source, item in mounts.items():
            if item['classification'] == 'backup':
                require(tree_fingerprint(host.APP_DIR / source) == {k: item[k] for k in ('tree_sha256', 'files', 'bytes')}, 'business_tree_changed')
        manifest = {'schema': 'cnb-recovery-export/v1', 'project': args.project, 'environment': args.environment,
                    'export_id': args.export_id, 'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'source_release_sha256': sha(release_raw), 'source_release': release,
                    'host_policy_sha256': args.policy_sha256, 'controller_sha256': args.controller_sha256,
                    'recovery_policy_sha256': args.recovery_policy_sha256, 'source_docker_id_sha256': docker_sha,
                    'postgres': {'image': db_container['image'], 'version_num': version, 'database': database['name']},
                    'files': files, 'database': before, 'mounts': mounts,
                    'scope': {'postgres': True, 'business_mounts': sorted(k for k,v in recovery['mounts'].items() if v == 'backup'),
                              'rebuildable_mounts': sorted(k for k,v in recovery['mounts'].items() if v == 'rebuild'),
                              'redis': False, 'full_host': False}}
        write_new(payload / 'manifest.json', canonical(manifest))
        archive = output / 'export.tar'
        descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            with tarfile.open(fileobj=stream, mode='w') as tar:
                for name in ['manifest.json', *sorted(files)]:
                    with regular(payload / name) as source:
                        member = tarfile.TarInfo(name)
                        member.mode, member.size = 0o600, os.fstat(source.fileno()).st_size
                        tar.addfile(member, source)
            stream.flush()
            os.fsync(stream.fileno())
        result = {'schema': 'cnb-recovery-export-receipt/v1', 'status': 'exported', 'archive_sha256': file_record(archive)['sha256'],
                  'manifest_sha256': sha(canonical(manifest)), 'external_restore_verified': False}
        write_new(output / 'export-receipt.json', canonical(result))
    finally:
        resume_source(args, host, docker, account)
    return result


def validate_manifest(model):
    expected = {'schema', 'project', 'environment', 'export_id', 'created_at', 'source_release_sha256', 'source_release',
                'host_policy_sha256', 'controller_sha256', 'recovery_policy_sha256', 'source_docker_id_sha256',
                'postgres', 'files', 'database', 'mounts', 'scope'}
    require(type(model) is dict and set(model) == expected and model['schema'] == 'cnb-recovery-export/v1', 'export_manifest_invalid')
    require(NAME.fullmatch(model['project']) and NAME.fullmatch(model['export_id'])
            and model['environment'] in ('test', 'production'), 'export_scope_invalid')
    for key in ('source_release_sha256', 'host_policy_sha256', 'controller_sha256', 'recovery_policy_sha256', 'source_docker_id_sha256'):
        require(type(model[key]) is str and HASH.fullmatch(model[key]), 'export_digest_invalid')
    require(sha(canonical(model['source_release'])) == model['source_release_sha256']
            and model['source_release'].get('status') == 'passed', 'export_release_mismatch')
    pg = model['postgres']
    require(type(pg) is dict and set(pg) == {'image', 'version_num', 'database'} and IMAGE.fullmatch(pg['image'])
            and type(pg['version_num']) is int and 160000 <= pg['version_num'] < 170000
            and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', pg['database']), 'postgres_manifest_invalid')
    require(type(model['mounts']) is dict and len(model['mounts']) <= 256, 'mount_manifest_invalid')
    names = {'database.dump'}
    backup, rebuild = [], []
    for source, item in model['mounts'].items():
        require(MOUNT.fullmatch(source) and type(item) is dict, 'mount_manifest_invalid')
        if item.get('classification') == 'rebuild':
            require(set(item) == {'classification'}, 'mount_manifest_invalid')
            rebuild.append(source)
        else:
            require(set(item) == {'classification', 'archive', 'tree_sha256', 'files', 'bytes'}
                    and item['classification'] == 'backup' and item['archive'] == 'mounts/' + source + '.tar'
                    and HASH.fullmatch(item['tree_sha256']) and type(item['files']) is int and 0 <= item['files'] <= MAX_FILES
                    and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_BYTES, 'mount_manifest_invalid')
            names.add(item['archive'])
            backup.append(source)
    require(model['scope'] == {'postgres': True, 'business_mounts': sorted(backup), 'rebuildable_mounts': sorted(rebuild),
                               'redis': False, 'full_host': False}, 'restore_scope_mismatch')
    require(type(model['files']) is dict and set(model['files']) == names, 'export_file_set_mismatch')
    total = 0
    for name, item in model['files'].items():
        safe_relative(name)
        require(type(item) is dict and set(item) == {'bytes', 'sha256'} and HASH.fullmatch(item['sha256'])
                and type(item['bytes']) is int and 0 < item['bytes'] <= MAX_BYTES, 'export_file_record_invalid')
        total += item['bytes']
    require(total <= MAX_BYTES, 'export_too_large')
    fingerprint = model['database']
    require(type(fingerprint) is dict and set(fingerprint) == {'schema_sha256', 'tables', 'sequences_sha256'}
            and HASH.fullmatch(fingerprint['schema_sha256']) and HASH.fullmatch(fingerprint['sequences_sha256'])
            and type(fingerprint['tables']) is list and 1 <= len(fingerprint['tables']) <= 10000, 'database_fingerprint_invalid')
    seen = set()
    for table in fingerprint['tables']:
        require(type(table) is dict and set(table) == {'schema', 'name', 'rows', 'sha256'}
                and type(table['rows']) is int and table['rows'] >= 0 and HASH.fullmatch(table['sha256'])
                and all(type(table[k]) is str and table[k] and '\x00' not in table[k] for k in ('schema','name')), 'table_fingerprint_invalid')
        key = (table['schema'], table['name'])
        require(key not in seen, 'duplicate_table_fingerprint')
        seen.add(key)
    require(sum(t['rows'] for t in fingerprint['tables']) > 0, 'empty_backup_is_not_business_recovery')
    return model


@contextlib.contextmanager
def verified_archive(path, archive_sha, manifest_sha):
    require(HASH.fullmatch(archive_sha) and HASH.fullmatch(manifest_sha), 'transfer_pin_invalid')
    with regular(path) as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == archive_sha, 'transfer_checksum_mismatch')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            members = []
            for member in tar:
                require(len(members) < 258, 'too_many_export_members')
                members.append(member)
            require(len(members) <= 258 and len({m.name for m in members}) == len(members)
                    and all(m.isfile() and 0 < m.size <= MAX_BYTES for m in members), 'export_archive_invalid')
            by_name = {m.name: m for m in members}
            require('manifest.json' in by_name and by_name['manifest.json'].size <= 1024 ** 2, 'export_manifest_missing')
            raw = tar.extractfile(by_name['manifest.json']).read()
            require(sha(raw) == manifest_sha, 'manifest_checksum_mismatch')
            model = validate_manifest(strict_json(raw))
            require(raw == canonical(model) and set(by_name) == {'manifest.json', *model['files']}, 'export_members_mismatch')
            for name, record in model['files'].items():
                require(by_name[name].size == record['bytes'] and hashlib.file_digest(tar.extractfile(by_name[name]), 'sha256').hexdigest()
                        == record['sha256'], 'export_payload_checksum_mismatch')
            yield tar, model


def local_docker():
    binary = shutil.which('docker')
    require(binary is not None, 'local_docker_required')
    environment = {**CLEAN, 'HOME': str(Path.home())}
    docker = Docker([binary], environment)
    context = docker.run(['context', 'show'], maximum=1024, timeout=30).decode().strip()
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', context), 'local_docker_context_invalid')
    endpoint = docker.run(['context', 'inspect', context, '--format', '{{.Endpoints.docker.Host}}'], maximum=4096, timeout=30).decode().strip()
    require(endpoint.startswith('unix:///'), 'local_unix_docker_required')
    return Docker([binary, '--context', context], environment)


def restore_local(args):
    require(HASH.fullmatch(args.archive_sha256) and HASH.fullmatch(args.manifest_sha256), 'transfer_pin_invalid')
    archive = Path(args.archive).resolve(strict=True)
    destination = Path(args.destination).absolute()
    require(destination.parent.resolve(strict=True) == destination.parent and not os.path.lexists(destination), 'new_private_destination_required')
    with verified_archive(archive, args.archive_sha256, args.manifest_sha256) as (tar, model):
        docker = local_docker()
        target_id = docker.identity()
        require(target_id != model['source_docker_id_sha256'], 'different_docker_daemon_required')
        image = model['postgres']['image']
        image_info = strict_json(docker.run(['image', 'inspect', '--format', '{"os":{{json .Os}},"architecture":{{json .Architecture}},"id":{{json .Id}}}', image]))
        require(image_info['os'] == 'linux' and image_info['architecture'] == 'amd64', 'cached_linux_amd64_postgres_required')
        if not args.apply:
            return {'status': 'preview', 'manifest_sha256': args.manifest_sha256, 'scope': model['scope'], 'postgres_image': image}
        destination.mkdir(mode=0o700)
        sync_dir(destination.parent)
        write_new(destination / 'restore.pending.json', canonical({'archive_sha256': args.archive_sha256, 'manifest_sha256': args.manifest_sha256}))
        payload = destination / 'payload'
        payload.mkdir(mode=0o700)
        (payload / 'mounts').mkdir(mode=0o700)
        for member in tar.getmembers():
            path = payload / member.name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                shutil.copyfileobj(tar.extractfile(member), stream)
                stream.flush()
                os.fsync(stream.fileno())
        for name, record in model['files'].items():
            require(file_record(payload / name) == record, 'extracted_payload_changed')
    resource_name = 'cnb-recovery-' + secrets.token_hex(12)
    require(resource_name not in docker.run(['volume', 'ls', '--format', '{{.Name}}', '--filter', 'name=' + resource_name]).decode().splitlines(),
            'restore_volume_already_exists')
    volume = docker.run(['volume', 'create', '--label', 'cnb.recovery.manifest=' + args.manifest_sha256, resource_name]).decode().strip()
    require(volume == resource_name, 'restore_volume_identity_missing')
    write_new(destination / 'target.json', canonical({'container_name': resource_name, 'volume': volume, 'docker_id_sha256': target_id}))
    env = ('POSTGRES_USER=recovery\nPOSTGRES_DB=' + model['postgres']['database'] + '\nPOSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n').encode()
    write_new(destination / 'restore.env', env)
    created = None
    try:
        created = docker.run(['run', '--detach', '--pull=never', '--platform=linux/amd64', '--network=none', '--name', resource_name,
                              '--env-file', str(destination / 'restore.env'), '--mount', 'type=volume,src=' + volume + ',dst=/var/lib/postgresql/data', image]).decode().strip()
        require(HASH.fullmatch(created), 'restore_container_identity_missing')
        write_new(destination / 'container.json', canonical({'id': created}))
        pg = Postgres(docker, created, 'recovery', model['postgres']['database'])
        deadline = time.monotonic() + 90
        while True:
            try:
                ready = docker.run(['exec', created, 'cat', '/proc/1/comm'], maximum=128, timeout=5).strip() == b'postgres'
                if ready and pg.version() == model['postgres']['version_num']:
                    break
            except RecoveryError:
                pass
            require(time.monotonic() < deadline, 'restore_postgres_not_ready_or_version_mismatch')
            time.sleep(1)
        pg.restore(payload / 'database.dump')
        restored = pg.fingerprint()
        write_new(destination / 'restored-database.json', canonical(restored))
        require(restored == model['database'], 'restored_database_mismatch')
        business = destination / 'business'
        business.mkdir(mode=0o700)
        for source, item in model['mounts'].items():
            if item['classification'] == 'backup':
                restore_tree(payload / item['archive'], business / source)
                require(tree_fingerprint(business / source) == {k: item[k] for k in ('tree_sha256', 'files', 'bytes')}, 'restored_business_files_mismatch')
        docker.run(['stop', '--time', '30', created], timeout=60)
        require(not docker.inspect(created)['running'], 'isolated_target_not_stopped')
        result = {'schema': 'cnb-recovery-restore-receipt/v1', 'status': 'verified', 'external_restore_verified': True,
                  'archive_sha256': args.archive_sha256, 'manifest_sha256': args.manifest_sha256,
                  'source_release_sha256': model['source_release_sha256'], 'source_docker_id_sha256': model['source_docker_id_sha256'],
                  'target_docker_id_sha256': target_id, 'postgres_image': image, 'postgres_version_num': model['postgres']['version_num'],
                  'schema_equal': True, 'all_table_data_equal': True, 'sequences_equal': True, 'business_files_equal': True,
                  'file_ownership_remapped_to_local_user': True, 'scope': model['scope'], 'target_volume': volume,
                  'target_container_id': created, 'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}
        write_new(destination / 'restore-receipt.json', canonical(result))
        os.unlink(destination / 'restore.pending.json')
        sync_dir(destination)
        return result
    finally:
        if created and HASH.fullmatch(created):
            docker.run(['stop', '--time', '30', created], timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('export', 'resume-source'):
        sub = commands.add_parser(command)
        for name in ('project', 'environment', 'policy-sha256', 'controller-sha256', 'recovery-policy-sha256', 'export-id'):
            sub.add_argument('--' + name, required=True)
        sub.add_argument('--apply', action='store_true')
    local = commands.add_parser('restore-local')
    for name in ('archive', 'archive-sha256', 'manifest-sha256', 'destination'):
        local.add_argument('--' + name, required=True)
    local.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'restore-local':
        result = restore_local(args)
    else:
        host, recovery, docker = load_source(args)
        with release_lock(host) as account:
            if args.command == 'export':
                result = export_source(args, host, recovery, docker, account)
            else:
                result = resume_source(args, host, docker, account, apply=args.apply)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Database rows, runtime values, subprocess output and exception details remain private.
        print(json.dumps({'status': 'stopped_review_required', 'reason': str(exc) if isinstance(exc, RecoveryError) else type(exc).__name__}, sort_keys=True))
        raise SystemExit(1)
