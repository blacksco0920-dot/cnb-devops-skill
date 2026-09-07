#!/usr/bin/env python3
"""Fixed production authorization entry; shares the existing transaction engine.

Signature and preparation checks adapt the bounded FinAgent production sources.
Only the administrator's public key is installed; no host Git credentials exist.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from contextlib import redirect_stdout
from types import ModuleType

MAX_ENVELOPE = 48 * 1024
MAX_CANDIDATE = 24 * 1024
DOMAIN = b'cnb-production-approval-v1\0'
OPENSSL = '/usr/bin/openssl'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
AUTHORITY_KEYS = {'schema', 'project', 'environment', 'controller_program_sha256',
                  'host_policy_sha256', 'controller_compose_sha256', 'approval_public_key_sha256'}


class ProductionError(ValueError):
    pass


def require(value, code):
    if not value:
        raise ProductionError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'production_fields_invalid')
    return value


def canonical(value):
    def check(item):
        if type(item) is dict:
            require(all(type(k) is str and k.isascii() for k in item), 'production_json_keys')
            for child in item.values():
                check(child)
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is int:
            require(abs(item) <= 9007199254740991, 'production_json_number')
        else:
            require(item is None or type(item) in (str, bool), 'production_json_value')
    try:
        check(value)
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        raise ProductionError('production_json_invalid') from exc


def parse_canonical(raw, limit=64 * 1024):
    require(type(raw) is bytes and 0 < len(raw) <= limit, 'production_json_size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'production_duplicate_key')
            result[key] = value
        return result
    def forbidden(_):
        raise ProductionError('production_json_number')
    try:
        model = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique,
                           parse_constant=forbidden, parse_float=forbidden)
        require(canonical(model) == raw, 'production_json_not_canonical')
        return model
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProductionError('production_json_invalid') from exc


def validate_authority(model):
    exact(model, AUTHORITY_KEYS)
    require(model['schema'] == 'cnb-production-authority/v1' and model['environment'] == 'production'
            and type(model['project']) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', model['project']), 'production_authority_scope')
    for field in AUTHORITY_KEYS - {'schema', 'project', 'environment'}:
        require(type(model[field]) is str and HEX64.fullmatch(model[field]), 'production_authority_hash')
    return model


def render_tat_template(policy, wrapper_sha256, authority_sha256):
    install = policy['install_dir']
    require(type(install) is str and re.fullmatch(r'/opt/cnb-devops/[a-z0-9/-]+', install)
            and '..' not in install.split('/'), 'production_install_path')
    require(all(type(v) is str and HEX64.fullmatch(v) for v in (wrapper_sha256, authority_sha256)), 'production_template_hash')
    # The Python gate executes captured verified bytes, never a reopened program.
    return ('''#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 30
/usr/bin/python3 -I - "$0" <<'CNB_PRODUCTION_GATE'
import hashlib, os, pathlib, stat, sys
root = pathlib.Path(INSTALL_LITERAL)
captured = {}
for name, expected, mode in [('production-release.py', ENTRY_LITERAL, 0o555), ('production-authority.json', AUTHORITY_LITERAL, 0o444)]:
    path = root / name
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022: raise SystemExit(31)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(512 * 1024 + 1)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode or hashlib.sha256(raw).hexdigest() != expected: raise SystemExit(32)
    captured[name] = raw
entry = str(root / 'production-release.py')
sys.argv = [entry, '--tat-script', sys.argv[1]]
exec(compile(captured['production-release.py'], entry, 'exec'), {'__name__': '__main__', '__file__': entry})
CNB_PRODUCTION_GATE
# cnb-production-request:{{release_request_b64url}}
'''.replace('INSTALL_LITERAL', repr(install)).replace('ENTRY_LITERAL', repr(wrapper_sha256))
            .replace('AUTHORITY_LITERAL', repr(authority_sha256))).encode('ascii')


APPROVAL_KEYS = {'schema', 'project', 'environment', 'authorize', 'approval_id', 'candidate_tag',
                 'candidate_manifest_sha256', 'candidate_bytes_sha256', 'application_commit', 'build_id',
                 'authority_sha256', 'prepared_sha256', 'previous_release_sha256', 'issued_at', 'expires_at'}
CANDIDATE_KEYS = {'project', 'environment', 'controller', 'policy_sha256', 'release_receipt_sha256',
                  'application_commit', 'build_id', 'build_url', 'candidate_tag', 'controller_commit',
                  'controller_compose_sha256', 'controller_program_sha256', 'created_at', 'evidence',
                  'manifest_sha256', 'schema', 'services'}
READY_KEYS = {'schema', 'status', 'project', 'environment', 'controller', 'application_commit', 'build_id',
              'images', 'candidate_tag', 'candidate_manifest_sha256', 'candidate_bytes_sha256', 'production_entry_sha256',
              'production_authority_sha256', 'controller_program_sha256', 'policy_sha256', 'controller_compose_sha256',
              'prepared_created_at', 'prepared_expires_at', 'previous_release_sha256', 'host_fingerprint_sha256'}
RESULT_KEYS = {'schema', 'status', 'project', 'environment', 'approval_id', 'approval_sha256', 'candidate_tag',
               'candidate_manifest_sha256', 'candidate_bytes_sha256', 'prepared_sha256', 'production_entry_sha256',
               'production_authority_sha256', 'release_record_sha256', 'release'}
EXECUTION_KEYS = {'schema', 'status', 'approval_sha256', 'request_sha256', 'started_at', 'previous_release_sha256', 'result'}


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value), 'production_time')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except ValueError as exc:
        raise ProductionError('production_time') from exc


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def unbase64(value, limit=MAX_ENVELOPE):
    require(type(value) is str and 0 < len(value) <= limit and re.fullmatch(r'[A-Za-z0-9_-]+', value), 'production_base64url')
    raw = base64.urlsafe_b64decode(value + '=' * ((4 - len(value) % 4) % 4))
    require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') == value, 'production_base64url')
    return raw


def validate_approval_payload(value):
    exact(value, APPROVAL_KEYS)
    require(value['schema'] == 'cnb-production-approval/v1' and value['environment'] == 'production'
            and value['authorize'] == 'production-apply', 'production_approval_scope')
    patterns = {'project': r'[a-z][a-z0-9-]{0,62}', 'approval_id': r'[0-9a-f]{32}',
                'application_commit': r'[0-9a-f]{40}', 'build_id': r'cnb-[a-z0-9][a-z0-9-]{2,127}',
                'candidate_tag': r'[a-z][a-z0-9-]{0,191}'}
    for field, pattern in patterns.items():
        require(type(value[field]) is str and re.fullmatch(pattern, value[field]), 'production_approval_identity')
    for field in ('candidate_manifest_sha256', 'candidate_bytes_sha256', 'authority_sha256',
                  'prepared_sha256', 'previous_release_sha256'):
        require(type(value[field]) is str and HEX64.fullmatch(value[field]), 'production_approval_hash')
    require(0 < utc(value['expires_at']) - utc(value['issued_at']) <= 3600, 'production_approval_lifetime')
    return value


def validate_public_key(raw):
    require(type(raw) is bytes and re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/]{59}=\n-----END PUBLIC KEY-----\n', raw), 'production_public_key')
    encoded = raw.splitlines()[1]
    der = base64.b64decode(encoded, validate=True)
    require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100')
            and base64.b64encode(der) == encoded, 'production_public_key')
    return raw


def verify_approval_signature(envelope, public_key):
    exact(envelope, ('schema', 'payload_b64url', 'signature_b64url'))
    require(envelope['schema'] == 'cnb-production-approval-envelope/v1', 'production_approval_envelope')
    raw, signature = unbase64(envelope['payload_b64url'], 8192), unbase64(envelope['signature_b64url'], 86)
    require(len(signature) == 64, 'production_signature_size')
    payload = validate_approval_payload(parse_canonical(raw, 8192))
    validate_public_key(public_key)
    with tempfile.TemporaryDirectory(prefix='cnb-production-signature-') as directory:
        directory = Path(directory)
        for name, data in (('message', DOMAIN + raw), ('signature', signature), ('public.pem', public_key)):
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
        result = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', str(directory / 'public.pem'),
                                 '-in', str(directory / 'message'), '-sigfile', str(directory / 'signature')],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=15, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, check=False)
        require(result.returncode == 0, 'production_signature_rejected')
    return payload


def validate_candidate(raw, policy):
    value = exact(parse_canonical(raw, MAX_CANDIDATE), CANDIDATE_KEYS)
    require(value['schema'] == 'cnb-candidate/v1' and value['project'] == policy['project']
            and value['environment'] == 'test', 'production_candidate_scope')
    require(type(value['application_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', value['application_commit'])
            and value['controller_commit'] == value['application_commit'], 'production_candidate_commit')
    require(type(value['build_id']) is str and re.fullmatch(r'cnb-[a-z0-9][a-z0-9-]{2,127}', value['build_id'])
            and value['candidate_tag'] == policy['project'] + '-candidate-' + value['build_id'], 'production_candidate_tag')
    utc(value['created_at'])
    for name in ('policy_sha256', 'release_receipt_sha256', 'controller_compose_sha256', 'controller_program_sha256', 'manifest_sha256'):
        require(type(value[name]) is str and HEX64.fullmatch(value[name]), 'production_candidate_hash')
    unsigned = dict(value)
    unsigned.pop('manifest_sha256')
    require(sha(canonical(unsigned)[:-1]) == value['manifest_sha256'], 'production_candidate_content')
    exact(value['services'], policy['services'])
    for role, spec in policy['services'].items():
        require(type(value['services'][role]) is str and re.fullmatch(re.escape(spec['image_repository']) + r'@sha256:[0-9a-f]{64}', value['services'][role]), 'production_candidate_image')
    exact(value['evidence'], ('build', 'runtime', 'public'))
    for plane, keys in {'build': ('status', 'verified_at', 'reference'),
                        'runtime': ('status', 'verified_at', 'reference', 'container_count'),
                        'public': ('status', 'verified_at', 'reference', 'probe_count', 'probes')}.items():
        evidence = exact(value['evidence'][plane], keys)
        require(evidence['status'] == 'passed', 'production_candidate_evidence')
        utc(evidence['verified_at'])
        require(type(evidence['reference']) is str and re.fullmatch(r'(https://[^\s]+|tat:inv-[A-Za-z0-9-]{8,64})', evidence['reference']), 'production_candidate_reference')
    public = value['evidence']['public']
    require(value['evidence']['build']['reference'] == value['build_url']
            and type(value['evidence']['runtime']['container_count']) is int
            and value['evidence']['runtime']['container_count'] == len(policy['services'])
            and type(public['probes']) is list and 0 < len(public['probes']) <= 128
            and all(type(url) is str and re.fullmatch(r'https://[^\s]+', url) for url in public['probes'])
            and public['probes'] == sorted(set(public['probes']))
            and type(public['probe_count']) is int and public['probe_count'] == len(public['probes']), 'production_candidate_coverage')
    for url in [value['build_url'], *public['probes']]:
        parts = urlsplit(url)
        require(parts.scheme == 'https' and parts.hostname and not parts.username and not parts.password and not parts.fragment,
                'production_candidate_url')
    return value


def read_file(path, mode, uid, gid, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, mode), 'production_file_metadata')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(0 < len(raw) <= limit and before.st_size == len(raw)
            and (before.st_ino, before.st_dev, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_ino, after.st_dev, after.st_mtime_ns, after.st_ctime_ns), 'production_file_changed')
    return raw


def root_file(path, mode=0o444):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'production_authority_directory')
    return read_file(path, mode, 0, 0)


class ProductionRelease:
    def __init__(self, core, authority, authority_raw, public_key, entry_hash):
        self.core, self.authority, self.authority_hash = core, validate_authority(authority), sha(authority_raw)
        self.public_key, self.entry_hash = validate_public_key(public_key), entry_hash
        require(sha(public_key) == authority['approval_public_key_sha256'], 'production_public_key_hash')
        self.state = core.APP_DIR / '.production'
        self.uid, self.gid = os.geteuid(), os.getegid()

    def private(self, path):
        return read_file(path, 0o600, self.uid, self.gid)

    def state_directory(self):
        info = self.core.ENV_PATH.lstat()
        require(info.st_uid == self.uid and info.st_gid == self.gid, 'production_release_user')
        try:
            os.mkdir(self.state, 0o700)
            self.core._fsync_directory(self.core.APP_DIR)
        except FileExistsError:
            pass
        info = self.state.lstat()
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.uid, self.gid, 0o700), 'production_state_directory')

    def write(self, name, value, replace=False):
        path, raw = self.state / name, canonical(value)
        if replace:
            self.core._atomic_write(path, raw, 0o600, self.uid, self.gid)
        else:
            self.core._write_new(path, raw, 0o600, self.uid, self.gid)
            self.core._fsync_directory(self.state)
        require(self.private(path) == raw, 'production_state_readback')

    def pending_gate(self, allowed=None):
        for path in self.state.iterdir():
            if path.name.startswith('execution-') and path.suffix == '.json':
                record = self.execution(path)
                require(record.get('status') == 'complete' or path.name == allowed, 'production_pending_review')

    def execution(self, path):
        require(re.fullmatch(r'execution-[0-9a-f]{32}\.json', path.name), 'production_execution_name')
        record = exact(parse_canonical(self.private(path)), EXECUTION_KEYS)
        require(record['schema'] == 'cnb-production-execution/v1' and record['status'] in ('pending', 'complete'), 'production_execution_schema')
        utc(record['started_at'])
        for key in ('approval_sha256', 'request_sha256', 'previous_release_sha256'):
            require(type(record[key]) is str and HEX64.fullmatch(record[key]), 'production_execution_hash')
        if record['status'] == 'pending':
            require(record['result'] is None, 'production_execution_pending_result')
        else:
            result = exact(record['result'], RESULT_KEYS)
            require(result['schema'] == 'cnb-production-result/v1' and result['status'] == 'passed'
                    and result['project'] == self.core.POLICY['project'] and result['environment'] == 'production'
                    and result['approval_id'] == path.name[10:-5] and result['approval_sha256'] == record['approval_sha256'],
                    'production_execution_result')
            for key in ('candidate_manifest_sha256', 'candidate_bytes_sha256', 'prepared_sha256', 'production_entry_sha256',
                        'production_authority_sha256', 'release_record_sha256'):
                require(type(result[key]) is str and HEX64.fullmatch(result[key]), 'production_execution_hash')
            require(type(result['release']) is dict and result['release'].get('schema') == 'cnb-deploy-result/v1'
                    and result['release'].get('status') == 'passed', 'production_execution_receipt')
        return record

    def request(self, candidate):
        return dict(schema='cnb-release-request/v1', project=self.core.POLICY['project'], environment='production',
                    controller=self.core.CONTROLLER_ID, git_sha=candidate['application_commit'],
                    controller_commit=candidate['controller_commit'], build_id=candidate['build_id'], images=candidate['services'])

    def fingerprint(self):
        core = self.core
        release_raw, record = core._load_private_record(core.RELEASE_PATH, kind='release', uid=self.uid, gid=self.gid, required=True)
        facts = {'release_sha256': sha(release_raw), 'env_sha256': sha(self.private(core.ENV_PATH)),
                 'compose_sha256': sha(read_file(core.COMPOSE_PATH, 0o644, self.uid, self.gid))}
        names = core._run(core._docker_prefix() + ['ps', '-a', '--format', '{{.Names}}'], timeout=20, max_output=65536).decode('ascii').splitlines()
        scoped = set(core.CONTAINERS.values()) | {core.POLICY['database']['container']}
        if core.POLICY.get('redis'):
            scoped.add(core.POLICY['redis']['container'])
        facts['containers'] = {name: core._run(core._docker_prefix() + ['inspect', '--format', '{{.Id}} {{.Image}} {{.State.Status}}', name], timeout=20, max_output=1024).decode('ascii').strip()
                               for name in sorted(scoped.intersection(names))}
        facts['networks'] = {name: core._run(core._docker_prefix() + ['network', 'inspect', '--format', '{{.Id}}', name], timeout=20, max_output=128).decode('ascii').strip()
                             for name in core.POLICY['networks']}
        return facts['release_sha256'], sha(canonical(facts))

    def preflight(self, candidate):
        core = self.core
        env = self.private(core.ENV_PATH)
        with tempfile.TemporaryDirectory(prefix='.preflight-', dir=self.state) as directory:
            directory = Path(directory)
            candidate_env, candidate_compose = directory / '.env', directory / 'compose.yml'
            core._write_new(candidate_env, core.update_env_text(env.decode('utf-8'), candidate['services']).encode('utf-8'), 0o600, self.uid, self.gid)
            core._write_new(candidate_compose, core._read_controller_compose(), 0o600, self.uid, self.gid)
            core._preflight(env.decode('utf-8'), candidate['services'], candidate_compose, candidate_env)
            core._assert_empty_baseline_runtime(env, self.uid, self.gid)

    def readiness_locked(self, candidate, candidate_raw):
        self.state_directory()
        self.pending_gate()
        self.preflight(candidate)
        previous, fingerprint = self.fingerprint()
        created = int(time.time())
        receipt = dict(schema='cnb-production-readiness/v1', status='ready', project=self.core.POLICY['project'], environment='production',
                       controller=self.core.CONTROLLER_ID, application_commit=candidate['application_commit'], build_id=candidate['build_id'],
                       images=candidate['services'], candidate_tag=candidate['candidate_tag'], candidate_manifest_sha256=candidate['manifest_sha256'],
                       candidate_bytes_sha256=sha(candidate_raw), production_entry_sha256=self.entry_hash, production_authority_sha256=self.authority_hash,
                       controller_program_sha256=self.authority['controller_program_sha256'], policy_sha256=self.authority['host_policy_sha256'],
                       controller_compose_sha256=self.authority['controller_compose_sha256'], prepared_created_at=timestamp(created),
                       prepared_expires_at=timestamp(created + 86400), previous_release_sha256=previous, host_fingerprint_sha256=fingerprint)
        prepared = dict(schema='cnb-production-prepared/v1', nonce=os.urandom(16).hex(), receipt=receipt)
        digest = sha(canonical(prepared))
        self.write('prepared-' + digest + '.json', prepared)
        return dict(receipt, prepared_sha256=digest)

    def validate_approval(self, envelope, candidate, candidate_raw):
        value = verify_approval_signature(envelope, self.public_key)
        expected = {'project': self.core.POLICY['project'], 'candidate_tag': candidate['candidate_tag'],
                    'candidate_manifest_sha256': candidate['manifest_sha256'], 'candidate_bytes_sha256': sha(candidate_raw),
                    'application_commit': candidate['application_commit'], 'build_id': candidate['build_id'], 'authority_sha256': self.authority_hash}
        require(all(value[k] == v for k, v in expected.items()), 'production_approval_binding')
        require(utc(value['issued_at']) <= time.time() < utc(value['expires_at']), 'production_approval_expired')
        return value

    def prepared(self, approval, candidate):
        raw = self.private(self.state / ('prepared-' + approval['prepared_sha256'] + '.json'))
        require(sha(raw) == approval['prepared_sha256'], 'production_prepared_hash')
        model = exact(parse_canonical(raw), ('schema', 'nonce', 'receipt'))
        require(model['schema'] == 'cnb-production-prepared/v1' and type(model['nonce']) is str
                and re.fullmatch(r'[0-9a-f]{32}', model['nonce']), 'production_prepared_schema')
        ready = exact(model['receipt'], READY_KEYS)
        require(ready['schema'] == 'cnb-production-readiness/v1' and ready['status'] == 'ready'
                and ready['project'] == self.core.POLICY['project'] and ready['environment'] == 'production'
                and ready['controller'] == self.core.CONTROLLER_ID and ready['images'] == candidate['services'], 'production_prepared_scope')
        for key in ('candidate_tag', 'candidate_manifest_sha256', 'candidate_bytes_sha256', 'application_commit', 'build_id', 'previous_release_sha256'):
            require(ready[key] == approval[key], 'production_prepared_binding')
        require(ready['production_authority_sha256'] == self.authority_hash and ready['production_entry_sha256'] == self.entry_hash
                and ready['controller_program_sha256'] == self.authority['controller_program_sha256']
                and ready['controller_compose_sha256'] == self.authority['controller_compose_sha256']
                and ready['policy_sha256'] == self.authority['host_policy_sha256'],
                'production_prepared_controller')
        require(type(ready['host_fingerprint_sha256']) is str and HEX64.fullmatch(ready['host_fingerprint_sha256']), 'production_prepared_hash')
        require(utc(ready['prepared_created_at']) <= utc(approval['issued_at']) < utc(approval['expires_at']) <= utc(ready['prepared_expires_at'])
                and utc(ready['prepared_expires_at']) - utc(ready['prepared_created_at']) == 86400, 'production_prepared_expired')
        return ready

    def core_receipt(self, candidate, started_at):
        core = self.core
        raw, record = core._load_private_record(core.RELEASE_PATH, kind='release', uid=self.uid, gid=self.gid, required=True)
        require(record['schema'] == core.RELEASE_SCHEMA_V2 and record['git_sha'] == candidate['application_commit']
                and record['build_id'] == candidate['build_id'] and record['images'] == candidate['services']
                and record['controller_program_sha256'] == self.authority['controller_program_sha256']
                and record['controller_compose_sha256'] == self.authority['controller_compose_sha256']
                and datetime.fromisoformat(record['deployed_at'].replace('Z', '+00:00')).timestamp() >= utc(started_at), 'production_reconcile_required')
        root = core.APP_DIR / 'backups/releases'
        manifest = core.load_snapshot_manifest(root / record['snapshot'], release_root=root, uid=self.uid, gid=self.gid)
        require(sha(self.private(root / record['snapshot'] / core.SNAPSHOT_MANIFEST)) == record['snapshot_manifest_sha256'], 'production_snapshot_binding')
        receipt = dict(schema='cnb-deploy-result/v1', status='passed', project=core.POLICY['project'], environment='production',
                       controller=core.CONTROLLER_ID, git_sha=candidate['application_commit'], controller_commit=candidate['controller_commit'],
                       build_id=candidate['build_id'], images=candidate['services'], controller_program_sha256=self.authority['controller_program_sha256'],
                       controller_compose_sha256=self.authority['controller_compose_sha256'], policy_sha256=self.authority['host_policy_sha256'],
                       database_backup_sha256=manifest['files']['database.dump']['sha256'], container_count=len(core.SERVICES),
                       probe_count=len(core.PUBLIC_PROBES), probes=list(core.PUBLIC_PROBES))
        return raw, receipt

    def finalize(self, execution, approval, candidate):
        raw, receipt = self.core_receipt(candidate, execution['started_at'])
        require(sha(raw) != execution['previous_release_sha256'], 'production_reconcile_required')
        result = dict(schema='cnb-production-result/v1', status='passed', project=self.core.POLICY['project'], environment='production',
                      approval_id=approval['approval_id'], approval_sha256=execution['approval_sha256'], candidate_tag=candidate['candidate_tag'],
                      candidate_manifest_sha256=candidate['manifest_sha256'], candidate_bytes_sha256=approval['candidate_bytes_sha256'],
                      prepared_sha256=approval['prepared_sha256'], production_entry_sha256=self.entry_hash,
                      production_authority_sha256=self.authority_hash, release_record_sha256=sha(raw), release=receipt)
        completed = dict(execution, status='complete', result=result)
        if execution['status'] == 'complete':
            require(execution == completed, 'production_replay_receipt_changed')
            return result
        self.write('execution-' + approval['approval_id'] + '.json', completed, replace=True)
        return result

    def apply(self, candidate, candidate_raw, envelope):
        approval = self.validate_approval(envelope, candidate, candidate_raw)
        request = self.request(candidate)
        name = 'execution-' + approval['approval_id'] + '.json'
        execution = None
        def authorize_locked(actual):
            nonlocal execution
            require(actual == request, 'production_core_request_changed')
            require(utc(approval['issued_at']) <= time.time() < utc(approval['expires_at']), 'production_approval_expired')
            self.state_directory()
            self.pending_gate(allowed=name)
            if os.path.lexists(self.state / name):
                execution = self.execution(self.state / name)
                require(execution.get('approval_sha256') == sha(canonical(envelope)) and execution.get('request_sha256') == sha(canonical(request)), 'production_replay_mismatch')
                # A complete record or a successful-core/pending-audit interruption is
                # resolved only against the exact current release and managed backup.
                result = self.finalize(execution, approval, candidate)
                return result['release']
            ready = self.prepared(approval, candidate)
            self.preflight(candidate)
            previous, fingerprint = self.fingerprint()
            require(previous == ready['previous_release_sha256'] and fingerprint == ready['host_fingerprint_sha256'], 'production_readiness_host_drift')
            require(utc(approval['issued_at']) <= time.time() < utc(approval['expires_at']), 'production_approval_expired')
            execution = dict(schema='cnb-production-execution/v1', status='pending', approval_sha256=sha(canonical(envelope)),
                             request_sha256=sha(canonical(request)), started_at=timestamp(int(time.time())), previous_release_sha256=previous, result=None)
            self.write(name, execution)
            return None
        output = io.StringIO()
        with redirect_stdout(output):
            result = self.core.deploy(release_override=request, authorize_locked=authorize_locked)
        if result != 0:
            # Only the fixed core's bounded public reason codes may leave this
            # wrapper; runtime .env and command output never become diagnostics.
            reason = 'production_core_failed_pending_review'
            try:
                failure = json.loads(output.getvalue())
                if (set(failure) == {'schema', 'status', 'phase', 'reason'} and failure['schema'] == 'cnb-deploy-result/v1'
                        and failure['status'] == 'failed' and all(type(failure[key]) is str and re.fullmatch(r'[a-z_]{1,96}', failure[key]) for key in ('phase', 'reason'))):
                    reason += ':' + failure['phase'] + ':' + failure['reason']
            except (ValueError, TypeError):
                pass
            raise ProductionError(reason)
        with self.lock():
            self.core._assert_release_unblocked()
            return self.finalize(execution, approval, candidate)

    def lock(self):
        from contextlib import contextmanager
        @contextmanager
        def held():
            fd = os.open(self.core.LOCK_PATH, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (self.uid, self.gid, 0o600), 'production_lock')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(fd)
        return held()


def load_installed():
    install = Path(__file__).parent
    authority_raw = root_file(install / 'production-authority.json')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'production_duplicate_key')
            value[key] = item
        return value
    authority = validate_authority(json.loads(authority_raw.decode('utf-8'), object_pairs_hook=unique))
    program = root_file(install / 'tat-deploy-test.py', 0o555)
    policy_raw = root_file(install / 'host-policy.json')
    require(sha(program) == authority['controller_program_sha256'] and sha(policy_raw) == authority['host_policy_sha256']
            and sha(root_file(install / 'docker-compose.yml')) == authority['controller_compose_sha256'], 'production_installed_hash')
    core = ModuleType('fixed_production_core')
    core.__file__ = str(install / 'tat-deploy-test.py')
    exec(compile(program, core.__file__, 'exec'), core.__dict__)
    core.install_policy()
    require(core.POLICY['environment'] == 'production' and core.POLICY['project'] == authority['project'], 'production_installed_scope')
    return ProductionRelease(core, authority, authority_raw, root_file(install / 'approval-ed25519.pub'), sha(root_file(Path(__file__), 0o555)))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--tat-script', required=True, type=Path)
    args = parser.parse_args(argv)
    production = load_installed()
    info = args.tat_script.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 64 * 1024, 'production_tat_script')
    raw = args.tat_script.read_bytes()
    template = render_tat_template(production.core.POLICY, production.entry_hash, production.authority_hash)
    before, after = template.split(b'{{release_request_b64url}}')
    require(raw.startswith(before) and raw.endswith(after), 'production_tat_template')
    encoded = raw[len(before):-len(after)] if after else raw[len(before):]
    model = exact(parse_canonical(unbase64(encoded.decode('ascii'))), ('schema', 'action', 'candidate_b64url', 'approval'))
    require(model['schema'] == 'cnb-production-request/v1' and model['action'] in ('readiness', 'apply'), 'production_request_scope')
    candidate_raw = unbase64(model['candidate_b64url'])
    candidate = validate_candidate(candidate_raw, production.core.POLICY)
    production.core.validate_release_request_model(production.request(candidate))
    if model['action'] == 'readiness':
        require(model['approval'] is None, 'production_readiness_approval')
        with production.lock():
            production.core._assert_release_unblocked()
            receipt = production.readiness_locked(candidate, candidate_raw)
    else:
        receipt = production.apply(candidate, candidate_raw, model['approval'])
    sys.stdout.buffer.write(canonical(receipt))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        reason = str(error) if isinstance(error, ProductionError) else 'production_execution_failed'
        sys.stdout.write(json.dumps({'schema': 'cnb-production-result/v1', 'status': 'failed', 'reason': reason}, sort_keys=True, separators=(',', ':')) + '\n')
        raise SystemExit(1)
