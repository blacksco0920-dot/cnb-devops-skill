#!/usr/bin/env python3
"""Compose pinned verification receipts into an existing project's local index.

This entry never contacts a cloud or executes a project command. Its current
record is an index, not authority to release or a replacement for live gates.
"""
import argparse
import base64
import binascii
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

SCHEMA = 'cnb-project-closeout/v1'
CHECKS = ('business', 'ui', 'coexistence', 'recovery')
RESOURCES = ('tat_binding', 'cam_identity', 'release_credential_receipt', 'accepted_installation')
SPEC_KEYS = {'schema', 'project', 'environment', 'project_dir', 'state_file', 'status_document',
             'output_dir', 'deployment', 'required_checks', 'checks', 'resource_refs'}
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
NAME = re.compile(r'[a-z][a-z0-9-]{0,62}\Z')
BUILD = re.compile(r'cnb-[a-z0-9][a-z0-9-]{2,127}\Z')
IMAGE = re.compile(r'[a-z0-9][a-z0-9._:/-]{1,255}@sha256:[0-9a-f]{64}\Z')
DEPLOYMENT_FILES = {'candidate.json', 'readiness.json', 'approval.json', 'describe-commands.json',
                    'describe-invocation-tasks.json', 'annotations-response.json', 'production-receipt.json'}
DEPLOYMENT_HASHES = ('candidate_manifest_sha256', 'candidate_bytes_sha256', 'production_receipt_sha256',
                     'release_record_sha256', 'approval_sha256', 'prepared_sha256', 'production_entry_sha256',
                     'production_authority_sha256', 'controller_program_sha256', 'controller_compose_sha256',
                     'policy_sha256', 'bundle_lock_sha256', 'production_lock_sha256')
TEST_DEPLOYMENT_FILES = {'candidate.json', 'candidate-tag.raw', 'binding.json', 'describe-commands.json',
                         'describe-invocation-tasks.json', 'release-receipt.json'}
TEST_DEPLOYMENT_HASHES = ('candidate_manifest_sha256', 'candidate_bytes_sha256', 'tag_object_sha256',
                          'binding_sha256', 'release_receipt_sha256', 'controller_program_sha256',
                          'controller_compose_sha256', 'policy_sha256', 'bundle_lock_sha256',
                          'verification_spec_sha256', 'input_sha256')
TEST_RELEASE_KEYS = {'schema', 'status', 'project', 'environment', 'controller', 'git_sha', 'controller_commit',
                     'build_id', 'images', 'controller_program_sha256', 'controller_compose_sha256', 'policy_sha256',
                     'database_backup_sha256', 'container_count', 'probe_count', 'probes'}


class CloseoutError(ValueError):
    pass


def require(value, code):
    if not value:
        raise CloseoutError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, 'NONFINITE_JSON'))
    except (UnicodeError, json.JSONDecodeError):
        raise CloseoutError('JSON_INVALID') from None


def path_value(value):
    require(type(value) is str and 0 < len(value) <= 4096 and not re.search(r'[\x00-\x1f\x7f]', value), 'PATH_INVALID')
    path = Path(value)
    require(path.is_absolute() and str(path) == value and path.resolve() == path, 'PATH_INVALID')
    return path


def directory(path, private=False):
    require(path.is_absolute() and path.resolve() == path, 'DIRECTORY_UNSAFE')
    for current in (path, *path.parents):
        info = current.lstat()
        sticky_root = current != path and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and (not info.st_mode & 0o022 or sticky_root), 'DIRECTORY_UNSAFE')
        if current == path and private:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_UNSAFE')


def read(path, private=True, limit=2 * 1024 * 1024):
    directory(path.parent, private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 < before.st_size <= limit, 'FILE_UNSAFE')
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, 'PRIVATE_FILE_UNSAFE')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after, named = os.fstat(fd), path.lstat()
        require(len(data) == before.st_size <= limit and not stat.S_ISLNK(named.st_mode)
                and (before.st_ino, before.st_dev) == (named.st_ino, named.st_dev)
                and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'FILE_CHANGED')
        return bytes(data)
    finally:
        os.close(fd)


def atomic(path, raw, mode=0o600):
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temp.exists():
            temp.unlink()


def stamp(value):
    require(type(value) is str and len(value) <= 40, 'TIMESTAMP_INVALID')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(result.tzinfo is not None and result.utcoffset().total_seconds() == 0, 'TIMESTAMP_INVALID')
        return result
    except (ValueError, OverflowError):
        raise CloseoutError('TIMESTAMP_INVALID') from None


def reference_bytes(ref, inputs, base=None):
    require(type(ref) is dict and set(ref) == {'path', 'sha256'}
            and type(ref['sha256']) is str and HASH.fullmatch(ref['sha256']), 'REFERENCE_INVALID')
    name = ref['path']
    if base is not None and type(name) is str and not Path(name).is_absolute():
        require(re.fullmatch(r'[A-Za-z0-9._/-]{1,255}', name)
                and all(p not in ('', '.', '..') for p in name.split('/')), 'REFERENCE_INVALID')
        path = path_value(str(base / name))
    else:
        path = path_value(name)
    data = read(path)
    require(sha(data) == ref['sha256'], 'EVIDENCE_HASH_MISMATCH')
    inputs[str(path)] = ref['sha256']
    return data


def reference(ref, inputs, base=None):
    return decode(reference_bytes(ref, inputs, base))


def referenced_evidence(doc, path, inputs):
    refs = doc.get('evidence')
    require(type(refs) in (list, dict) and 0 < len(refs) <= 32, 'NESTED_EVIDENCE_REQUIRED')
    for ref in refs.values() if type(refs) is dict else refs:
        reference(ref, inputs, path.parent)


def identity(doc, deployment, project, environment, allow_no_project=False):
    require(type(doc) is dict and doc.get('environment') == environment, 'RECEIPT_SCOPE_MISMATCH')
    require(doc.get('project') == project or allow_no_project and 'project' not in doc, 'RECEIPT_SCOPE_MISMATCH')
    commits = [doc[k] for k in ('application_commit', 'git_sha') if k in doc]
    require(commits and all(c == deployment['application_commit'] for c in commits)
            and doc.get('build_id') == deployment['build_id'], 'RECEIPT_IDENTITY_MISMATCH')


def passed_checks(doc):
    values = doc.get('checks')
    require(type(values) in (list, dict) and 0 < len(values) <= 4096, 'CHECKS_REQUIRED')
    if type(values) is dict:
        require(all(v is True for v in values.values()), 'CHECK_FAILED')
    else:
        require(all(type(v) is dict and v.get('status') == 'passed'
                    and v.get('passed', True) is True for v in values), 'CHECK_FAILED')
    return len(values)


def complete_deployment(deployment, path, inputs):
    """Require the full fixed-verifier record, not a caller-written passed flag.

    Signature/executed-command validation belongs to release-session verify/status.
    This consumer binds the already accepted summary to its immutable source bytes.
    """
    require(all(type(deployment.get(k)) is str and HASH.fullmatch(deployment[k]) for k in DEPLOYMENT_HASHES)
            and deployment.get('signature') == 'verified_ed25519'
            and deployment.get('signature_valid_across_execution') is True
            and type(deployment.get('approval_id')) is str and re.fullmatch(r'[0-9a-f]{32}', deployment['approval_id']),
            'DEPLOYMENT_RECORD_INCOMPLETE')
    refs = deployment.get('evidence')
    require(type(refs) is list and len(refs) == len(DEPLOYMENT_FILES)
            and all(type(ref) is dict and type(ref.get('path')) is str for ref in refs)
            and {ref['path'] for ref in refs} == DEPLOYMENT_FILES, 'DEPLOYMENT_FILES_INCOMPLETE')
    docs = {ref['path']: reference(ref, inputs, path.parent) for ref in refs}
    pinned = {ref['path']: ref['sha256'] for ref in refs}
    require(pinned['candidate.json'] == deployment['candidate_bytes_sha256']
            and pinned['approval.json'] == deployment['approval_sha256']
            and pinned['production-receipt.json'] == deployment['production_receipt_sha256'], 'DEPLOYMENT_SOURCE_MISMATCH')
    candidate, prepared, result = docs['candidate.json'], docs['readiness.json'], docs['production-receipt.json']
    require(type(candidate) is dict and candidate.get('schema') == 'cnb-candidate/v1'
            and candidate.get('project') == deployment['project'] and candidate.get('environment') == 'test'
            and candidate.get('application_commit') == deployment['application_commit']
            and candidate.get('build_id') == deployment['build_id']
            and candidate.get('candidate_tag') == deployment['candidate_tag']
            and candidate.get('services') == deployment['images']
            and candidate.get('manifest_sha256') == deployment['candidate_manifest_sha256'], 'CANDIDATE_SOURCE_MISMATCH')
    require(type(prepared) is dict and prepared.get('prepared_sha256') == deployment['prepared_sha256'], 'READINESS_SOURCE_MISMATCH')
    require(type(result) is dict and result.get('schema') == 'cnb-production-result/v1' and result.get('status') == 'passed', 'PRODUCTION_SOURCE_MISMATCH')
    for key in ('project', 'environment', 'candidate_tag', 'candidate_bytes_sha256', 'candidate_manifest_sha256',
                'approval_id', 'approval_sha256', 'prepared_sha256', 'production_entry_sha256',
                'production_authority_sha256', 'release_record_sha256'):
        require(result.get(key) == deployment.get(key), 'PRODUCTION_SOURCE_MISMATCH')
    release = result.get('release')
    require(type(release) is dict and release.get('schema') == 'cnb-deploy-result/v1' and release.get('status') == 'passed'
            and release.get('git_sha') == deployment['application_commit'] and release.get('build_id') == deployment['build_id']
            and release.get('images') == deployment['images'], 'RELEASE_SOURCE_MISMATCH')
    for key in ('controller_program_sha256', 'controller_compose_sha256', 'policy_sha256'):
        require(release.get(key) == deployment[key], 'RELEASE_SOURCE_MISMATCH')
    require(stamp(deployment['approval_issued_at']) <= stamp(deployment['execution_started_at'])
            <= stamp(deployment['execution_finished_at']) < stamp(deployment['approval_expires_at']), 'APPROVAL_EXECUTION_WINDOW_INVALID')


def tat_bytes(value):
    require(type(value) is str and 0 < len(value) <= 128 * 1024, 'TEST_TAT_SOURCE_MISMATCH')
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise CloseoutError('TEST_TAT_SOURCE_MISMATCH') from None
    require(base64.b64encode(result).decode() == value, 'TEST_TAT_SOURCE_MISMATCH')
    return result


def complete_test_deployment(deployment, path, inputs):
    """Bind the fixed test verifier's summary to its saved evidence bytes.

    The bundle verifier owns configuration and TAT policy validation. Rechecking
    the saved tag and command here establishes source integrity, not a fresh
    remote ref or current-runtime observation.
    """
    require(all(type(deployment.get(k)) is str and HASH.fullmatch(deployment[k]) for k in TEST_DEPLOYMENT_HASHES)
            and deployment.get('saved_tag_verified') is True
            and deployment.get('current_annotations_status') == 'not_checked'
            and deployment.get('current_tag_status') == 'not_checked'
            and all(type(deployment.get(k)) is str and re.fullmatch(pattern, deployment[k]) for k, pattern in
                    [('controller', r'[a-z][a-z0-9-]{0,95}'), ('region', r'[a-z]+-[a-z]+[0-9]*'),
                     ('instance_id', r'(?:lhins|ins)-[A-Za-z0-9-]{8,64}'), ('command_id', r'cmd-[A-Za-z0-9-]{8,64}')]),
            'TEST_DEPLOYMENT_RECORD_INCOMPLETE')
    require(stamp(deployment['execution_started_at']) <= stamp(deployment['execution_finished_at'])
            <= stamp(deployment['candidate_created_at']) <= stamp(deployment['verified_at']), 'TEST_DEPLOYMENT_TIME_INVALID')
    refs = deployment.get('evidence')
    require(type(refs) is list and len(refs) == len(TEST_DEPLOYMENT_FILES)
            and all(type(ref) is dict and type(ref.get('path')) is str for ref in refs)
            and {ref['path'] for ref in refs} == TEST_DEPLOYMENT_FILES, 'TEST_DEPLOYMENT_FILES_INCOMPLETE')
    sources = {ref['path']: reference_bytes(ref, inputs, path.parent) for ref in refs}
    docs = {name: decode(content) for name, content in sources.items() if name != 'candidate-tag.raw'}
    for name, key in [('candidate.json', 'candidate_bytes_sha256'), ('candidate-tag.raw', 'tag_object_sha256'),
                      ('binding.json', 'binding_sha256'), ('release-receipt.json', 'release_receipt_sha256')]:
        require(sha(sources[name]) == deployment[key], 'TEST_DEPLOYMENT_SOURCE_MISMATCH')
    candidate, binding, release = docs['candidate.json'], docs['binding.json'], docs['release-receipt.json']
    require(type(candidate) is dict and candidate.get('schema') == 'cnb-candidate/v1'
            and candidate.get('environment') == 'test'
            and all(candidate.get(k) == deployment[k] for k in ('project', 'application_commit', 'build_id',
                    'candidate_tag', 'controller', 'controller_program_sha256', 'controller_compose_sha256',
                    'policy_sha256', 'release_receipt_sha256'))
            and candidate.get('controller_commit') == deployment['application_commit']
            and candidate.get('services') == deployment['images']
            and candidate.get('created_at') == deployment['candidate_created_at']
            and candidate.get('manifest_sha256') == deployment['candidate_manifest_sha256']
            and sha(encode({k: v for k, v in candidate.items() if k != 'manifest_sha256'})[:-1]) == candidate['manifest_sha256']
            and encode(candidate) == sources['candidate.json'], 'CANDIDATE_SOURCE_MISMATCH')
    evidence = candidate.get('evidence')
    require(type(evidence) is dict and set(evidence) == {'build', 'runtime', 'public'}
            and all(type(item) is dict and item.get('status') == 'passed' for item in evidence.values())
            and evidence['runtime'].get('reference') == evidence['public'].get('reference') == 'tat:' + deployment['invocation_id'],
            'CANDIDATE_SOURCE_MISMATCH')
    tag = sources['candidate-tag.raw']
    head, separator, message = tag.partition(b'\n\n')
    headers = {}
    for line in head.split(b'\n'):
        name, space, value = line.partition(b' ')
        require(space and value and name in (b'object', b'type', b'tag', b'tagger') and name not in headers,
                'TEST_TAG_SOURCE_MISMATCH')
        headers[name] = value
    require(separator and {b'object', b'type', b'tag'} <= set(headers)
            and headers[b'object'] == deployment['application_commit'].encode()
            and headers[b'type'] == b'commit' and headers[b'tag'] == deployment['candidate_tag'].encode()
            and message == sources['candidate.json'], 'TEST_TAG_SOURCE_MISMATCH')
    require(type(binding) is dict and binding.get('schema') == 'cnb-tat-binding/v1' and binding.get('environment') == 'test'
            and all(binding.get(k) == deployment.get(k) for k in ('project', 'region', 'instance_id', 'command_id'))
            and all(binding.get(k) == deployment[v] for k, v in [('program_sha256', 'controller_program_sha256'),
                    ('compose_sha256', 'controller_compose_sha256'), ('policy_sha256', 'policy_sha256')])
            and type(binding.get('command_sha256')) is str and HASH.fullmatch(binding['command_sha256']),
            'TEST_BINDING_SOURCE_MISMATCH')
    require(type(release) is dict and set(release) == TEST_RELEASE_KEYS
            and release.get('schema') == 'cnb-deploy-result/v1' and release.get('status') == 'passed'
            and type(release.get('database_backup_sha256')) is str and HASH.fullmatch(release['database_backup_sha256'])
            and all(release.get(k) == deployment[k] for k in ('project', 'environment', 'controller', 'build_id', 'images',
                    'controller_program_sha256', 'controller_compose_sha256', 'policy_sha256'))
            and release.get('git_sha') == release.get('controller_commit') == deployment['application_commit']
            and type(release.get('container_count')) is int and type(evidence['runtime'].get('container_count')) is int
            and release.get('container_count') == evidence['runtime'].get('container_count') == len(deployment['images'])
            and release.get('probes') == evidence['public'].get('probes')
            and type(release.get('probes')) is list and len(release['probes']) > 0
            and type(release.get('probe_count')) is int and type(evidence['public'].get('probe_count')) is int
            and release.get('probe_count') == evidence['public'].get('probe_count') == len(release['probes']),
            'RELEASE_SOURCE_MISMATCH')
    commands, tasks = docs['describe-commands.json'], docs['describe-invocation-tasks.json']
    require(type(commands) is dict and type(commands.get('TotalCount')) is int and commands['TotalCount'] == 1
            and type(commands.get('CommandSet')) is list and len(commands['CommandSet']) == 1
            and type(tasks) is dict and type(tasks.get('TotalCount')) is int and tasks['TotalCount'] == 1
            and type(tasks.get('InvocationTaskSet')) is list and len(tasks['InvocationTaskSet']) == 1, 'TEST_TAT_SOURCE_MISMATCH')
    command, task = commands['CommandSet'][0], tasks['InvocationTaskSet'][0]
    require(type(command) is dict and command.get('CommandId') == deployment['command_id']
            and type(task) is dict and task.get('InvocationId') == deployment['invocation_id']
            and task.get('InstanceId') == deployment['instance_id'] and task.get('CommandId') == deployment['command_id']
            and task.get('TaskStatus') == 'SUCCESS', 'TEST_TAT_SOURCE_MISMATCH')
    confs = command.get('DefaultParameterConfs')
    valid_confs = (type(confs) is list and len(confs) == 1 and type(confs[0]) is dict
                   and confs[0] == {'ParameterName': 'release_request_b64url', 'ParameterValue': 'INVALID', 'ParameterDescription': ''})
    absent_confs = confs is None or type(confs) is list and len(confs) == 0
    # Match both API representations accepted by the bundle's fixed verifier;
    # conflicting populated representations must never hide one another.
    valid_defaults = (command.get('DefaultParameters') == '{"release_request_b64url":"INVALID"}' and (absent_confs or valid_confs)
                      or command.get('DefaultParameters') == '' and valid_confs)
    require(command.get('EnableParameter') is True and command.get('CreatedBy') == 'USER'
            and valid_defaults, 'TEST_TAT_SOURCE_MISMATCH')
    content = tat_bytes(command.get('Content'))
    require(sha(content) == binding['command_sha256'] and b'\0' not in content
            and content.count(b'{{release_request_b64url}}') == 1
            and not re.search(rb'\{\{|\}\}', content.replace(b'{{release_request_b64url}}', b'')), 'TEST_TAT_SOURCE_MISMATCH')
    request = {'schema': 'cnb-release-request/v1', 'project': deployment['project'], 'environment': 'test',
               'controller': deployment['controller'], 'git_sha': deployment['application_commit'],
               'controller_commit': deployment['application_commit'], 'build_id': deployment['build_id'], 'images': deployment['images']}
    script = content.replace(b'{{release_request_b64url}}', base64.urlsafe_b64encode(encode(request)[:-1]).rstrip(b'='))
    document, result = task.get('CommandDocument'), task.get('TaskResult')
    require(type(document) is dict and type(result) is dict
            and type(result.get('ExitCode')) is int and result['ExitCode'] == 0
            and type(result.get('Dropped')) is int and result['Dropped'] == 0
            and result.get('ExecStartTime') == deployment['execution_started_at']
            and result.get('ExecEndTime') == deployment['execution_finished_at']
            and tat_bytes(result.get('Output')) == sources['release-receipt.json']
            and tat_bytes(document.get('Content')) == script, 'TEST_TAT_SOURCE_MISMATCH')
    for source in (command, document):
        require(source.get('CommandType') == 'SHELL'
                and all(k in binding and source.get(s) == binding[k] for s, k in
                        [('Username', 'username'), ('WorkingDirectory', 'working_directory'), ('Timeout', 'timeout')])
                and source.get('OutputCOSBucketUrl') in (None, '') and source.get('OutputCOSKeyPrefix') in (None, ''),
                'TEST_TAT_SOURCE_MISMATCH')


def inspect_spec(spec_path):
    spec_raw = read(path_value(str(spec_path)))
    spec = decode(spec_raw)
    require(type(spec) is dict and set(spec) == SPEC_KEYS and spec.get('schema') == SCHEMA, 'SPEC_INVALID')
    require(type(spec['project']) is str and NAME.fullmatch(spec['project'])
            and spec['environment'] in ('test', 'production'), 'SPEC_SCOPE_INVALID')
    project_dir, state_file, document, out = [path_value(spec[k]) for k in
                                            ('project_dir', 'state_file', 'status_document', 'output_dir')]
    directory(project_dir)
    require(document.suffix == '.md' and document.is_relative_to(project_dir) and not '.git' in document.relative_to(project_dir).parts,
            'DOCUMENT_OUTSIDE_PROJECT')
    for p in (spec_path, state_file, out):
        require(not p.is_relative_to(project_dir), 'PRIVATE_PATH_IN_PROJECT')
    directory(state_file.parent, True)
    directory(out if out.exists() else out.parent, True)
    require(out != state_file.parent and not state_file.is_relative_to(out)
            and len({str(spec_path), str(state_file), str(document), str(out)}) == 4, 'OUTPUT_PATH_CONFLICT')
    require(type(spec['required_checks']) is list and len(spec['required_checks']) <= len(CHECKS)
            and len(set(spec['required_checks'])) == len(spec['required_checks'])
            and all(k in CHECKS for k in spec['required_checks']), 'REQUIRED_CHECKS_INVALID')
    require(type(spec['checks']) is dict and set(spec['checks']) <= set(CHECKS)
            and type(spec['resource_refs']) is dict and set(spec['resource_refs']) <= set(RESOURCES), 'CHECK_SPEC_INVALID')
    inputs = {str(spec_path): sha(spec_raw)}
    deployment = reference(spec['deployment'], inputs)
    deployment_schema = {'production': 'cnb-deployment-verification/v1', 'test': 'cnb-test-deployment-verification/v1'}
    require(type(deployment) is dict and deployment.get('schema') == deployment_schema[spec['environment']]
            and deployment.get('status') == 'verified' and deployment.get('project') == spec['project']
            and deployment.get('environment') == spec['environment'], 'DEPLOYMENT_INVALID')
    require(type(deployment.get('application_commit')) is str and COMMIT.fullmatch(deployment['application_commit'])
            and type(deployment.get('build_id')) is str and BUILD.fullmatch(deployment['build_id'])
            and type(deployment.get('candidate_tag')) is str
            and re.fullmatch(r'[a-z][a-z0-9-]{0,191}', deployment['candidate_tag'])
            and type(deployment.get('invocation_id')) is str
            and re.fullmatch(r'inv-[A-Za-z0-9-]{8,64}', deployment['invocation_id']), 'DEPLOYMENT_IDENTITY_INVALID')
    images = deployment.get('images')
    require(type(images) is dict and 1 <= len(images) <= 16
            and all(NAME.fullmatch(k) and type(v) is str and IMAGE.fullmatch(v) for k, v in images.items()), 'IMAGES_INVALID')
    require(deployment.get('verification_scope') == 'historical_completed_deployment'
            and deployment.get('current_runtime_verified') is False
            and deployment.get('evidence_base') == 'receipt_directory', 'DEPLOYMENT_SCOPE_INVALID')
    end = stamp(deployment['execution_finished_at'])
    require(stamp(deployment['execution_started_at']) <= end <= stamp(deployment['verified_at']), 'DEPLOYMENT_TIME_INVALID')
    validator = complete_test_deployment if spec['environment'] == 'test' else complete_deployment
    validator(deployment, path_value(spec['deployment']['path']), inputs)
    current = {'schema': 'cnb-environment-current/v1', 'project': spec['project'], 'environment': spec['environment'],
               'application_commit': deployment['application_commit'], 'build_id': deployment['build_id'],
               'candidate_tag': deployment['candidate_tag'], 'invocation_id': deployment['invocation_id'],
               'images': images, 'deployment': spec['deployment'], 'verified_at': deployment['verified_at'],
               'closeout_spec': {'path': str(spec_path), 'sha256': sha(spec_raw)},
               'historical_deployment_verified': True, 'current_runtime_verified': False,
               'checks': {}, 'resource_refs': spec['resource_refs'], 'required_checks': spec['required_checks']}
    for name, ref in spec['checks'].items():
        doc = reference(ref, inputs)
        identity(doc, deployment, spec['project'], spec['environment'], name in ('business', 'ui'))
        require(doc.get('status') in ('passed', 'verified'), 'CHECK_NOT_PASSED')
        summary = {'receipt': ref, 'status': 'verified'}
        if name in ('business', 'ui'):
            require(type(doc.get('schema')) is str and re.fullmatch(r'[A-Za-z0-9._/-]{1,128}', doc['schema']), 'CHECK_SCHEMA_INVALID')
            summary.update(check_count=passed_checks(doc), project_field_present='project' in doc)
        elif name == 'coexistence':
            require(doc.get('schema') == 'cnb-coexistence-verification/v1'
                    and doc.get('observation_source') == 'live', 'LIVE_COEXISTENCE_REQUIRED')
            require(doc.get('candidate_sha256') == deployment['candidate_bytes_sha256']
                    and doc.get('policy_sha256') == deployment['policy_sha256'], 'COEXISTENCE_RELEASE_MISMATCH')
            summary.update(check_count=passed_checks(doc), observed_at=doc['observed_at'])
            require(stamp(doc['observed_at']) >= end, 'COEXISTENCE_PRECEDES_RELEASE')
            referenced_evidence(doc, path_value(ref['path']), inputs)
            current.update(current_runtime_verified=True, runtime_observed_at=doc['observed_at'])
        else:
            require(doc.get('schema') == 'cnb-recovery-session-result/v1'
                    and doc.get('external_restore_verified') is True and doc.get('source_unchanged') is True, 'RECOVERY_NOT_VERIFIED')
            restore_path = str(path_value(ref['path']).parent / 'restore/restore-receipt.json')
            restored = reference({'path': restore_path, 'sha256': doc.get('restore_receipt_sha256')}, inputs)
            require(restored.get('schema') == 'cnb-recovery-restore-receipt/v1' and restored.get('status') == 'verified'
                    and all(restored.get(k) is True for k in ('external_restore_verified', 'all_table_data_equal',
                                                             'schema_equal', 'sequences_equal', 'business_files_equal'))
                    and HASH.fullmatch(restored.get('source_docker_id_sha256', ''))
                    and HASH.fullmatch(restored.get('target_docker_id_sha256', ''))
                    and restored['source_docker_id_sha256'] != restored['target_docker_id_sha256'], 'RESTORE_INVALID')
            scope = doc.get('scope')
            require(type(scope) is dict and scope.get('postgres') is True and type(scope.get('business_mounts')) is list
                    and all(type(v) is str and NAME.fullmatch(v) for v in scope['business_mounts'])
                    and scope.get('full_host') is False and scope.get('redis') is False, 'RECOVERY_SCOPE_INVALID')
            summary['scope'] = {k: scope[k] for k in ('postgres', 'business_mounts', 'full_host', 'redis')}
        current['checks'][name] = summary
    for ref in spec['resource_refs'].values():
        resource = reference(ref, inputs)
        require(type(resource) is dict and type(resource.get('schema')) is str, 'RESOURCE_RECEIPT_REQUIRED')
        if 'project' in resource:
            require(resource['project'] == spec['project'], 'RESOURCE_SCOPE_MISMATCH')
        if 'environment' in resource:
            require(resource['environment'] == spec['environment'], 'RESOURCE_SCOPE_MISMATCH')
    current['pending_checks'] = [k for k in spec['required_checks'] if k not in current['checks']]
    current['status'] = ('declared_acceptance_verified' if spec['required_checks'] and not current['pending_checks']
                         else 'deployment_verified')
    current['next_action'] = 'verify_' + current['pending_checks'][0] if current['pending_checks'] else 'none'
    return spec, current, inputs


def document_bytes(before, current):
    try:
        text = before.decode('utf-8')
    except UnicodeError:
        raise CloseoutError('DOCUMENT_UTF8_REQUIRED') from None
    env = current['environment']
    begin, finish = f'<!-- cnb-devops:current:{env}:begin -->', f'<!-- cnb-devops:current:{env}:end -->'
    require(text.count(begin) == text.count(finish) and text.count(begin) <= 1, 'DOCUMENT_MARKER_CONFLICT')
    labels = {'business': '业务', 'ui': '页面', 'coexistence': '共存', 'recovery': '恢复'}
    scope = '、'.join(labels[k] for k in CHECKS if k in current['checks']) or '仅发布回执'
    block = '\n'.join([begin, f'## {env} 当前发布（自动维护）', '',
                       '接管以本段和已登记私密状态中的该环境 `current` 为准；其余正文保留人工说明与历史。', '',
                       f'- 发布状态：`{current["status"]}`；已核验范围：{scope}。',
                       f'- 提交：`{current["application_commit"]}`；构建：`{current["build_id"]}`。',
                       f'- 候选：`{current["candidate_tag"]}`；发布执行：`{current["invocation_id"]}`。',
                       f'- 发布回执 SHA256：`{current["deployment"]["sha256"]}`。',
                       f'- 发布回查时间：`{current["verified_at"]}`；运行观测时间：`{current.get("runtime_observed_at", "未核验")}`。',
                       f'- 下一动作：`{current["next_action"]}`。历史发布成功不代表持续健康，也不赋予新发布权限。',
                       finish])
    if begin in text:
        left, right = text.index(begin), text.index(finish)
        require(left < right, 'DOCUMENT_MARKER_CONFLICT')
        # A nested marker is always ambiguous, including another environment.
        require('<!-- cnb-devops:' not in text[left + len(begin):right], 'DOCUMENT_MARKER_CONFLICT')
        return (text[:left] + block + text[right + len(finish):]).encode()
    return (block + '\n\n' + text).encode()


def desired_state(before, current):
    state = decode(before)
    require(type(state) is dict and state.get('project') == current['project'], 'STATE_PROJECT_MISMATCH')
    envs = state.setdefault('environments', {})
    require(type(envs) is dict, 'STATE_ENVIRONMENTS_INVALID')
    env = envs.setdefault(current['environment'], {})
    require(type(env) is dict, 'STATE_ENVIRONMENT_INVALID')
    env.update(current=current, deployment_status=current['status'], application_commit=current['application_commit'],
               build_id=current['build_id'], candidate_tag=current['candidate_tag'], invocation_id=current['invocation_id'],
               next_action=current['next_action'], acceptance=current['checks'])
    env.pop('acceptance_sha256', None)  # The old single receipt is in before-state.json.
    for key, ref in current['resource_refs'].items():
        env[key] = ref['path']
    # These top-level fields describe the last reconciled environment only;
    # other environment records and historical/custom metadata remain intact.
    state.update(current_environment=current['environment'], current_state_source='environments.' + current['environment'] + '.current',
                 application_commit=current['application_commit'],
                 status=current['environment'] + '_' + current['status'], next_action=current['next_action'],
                 next_actions=[] if current['next_action'] == 'none' else [current['next_action']],
                 remaining=current['pending_checks'], updated_at=current['verified_at'])
    if current['environment'] == 'test':
        state['test_build_id'] = current['build_id']
    return encode(state)


def verify_inputs(inputs):
    for name, expected in inputs.items():
        require(sha(read(Path(name))) == expected, 'INPUT_CHANGED')


def reconcile(spec_path, apply=False):
    spec, current, inputs = inspect_spec(path_value(str(spec_path)))
    state_file, document, out = [Path(spec[k]) for k in ('state_file', 'status_document', 'output_dir')]
    state_raw, doc_raw = read(state_file), read(document, private=False)
    after_state, after_doc = desired_state(state_raw, current), document_bytes(doc_raw, current)
    if not apply:
        return {'schema': 'cnb-project-closeout-result/v1', 'status': 'preview', 'current': current}
    lock = state_file.with_name('.' + state_file.name + '.closeout.lock')
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'LOCK_UNSAFE')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CloseoutError('STATE_LOCKED') from None
        verify_inputs(inputs)
        require(read(state_file) == state_raw and read(document, private=False) == doc_raw, 'CURRENT_STATE_CHANGED')
        request_hash = sha(encode({'spec': spec, 'inputs': inputs}))
        if out.exists():
            directory(out, True)
            pending = decode(read(out / 'pending.json'))
            require(type(pending) is dict and set(pending) == {'schema', 'request_sha256', 'files', 'document_mode'}
                    and pending.get('schema') == 'cnb-project-closeout-transaction/v1'
                    and pending.get('request_sha256') == request_hash
                    and type(pending['document_mode']) is int and pending['document_mode'] in (0o600, 0o644), 'CLOSEOUT_INPUT_CHANGED')
            for name, expected in pending['files'].items():
                require(name in ('before-state.json', 'before-document.md', 'after-state.json', 'after-document.md')
                        and sha(read(out / name)) == expected, 'TRANSACTION_CHANGED')
            require(set(pending['files']) == {'before-state.json', 'before-document.md', 'after-state.json', 'after-document.md'}, 'TRANSACTION_CHANGED')
            require(decode(read(out / 'after-state.json'))['environments'][spec['environment']]['current'] == current, 'TRANSACTION_CHANGED')
            after_state, after_doc = read(out / 'after-state.json'), read(out / 'after-document.md')
            require(after_state == desired_state(read(out / 'before-state.json'), current)
                    and after_doc == document_bytes(read(out / 'before-document.md'), current), 'TRANSACTION_CHANGED')
            require(state_raw in (read(out / 'before-state.json'), after_state)
                    and doc_raw in (read(out / 'before-document.md'), after_doc), 'CURRENT_STATE_CHANGED')
            if (out / 'receipt.json').exists():
                receipt = decode(read(out / 'receipt.json'))
                require(receipt.get('request_sha256') == request_hash and receipt.get('status') == 'updated'
                        and receipt.get('state_sha256') == sha(after_state) and receipt.get('document_sha256') == sha(after_doc)
                        and state_raw == after_state and doc_raw == after_doc, 'COMPLETED_STATE_CHANGED')
                return {'schema': 'cnb-project-closeout-result/v1', 'status': 'updated', 'reused': True, 'current': current}
        else:
            # Publish the entire transaction directory before touching either
            # destination. An orphan staging directory grants no completion.
            staging = out.with_name('.' + out.name + '.' + uuid.uuid4().hex + '.pending')
            staging.mkdir(mode=0o700)
            files = {'before-state.json': state_raw, 'before-document.md': doc_raw,
                     'after-state.json': after_state, 'after-document.md': after_doc}
            for name, content in files.items():
                atomic(staging / name, content)
            pending = {'schema': 'cnb-project-closeout-transaction/v1', 'request_sha256': request_hash,
                       'files': {k: sha(v) for k, v in files.items()}, 'document_mode': stat.S_IMODE(document.stat().st_mode)}
            require(pending['document_mode'] in (0o600, 0o644), 'DOCUMENT_MODE_INVALID')
            atomic(staging / 'pending.json', encode(pending))
            os.rename(staging, out)
        if read(state_file) != after_state:
            atomic(state_file, after_state)
        if read(document, private=False) != after_doc:
            atomic(document, after_doc, pending['document_mode'])
        require(read(state_file) == after_state and read(document, private=False) == after_doc, 'WRITE_READBACK_FAILED')
        receipt = {'schema': 'cnb-project-closeout-receipt/v1', 'status': 'updated', 'project': spec['project'],
                   'environment': spec['environment'], 'request_sha256': request_hash,
                   'state_sha256': sha(after_state), 'document_sha256': sha(after_doc),
                   'current_status': current['status'], 'evidence': inputs, 'cloud_writes': False}
        atomic(out / 'receipt.json', encode(receipt))
        return {'schema': 'cnb-project-closeout-result/v1', 'status': 'updated', 'reused': False, 'current': current}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', required=True, help='Absolute protected cnb-project-closeout/v1 JSON')
    parser.add_argument('--apply', action='store_true', help='Only write the existing local state and status document; no cloud calls')
    args = parser.parse_args()
    try:
        result = reconcile(Path(args.spec), args.apply)
        # CLI summaries exclude all absolute private references and unowned data.
        safe_current = {k: result['current'][k] for k in ('project', 'environment', 'status', 'application_commit', 'build_id',
                        'current_runtime_verified', 'pending_checks', 'next_action')}
        print(json.dumps({**{k: v for k, v in result.items() if k != 'current'}, 'current': safe_current}, sort_keys=True))
    except (CloseoutError, OSError, KeyError, TypeError, ValueError, RecursionError) as error:
        code = str(error) if isinstance(error, CloseoutError) else 'LOCAL_CLOSEOUT_FAILED'
        print(json.dumps({'status': 'stopped', 'code': code}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
