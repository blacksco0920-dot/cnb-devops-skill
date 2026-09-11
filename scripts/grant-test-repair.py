#!/usr/bin/env python3
"""Verify collected build/recovery evidence and grant one fixed test repair.

Preview is offline and retained locally. Apply uses the installed root helper;
only request, migration paths and the isolated restore receipt are uploaded.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType, SimpleNamespace


def module(path):
    result = ModuleType('grant_dependency')
    result.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


ROOT = Path(__file__).resolve().parent
rehearsal = module(ROOT / 'rehearse-recovery.py')
collector = module(ROOT / 'repair-session.py')
read_safe, strict_json, canonical, sha = rehearsal.read_safe, rehearsal.strict_json, rehearsal.canonical, rehearsal.sha


def require(value, code):
    if not value:
        raise ValueError(code)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle-dir', 'target', 'accepted-installation', 'build-evidence-dir',
                 'recovery-evidence-dir', 'migration-spec', 'evidence-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('lock-sha256', 'expires-at'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true')
    return parser.parse_args(argv)


def private_json(path):
    raw = read_safe(path, {0o600})
    model = strict_json(raw)
    require(raw == canonical(model), 'REPAIR_EVIDENCE_NOT_CANONICAL')
    return raw, model


def validate_build(plan, directory):
    inputs = {}
    def read(name):
        raw, value = private_json(directory / name)
        inputs[name] = sha(raw)
        return value
    build, request, source = read('build-evidence.json'), read('request.json'), read('source-files.json')
    require(type(build) is dict and build.get('schema') == 'cnb-test-repair-build-evidence/v1'
            and build.get('status') == 'verified' and build.get('verification_passed') is True, 'REPAIR_BUILD_EVIDENCE_INVALID')
    plan.bundle['host'].validate_release_request_model(request)
    require(request['environment'] == 'test' and request['project'] == plan.scope['project'], 'REPAIR_BUILD_SCOPE_MISMATCH')
    expected_files = {'deploy/vendor/cnb-devops/' + name: sha(raw) for name, raw in plan.bundle['files'].items()}
    require(type(source) is dict and set(source) == {'pipeline_verified', 'test_branch', 'files'}
            and source['pipeline_verified'] is True and type(source['files']) is dict
            and set(source['files']) == set(expected_files) | {'.cnb.yml', 'deploy/project.yml'}
            and all(source['files'].get(name) == digest for name, digest in expected_files.items())
            and all(type(value) is str and plan.recovery.HASH.fullmatch(value) for value in source['files'].values()),
            'REPAIR_SOURCE_ARTIFACT_MISMATCH')
    config = strict_json(plan.bundle['files']['ci-config.json'])
    builds, status = read('builds.json'), read('status.json')
    pipeline = collector.selected_pipeline(plan.bundle, request['build_id'], status)
    stages = {}
    for name in ('verify project', 'record digests and remove push credentials'):
        matches = [item for item in pipeline['stages'] if item.get('name') == name]
        require(len(matches) == 1, 'REPAIR_STAGE_AMBIGUOUS')
        stage_id = matches[0]['id']
        require(type(stage_id) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', stage_id), 'REPAIR_STAGE_ID_INVALID')
        stages[stage_id] = read(stage_id + '.json')['data']
    expected = collector.validate_build_evidence(plan.bundle, request['git_sha'], request['build_id'], source['test_branch'],
                 config['cnb_repository'], builds, status, stages)
    require(build == expected and request == expected['request'], 'REPAIR_BUILD_EVIDENCE_MISMATCH')
    handoff = read_safe(directory / 'handoff.txt', {0o600})
    require(handoff == (build['handoff'] + '\n').encode(), 'REPAIR_BUILD_HANDOFF_MISMATCH')
    inputs['handoff.txt'] = sha(handoff)
    return request, inputs


def validate_recovery(plan, directory, result):
    state_raw, state = private_json(directory / 'state.json')
    require(type(state) is dict and state.get('schema') == 'cnb-recovery-session/v2'
            and state.get('status') == 'verified' and state.get('resume_stage') == 'complete'
            and type(state.get('evidence')) is dict, 'REPAIR_VERIFIED_RECOVERY_REQUIRED')
    names = {'result.json', 'source-before.json', 'source-after.json', 'source-final.json', 'export-result.json',
             'journal.json', 'export-receipt.json', 'source-resumed.json', 'export.tar', 'restore/restore-receipt.json'}
    require(names <= set(state['evidence']), 'REPAIR_RECOVERY_EVIDENCE_MISSING')
    reader = rehearsal.Session(plan)
    for name, expected in state['evidence'].items():
        require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?', name)
                and '..' not in Path(name).parts and reader.record(directory / name) == expected, 'REPAIR_RECOVERY_EVIDENCE_CHANGED')
    def read(name):
        return private_json(directory / name)[1]
    before, after, final = [rehearsal.validate_source(plan, read('source-' + stage + '.json')) for stage in ('before', 'after', 'final')]
    exported = rehearsal.verify_export(plan, before, after)
    require(rehearsal.verify_export(plan, before, final) == exported, 'REPAIR_RECOVERY_SOURCE_CHANGED')
    transfer = exported['receipt']
    require(read('journal.json') == exported['journal'] and read('source-resumed.json') == exported['resumed']
            and read('export-receipt.json') == read('export-result.json') == transfer, 'REPAIR_RECOVERY_RECEIPT_CHANGED')
    with plan.recovery.verified_archive(directory / 'export.tar', transfer['archive_sha256'], transfer['manifest_sha256']) as (_, manifest):
        require(all(manifest.get(key) == value for key, value in plan.scope.items())
                and manifest['source_release'] == before['source_release']
                and manifest['source_release_sha256'] == before['source_release_sha256']
                and manifest['source_baseline_sha256'] == before['source_baseline_sha256']
                and manifest['source_docker_id_sha256'] == before['source_docker_id_sha256']
                and manifest['postgres'] == before['postgres'], 'REPAIR_RECOVERY_ARCHIVE_MISMATCH')
    receipt_raw, receipt = private_json(directory / 'restore/restore-receipt.json')
    target_id = receipt.get('target_docker_id_sha256')
    require(type(target_id) is str and plan.recovery.HASH.fullmatch(target_id)
            and target_id != before['source_docker_id_sha256'], 'REPAIR_DIFFERENT_RESTORE_DAEMON_REQUIRED')
    rehearsal.verify_restore(plan, receipt, manifest, transfer, target_id)
    require(result.get('restore_receipt_sha256') == sha(receipt_raw) and result.get('scope') == manifest['scope']
            and result.get('source_baseline_sha256') == manifest['source_baseline_sha256']
            and result.get('source_unchanged') is True and result.get('external_restore_verified') is True,
            'REPAIR_RECOVERY_RESULT_MISMATCH')
    require(not os.path.lexists(directory / 'restore/restore.pending.json')
            and read('restore/restored-database.json') == manifest['database'], 'REPAIR_RESTORE_DATABASE_EVIDENCE_MISMATCH')
    target, container = read('restore/target.json'), read('restore/container.json')
    require(target['docker_id_sha256'] == target_id and target['volume'] == receipt['target_volume']
            and container['id'] == receipt['target_container_id'], 'REPAIR_RESTORE_TARGET_MISMATCH')
    for name, record in manifest['mounts'].items():
        if record['classification'] == 'backup':
            require(plan.recovery.tree_fingerprint(directory / 'restore/business' / name)
                    == {key: record[key] for key in ('tree_sha256', 'files', 'bytes')}, 'REPAIR_RESTORE_FILES_CHANGED')
    parent = manifest['source_release']
    source_binding = {'failed_snapshot': parent['snapshot'], 'failed_snapshot_manifest_sha256': parent['snapshot_manifest_sha256'],
                      'accepted_release_sha256': parent['previous_release_sha256']}
    return transfer, receipt_raw, {'state_sha256': sha(state_raw), 'evidence': state['evidence']}, source_binding


def prepare(args):
    _, result = private_json(args.recovery_evidence_dir / 'result.json')
    require(type(result) is dict and result.get('schema') == 'cnb-recovery-session-result/v2'
            and result.get('status') == 'verified' and result.get('environment') == 'test'
            and result.get('source_kind') == 'failed-test-release' and result.get('public_identity_verified') is False
            and result.get('business_acceptance_verified') is False and result.get('bundle_lock_sha256') == args.lock_sha256,
            'REPAIR_FAILED_SOURCE_RECOVERY_REQUIRED')
    recovery_args = SimpleNamespace(bundle_dir=args.bundle_dir, lock_sha256=args.lock_sha256, target=args.target,
        accepted_installation=args.accepted_installation, evidence_dir=args.evidence_dir,
        git_sha=result['git_sha'], build_id=result['build_id'], export_id=result['export_id'],
        failed_transaction_sha256=result['source_release_sha256'], pull_docker_config=None, apply=False)
    plan = rehearsal.prepare(recovery_args)
    require(plan.scope['environment'] == 'test' and result['project'] == plan.scope['project']
            and result['installed_lock_sha256'] == plan.request['installed_lock_sha256']
            and 'host/repair-test-release.py' in plan.bundle['files'], 'REPAIR_BUNDLE_SCOPE_MISMATCH')
    helper = rehearsal.module_from_bytes(plan.bundle['files']['host/repair-test-release.py'], args.bundle_dir / 'host/repair-test-release.py')
    spec_raw, spec = private_json(args.migration_spec)
    try:
        helper.validate_spec(plan.bundle['host'], spec)
        expires = helper.timestamp(args.expires_at)
    except Exception as error:
        raise ValueError('REPAIR_MIGRATION_SPEC_OR_EXPIRY_INVALID') from error
    require(0 < (expires - datetime.now(timezone.utc)).total_seconds() <= 3600, 'REPAIR_GRANT_EXPIRY_INVALID')
    request, build_inputs = validate_build(plan, args.build_evidence_dir)
    transfer, restore_raw, recovery_inputs, source_binding = validate_recovery(plan, args.recovery_evidence_dir, result)
    request_raw = canonical(request)
    files = {'request.json': request_raw, 'migration-spec.json': spec_raw, 'restore-receipt.json': restore_raw}
    grant = {'request_sha256': sha(request_raw), 'files': {name: {'sha256': sha(raw), 'base64': base64.b64encode(raw).decode('ascii')}
              for name, raw in files.items()}, 'archive_sha256': transfer['archive_sha256'],
             'manifest_sha256': transfer['manifest_sha256'], 'restore_receipt_sha256': sha(restore_raw), 'expires_at': args.expires_at}
    inputs = {'schema': 'cnb-test-repair-grant-input/v1', 'recovery_binding': plan.binding,
              'build_evidence': build_inputs, 'recovery_evidence': recovery_inputs,
              'files': {name: sha(raw) for name, raw in files.items()}, 'expires_at': args.expires_at,
              'source_binding': source_binding}
    return SimpleNamespace(args=args, recovery_plan=plan, helper=helper, request=request, files=files,
                           grant=grant, inputs=inputs, binding=sha(canonical(inputs)), source_binding=source_binding)


class Evidence:
    def __init__(self, plan):
        self.plan, self.root = plan, plan.args.evidence_dir.absolute()
    def __enter__(self):
        rehearsal.safe_directory_ancestors(self.root.parent)
        if not os.path.lexists(self.root):
            self.root.mkdir(mode=0o700)
            rehearsal.sync_directory(self.root.parent)
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'REPAIR_EVIDENCE_DIRECTORY_UNSAFE')
        self.fd = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600, 'REPAIR_EVIDENCE_LOCK_INVALID')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root / 'state.json'
            if os.path.lexists(path):
                _, self.state = private_json(path)
                require(self.state.get('schema') == 'cnb-test-repair-grant-session/v1'
                        and self.state.get('binding') == self.plan.binding, 'REPAIR_GRANT_INPUT_CHANGED')
                for name, digest in self.state['files'].items():
                    require(re.fullmatch('[A-Za-z0-9_.-]+', name) and sha(read_safe(self.root / name, {0o600})) == digest,
                            'REPAIR_GRANT_EVIDENCE_CHANGED')
            else:
                require({p.name for p in self.root.iterdir()} == {'.lock'}, 'REPAIR_NEW_GRANT_DIRECTORY_REQUIRED')
                self.state = {'schema': 'cnb-test-repair-grant-session/v1', 'binding': self.plan.binding,
                              'files': {}, 'apply_started': False, 'status': 'prepared'}
            for name, raw in self.plan.files.items():
                self.retain(name, raw)
            self.retain('inputs.json', canonical(self.plan.inputs))
            return self
        except BaseException:
            os.close(self.fd)
            raise
    def __exit__(self, kind, error, traceback):
        try:
            if error is not None:
                self.state['status'] = 'stopped_review_required'
                self.save()
        finally:
            os.close(self.fd)
    def save(self):
        rehearsal.atomic_write(self.root / 'state.json', canonical(self.state))
    def retain(self, name, raw):
        path = self.root / name
        if os.path.lexists(path):
            require(read_safe(path, {0o600}) == raw, 'REPAIR_GRANT_EVIDENCE_CHANGED')
        else:
            rehearsal.atomic_write(path, raw)
        self.state['files'][name] = sha(raw)
        self.save()


def execute(plan, transport=None):
    result = {'schema': 'cnb-test-repair-grant-result/v1', 'status': 'preview',
        'project': plan.recovery_plan.scope['project'], 'environment': 'test',
        'failed_transaction_sha256': plan.recovery_plan.args.failed_transaction_sha256,
        'request_sha256': plan.grant['request_sha256'], 'expires_at': plan.args.expires_at,
        'archive_sha256': plan.grant['archive_sha256'], 'manifest_sha256': plan.grant['manifest_sha256'],
        'restore_receipt_sha256': plan.grant['restore_receipt_sha256'],
        'public_identity_verified': False, 'business_acceptance_verified': False,
        'actions': ['prepare-pinned-migration-images', 'review-host-grant', 'grant-once', 'readback-permit']}
    with Evidence(plan) as evidence:
        evidence.retain('preview.json', canonical(result))
        if not plan.args.apply:
            return result
        transport = transport or rehearsal.SSHTransport(plan.recovery_plan)
        def call(mode):
            number = evidence.state.get('remote_attempts', 0)
            evidence.state.update(remote_attempts=number + 1, status='remote-' + mode)
            evidence.save()
            try:
                raw = transport.grant_repair(plan.grant, mode)
            except Exception as error:
                raw = getattr(error, 'remote_response', None)
                if type(raw) is bytes and 0 < len(raw) <= 1024 * 1024:
                    evidence.retain('remote-' + str(number).zfill(3) + '-' + mode + '-error.json', raw)
                raise
            require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, 'REPAIR_REMOTE_RESPONSE_INVALID')
            evidence.retain('remote-' + str(number).zfill(3) + '-' + mode + '.json', raw)
            response = strict_json(raw)
            validate_remote(plan, response, mode)
            return response
        # A fresh helper review can replace an expired prior permit after full validation.
        # An uncertain apply must first read back the already requested permit.
        observed = call('inspect') if evidence.state['apply_started'] or evidence.state['status'] == 'granted' else {'status': 'absent'}
        if observed['status'] == 'absent':
            reviewed = call('preview')
            if reviewed['status'] not in ('granted', 'unchanged'):
                evidence.state['apply_started'] = True
                evidence.save()
                call('apply')
            observed = call('inspect')
        require(observed['status'] == 'granted', 'REPAIR_PERMIT_READBACK_REQUIRED')
        result.update(status='granted', permit_sha256=observed['receipt']['permit_sha256'],
                      permit_id=observed['receipt']['permit_id'])
        evidence.retain('result.json', canonical(result))
        evidence.state['status'] = 'granted'
        evidence.save()
        return result


def validate_remote(plan, response, mode):
    require(type(response) is dict and set(response) == {'schema', 'status', 'receipt', 'permit'}
            and response['schema'] == 'cnb-test-repair-grant-remote/v1', 'REPAIR_REMOTE_RESPONSE_INVALID')
    if response['status'] == 'absent':
        require(mode == 'inspect' and response['receipt'] is None and response['permit'] is None, 'REPAIR_REMOTE_RESPONSE_INVALID')
        return
    status = response['status']
    require(status in ('preview', 'granted', 'unchanged') and (mode == 'preview' or status != 'preview'), 'REPAIR_REMOTE_RESPONSE_INVALID')
    receipt = response['receipt']
    expected = {'schema': 'cnb-test-repair-grant/v1', 'status': status,
        'project': plan.recovery_plan.scope['project'], 'environment': 'test',
        'request_sha256': plan.grant['request_sha256'], 'failed_transaction_sha256': plan.recovery_plan.args.failed_transaction_sha256,
        'archive_sha256': plan.grant['archive_sha256'], 'manifest_sha256': plan.grant['manifest_sha256'],
        'restore_receipt_sha256': plan.grant['restore_receipt_sha256'], 'expires_at': plan.args.expires_at}
    require(type(receipt) is dict and set(receipt) == set(expected) | {'source_state_sha256', 'migration_evidence_sha256', 'permit_sha256', 'permit_id'}
            and all(receipt.get(key) == value for key, value in expected.items())
            and all(type(receipt[key]) is str and plan.recovery_plan.recovery.HASH.fullmatch(receipt[key])
                    for key in ('source_state_sha256', 'migration_evidence_sha256')), 'REPAIR_REMOTE_RECEIPT_MISMATCH')
    if status == 'preview':
        require(response['permit'] is None and receipt['permit_sha256'] is None and receipt['permit_id'] is None,
                'REPAIR_REMOTE_PREVIEW_INVALID')
        return
    permit = plan.helper.validate_permit(plan.recovery_plan.bundle['host'], response['permit'], plan.request)
    binding = {**{key: value for key, value in expected.items() if key not in ('schema', 'status')},
        'controller_sha256': plan.recovery_plan.scope['controller_sha256'],
        'policy_sha256': plan.recovery_plan.scope['host_policy_sha256'],
        'recovery_policy_sha256': plan.recovery_plan.scope['recovery_policy_sha256'],
        'compose_sha256': plan.recovery_plan.bundle['host'].CONTROLLER_COMPOSE_SHA256,
        'migration_spec': strict_json(plan.files['migration-spec.json']), **plan.source_binding}
    require(all(permit.get(key) == value for key, value in binding.items())
            and plan.helper.grant_receipt(status, permit, canonical(permit)) == receipt,
            'REPAIR_PERMIT_READBACK_MISMATCH')


def main(argv=None):
    os.umask(0o077)
    try:
        result = execute(prepare(parse_args(argv)))
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        code = str(error)
        if not re.fullmatch('[A-Z][A-Z_]+|repair_[a-z_]+', code):
            code = 'REPAIR_GRANT_INCOMPLETE'
        print(json.dumps({'schema': 'cnb-test-repair-grant-result/v1', 'status': 'stopped_review_required', 'code': code}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
