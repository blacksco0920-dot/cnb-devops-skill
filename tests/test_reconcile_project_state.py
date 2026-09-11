"""Exercise local closeout against real files; no deployment or cloud doubles."""
import base64
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ENTRY = Path(__file__).resolve().parents[1] / 'scripts/reconcile-project-state.py'
COMMIT = 'a' * 40
BUILD = 'cnb-test-build-one'


def raw(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


class CloseoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / 'project'
        self.private = self.root / 'private'
        self.project.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)
        self.document = self.project / 'PROJECT_STATE.md'
        self.document.write_text('# Project\n\nHuman notes stay here.\n')
        self.state = self.private / 'state.json'
        self.original = {'schema': 'legacy-example/v1', 'project': 'sample', 'status': 'waiting_approval',
                         'user_authorization': {'source': 'explicit prior user request'},
                         'first_cloud_failure': {'status': 'failed', 'build_id': 'cnb-old'},
                         'environments': {'test': {'build_id': 'untouched-test'},
                                          'production': {'deployment_status': 'not_started', 'build_id': 'cnb-old'}}}
        self.put(self.state, self.original)
        self.identity = {'project': 'sample', 'environment': 'production',
                         'application_commit': COMMIT, 'build_id': BUILD}
        images = {'api': 'registry.invalid/sample/api@sha256:' + 'b' * 64}
        candidate = {**self.identity, 'environment': 'test', 'schema': 'cnb-candidate/v1',
                     'candidate_tag': 'sample-candidate-' + BUILD, 'services': images, 'manifest_sha256': '3' * 64}
        source_files = {'candidate.json': candidate, 'readiness.json': {'prepared_sha256': '4' * 64},
                        'approval.json': {'schema': 'test-approval-fixture/v1'},
                        'describe-commands.json': {'CommandSet': []}, 'describe-invocation-tasks.json': {'InvocationTaskSet': []},
                        'annotations-response.json': [], 'production-receipt.json': {'status': 'passed'}}
        source_files['production-receipt.json'] = {'schema': 'cnb-production-result/v1', 'status': 'passed',
            'project': 'sample', 'environment': 'production', 'candidate_tag': candidate['candidate_tag'],
            'candidate_bytes_sha256': digest(raw(candidate)), 'candidate_manifest_sha256': '3' * 64,
            'approval_id': '5' * 32, 'approval_sha256': digest(raw(source_files['approval.json'])),
            'prepared_sha256': '4' * 64, 'production_entry_sha256': 'a' * 64, 'production_authority_sha256': 'b' * 64,
            'release_record_sha256': '9' * 64, 'release': {'schema': 'cnb-deploy-result/v1', 'status': 'passed',
                'git_sha': COMMIT, 'build_id': BUILD, 'images': images, 'controller_program_sha256': 'c' * 64,
                'controller_compose_sha256': 'd' * 64, 'policy_sha256': '6' * 64}}
        for name, value in source_files.items():
            self.put(self.private / name, value)
        deployment = {**self.identity, 'schema': 'cnb-deployment-verification/v1', 'status': 'verified',
                      'candidate_tag': 'sample-candidate-' + BUILD, 'invocation_id': 'inv-12345678',
                      'verified_at': '2026-09-11T04:50:00Z', 'execution_started_at': '2026-09-11T04:26:00Z',
                      'execution_finished_at': '2026-09-11T04:27:00Z',
                      'verification_scope': 'historical_completed_deployment', 'current_runtime_verified': False,
                      'images': images, 'signature': 'verified_ed25519', 'signature_valid_across_execution': True,
                      'approval_id': '5' * 32, 'approval_issued_at': '2026-09-11T04:20:00Z',
                      'approval_expires_at': '2026-09-11T05:20:00Z',
                      'candidate_bytes_sha256': digest((self.private / 'candidate.json').read_bytes()),
                      'candidate_manifest_sha256': '3' * 64, 'policy_sha256': '6' * 64,
                      'approval_sha256': digest((self.private / 'approval.json').read_bytes()),
                      'production_receipt_sha256': digest((self.private / 'production-receipt.json').read_bytes()),
                      'bundle_lock_sha256': '7' * 64, 'production_lock_sha256': '8' * 64,
                      'prepared_sha256': '4' * 64, 'release_record_sha256': '9' * 64,
                      'production_entry_sha256': 'a' * 64, 'production_authority_sha256': 'b' * 64,
                      'controller_program_sha256': 'c' * 64, 'controller_compose_sha256': 'd' * 64,
                      'region': 'test-region', 'instance_id': 'lhins-SYNTHETIC', 'command_id': 'cmd-example1',
                      'evidence_base': 'receipt_directory',
                      'evidence': [{'path': name, 'sha256': digest((self.private / name).read_bytes())} for name in source_files]}
        self.deployment = self.private / 'deployment.json'
        self.put(self.deployment, deployment)
        self.spec = {'schema': 'cnb-project-closeout/v1', **{k: self.identity[k] for k in ['project', 'environment']},
                     'project_dir': str(self.project), 'state_file': str(self.state),
                     'status_document': str(self.document), 'output_dir': str(self.private / 'closeout'),
                     'deployment': self.ref(self.deployment), 'required_checks': ['business', 'ui', 'coexistence', 'recovery'],
                     'checks': {}, 'resource_refs': {}}
        self.spec_path = self.private / 'closeout-spec.json'
        self.put(self.spec_path, self.spec)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, path, value):
        path.write_bytes(raw(value))
        path.chmod(0o600)

    def ref(self, path):
        return {'path': str(path), 'sha256': digest(path.read_bytes())}

    def invoke(self, apply=False, ok=True):
        self.assertTrue(ENTRY.is_file(), 'fixed local state closeout entry is missing')
        self.put(self.spec_path, self.spec)
        command = [sys.executable, str(ENTRY), '--spec', str(self.spec_path)]
        if apply:
            command.append('--apply')
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr + result.stdout)
        return json.loads(result.stdout if ok else result.stderr)

    def complete_checks(self):
        for name in ['business', 'ui']:
            path = self.private / (name + '.json')
            self.put(path, {'schema': 'sample-' + name + '/v1', 'status': 'passed',
                            'environment': self.identity['environment'], 'git_sha': COMMIT, 'build_id': BUILD,
                            'checks': [{'name': 'real-flow', 'status': 'passed'}]})
            self.spec['checks'][name] = self.ref(path)
        source = self.private / 'observation.json'
        self.put(source, {'schema': 'coexistence-observation/v1'})
        coexist = self.private / 'coexistence.json'
        self.put(coexist, {**self.identity, 'schema': 'cnb-coexistence-verification/v1', 'status': 'verified',
                           'observed_at': '2026-09-11T04:55:00Z', 'observation_source': 'live', 'checks': {'neighbor': True},
                           'candidate_sha256': json.loads(self.deployment.read_text())['candidate_bytes_sha256'],
                           'policy_sha256': '6' * 64,
                           'evidence': {'observation': self.ref(source)}})
        self.spec['checks']['coexistence'] = self.ref(coexist)
        restore = self.private / 'restore'
        restore.mkdir(mode=0o700)
        receipt = restore / 'restore-receipt.json'
        self.put(receipt, {'schema': 'cnb-recovery-restore-receipt/v1', 'status': 'verified',
                           'external_restore_verified': True, 'all_table_data_equal': True, 'schema_equal': True,
                           'sequences_equal': True, 'business_files_equal': True,
                           'source_docker_id_sha256': '1' * 64, 'target_docker_id_sha256': '2' * 64})
        recovery = self.private / 'recovery.json'
        self.put(recovery, {**self.identity, 'git_sha': COMMIT, 'schema': 'cnb-recovery-session-result/v1',
                            'status': 'verified', 'external_restore_verified': True, 'source_unchanged': True,
                            'restore_receipt_sha256': self.ref(receipt)['sha256'],
                            'scope': {'postgres': True, 'business_mounts': ['uploads'], 'redis': False, 'full_host': False}})
        self.spec['checks']['recovery'] = self.ref(recovery)

    def use_test_deployment(self):
        self.identity['environment'] = self.spec['environment'] = 'test'
        images = {'api': 'registry.invalid/sample/api@sha256:' + 'b' * 64}
        controller = 'sample-test-v1'
        command = b'#!/bin/sh\nrequest="{{release_request_b64url}}"\nexec /opt/release/command\n'
        binding = {'schema': 'cnb-tat-binding/v1', 'project': 'sample', 'environment': 'test',
                   'region': 'ap-guangzhou', 'instance_id': 'lhins-SYNTHETIC', 'command_id': 'cmd-example1',
                   'command_sha256': digest(command), 'username': 'release', 'working_directory': '/home/release',
                   'timeout': 3600, 'program_sha256': 'c' * 64, 'compose_sha256': 'd' * 64, 'policy_sha256': '6' * 64}
        request = {'schema': 'cnb-release-request/v1', 'project': 'sample', 'environment': 'test',
                   'controller': controller, 'git_sha': COMMIT, 'controller_commit': COMMIT, 'build_id': BUILD, 'images': images}
        release = {**request, 'schema': 'cnb-deploy-result/v1', 'status': 'passed',
                   'controller_program_sha256': 'c' * 64, 'controller_compose_sha256': 'd' * 64, 'policy_sha256': '6' * 64,
                   'database_backup_sha256': 'f' * 64, 'container_count': 1, 'probe_count': 1,
                   'probes': ['https://sample.example/health']}
        release_raw = canonical(release) + b'\n'
        created = '2026-09-11T04:30:00Z'
        build_url = 'https://cnb.cool/example/sample/-/build/logs/' + BUILD
        candidate = {**self.identity, 'schema': 'cnb-candidate/v1', 'controller': controller, 'controller_commit': COMMIT,
                     'candidate_tag': 'sample-candidate-' + BUILD, 'services': images, 'build_url': build_url,
                     'created_at': created, 'controller_program_sha256': 'c' * 64, 'controller_compose_sha256': 'd' * 64,
                     'policy_sha256': '6' * 64, 'release_receipt_sha256': digest(release_raw),
                     'evidence': {'build': {'status': 'passed', 'verified_at': created, 'reference': build_url},
                                  'runtime': {'status': 'passed', 'verified_at': created, 'reference': 'tat:inv-12345678', 'container_count': 1},
                                  'public': {'status': 'passed', 'verified_at': created, 'reference': 'tat:inv-12345678',
                                             'probe_count': 1, 'probes': release['probes']}}}
        candidate['manifest_sha256'] = digest(canonical(candidate))
        candidate_raw = canonical(candidate) + b'\n'
        tag_raw = (f'object {COMMIT}\ntype commit\ntag {candidate["candidate_tag"]}\n'
                   f'tagger Release <release@example.invalid> {int(datetime.fromisoformat(created).timestamp())} +0000\n\n').encode() + candidate_raw
        command_fields = {'CommandType': 'SHELL', 'Username': binding['username'],
                          'WorkingDirectory': binding['working_directory'], 'Timeout': binding['timeout'],
                          'OutputCOSBucketUrl': '', 'OutputCOSKeyPrefix': ''}
        commands = {'TotalCount': 1, 'CommandSet': [{**command_fields, 'CommandId': binding['command_id'],
                    'Content': base64.b64encode(command).decode(), 'EnableParameter': True, 'CreatedBy': 'USER',
                    'DefaultParameters': '{"release_request_b64url":"INVALID"}'}]}
        script = command.replace(b'{{release_request_b64url}}', base64.urlsafe_b64encode(canonical(request)).rstrip(b'='))
        tasks = {'TotalCount': 1, 'InvocationTaskSet': [{'InvocationId': 'inv-12345678',
                 'InstanceId': binding['instance_id'], 'CommandId': binding['command_id'], 'TaskStatus': 'SUCCESS',
                 'CommandDocument': {**command_fields, 'Content': base64.b64encode(script).decode()},
                 'TaskResult': {'ExitCode': 0, 'Dropped': 0, 'Output': base64.b64encode(release_raw).decode(),
                                'ExecStartTime': '2026-09-11T04:26:00Z', 'ExecEndTime': '2026-09-11T04:27:00Z'}}]}
        sources = {'candidate.json': candidate_raw, 'candidate-tag.raw': tag_raw, 'binding.json': raw(binding),
                   'describe-commands.json': raw(commands), 'describe-invocation-tasks.json': raw(tasks),
                   'release-receipt.json': release_raw}
        for name, content in sources.items():
            path = self.private / name
            path.write_bytes(content)
            path.chmod(0o600)
        deployment = {**self.identity, 'schema': 'cnb-test-deployment-verification/v1', 'status': 'verified',
                      'candidate_tag': candidate['candidate_tag'], 'invocation_id': 'inv-12345678', 'controller': controller,
                      'verified_at': '2026-09-11T04:50:00Z', 'candidate_created_at': created,
                      'execution_started_at': tasks['InvocationTaskSet'][0]['TaskResult']['ExecStartTime'],
                      'execution_finished_at': tasks['InvocationTaskSet'][0]['TaskResult']['ExecEndTime'],
                      'verification_scope': 'historical_completed_deployment', 'current_runtime_verified': False,
                      'images': images, 'saved_tag_verified': True, 'current_annotations_status': 'not_checked',
                      'current_tag_status': 'not_checked', 'candidate_manifest_sha256': candidate['manifest_sha256'],
                      'candidate_bytes_sha256': digest(candidate_raw), 'tag_object_sha256': digest(tag_raw),
                      'binding_sha256': digest(sources['binding.json']), 'release_receipt_sha256': digest(release_raw),
                      'controller_program_sha256': 'c' * 64, 'controller_compose_sha256': 'd' * 64, 'policy_sha256': '6' * 64,
                      'bundle_lock_sha256': '7' * 64, 'verification_spec_sha256': '8' * 64, 'input_sha256': '9' * 64,
                      **{k: binding[k] for k in ['region', 'instance_id', 'command_id']}, 'evidence_base': 'receipt_directory',
                      'evidence': [{'path': name, 'sha256': digest(content)} for name, content in sources.items()]}
        self.put(self.deployment, deployment)
        self.spec['deployment'] = self.ref(self.deployment)

    def change_deployment(self, updates):
        self.put(self.deployment, {**json.loads(self.deployment.read_text()), **updates})
        self.spec['deployment'] = self.ref(self.deployment)

    def repin_test_source(self, name, content):
        path = self.private / name
        path.write_bytes(content)
        deployment = json.loads(self.deployment.read_text())
        for ref in deployment['evidence']:
            if ref['path'] == name:
                ref['sha256'] = digest(content)
        key = {'candidate.json': 'candidate_bytes_sha256', 'candidate-tag.raw': 'tag_object_sha256',
               'binding.json': 'binding_sha256', 'release-receipt.json': 'release_receipt_sha256'}.get(name)
        if key:
            deployment[key] = digest(content)
        self.change_deployment(deployment)

    def repin_test_candidate(self, candidate):
        candidate.pop('manifest_sha256', None)
        candidate['manifest_sha256'] = digest(canonical(candidate))
        self.change_deployment({'candidate_manifest_sha256': candidate['manifest_sha256']})
        candidate_raw = canonical(candidate) + b'\n'
        self.repin_test_source('candidate.json', candidate_raw)
        header = (self.private / 'candidate-tag.raw').read_bytes().partition(b'\n\n')[0]
        self.repin_test_source('candidate-tag.raw', header + b'\n\n' + candidate_raw)

    def test_test_deployment_closes_only_test_and_repeats_without_writes(self):
        self.use_test_deployment()
        self.complete_checks()
        self.invoke(apply=True)
        state = json.loads(self.state.read_text())
        self.assertEqual(state['environments']['test']['current']['status'], 'declared_acceptance_verified')
        self.assertEqual(state['environments']['production'], self.original['environments']['production'])
        self.assertEqual(state['test_build_id'], BUILD)
        self.assertIn('Human notes stay here.', self.document.read_text())
        self.assertIn('cnb-devops:current:test:begin', self.document.read_text())
        paths = [self.state, self.document, Path(self.spec['output_dir']) / 'receipt.json']
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]
        self.assertTrue(self.invoke(apply=True)['reused'])
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths])

    def test_test_preview_retains_pending_acceptance_and_no_current_runtime_claim(self):
        self.use_test_deployment()
        before = self.state.read_bytes(), self.document.read_bytes()
        current = self.invoke()['current']
        self.assertEqual(current['status'], 'deployment_verified')
        self.assertEqual(current['pending_checks'], ['business', 'ui', 'coexistence', 'recovery'])
        self.assertFalse(current['current_runtime_verified'])
        self.assertEqual(before, (self.state.read_bytes(), self.document.read_bytes()))
        self.assertFalse(Path(self.spec['output_dir']).exists())

    def test_production_verification_schema_cannot_close_test_environment(self):
        self.spec['environment'] = 'test'
        result = json.loads((self.private / 'production-receipt.json').read_text())
        result['environment'] = 'test'
        self.put(self.private / 'production-receipt.json', result)
        deployment = json.loads(self.deployment.read_text())
        deployment['environment'] = 'test'
        deployment['production_receipt_sha256'] = self.ref(self.private / 'production-receipt.json')['sha256']
        for ref in deployment['evidence']:
            if ref['path'] == 'production-receipt.json':
                ref['sha256'] = deployment['production_receipt_sha256']
        self.change_deployment(deployment)
        self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'DEPLOYMENT_INVALID')
        self.assertEqual(json.loads(self.state.read_text()), self.original)

    def test_test_schema_cannot_close_production_environment(self):
        self.use_test_deployment()
        self.spec['environment'] = 'production'
        self.change_deployment({'environment': 'production'})
        self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'DEPLOYMENT_INVALID')

    def test_test_receipt_requires_full_records_and_saved_historical_scope(self):
        for update in [{'saved_tag_verified': False}, {'current_annotations_status': 'verified'},
                       {'current_tag_status': 'verified'}, {'bundle_lock_sha256': 'invalid'},
                       {'controller': ''}, {'region': ''}, {'instance_id': ''}, {'command_id': ''}, {'evidence': []}]:
            with self.subTest(update=update):
                self.use_test_deployment()
                self.change_deployment(update)
                result = self.invoke(apply=True, ok=False)
                self.assertIn(result['code'], ['TEST_DEPLOYMENT_RECORD_INCOMPLETE', 'TEST_DEPLOYMENT_FILES_INCOMPLETE'])
                self.assertEqual(json.loads(self.state.read_text()), self.original)

    def test_test_tag_headers_and_exact_message_are_revalidated_after_repinning(self):
        for old, new in [(b'type commit', b'type tree'), (COMMIT.encode(), b'f' * 40),
                         (b'tag sample-candidate-', b'tag other-candidate-'),
                         (b'type commit\n', b'type commit\ntype commit\n'),
                         (b'\n\n', b'\nencoding utf-8\n\n'), (b'"status":"passed"', b'"status":"failed"')]:
            with self.subTest(old=old, new=new):
                self.use_test_deployment()
                tag = (self.private / 'candidate-tag.raw').read_bytes().replace(old, new, 1)
                self.repin_test_source('candidate-tag.raw', tag)
                self.assertEqual(self.invoke(ok=False)['code'], 'TEST_TAG_SOURCE_MISMATCH')

    def test_test_candidate_source_and_execution_window_are_revalidated(self):
        for field, value in [('services', {}), ('controller_commit', 'f' * 40), ('manifest_sha256', '0' * 64),
                             ('created_at', '2026-09-11T04:20:00Z'), ('environment', 'production')]:
            with self.subTest(field=field):
                self.use_test_deployment()
                candidate = json.loads((self.private / 'candidate.json').read_text())
                candidate[field] = value
                self.repin_test_source('candidate.json', canonical(candidate) + b'\n')
                self.assertEqual(self.invoke(ok=False)['code'], 'CANDIDATE_SOURCE_MISMATCH')
        for updates in [{'execution_finished_at': '2026-09-11T04:31:00Z'},
                        {'candidate_created_at': '2026-09-11T04:20:00Z'}, {'verified_at': '2026-09-11T04:29:00Z'}]:
            with self.subTest(updates=updates):
                self.use_test_deployment()
                self.change_deployment(updates)
                self.assertEqual(self.invoke(ok=False)['code'], 'TEST_DEPLOYMENT_TIME_INVALID')

    def test_test_binding_identity_and_controller_hashes_cannot_be_repointed(self):
        for field, value in [('environment', 'production'), ('instance_id', 'lhins-DIFFERENT'),
                             ('command_id', 'cmd-different'), ('program_sha256', '0' * 64),
                             ('compose_sha256', '0' * 64), ('policy_sha256', '0' * 64)]:
            with self.subTest(field=field):
                self.use_test_deployment()
                binding = json.loads((self.private / 'binding.json').read_text())
                binding[field] = value
                self.repin_test_source('binding.json', raw(binding))
                self.assertEqual(self.invoke(ok=False)['code'], 'TEST_BINDING_SOURCE_MISMATCH')

    def test_test_candidate_invocation_cannot_be_repointed_with_fresh_hashes(self):
        for plane in ['runtime', 'public']:
            with self.subTest(plane=plane):
                self.use_test_deployment()
                candidate = json.loads((self.private / 'candidate.json').read_text())
                candidate['evidence'][plane]['reference'] = 'tat:inv-DIFFERENT'
                self.repin_test_candidate(candidate)
                self.assertEqual(self.invoke(ok=False)['code'], 'CANDIDATE_SOURCE_MISMATCH')

    def test_test_release_source_cannot_change_identity_after_every_hash_is_repinned(self):
        for field, value in [('schema', 'other/v1'), ('status', 'failed'), ('project', 'other'),
                             ('environment', 'production'), ('controller', 'sample-production-v1'),
                             ('git_sha', 'f' * 40), ('controller_commit', 'f' * 40), ('build_id', 'cnb-other-build'),
                             ('images', {}), ('controller_program_sha256', 'f' * 64),
                             ('controller_compose_sha256', 'f' * 64), ('policy_sha256', 'f' * 64),
                             ('container_count', True), ('probe_count', True), ('probes', []),
                             ('database_backup_sha256', 'invalid'), ('database_backup_sha256', None),
                             ('database_backup_sha256', True), ('unexpected_receipt_key', 'not-v1')]:
            with self.subTest(field=field):
                self.use_test_deployment()
                release = json.loads((self.private / 'release-receipt.json').read_text())
                release[field] = value
                content = canonical(release) + b'\n'
                self.repin_test_source('release-receipt.json', content)
                candidate = json.loads((self.private / 'candidate.json').read_text())
                candidate['release_receipt_sha256'] = digest(content)
                self.repin_test_candidate(candidate)
                tasks = json.loads((self.private / 'describe-invocation-tasks.json').read_text())
                tasks['InvocationTaskSet'][0]['TaskResult']['Output'] = base64.b64encode(content).decode()
                self.repin_test_source('describe-invocation-tasks.json', raw(tasks))
                self.assertEqual(self.invoke(ok=False)['code'], 'RELEASE_SOURCE_MISMATCH')
                self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'RELEASE_SOURCE_MISMATCH')
                self.assertEqual(json.loads(self.state.read_text()), self.original)
                self.assertFalse(Path(self.spec['output_dir']).exists())

    def test_test_saved_command_policy_conflicts_rejected_after_repinning(self):
        good_conf = {'ParameterName': 'release_request_b64url', 'ParameterValue': 'INVALID', 'ParameterDescription': ''}
        updates = [{'DefaultParameters': '{"release_request_b64url":"ALLOW"}'}, {'EnableParameter': False},
                   {'EnableParameter': 1}, {'CreatedBy': 'OTHER'}, {'DefaultParameters': ''},
                   {'DefaultParameterConfs': [{**good_conf, 'ParameterValue': 'ALLOW'}]},
                   {'DefaultParameterConfs': [{**good_conf, 'ParameterName': 'other'}]},
                   {'DefaultParameterConfs': [{**good_conf, 'ParameterDescription': 'unbound'}]},
                   {'DefaultParameterConfs': [{**good_conf, 'extra': 'field'}]},
                   {'DefaultParameterConfs': [good_conf, good_conf]}]
        for update in updates:
            with self.subTest(update=update):
                self.use_test_deployment()
                commands = json.loads((self.private / 'describe-commands.json').read_text())
                commands['CommandSet'][0].update(update)
                self.repin_test_source('describe-commands.json', raw(commands))
                self.assertEqual(self.invoke(ok=False)['code'], 'TEST_TAT_SOURCE_MISMATCH')
                self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'TEST_TAT_SOURCE_MISMATCH')
                self.assertEqual(json.loads(self.state.read_text()), self.original)
                self.assertFalse(Path(self.spec['output_dir']).exists())

    def test_test_saved_command_supports_both_official_parameter_default_representations(self):
        conf = {'ParameterName': 'release_request_b64url', 'ParameterValue': 'INVALID', 'ParameterDescription': ''}
        for update in [{'DefaultParameterConfs': None}, {'DefaultParameterConfs': []}, {'DefaultParameterConfs': [conf]},
                       {'DefaultParameters': '', 'DefaultParameterConfs': [conf]}]:
            with self.subTest(update=update):
                self.use_test_deployment()
                commands = json.loads((self.private / 'describe-commands.json').read_text())
                commands['CommandSet'][0].update(update)
                self.repin_test_source('describe-commands.json', raw(commands))
                self.assertEqual(self.invoke()['current']['status'], 'deployment_verified')

    def test_test_task_and_saved_command_evidence_cannot_be_repointed(self):
        for change in ['task_count', 'instance', 'invocation', 'command', 'failed', 'dropped', 'exit',
                       'output', 'timestamp', 'script', 'saved_command', 'saved_hash', 'boolean_count',
                       'boolean_dropped', 'boolean_exit']:
            with self.subTest(change=change):
                self.use_test_deployment()
                name = 'describe-invocation-tasks.json'
                data = json.loads((self.private / name).read_text())
                task = data['InvocationTaskSet'][0]
                if change == 'task_count': data['InvocationTaskSet'].append(task)
                elif change == 'boolean_count': data['TotalCount'] = True
                elif change == 'instance': task['InstanceId'] = 'lhins-DIFFERENT'
                elif change == 'invocation': task['InvocationId'] = 'inv-DIFFERENT'
                elif change == 'command': task['CommandId'] = 'cmd-DIFFERENT'
                elif change == 'failed': task['TaskStatus'] = 'FAILED'
                elif change == 'dropped': task['TaskResult']['Dropped'] = 1
                elif change == 'exit': task['TaskResult']['ExitCode'] = 1
                elif change == 'boolean_dropped': task['TaskResult']['Dropped'] = False
                elif change == 'boolean_exit': task['TaskResult']['ExitCode'] = False
                elif change == 'output': task['TaskResult']['Output'] = base64.b64encode(b'{}\n').decode()
                elif change == 'timestamp': task['TaskResult']['ExecEndTime'] = '2026-09-11T04:28:00Z'
                elif change == 'script': task['CommandDocument']['Content'] = base64.b64encode(b'echo passed\n').decode()
                else:
                    name = 'describe-commands.json'
                    data = json.loads((self.private / name).read_text())
                    if change == 'saved_command': data['CommandSet'][0]['CommandId'] = 'cmd-DIFFERENT'
                    else: data['CommandSet'][0]['Content'] = base64.b64encode(b'echo passed\n').decode()
                self.repin_test_source(name, raw(data))
                self.assertEqual(self.invoke(ok=False)['code'], 'TEST_TAT_SOURCE_MISMATCH')

    def test_raw_tag_does_not_allow_non_json_business_receipts(self):
        self.use_test_deployment()
        self.spec['checks']['business'] = self.ref(self.private / 'candidate-tag.raw')
        self.assertEqual(self.invoke(ok=False)['code'], 'JSON_INVALID')

    def test_preview_has_no_output_or_state_changes(self):
        before = self.state.read_bytes(), self.document.read_bytes()
        result = self.invoke()
        self.assertEqual(result['status'], 'preview')
        self.assertEqual(result['current']['status'], 'deployment_verified')
        self.assertEqual(result['current']['pending_checks'], ['business', 'ui', 'coexistence', 'recovery'])
        self.assertEqual(before, (self.state.read_bytes(), self.document.read_bytes()))
        self.assertFalse(Path(self.spec['output_dir']).exists())

    def test_incomplete_acceptance_cannot_become_accepted(self):
        self.invoke(apply=True)
        current = json.loads(self.state.read_text())['environments']['production']['current']
        self.assertEqual(current['status'], 'deployment_verified')
        self.assertFalse(current['current_runtime_verified'])
        self.assertEqual(current['next_action'], 'verify_business')

    def test_current_indexes_exact_input_for_independent_read_only_resume(self):
        self.complete_checks()
        self.invoke(apply=True)
        current = json.loads(self.state.read_text())['environments']['production']['current']
        self.assertEqual(current.get('closeout_spec'), self.ref(self.spec_path))
        indexed = current['closeout_spec']
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in (self.state, self.document)]
        resumed = subprocess.run([sys.executable, str(ENTRY), '--spec', indexed['path']],
                                 capture_output=True, text=True)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout)['current']['next_action'], 'none')
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mtime_ns) for p in (self.state, self.document)])

    def test_completed_closeout_preserves_other_state_and_repeats_without_writes(self):
        self.complete_checks()
        first = self.invoke(apply=True)
        result = json.loads(self.state.read_text())
        current = result['environments']['production']['current']
        self.assertEqual(current['status'], 'declared_acceptance_verified')
        self.assertEqual(current['next_action'], 'none')
        self.assertEqual(result['environments']['production']['build_id'], BUILD)
        self.assertEqual(result['environments']['test'], self.original['environments']['test'])
        self.assertEqual(result['user_authorization'], self.original['user_authorization'])
        self.assertEqual(result['first_cloud_failure'], self.original['first_cloud_failure'])
        self.assertIn('Human notes stay here.', self.document.read_text())
        self.assertNotIn(str(self.private), self.document.read_text())
        paths = [self.state, self.document, Path(self.spec['output_dir']) / 'receipt.json']
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]
        again = self.invoke(apply=True)
        self.assertTrue(again['reused'])
        self.assertEqual(first['current'], again['current'])
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths])
        snapshot = Path(self.spec['output_dir']) / 'before-state.json'
        self.assertEqual(json.loads(snapshot.read_text()), self.original)

    def test_bad_scope_hash_and_evidence_fail_before_state_write(self):
        for change in ['wrong_build', 'hash', 'nested_hash', 'wrong_environment']:
            with self.subTest(change=change):
                original = self.deployment.read_bytes()
                d = json.loads(original)
                if change == 'wrong_build':
                    d['build_id'] = 'bad build with spaces'
                elif change == 'nested_hash':
                    d['evidence'][0]['sha256'] = 'f' * 64
                elif change == 'wrong_environment':
                    d['environment'] = 'test'
                self.put(self.deployment, d)
                self.spec['deployment'] = self.ref(self.deployment)
                if change == 'hash':
                    self.spec['deployment']['sha256'] = '0' * 64
                before = self.state.read_bytes()
                self.invoke(apply=True, ok=False)
                self.assertEqual(before, self.state.read_bytes())
                self.assertFalse(Path(self.spec['output_dir']).exists())
                self.deployment.write_bytes(original)

    def test_checks_cannot_use_fixture_or_other_candidate_or_empty_pass(self):
        self.complete_checks()
        for name, update in [('coexistence', {'observation_source': 'fixture'}),
                             ('business', {'git_sha': 'f' * 40}), ('ui', {'checks': []}),
                             ('business', {'status': 'failed'}),
                             ('coexistence', {'candidate_sha256': '0' * 64}),
                             ('coexistence', {'policy_sha256': '0' * 64})]:
            with self.subTest(name=name, update=update):
                path = Path(self.spec['checks'][name]['path'])
                original = path.read_bytes()
                self.put(path, {**json.loads(original), **update})
                self.spec['checks'][name] = self.ref(path)
                self.invoke(apply=True, ok=False)
                self.assertFalse(Path(self.spec['output_dir']).exists())
                path.write_bytes(original)
                self.spec['checks'][name] = self.ref(path)

    def test_partial_deployment_summary_cannot_be_promoted(self):
        d = json.loads(self.deployment.read_text())
        d.pop('signature')
        d['evidence'] = d['evidence'][:1]
        self.put(self.deployment, d)
        self.spec['deployment'] = self.ref(self.deployment)
        self.invoke(apply=True, ok=False)
        self.assertFalse(Path(self.spec['output_dir']).exists())

    def test_unowned_document_edits_after_completion_are_not_overwritten(self):
        self.invoke(apply=True)
        self.document.write_text(self.document.read_text() + '\nHuman newer change.\n')
        before = self.document.read_bytes()
        self.invoke(apply=True, ok=False)
        self.assertEqual(before, self.document.read_bytes())

    def test_unsafe_private_file_or_document_outside_project_fails(self):
        self.deployment.chmod(0o644)
        self.invoke(ok=False)
        self.deployment.chmod(0o600)
        self.spec['status_document'] = str(self.private / 'outside.md')
        self.invoke(ok=False)

    def module(self):
        spec = importlib.util.spec_from_file_location('closeout_under_test', ENTRY)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_interrupted_document_write_resumes_same_transaction(self):
        self.complete_checks()
        self.put(self.spec_path, self.spec)
        module = self.module()
        original_atomic = module.atomic
        before_doc = self.document.read_bytes()

        def interrupted(path, data, mode=0o600):
            if path == self.document:
                raise OSError('simulated disk failure before document rename')
            return original_atomic(path, data, mode)

        with mock.patch.object(module, 'atomic', side_effect=interrupted):
            with self.assertRaises(OSError):
                module.reconcile(self.spec_path, True)
        out = Path(self.spec['output_dir'])
        self.assertNotEqual(self.state.read_bytes(), (out / 'before-state.json').read_bytes())
        self.assertEqual(self.document.read_bytes(), before_doc)
        self.assertFalse((out / 'receipt.json').exists())
        self.invoke(apply=True)
        self.assertEqual(json.loads((out / 'before-state.json').read_text()), self.original)
        self.assertTrue((out / 'receipt.json').exists())

    def test_concurrent_closeout_and_duplicate_document_markers_block(self):
        import fcntl
        lock = self.state.with_name('.state.json.closeout.lock')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'STATE_LOCKED')
        finally:
            os.close(fd)
        self.document.write_text('<!-- cnb-devops:current:production:begin -->\nUnfinished hand edit')
        self.assertEqual(self.invoke(apply=True, ok=False)['code'], 'DOCUMENT_MARKER_CONFLICT')

    def test_synchronized_legacy_aliases_cannot_retain_old_acceptance_hash(self):
        state = json.loads(self.state.read_text())
        state['environments']['production']['acceptance_sha256'] = '0' * 64
        self.put(self.state, state)
        self.invoke(apply=True)
        updated = json.loads(self.state.read_text())
        self.assertNotIn('acceptance_sha256', updated['environments']['production'])
        self.assertEqual(updated['application_commit'], COMMIT)


if __name__ == '__main__':
    unittest.main()
