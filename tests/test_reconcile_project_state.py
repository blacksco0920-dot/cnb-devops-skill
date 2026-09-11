"""Exercise local closeout against real files; no deployment or cloud doubles."""
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
                            'environment': 'production', 'git_sha': COMMIT, 'build_id': BUILD,
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
