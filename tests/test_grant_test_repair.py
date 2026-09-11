"""Fixed grant orchestration uses verified local evidence and synthetic transport."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import test_rehearse_recovery as recovery_fixture
import test_repair_session as build_fixture
from test_rehearse_recovery import SourceTransport, canonical, sha

SCRIPT = Path(__file__).parents[1] / 'scripts/grant-test-repair.py'


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'fixed grant orchestrator is missing')
        spec = importlib.util.spec_from_file_location('grant_test_repair', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.fixture = recovery_fixture.RecoverySessionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.bundle = self.fixture.root, self.fixture.bundle
        extra = {'ci-config.json': canonical({'cnb_repository': 'team/sample'}),
                 'host/repair-test-release.py': (SCRIPT.parents[1] / 'assets/cnb-tcr-tat/host/repair-test-release.py').read_bytes()}
        for name, raw in extra.items():
            (self.bundle / name).write_bytes(raw)
        lock = json.loads((self.bundle / 'artifact-lock.json').read_bytes())
        lock['files'].update({name: sha(raw) for name, raw in extra.items()})
        (self.bundle / 'artifact-lock.json').write_bytes(canonical(lock))
        self.lock = sha(canonical(lock))
        self.fixture.argv[self.fixture.argv.index('--lock-sha256') + 1] = self.lock
        self.recovery_plan = self.fixture.failed_plan()
        self.source = SourceTransport(self.recovery_plan)
        self.fixture.m.execute(self.recovery_plan, self.source)
        self.build_dir = self.root / 'build'
        self.build_dir.mkdir(mode=0o700)
        fixture = build_fixture.RepairBuildTests()
        fixture.setUp()
        fixture.bundle = self.recovery_plan.bundle
        fixture.request.update(controller=fixture.bundle['host'].CONTROLLER_ID)
        fixture.request['images'] = {role: fixture.bundle['policy']['services'][role]['image_repository'] + '@sha256:' + 'b' * 64
                                     for role in fixture.bundle['host'].SERVICES}
        fixture.handoff.update(request=fixture.request, ci_config_sha256=sha(extra['ci-config.json']))
        fixture.encoded = base64.urlsafe_b64encode(canonical(fixture.handoff).rstrip(b'\n')).decode().rstrip('=')
        fixture.stages[str(len(fixture.stages)-1)]['content'] = ['CNB_TEST_BUILD_HANDOFF=' + fixture.encoded]
        self.build_fixture = fixture
        build = fixture.validate()
        source_files = {'pipeline_verified': True, 'test_branch': 'test', 'files': {
            **{'deploy/vendor/cnb-devops/' + name: sha(raw) for name, raw in fixture.bundle['files'].items()},
            '.cnb.yml': 'a' * 64, 'deploy/project.yml': 'b' * 64}}
        values = {'build-evidence.json': build, 'request.json': fixture.request, 'source-files.json': source_files,
                  'builds.json': fixture.builds, 'status.json': fixture.status}
        values.update({name + '.json': {'data': stage} for name, stage in fixture.stages.items()
                       if stage['name'] in ('verify project', 'record digests and remove push credentials')})
        for name, value in values.items():
            self.write(self.build_dir / name, canonical(value))
        self.write(self.build_dir / 'handoff.txt', (fixture.encoded + '\n').encode())
        self.spec_path = self.root / 'migration-spec.json'
        self.write(self.spec_path, canonical({'schema': 'cnb-prisma-repair-inspection/v1', 'service': 'api',
            'schema_path': 'app/prisma/schema.prisma', 'migrations_path': 'app/prisma/migrations',
            'lock_path': 'app/prisma/migrations/migration_lock.toml'}))
        self.expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat().replace('+00:00', 'Z')
        self.argv = ['--bundle-dir', str(self.bundle), '--lock-sha256', self.lock, '--target', str(self.root / 'target.json'),
            '--accepted-installation', str(self.root / 'accepted.json'), '--build-evidence-dir', str(self.build_dir),
            '--recovery-evidence-dir', str(self.recovery_plan.args.evidence_dir), '--migration-spec', str(self.spec_path),
            '--expires-at', self.expiry, '--evidence-dir', str(self.root / 'grant')]

    def write(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def plan(self):
        return self.m.prepare(self.m.parse_args(self.argv))

    def test_offline_preview_derives_failed_identity_and_persists_reviewable_inputs(self):
        with mock.patch.object(self.m.subprocess, 'run', side_effect=AssertionError('preview contacted host')):
            plan = self.plan()
            result = self.m.execute(plan)
        self.assertEqual(result['status'], 'preview')
        self.assertEqual(result['failed_transaction_sha256'], self.recovery_plan.args.failed_transaction_sha256)
        self.assertEqual(result['request_sha256'], sha(canonical(self.build_fixture.request)))
        self.assertFalse(result['public_identity_verified'])
        self.assertEqual((self.root / 'grant/request.json').read_bytes(), canonical(self.build_fixture.request))
        self.assertTrue((self.root / 'grant/preview.json').is_file())

    def test_tampered_build_source_hash_and_restore_record_are_rejected_before_transport(self):
        path = self.build_dir / 'source-files.json'
        original = path.read_bytes()
        model = json.loads(original)
        model['files']['deploy/vendor/cnb-devops/host/tat-deploy-test.py'] = 'e' * 64
        self.write(path, canonical(model))
        with self.assertRaisesRegex(ValueError, 'SOURCE'):
            self.plan()
        self.write(path, original)
        receipt = self.recovery_plan.args.evidence_dir / 'restore/restore-receipt.json'
        model = json.loads(receipt.read_bytes())
        model['all_table_data_equal'] = False
        self.write(receipt, canonical(model))
        with self.assertRaises(ValueError):
            self.plan()
        self.assertFalse((self.root / 'grant').exists())

    def test_raw_build_revalidation_rejects_forged_verified_summary(self):
        path = self.build_dir / '2.json'
        model = json.loads(path.read_bytes())
        model['data']['content'] = ['verification skipped']
        self.write(path, canonical(model))
        with self.assertRaisesRegex(ValueError, 'VERIFICATION'):
            self.plan()

    def test_expired_grant_and_changed_migration_paths_are_refused_offline(self):
        self.argv[self.argv.index('--expires-at') + 1] = '2020-01-01T00:00:00Z'
        with self.assertRaises(ValueError):
            self.plan()
        self.argv[self.argv.index('--expires-at') + 1] = self.expiry
        model = json.loads(self.spec_path.read_bytes())
        model['schema_path'] = '../../etc/passwd'
        self.write(self.spec_path, canonical(model))
        with self.assertRaises(ValueError):
            self.plan()

    def permit(self, plan):
        source = self.source.model['source_release']
        return {'schema': 'cnb-test-repair-permit/v1', 'permit_id': 'd' * 32,
            'project': plan.request['project'], 'environment': 'test', 'controller': plan.request['controller'],
            'issued_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'expires_at': plan.args.expires_at,
            'controller_sha256': plan.recovery_plan.scope['controller_sha256'],
            'policy_sha256': plan.recovery_plan.scope['host_policy_sha256'],
            'compose_sha256': plan.recovery_plan.bundle['host'].CONTROLLER_COMPOSE_SHA256,
            'recovery_policy_sha256': plan.recovery_plan.scope['recovery_policy_sha256'],
            'failed_transaction_sha256': plan.recovery_plan.args.failed_transaction_sha256,
            'failed_snapshot': source['snapshot'], 'failed_snapshot_manifest_sha256': source['snapshot_manifest_sha256'],
            'accepted_release_sha256': source['previous_release_sha256'], 'source_state_sha256': 'c' * 64,
            'migration_spec': json.loads(plan.files['migration-spec.json']), 'migration_evidence_sha256': 'e' * 64,
            'archive_sha256': plan.grant['archive_sha256'], 'manifest_sha256': plan.grant['manifest_sha256'],
            'restore_receipt_sha256': plan.grant['restore_receipt_sha256'], 'request_sha256': plan.grant['request_sha256']}

    def transport(self, plan, lose_apply=False):
        owner = self
        class Transport:
            def __init__(self):
                self.calls, self.current, self.candidate, self.lose = [], None, owner.permit(plan), lose_apply
            def grant_repair(self, payload, mode):
                owner.assertEqual(set(payload['files']), {'request.json', 'migration-spec.json', 'restore-receipt.json'})
                owner.assertNotIn('export.tar', payload['files'])
                self.calls.append(mode)
                if mode == 'inspect' and self.current is None:
                    status, receipt, permit = 'absent', None, None
                elif mode == 'preview':
                    status, permit = 'preview', None
                    receipt = plan.helper.grant_receipt(status, self.candidate)
                else:
                    if mode == 'apply':
                        self.current = copy.deepcopy(self.candidate)
                        if self.lose:
                            self.lose = False
                            raise OSError('synthetic response lost after grant')
                    status, permit = 'granted', self.current
                    receipt = plan.helper.grant_receipt(status, permit, canonical(permit))
                return canonical({'schema': 'cnb-test-repair-grant-remote/v1', 'status': status, 'receipt': receipt, 'permit': permit})
        return Transport()

    def remote_args(self, plan):
        scope = plan.recovery_plan.scope
        return SimpleNamespace(project=scope['project'], environment=scope['environment'], export_id=scope['export_id'],
            controller_sha256=scope['controller_sha256'], policy_sha256=scope['host_policy_sha256'],
            recovery_policy_sha256=scope['recovery_policy_sha256'], failed_transaction_sha256=plan.recovery_plan.args.failed_transaction_sha256)

    def test_apply_persists_raw_review_grant_and_readback(self):
        self.argv.append('--apply')
        plan = self.plan()
        transport = self.transport(plan)
        result = self.m.execute(plan, transport)
        self.assertEqual(result['status'], 'granted')
        self.assertEqual(transport.calls, ['preview', 'apply', 'inspect'])
        self.assertEqual(result['permit_sha256'], sha(canonical(transport.current)))
        self.assertTrue((self.root / 'grant/remote-000-preview.json').is_file())
        self.assertTrue((self.root / 'grant/remote-001-apply.json').is_file())
        self.assertTrue((self.root / 'grant/remote-002-inspect.json').is_file())

    def test_fresh_grant_enters_helper_review_so_an_expired_old_permit_can_be_replaced(self):
        self.argv.append('--apply')
        plan = self.plan()
        transport = self.transport(plan)
        original = transport.grant_repair
        def call(payload, mode):
            if mode == 'inspect' and transport.current is None:
                raise ValueError('old active permit expired')
            return original(payload, mode)
        transport.grant_repair = call
        self.assertEqual(self.m.execute(plan, transport)['status'], 'granted')

    def test_uncertain_grant_is_read_back_without_reapplying(self):
        self.argv.append('--apply')
        plan = self.plan()
        transport = self.transport(plan, lose_apply=True)
        with self.assertRaises(OSError):
            self.m.execute(plan, transport)
        state = json.loads((self.root / 'grant/state.json').read_bytes())
        self.assertTrue(state['apply_started'])
        self.assertEqual(state['status'], 'stopped_review_required')
        result = self.m.execute(self.plan(), transport)
        self.assertEqual(result['status'], 'granted')
        self.assertEqual(transport.calls.count('apply'), 1)
        self.assertEqual(transport.calls[-1], 'inspect')

    def test_remote_failure_raw_response_is_preserved_before_stopping(self):
        self.argv.append('--apply')
        plan = self.plan()
        raw = b'{"status":"stopped_review_required","code":"RECOVERY_REMOTE_INCOMPLETE"}\n'
        class Transport:
            def grant_repair(self, payload, mode):
                error = OSError('synthetic failed remote review')
                error.remote_response = raw
                raise error
        with self.assertRaises(OSError):
            self.m.execute(plan, Transport())
        self.assertEqual((self.root / 'grant/remote-000-preview-error.json').read_bytes(), raw)

    def test_readback_with_a_different_baseline_or_snapshot_is_not_accepted(self):
        plan = self.plan()
        for key, value in [('accepted_release_sha256', 'f' * 64),
                           ('failed_snapshot_manifest_sha256', 'f' * 64)]:
            with self.subTest(key=key):
                permit = self.permit(plan)
                permit[key] = value
                response = {'schema': 'cnb-test-repair-grant-remote/v1', 'status': 'granted', 'permit': permit,
                    'receipt': plan.helper.grant_receipt('granted', permit, canonical(permit))}
                with self.assertRaisesRegex(ValueError, 'READBACK'):
                    self.m.validate_remote(plan, response, 'inspect')

    def test_remote_readback_keeps_full_request_identity_for_real_helper_validation(self):
        plan = self.plan()
        permit = self.permit(plan)
        host = plan.recovery_plan.bundle['host']
        permit_path = Path(host.POLICY['install_dir']) / 'test-repair/permit.json'
        files = {permit_path: canonical(permit), permit_path.parent / 'permits' / (permit['permit_id'] + '.json'): canonical(permit)}
        request = {**plan.recovery_plan.request, 'grant': plan.grant, 'grant_mode': 'inspect'}
        recovery = plan.recovery_plan.recovery
        with mock.patch.object(recovery, 'root_read', lambda path, mode: files[path]), \
             mock.patch.object(self.m.os.path, 'lexists', lambda path: Path(path) in files):
            result = self.m.rehearsal.remote_grant(recovery, host,
                {'repair-test-release.py': plan.recovery_plan.bundle['files']['host/repair-test-release.py']},
                self.remote_args(plan), request)
        self.assertEqual(result['status'], 'granted')
        self.assertEqual(result['receipt']['request_sha256'], sha(canonical(plan.request)))
        self.assertEqual(result['permit'], permit)

    def test_remote_preparation_writes_only_fixed_small_files_and_uses_source_archive(self):
        plan = self.plan()
        host, recovery = plan.recovery_plan.bundle['host'], plan.recovery_plan.recovery
        expected_root = '/var/lib/cnb-devops/sample/test/repairs/' + plan.grant['request_sha256']
        receipt = plan.helper.grant_receipt('preview', self.permit(plan))
        source = plan.recovery_plan.bundle['files']['host/repair-test-release.py']
        source += ('\ndef grant(args):\n'
                   '    assert args.request == ' + repr(expected_root + '/request.json') + '\n'
                   '    assert args.archive == "/var/lib/cnb-devops/sample/test/exports/exercise-one/export.tar"\n'
                   '    assert args.apply is False\n'
                   '    return ' + repr(receipt) + '\n').encode()
        request = {**plan.recovery_plan.request, 'grant': plan.grant, 'grant_mode': 'preview',
                   'runtime': copy.deepcopy(plan.recovery_plan.request['runtime'])}
        request['runtime']['repair-test-release.py']['sha256'] = sha(source)
        written, directories = {}, []
        def write(path, raw):
            self.assertNotIn(path, written)
            written[path] = raw
        with mock.patch.object(recovery, 'root_read', lambda path, mode: written[path]), \
             mock.patch.object(recovery, 'root_directory', lambda path, mode: directories.append((path, mode))), \
             mock.patch.object(recovery, 'write_new', write), \
             mock.patch.object(self.m.os.path, 'lexists', lambda path: Path(path) in written):
            result = self.m.rehearsal.remote_grant(recovery, host, {'repair-test-release.py': source}, self.remote_args(plan), request)
            self.assertEqual(result['status'], 'preview')
            self.assertEqual(written, {Path(expected_root) / name: raw for name, raw in plan.files.items()})
            self.assertTrue(all(mode == 0o700 for path, mode in directories))
            again = self.m.rehearsal.remote_grant(recovery, host, {'repair-test-release.py': source}, self.remote_args(plan), request)
            self.assertEqual(again, result)
            request['grant'] = copy.deepcopy(plan.grant)
            request['grant']['files']['../../archive.tar'] = request['grant']['files']['request.json']
            with self.assertRaises(ValueError):
                self.m.rehearsal.remote_grant(recovery, host, {'repair-test-release.py': source}, self.remote_args(plan), request)
