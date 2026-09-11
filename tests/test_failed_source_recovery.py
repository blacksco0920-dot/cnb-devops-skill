"""A failed test release may be preserved, never accepted or silently replaced."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_bundle_host_policy import load_host, sample_policy
from test_rehearse_recovery import LocalDocker


class FailedSourceTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parents[1] / 'assets/cnb-tcr-tat/host/recover-project.py'
        spec = importlib.util.spec_from_file_location('failed_source_recovery', path)
        self.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.r)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.host = load_host()
        policy = sample_policy(('api',))
        policy['services']['api']['environment_refs'] = {'DATABASE_URL': 'DATABASE_URL'}
        self.host.configure_policy(policy, policy_sha256='b' * 64)
        self.host.APP_DIR = self.root
        self.host.ENV_PATH = self.root / '.env'
        self.host.COMPOSE_PATH = self.root / 'docker-compose.yml'
        self.host.RELEASE_PATH = self.root / '.release.json'
        self.host.TRANSACTION_PATH = self.root / '.release.transaction.json'
        self.host.RECOVERY_STATE_DIR = self.root / 'recovery'
        self.host.RECOVERY_STATE_DIR.mkdir(mode=0o700)
        self.host.RECOVERY_TRANSACTION_PATH = self.host.RECOVERY_STATE_DIR / 'pending.json'
        self.host.CONTROLLER_COMPOSE_PATH = self.root / 'controller.yml'
        compose = b'services: {}\n'
        self.host.CONTROLLER_COMPOSE_SHA256 = self.r.sha(compose)
        self.host.POLICY['compose_sha256'] = self.r.sha(compose)
        self.host.COMPOSE_PATH.write_bytes(compose)
        self.host.CONTROLLER_COMPOSE_PATH.write_bytes(compose)
        self.images = {'api': policy['services']['api']['image_repository'] + '@sha256:' + '1' * 64}
        self.env = b'SAMPLE_API_IMAGE=old\nDATABASE_URL=postgresql://synthetic@project-postgres/sample_test\n'
        self.host.ENV_PATH.write_bytes(self.host.update_env_text(self.env.decode(), self.images).encode())
        self.host.ENV_PATH.chmod(0o600)
        self.baseline = {'schema': self.host.EMPTY_BASELINE_SCHEMA, 'status': 'empty', 'images': {},
                         'project': 'sample', 'environment': 'test', 'controller': self.host.CONTROLLER_ID,
                         'policy_sha256': self.host.POLICY_SHA256, 'database': policy['database'],
                         'runtime_env_sha256': self.r.sha(self.env), 'controller_compose_sha256': self.r.sha(compose),
                         'created_at': '2026-09-09T00:00:00Z'}
        self.baseline_raw = self.r.canonical(self.baseline)
        self.host.RELEASE_PATH.write_bytes(self.baseline_raw)
        self.host.RELEASE_PATH.chmod(0o600)
        patch = mock.patch.object(self.host, '_installed_empty_baseline', return_value=(self.baseline, self.r.sha(self.baseline_raw)))
        patch.start()
        self.addCleanup(patch.stop)
        releases = self.root / 'backups' / 'releases'
        releases.mkdir(parents=True, mode=0o700)
        def backup(fd, name, uid, gid):
            raw = b'PGDMP-synthetic'
            self.host._write_new_at(fd, name, raw, 0o600, uid, gid)
            return self.r.sha(raw)
        with mock.patch.object(self.host, '_backup_database_at', side_effect=backup):
            snap = self.host.create_release_snapshot(releases, env_bytes=self.env, compose_bytes=compose,
                    git_sha='2' * 40, build_id='cnb-failed-one', created_at='2026-09-09T00:00:00Z',
                    uid=os.getuid(), gid=os.getgid())
        patch = mock.patch.object(self.host, '_validate_database_dump_descriptor', return_value=None)
        patch.start()
        self.addCleanup(patch.stop)
        self.transaction = {'schema': self.host.TRANSACTION_SCHEMA_V2, 'status': 'failed', 'phase': 'probe',
                'reason': 'public_probe_failed', 'controller': self.host.CONTROLLER_ID,
                'controller_program_sha256': '3' * 64, 'controller_compose_sha256': self.r.sha(compose),
                'git_sha': '2' * 40, 'build_id': 'cnb-failed-one', 'images': self.images, 'previous_images': {},
                'previous_release_sha256': self.r.sha(self.baseline_raw), 'snapshot': snap.name,
                'snapshot_manifest_sha256': snap.manifest_sha256, 'updated_at': '2026-09-09T00:01:00Z'}
        self.write_transaction()
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.original = {'id': '4' * 64, 'name': '/sample-test-api', 'image': self.images['api'],
                         'running': True, 'paused': False, 'restarting': False, 'health': 'healthy', 'auto_remove': False}
        self.args = SimpleNamespace(project='sample', environment='test', export_id='failed-preservation',
                policy_sha256='b' * 64, controller_sha256='3' * 64, recovery_policy_sha256='5' * 64,
                failed_transaction_sha256=self.digest)

    def write_transaction(self):
        self.raw = self.r.canonical(self.transaction)
        self.digest = self.r.sha(self.raw)
        self.host.TRANSACTION_PATH.write_bytes(self.raw)
        self.host.TRANSACTION_PATH.chmod(0o600)

    def test_explicit_exact_failed_source_preserves_real_failed_status(self):
        self.assertTrue(hasattr(self.r, 'source_record'), 'failed-source opt-in is missing')
        raw, record = self.r.source_record(self.host, self.account, self.digest)
        self.assertEqual(raw, self.raw)
        self.assertEqual(record['status'], 'failed')
        self.assertEqual(record['previous_release_sha256'], self.r.sha(self.baseline_raw))
        with self.assertRaises(self.r.RecoveryError):
            self.r.source_record(self.host, self.account)
        self.assertEqual(self.host.TRANSACTION_PATH.read_bytes(), self.raw)

    def test_changed_hash_phase_baseline_environment_and_production_are_refused(self):
        self.assertTrue(hasattr(self.r, 'source_record'), 'failed-source opt-in is missing')
        with self.assertRaises(self.r.RecoveryError):
            self.r.source_record(self.host, self.account, 'f' * 64)
        for phase in ('prepared', 'migration_complete', 'starting_runtime'):
            with self.subTest(phase=phase):
                self.transaction['phase'] = phase
                self.write_transaction()
                with self.assertRaises(self.r.RecoveryError):
                    self.r.source_record(self.host, self.account, self.digest)
        self.transaction['phase'] = 'probe'
        self.write_transaction()
        current = self.host.ENV_PATH.read_bytes()
        self.host.ENV_PATH.write_bytes(current.replace(b'synthetic', b'changed'))
        with self.assertRaises(self.r.RecoveryError):
            self.r.source_record(self.host, self.account, self.digest)
        self.host.ENV_PATH.write_bytes(current)
        self.transaction['previous_release_sha256'] = 'f' * 64
        self.write_transaction()
        with self.assertRaises(Exception):
            self.r.source_record(self.host, self.account, self.digest)
        self.host.POLICY['environment'] = 'production'
        with self.assertRaises(self.r.RecoveryError):
            self.r.source_record(self.host, self.account, self.digest)

    def test_failed_resume_restarts_exact_original_id_and_retains_application_marker(self):
        self.assertTrue(hasattr(self.r, 'source_record'), 'failed-source opt-in is missing')
        marker = self.r.canonical(self.r.journal_identity(self.args, self.digest, [self.original], self.transaction))
        self.host.RECOVERY_TRANSACTION_PATH.write_bytes(marker)
        (self.root / 'journal.json').write_bytes(marker)
        state = {**self.original, 'running': False}
        owner = self
        class Docker:
            def inspect(self, reference):
                owner.assertIn(reference, (state['id'], 'sample-test-api'))
                return dict(state)
            def run(self, args, **kwargs):
                if args[:2] == ['image', 'inspect']:
                    return b'[]\n'
                if args[0] == 'inspect':
                    owner.assertEqual(args[-1], state['id'])
                    return owner.r.canonical(['DATABASE_URL=postgresql://synthetic@project-postgres/sample_test'])
                owner.assertEqual(args, ['start', state['id']])
                state['running'] = True
                return b''
        with mock.patch.object(self.r, 'root_read', lambda p, mode: p.read_bytes()), \
             mock.patch.object(self.r, 'export_directory', return_value=self.root):
            result = self.r.resume_source(self.args, self.host, Docker(), self.account)
        self.assertTrue(state['running'])
        self.assertFalse(self.host.RECOVERY_TRANSACTION_PATH.exists())
        self.assertEqual(self.host.TRANSACTION_PATH.read_bytes(), self.raw)
        self.assertEqual(result['schema'], 'cnb-recovery-source-resume/v2')
        self.assertFalse(result['public_identity_verified'])

    def test_failed_runtime_rejects_changed_container_environment_and_stopped_source(self):
        self.assertTrue(hasattr(self.r, 'validate_failed_runtime'), 'runtime source checks are missing')
        class Docker:
            def run(self, args, **kwargs):
                return b'["DATABASE_URL=changed"]\n'
        with self.assertRaisesRegex(self.r.RecoveryError, 'source_runtime_environment_mismatch'):
            self.r.validate_failed_runtime(self.host, Docker(), self.transaction, [self.original])
        with self.assertRaisesRegex(self.r.RecoveryError, 'source_unhealthy'):
            self.r.validate_failed_runtime(self.host, Docker(), self.transaction, [{**self.original, 'running': False}])

    def test_failed_runtime_rejects_an_undeclared_image_environment_override(self):
        class Docker:
            def run(self, args, **kwargs):
                if args[:2] == ['image', 'inspect']:
                    return b'["PATH=/usr/bin"]\n'
                return b'["DATABASE_URL=postgresql://synthetic@project-postgres/sample_test","PATH=/tmp/unreviewed"]\n'
        with self.assertRaisesRegex(self.r.RecoveryError, 'source_runtime_environment_mismatch'):
            self.r.validate_failed_runtime(self.host, Docker(), self.transaction, [self.original])

    def test_policy_healthcheck_cannot_be_replaced_by_missing_health_state(self):
        self.host.POLICY['services']['api']['healthcheck'] = True
        class Docker:
            def run(self, args, **kwargs):
                if args[:2] == ['image', 'inspect']:
                    return b'[]\n'
                return b'["DATABASE_URL=postgresql://synthetic@project-postgres/sample_test"]\n'
        with self.assertRaisesRegex(self.r.RecoveryError, 'source_unhealthy'):
            self.r.validate_failed_runtime(self.host, Docker(), self.transaction, [{**self.original, 'health': None}])

    def test_failed_export_reconciles_empty_database_and_uploads_on_isolated_daemon(self):
        owner = self
        state = dict(self.original)
        pg_image = 'registry.invalid/postgres@sha256:' + '8' * 64
        uploads = self.root / 'uploads'
        uploads.mkdir()
        (uploads / 'proof.bin').write_bytes(b'\x00synthetic business upload\xff')
        (uploads / 'proof.bin').chmod(0o640)
        self.host.POLICY['services']['api']['mounts'] = [{'source': str(uploads), 'target': '/app/uploads'}]
        self.host.RECOVERY_ROOT = self.host.RECOVERY_STATE_DIR
        self.args.apply = True
        recovery = {'mounts': {'uploads': 'backup'},
                    'required_nonempty_tables': [{'schema': 'public', 'name': 'Orders', 'minimum_rows': 1}]}
        class EmptyDocker(LocalDocker):
            def run(self, args, **kwargs):
                if args[0] == 'exec' and kwargs.get('data', b'').startswith(b'SELECT COALESCE(json_agg'):
                    return b'[]\n'
                return super().run(args, **kwargs)
        class SourceDocker(EmptyDocker):
            def identity(self):
                return '9' * 64
            def inspect(self, reference):
                if reference == owner.host.POLICY['database']['container']:
                    return {'id': 'a' * 64, 'running': True, 'image': pg_image}
                owner.assertIn(reference, (state['id'], 'sample-test-api'))
                return dict(state)
            def run(self, args, **kwargs):
                if args[:2] == ['image', 'inspect']:
                    return b'[]\n'
                if args[0] == 'inspect':
                    owner.assertEqual(args[-1], state['id'])
                    if '.Config.Env' in args[-2]:
                        return owner.r.canonical(['DATABASE_URL=postgresql://synthetic@project-postgres/sample_test'])
                    return owner.r.canonical([{'Type': 'bind', 'Source': str(uploads), 'Destination': '/app/uploads'}])
                if args[0] in ('stop', 'start'):
                    owner.assertEqual(args[-1], state['id'])
                    state['running'] = args[0] == 'start'
                    return b''
                if 'pg_dump' in args and '--format=custom' in args:
                    kwargs['output'].write(b'PGDMP-demo')
                    return None
                return super().run(args, **kwargs)
        source = SourceDocker()
        output = self.root / 'export'
        def root_directory(path, mode=0o755):
            path.mkdir(exist_ok=True, parents=True)
        with mock.patch.object(self.r, 'root_read', lambda p, mode: p.read_bytes()), \
             mock.patch.object(self.r, 'root_directory', root_directory), \
             mock.patch.object(self.r, 'export_directory', return_value=output):
            receipt = self.r.export_source(self.args, self.host, recovery, source, self.account)
        self.assertEqual(receipt['schema'], 'cnb-recovery-export-receipt/v2')
        self.assertTrue(state['running'])
        self.assertEqual(self.host.TRANSACTION_PATH.read_bytes(), self.raw)
        self.assertEqual(self.host.RELEASE_PATH.read_bytes(), self.baseline_raw)
        self.assertFalse(self.host.RECOVERY_TRANSACTION_PATH.exists())
        target = EmptyDocker()
        restore = SimpleNamespace(archive=str(output / 'export.tar'), archive_sha256=receipt['archive_sha256'],
                manifest_sha256=receipt['manifest_sha256'], destination=str(self.root / 'restored'), apply=True)
        with mock.patch.object(self.r, 'local_docker', return_value=target):
            result = self.r.restore_local(restore)
        self.assertTrue(result['all_table_data_equal'])
        self.assertTrue(result['sequences_equal'])
        self.assertTrue(result['business_files_equal'])
        self.assertFalse(result['business_acceptance_verified'])
        self.assertFalse(result['public_identity_verified'])
        self.assertNotEqual(result['source_docker_id_sha256'], result['target_docker_id_sha256'])
        self.assertEqual((self.root / 'restored/business/uploads/proof.bin').read_bytes(), b'\x00synthetic business upload\xff')
        self.assertFalse(target.started)
