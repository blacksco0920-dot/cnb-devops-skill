"""Real session files and bundled archive/restore validation; synthetic SSH/Docker only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import test_bundle_host_installer as installer_fixture

SCRIPT = Path(__file__).parents[1] / 'scripts/rehearse-recovery.py'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class LocalDocker:
    """An isolated process boundary; the bundled Postgres/restore code runs normally."""
    def __init__(self):
        self.started = False
        self.volume = None
        self.container = 'e' * 64
        self.bad_data = False
        self.network_mode = 'none'
        self.prefix = ['docker']
        self.environment = {}

    def identity(self):
        return 'f' * 64

    def inspect(self, _reference):
        return {'id': self.container, 'running': self.started}

    def run(self, args, **options):
        if args[:2] == ['context', 'inspect']:
            return b'unix:///synthetic/docker.sock\n'
        if args[0] == 'inspect':
            return canonical({'network_mode': self.network_mode, 'ports': {}, 'networks': {'none': {}},
                              'mounts': [{'Type': 'volume', 'Name': self.volume, 'Destination': '/var/lib/postgresql/data'}]})
        if args[:2] == ['image', 'inspect']:
            return b'{"os":"linux","architecture":"amd64","id":"sha256:abc"}'
        if args[:2] == ['volume', 'ls']:
            return b''
        if args[:2] == ['volume', 'create']:
            self.volume = args[-1]
            return self.volume.encode()
        if args[0] == 'run':
            assert '--network=none' in args and '--pull=never' in args
            self.started = True
            return self.container.encode()
        if args[0] == 'stop':
            self.started = False
            return b''
        if args[0] == 'exec':
            if '/proc/1/comm' in args:
                return b'postgres\n'
            if 'pg_restore' in args:
                assert options['source'].read().startswith(b'PGDMP')
                return b''
            if 'pg_dump' in args:
                return b'synthetic schema\n'
            query = options['data']
            if query == b'SHOW server_version_num;':
                return b'160004\n'
            if query.startswith(b'SELECT COALESCE(json_agg'):
                return b'[{"schema":"public","name":"Orders","kind":"r"}]'
            if query.startswith(b'COPY '):
                options['output'].write((('9' if self.bad_data else 'a') * 64 + '\n').encode())
                return None
            return b'0\n'
        raise AssertionError(args)


class SourceTransport:
    def __init__(self, plan):
        self.plan = plan
        self.exports = 0
        self.downloads = []
        self.fail_download = False
        self.unknown_export = False
        self.pending = False
        self.bad_checksum = False
        self.changed = False
        release = {'status': 'passed', 'git_sha': '1' * 40, 'build_id': 'cnb-build-one',
                   'images': {role: 'registry.invalid/' + role + '@sha256:' + '2' * 64 for role in plan.bundle['host'].SERVICES}}
        self.containers = [{'id': str(index + 3) * 64, 'name': '/' + plan.bundle['host'].CONTAINERS[role], 'image': release['images'][role],
                            'running': True, 'paused': False, 'restarting': False, 'health': 'healthy', 'auto_remove': False}
                           for index, role in enumerate(plan.bundle['host'].SERVICES)]
        self.journal = {'schema': 'cnb-recovery-export-journal/v1', **plan.scope,
                        'source_release_sha256': sha(canonical(release)), 'containers': self.containers}
        model = {'schema': 'cnb-recovery-export/v1', **plan.scope, 'created_at': '2026-09-09T00:00:00Z',
                 'source_release_sha256': sha(canonical(release)), 'source_release': release,
                 'source_docker_id_sha256': '4' * 64,
                 'postgres': {'image': 'registry.invalid/postgres@sha256:' + '5' * 64, 'version_num': 160004, 'database': 'sample'},
                 'files': {'database.dump': {'bytes': 10, 'sha256': sha(b'PGDMP-demo')}},
                 'database': {'schema_sha256': sha(b'synthetic schema\n'), 'tables': [
                     {'schema': 'public', 'name': 'Orders', 'rows': 1, 'sha256': sha(('a' * 64 + '\n').encode())}],
                     'sequences_sha256': sha(b'[]\n')}, 'mounts': {},
                 'scope': {'postgres': True, 'business_mounts': [], 'rebuildable_mounts': [], 'redis': False, 'full_host': False}}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for name, raw in [('manifest.json', canonical(model)), ('database.dump', b'PGDMP-demo')]:
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
        self.archive = output.getvalue()
        self.receipt = {'schema': 'cnb-recovery-export-receipt/v1', 'status': 'exported',
                        'archive_sha256': sha(self.archive), 'manifest_sha256': sha(canonical(model)), 'external_restore_verified': False}
        self.resume = {'schema': 'cnb-recovery-source-resume/v1', 'status': 'resumed', 'journal_sha256': sha(canonical(self.journal))}
        self.snapshot = {'schema': 'cnb-recovery-source-state/v1', 'project': 'sample', 'environment': 'test',
                         'git_sha': '1' * 40, 'build_id': 'cnb-build-one', 'installed_lock_sha256': '8' * 64,
                         'source_release_sha256': model['source_release_sha256'], 'containers': self.containers,
                         'postgres': model['postgres'], 'source_docker_id_sha256': '4' * 64,
                         'public_identity_verified': True, 'pending': False, 'export': None}

    def inspect(self):
        result = copy.deepcopy(self.snapshot)
        result['pending'] = self.pending
        if self.changed:
            result['containers'][0]['id'] = '6' * 64
        if self.exports:
            result['export'] = {'journal': self.journal, 'receipt': self.receipt, 'resumed': None if self.pending else self.resume}
        return result

    def export(self, before):
        self.exports += 1
        if self.unknown_export:
            raise OSError('connection lost after export')
        return self.receipt

    def download(self, name, destination):
        self.downloads.append(name)
        if self.fail_download and name == 'export.tar':
            self.fail_download = False
            raise OSError('synthetic transfer interruption')
        raw = {'export.tar': self.archive, 'export-receipt.json': canonical(self.receipt),
               'source-resumed.json': canonical(self.resume), 'journal.json': canonical(self.journal)}[name]
        if self.bad_checksum and name == 'export.tar':
            raw += b'changed'
        destination.write_bytes(raw)
        destination.chmod(0o600)


class RecoverySessionTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'standard recovery session entry is missing')
        spec = importlib.util.spec_from_file_location('rehearse_recovery_test', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        helper = installer_fixture.HostInstallerTests()
        helper.setUp()
        helper.bundle(self.bundle, recovery=True)
        (self.bundle / 'host/install-project.py').write_bytes(installer_fixture.INSTALLER_PATH.read_bytes())
        lock = json.loads((self.bundle / 'artifact-lock.json').read_bytes())
        lock['files']['host/install-project.py'] = sha(installer_fixture.INSTALLER_PATH.read_bytes())
        (self.bundle / 'artifact-lock.json').write_bytes(canonical(lock))
        for name, value in [('identity', b'synthetic key'), ('known_hosts', b'synthetic known host'),
                            ('accepted.json', canonical({'schema': 'cnb-test-installation/v1', 'lock_sha256': '8' * 64}))]:
            (self.root / name).write_bytes(value)
            (self.root / name).chmod(0o600)
        target = {'host': 'sample.invalid', 'port': 22, 'user': 'root',
                  'identity_file': str(self.root / 'identity'), 'known_hosts_file': str(self.root / 'known_hosts')}
        (self.root / 'target.json').write_bytes(canonical(target))
        (self.root / 'target.json').chmod(0o600)
        self.argv = ['--bundle-dir', str(self.bundle), '--lock-sha256', sha((self.bundle / 'artifact-lock.json').read_bytes()),
                     '--target', str(self.root / 'target.json'), '--accepted-installation', str(self.root / 'accepted.json'),
                     '--git-sha', '1' * 40, '--build-id', 'cnb-build-one', '--export-id', 'exercise-one',
                     '--evidence-dir', str(self.root / 'session')]

    def prepare(self):
        plan = self.m.prepare(self.m.parse_args(self.argv))
        self.docker = LocalDocker()
        self.patch = mock.patch.object(plan.recovery, 'local_docker', return_value=self.docker)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        return plan

    def test_preview_is_offline_and_records_different_accepted_lock(self):
        output = io.StringIO()
        with mock.patch.object(self.m.subprocess, 'run', side_effect=AssertionError('preview ran a process')), contextlib.redirect_stdout(output):
            self.m.main(self.argv)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'preview')
        self.assertEqual(result['installed_lock_sha256'], '8' * 64)
        self.assertNotEqual(result['bundle_lock_sha256'], result['installed_lock_sha256'])
        self.assertFalse((self.root / 'session').exists())

    def test_full_restore_uses_real_bundle_verifier_and_preserves_stopped_volume(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        result = self.m.execute(plan, source)
        self.assertEqual(result['status'], 'verified')
        receipt = json.loads((plan.args.evidence_dir / 'restore/restore-receipt.json').read_bytes())
        self.assertTrue(receipt['all_table_data_equal'])
        self.assertTrue(receipt['external_restore_verified'])
        self.assertFalse(self.docker.started)
        self.assertIsNotNone(self.docker.volume)
        self.assertEqual(source.exports, 1)
        self.assertEqual((plan.args.evidence_dir / 'state.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.m.execute(plan, source)['status'], 'verified')
        self.assertEqual(source.exports, 1)

    def test_download_interruption_resumes_without_exporting_again(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.fail_download = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        result = self.m.execute(plan, source)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(source.exports, 1)

    def test_unknown_export_is_read_back_and_never_repeated(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.unknown_export = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        self.assertEqual(self.m.execute(plan, source)['status'], 'verified')
        self.assertEqual(source.exports, 1)

    def test_unresumed_source_blocks_download_and_restore(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.pending = True
        with self.assertRaisesRegex(self.m.SessionError, 'SOURCE_RESUME_REQUIRED'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 0)
        self.assertEqual(source.downloads, [])

    def test_changed_source_blocks_reuse(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.fail_download = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        source.changed = True
        with self.assertRaisesRegex(self.m.SessionError, 'SOURCE_CHANGED'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 1)

    def test_bad_transfer_never_starts_restore(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.bad_checksum = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        self.assertIsNone(self.docker.volume)

    def test_bundled_data_reconciliation_failure_is_not_success_and_no_retry(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        self.docker.bad_data = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        with self.assertRaisesRegex(self.m.SessionError, 'RESTORE_REVIEW_REQUIRED'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 1)

    def test_tampered_evidence_blocks_reuse(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        self.m.execute(plan, source)
        (plan.args.evidence_dir / 'source-before.json').write_bytes(b'{}')
        with self.assertRaisesRegex(self.m.SessionError, 'EVIDENCE_CHANGED'):
            self.m.execute(plan, source)

    def test_unsafe_target_and_private_file_modes_block_preview(self):
        (self.root / 'accepted.json').chmod(0o644)
        with self.assertRaises(Exception):
            self.m.prepare(self.m.parse_args(self.argv))
        (self.root / 'accepted.json').chmod(0o600)
        target = json.loads((self.root / 'target.json').read_bytes())
        target['host'] = 'host; touch /tmp/bad'
        (self.root / 'target.json').write_bytes(canonical(target))
        with self.assertRaisesRegex(self.m.SessionError, 'TARGET_INVALID'):
            self.m.prepare(self.m.parse_args(self.argv))

    def test_same_source_docker_is_rejected_before_stopping_writers(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.snapshot['source_docker_id_sha256'] = 'f' * 64
        with self.assertRaisesRegex(self.m.SessionError, 'DIFFERENT_DOCKER_REQUIRED'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 0)

    def test_missing_service_in_source_evidence_blocks_export(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.snapshot['containers'] = source.snapshot['containers'][:-1]
        with self.assertRaisesRegex(self.m.SessionError, 'SOURCE_SERVICE_SET_MISMATCH'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 0)

    def test_failed_stage_retains_explicit_resume_position(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.fail_download = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        state = json.loads((plan.args.evidence_dir / 'state.json').read_bytes())
        self.assertEqual(state['resume_stage'], 'download-export.tar')
        self.assertEqual(state['status'], 'stopped_review_required')
        self.assertTrue(state['events'][-1]['finished_at'])

    def test_world_writable_evidence_parent_is_rejected_without_mutation(self):
        parent = self.root / 'unsafe'
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.argv[-1] = str(parent / 'session')
        with self.assertRaisesRegex(self.m.SessionError, 'PRIVATE_DIRECTORY_INVALID'):
            self.m.prepare(self.m.parse_args(self.argv))
        self.assertFalse((parent / 'session').exists())

    def test_flock_excludes_concurrent_run_and_releases_after_exception(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        with self.m.Session(plan):
            with self.assertRaises(BlockingIOError):
                self.m.execute(plan, source)
        self.assertEqual(self.m.execute(plan, source)['status'], 'verified')
        self.assertEqual(source.exports, 1)

    def test_unknown_export_with_no_retained_remote_record_does_not_retry(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.unknown_export = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        source.exports = 0
        with self.assertRaisesRegex(self.m.SessionError, 'EXPORT_RESULT_UNKNOWN'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 0)

    def test_missing_local_image_blocks_before_export(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        old_run = self.docker.run
        def run(args, **options):
            if args[:2] == ['image', 'inspect']:
                raise OSError('missing image')
            return old_run(args, **options)
        self.docker.run = run
        with self.assertRaisesRegex(self.m.SessionError, 'CACHED_POSTGRES_OR_PULL_CONFIG_REQUIRED'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 0)

    def test_ssh_transport_uses_fixed_code_strict_host_key_and_stdin_request(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        def ssh(argv, **options):
            self.assertEqual(argv[0], '/usr/bin/ssh')
            for required in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentityAgent=none', 'PasswordAuthentication=no'):
                self.assertIn(required, argv)
            remote = shlex.split(argv[-1])
            self.assertIn('-I', remote)
            compile(remote[-1], '<fixed-remote-gate>', 'exec')
            request = json.loads(options['input'])
            self.assertEqual(request['action'], 'inspect')
            self.assertEqual(request['scope']['environment'], 'test')
            self.assertEqual(request['installed_lock_sha256'], '8' * 64)
            self.assertNotIn('synthetic key', ' '.join(argv))
            options['stdout'].write(canonical(source.inspect()))
            return subprocess.CompletedProcess(argv, 0)
        with mock.patch.object(self.m.subprocess, 'run', side_effect=ssh):
            result = self.m.SSHTransport(plan).inspect()
        self.assertEqual(result['git_sha'], '1' * 40)

    def test_changed_build_cannot_reuse_export_or_state(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        source.fail_download = True
        with self.assertRaises(Exception):
            self.m.execute(plan, source)
        index = self.argv.index('--build-id')
        self.argv[index + 1] = 'cnb-other-build'
        next_plan = self.prepare()
        with self.assertRaisesRegex(self.m.SessionError, 'SESSION_INPUT_CHANGED'):
            self.m.execute(next_plan, source)
        self.assertEqual(source.exports, 1)

    def test_changed_restore_network_invalidates_success_on_resume(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        self.m.execute(plan, source)
        self.docker.network_mode = 'bridge'
        with self.assertRaisesRegex(self.m.SessionError, 'RESTORE_TARGET_ISOLATION_MISMATCH'):
            self.m.execute(plan, source)
        self.assertEqual(source.exports, 1)

    def test_rehashed_false_restore_receipt_is_not_trusted_as_verified(self):
        plan = self.prepare()
        source = SourceTransport(plan)
        self.m.execute(plan, source)
        path = plan.args.evidence_dir / 'restore/restore-receipt.json'
        receipt = json.loads(path.read_bytes())
        receipt['all_table_data_equal'] = False
        path.write_bytes(canonical(receipt))
        state_path = plan.args.evidence_dir / 'state.json'
        state = json.loads(state_path.read_bytes())
        state['evidence']['restore/restore-receipt.json'] = {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size}
        state_path.write_bytes(canonical(state))
        with self.assertRaisesRegex(self.m.SessionError, 'RESTORE_RECEIPT_MISMATCH'):
            self.m.execute(plan, source)


if __name__ == '__main__':
    unittest.main()
