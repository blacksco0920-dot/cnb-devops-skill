"""Production authorization must run under the ordinary release lock, before mutation."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_bundle_host_policy import load_host, sample_policy


class ProductionCoreTests(unittest.TestCase):
    def setUp(self):
        self.host = load_host()
        self.policy = json.loads(json.dumps(sample_policy()).replace('-test', '-production')
                                 .replace('/test/', '/production/').replace('_test', '_production'))
        self.policy['environment'] = 'production'
        self.host.configure_policy(self.policy, policy_sha256='b' * 64)
        self.request = {'schema': 'cnb-release-request/v1', 'project': 'sample',
                        'environment': 'production', 'controller': self.policy['controller_id'],
                        'git_sha': 'c' * 40, 'controller_commit': 'c' * 40, 'build_id': 'cnb-prod-123',
                        'images': {name: item['image_repository'] + '@sha256:' + 'd' * 64
                                   for name, item in self.policy['services'].items()}}

    def test_environment_scope_uses_separate_lock_and_paths(self):
        self.assertEqual(self.host.PROJECT, 'sample-production')
        self.assertEqual(self.host.LOCK_PATH, Path('/opt/apps/.sample-production.deploy.lock'))
        self.assertEqual(self.host.APP_DIR, Path('/opt/apps/sample-production'))

    def test_unsigned_production_stops_before_argument_or_file_access(self):
        with mock.patch.object(self.host, '_arguments') as arguments, mock.patch.object(self.host.os, 'open') as opened:
            with self.assertRaisesRegex(self.host.DeploymentError, 'production_authorization_required'):
                self.host.deploy([])
            arguments.assert_not_called()
            opened.assert_not_called()

    def test_override_does_not_allow_cross_environment_or_changed_commit(self):
        for field, value in [('environment', 'test'), ('controller_commit', 'e' * 40)]:
            request = {**self.request, field: value}
            with mock.patch.object(self.host.os, 'open') as opened:
                with self.assertRaisesRegex(self.host.DeploymentError, 'release_request_invalid'):
                    self.host.deploy(release_override=request, authorize_locked=lambda _: None)
                opened.assert_not_called()

    def test_authorization_is_under_lock_and_precedes_candidate_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'release.lock'
            visited = []

            def authorize(model):
                self.assertEqual(model, self.request)
                with lock_path.open('rb') as second:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(second.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                visited.append(True)
                raise self.host.DeploymentError('approval_rejected')

            with mock.patch.object(self.host, 'LOCK_PATH', lock_path), \
                 mock.patch.object(self.host, '_read_controller_compose', return_value=b'compose'), \
                 mock.patch.object(self.host, 'controller_program_sha256', return_value='f' * 64), \
                 mock.patch.object(self.host, '_assert_release_unblocked'), \
                 mock.patch.object(self.host, '_regular_file') as checked, \
                 mock.patch.object(self.host, '_write_new') as written, \
                 mock.patch.object(self.host, 'create_release_snapshot') as backup, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                result = self.host.deploy(release_override=self.request, authorize_locked=authorize)
            self.assertEqual(result, 1)
            self.assertEqual(visited, [True])
            checked.assert_not_called()
            written.assert_not_called()
            backup.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())['reason'], 'approval_rejected')

    def test_cached_success_is_exact_and_never_starts_a_second_transaction(self):
        host = self.host
        receipt = {'schema': 'cnb-deploy-result/v1', 'status': 'passed', 'project': 'sample',
                   'environment': 'production', 'controller': host.CONTROLLER_ID,
                   'git_sha': self.request['git_sha'], 'controller_commit': self.request['controller_commit'],
                   'build_id': self.request['build_id'], 'images': self.request['images'],
                   'controller_program_sha256': 'f' * 64, 'controller_compose_sha256': host.CONTROLLER_COMPOSE_SHA256,
                   'policy_sha256': host.POLICY_SHA256, 'container_count': len(host.SERVICES),
                   'probe_count': len(host.PUBLIC_PROBES), 'probes': list(host.PUBLIC_PROBES),
                   'database_backup_sha256': '1' * 64}
        for changes in [{}, {'build_id': 'cnb-other-123'}, {'database_backup_sha256': 'bad'}, {'unexpected': True}]:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(host, 'LOCK_PATH', Path(directory) / 'release.lock'), \
                 mock.patch.object(host, '_read_controller_compose', return_value=b'compose'), \
                 mock.patch.object(host, 'controller_program_sha256', return_value='f' * 64), \
                 mock.patch.object(host, '_assert_release_unblocked'), \
                 mock.patch.object(host, '_regular_file') as checked, \
                 mock.patch.object(host, '_write_new') as written, \
                 mock.patch.object(host, 'create_release_snapshot') as backup, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                result = host.deploy(release_override=self.request, authorize_locked=lambda _: {**receipt, **changes})
                self.assertEqual(result, 1 if changes else 0)
                checked.assert_not_called()
                written.assert_not_called()
                backup.assert_not_called()
                if not changes:
                    self.assertEqual(json.loads(output.getvalue()), receipt)
                else:
                    self.assertEqual(json.loads(output.getvalue())['reason'], 'production_cached_receipt_invalid')


if __name__ == '__main__':
    unittest.main()
