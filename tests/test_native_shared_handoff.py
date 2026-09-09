"""A shared-host preview must bind actual local evidence before opening SSH."""
import hashlib
import io
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest import mock

import test_setup_host

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/setup-host.py'


class NativeSharedHandoffTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('shared_handoff_setup', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.target = self.root / 'target.json'
        self.target.write_bytes(b'{"host":"synthetic.example.test"}\n')
        self.target.chmod(0o600)
        target_sha = self.m.sha(self.target.read_bytes())
        self.plan = {'policy': {'project': 'sample', 'environment': 'test'}}
        self.inventory = {'schema': 'cnb-native-caddy-inventory/v1', 'status': 'verified', 'sites': []}
        inventory_sha = self.m.sha(self.canonical(self.inventory))
        self.models = {
            'inventory.json': self.inventory,
            'maintenance-authorization.json': {
                'schema': 'cnb-native-caddy-maintenance-authorization/v1', 'status': 'authorized',
                'project': 'sample', 'environment': 'test', 'source_target_sha256': target_sha,
                'inventory_sha256': inventory_sha, 'scope': ['preserve-existing', 'add-project-static-routes'],
                'authorization_source': 'Synthetic explicit shared-host test authorization'},
            'gateway-recovery-receipt.json': {
                'schema': 'cnb-native-caddy-recovery/v1', 'status': 'verified',
                'source_target_sha256': target_sha, 'source_inventory_sha256': inventory_sha,
                'source_unchanged': True, 'config_restored': True, 'tls_restored': True, 'isolated': True},
            'credential-review-receipt.json': {
                'schema': 'cnb-native-caddy-credential-review/v1', 'status': 'reviewed',
                'source_target_sha256': target_sha, 'inventory_sha256': inventory_sha,
                'unresolved': [], 'evidence': ['synthetic protected credential review']}}
        self.save()

    def canonical(self, value):
        return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

    def save(self):
        for name, value in self.models.items():
            path = self.root / name
            path.write_bytes(self.canonical(value))
            path.chmod(0o600)
        shared = {'schema': 'cnb-native-caddy-shared-input/v1',
                  'inventory_sha256': self.m.sha(self.canonical(self.inventory))}
        for field, name in [('maintenance_authorization_sha256', 'maintenance-authorization.json'),
                            ('gateway_recovery_receipt_sha256', 'gateway-recovery-receipt.json'),
                            ('credential_review_receipt_sha256', 'credential-review-receipt.json')]:
            shared[field] = self.m.sha((self.root / name).read_bytes())
        self.shared_raw = self.canonical(shared)
        path = self.root / 'native-caddy-shared-input.json'
        path.write_bytes(self.shared_raw)
        path.chmod(0o600)

    def test_only_bound_value_free_input_is_returned(self):
        self.assertEqual(self.m.native_shared_input(self.root, self.plan, self.target), self.shared_raw)

    def test_matching_hash_does_not_replace_required_success_or_target_scope(self):
        for name, key, bad in [('gateway-recovery-receipt.json', 'tls_restored', False),
                               ('gateway-recovery-receipt.json', 'source_target_sha256', '0' * 64),
                               ('maintenance-authorization.json', 'environment', 'production'),
                               ('credential-review-receipt.json', 'unresolved', ['exposed credential'])]:
            old = self.models[name][key]
            self.models[name][key] = bad
            self.save()
            with self.assertRaisesRegex(self.m.SetupError, 'SETUP_NATIVE_SHARED_EVIDENCE_INVALID'):
                self.m.native_shared_input(self.root, self.plan, self.target)
            self.models[name][key] = old

    def test_missing_or_changed_evidence_is_not_accepted(self):
        path = self.root / 'gateway-recovery-receipt.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(self.m.SetupError):
            self.m.native_shared_input(self.root, self.plan, self.target)
        path.unlink()
        with self.assertRaises(self.m.SetupError):
            self.m.native_shared_input(self.root, self.plan, self.target)


class NativeSharedArchiveHandoffTests(unittest.TestCase):
    def setUp(self):
        self.host = test_setup_host.SetupHostTests('test_preview_is_offline_and_never_prints_credentials')
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.m = self.host.m
        self.shared_dir, self.shared_raw = self.host.native_shared_directory()

    def args(self):
        return SimpleNamespace(bundle_dir=self.host.bundle, lock_sha256=self.host.lock,
                               target=self.host.target, bootstrap_spec=self.host.spec,
                               tcr_docker_config=self.host.config, caddy_baseline_sha256='a' * 64,
                               installed_lock_sha256=None, native_caddy_shared_dir=self.shared_dir)

    def test_prepare_archives_exact_shared_bytes_and_binds_expected_digest_for_driver(self):
        _plan, files, expected, _target = self.m.prepare(self.args())
        self.assertEqual(files['native-caddy-shared-input.json'], self.shared_raw)
        self.assertEqual(expected['native_caddy_shared_sha256'], hashlib.sha256(self.shared_raw).hexdigest())
        archive_raw = self.m.archive_bytes(files)
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:') as archive:
            member = archive.getmember('native-caddy-shared-input.json')
            self.assertEqual(member.mode, 0o600)
            self.assertEqual(archive.extractfile(member).read(), self.shared_raw)
        driver = test_setup_host.load(self.host.bundle / 'host/setup-project.py')
        _policy, _spec, _installer, _bootstrap, _caddy, accepted, _runtime = driver.validate_inputs(files, expected)
        self.assertEqual(accepted, self.shared_raw)

    def test_missing_evidence_or_target_mismatch_stops_before_server_contact(self):
        for mutate in ('missing', 'target'):
            with self.subTest(mutate=mutate):
                if mutate == 'missing':
                    path = self.shared_dir / 'gateway-recovery-receipt.json'
                    original = path.read_bytes()
                    path.unlink()
                else:
                    original = self.host.target.read_bytes()
                    self.host.target.write_bytes(original + b' ')
                try:
                    with mock.patch.object(self.m.subprocess, 'run', side_effect=AssertionError('invalid handoff contacted server')):
                        with self.assertRaisesRegex(self.m.SetupError, 'SETUP_NATIVE_SHARED_EVIDENCE_INVALID'):
                            self.m.main(self.host.args + ['--native-caddy-shared-dir', str(self.shared_dir), '--apply'])
                finally:
                    if mutate == 'missing':
                        path.write_bytes(original)
                        path.chmod(0o600)
                    else:
                        self.host.target.write_bytes(original)
