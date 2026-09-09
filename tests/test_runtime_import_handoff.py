"""Runtime imports must be validated and transported without exposing values."""
import hashlib
import contextlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import tarfile
import unittest
from unittest import mock

import test_setup_host


class RuntimeImportHandoffTests(unittest.TestCase):
    def setUp(self):
        self.host = test_setup_host.SetupHostTests('test_preview_is_offline_and_never_prints_credentials')
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.m = self.host.m
        self.runtime = self.host.root / 'runtime-import.env'
        self.raw = b'MINIMAX_API_KEY=synthetic-key\nINITIAL_ADMIN_PHONE=synthetic-phone\n'
        self.runtime.write_bytes(self.raw)
        self.runtime.chmod(0o600)

    def args(self):
        return SimpleNamespace(bundle_dir=self.host.bundle, lock_sha256=self.host.lock,
                               target=self.host.target, bootstrap_spec=self.host.spec,
                               tcr_docker_config=self.host.config, caddy_baseline_sha256='a' * 64,
                               installed_lock_sha256=None, native_caddy_shared_dir=None,
                               runtime_import=self.runtime)

    def test_exact_runtime_bytes_enter_archive_and_digest_is_bound_for_driver(self):
        _plan, files, expected, _target = self.m.prepare(self.args())
        self.assertEqual(files['runtime-import.env'], self.raw)
        self.assertEqual(expected['runtime_import_sha256'], hashlib.sha256(self.raw).hexdigest())
        archive_raw = self.m.archive_bytes(files)
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:') as archive:
            member = archive.getmember('runtime-import.env')
            self.assertEqual(member.mode, 0o600)
            self.assertEqual(archive.extractfile(member).read(), self.raw)
        driver = test_setup_host.load(self.host.bundle / 'host/setup-project.py')
        accepted = driver.validate_inputs(files, expected)[-1]
        self.assertEqual(accepted, self.raw)
        output = io.StringIO()
        with mock.patch.object(self.m.subprocess, 'run', side_effect=AssertionError('preview opened SSH')), contextlib.redirect_stdout(output):
            self.assertEqual(self.m.main(self.host.args + ['--runtime-import', str(self.runtime)]), 0)
        self.assertNotIn('synthetic-key', output.getvalue())
        self.assertNotIn('synthetic-phone', output.getvalue())

    def test_generated_key_conflict_and_missing_input_stop_before_ssh(self):
        for raw in (b'AUTH_TOKEN_SECRET=caller-value\n', None):
            with self.subTest(raw=raw):
                if raw is None:
                    self.runtime.unlink(missing_ok=True)
                else:
                    self.runtime.write_bytes(raw)
                with mock.patch.object(self.m.subprocess, 'run', side_effect=AssertionError('invalid runtime import opened SSH')):
                    with self.assertRaises(self.m.SetupError):
                        self.m.main(self.host.args + ['--runtime-import', str(self.runtime), '--apply'])

    def test_same_input_repeats_same_digest_and_driver_rejects_digest_mismatch(self):
        _plan, files, first, _target = self.m.prepare(self.args())
        _plan, _files, second, _target = self.m.prepare(self.args())
        self.assertEqual(first['runtime_import_sha256'], second['runtime_import_sha256'])
        bad = dict(first, runtime_import_sha256='0' * 64)
        driver = test_setup_host.load(self.host.bundle / 'host/setup-project.py')
        with self.assertRaisesRegex(driver.SetupError, 'SETUP_RUNTIME_IMPORT_DRIFT'):
            driver.validate_inputs(files, bad)

    def test_installed_retry_only_accepts_values_already_in_runtime(self):
        driver = test_setup_host.load(self.host.bundle / 'host/setup-project.py')
        actual = self.raw + b'GENERATED_SECRET=generated-value\n'
        driver.validate_installed_runtime_import(self.raw, actual)
        for changed in (actual.replace(b'synthetic-key', b'changed-key'), b'GENERATED_SECRET=generated-value\n'):
            with self.assertRaisesRegex(driver.SetupError, 'SETUP_RUNTIME_IMPORT_ALREADY_INSTALLED'):
                driver.validate_installed_runtime_import(self.raw, changed)

    def test_materialize_cleans_only_an_exact_interrupted_runtime_import(self):
        driver = test_setup_host.load(self.host.bundle / 'host/setup-project.py')
        installer = test_setup_host.load(self.host.bundle / 'host/install-project.py')
        task = self.host.root / 'interrupted-setup'
        task.mkdir(mode=0o700)
        residual = task / 'runtime-import.env'
        residual.write_bytes(self.raw)
        residual.chmod(0o600)
        actual_dir = installer.ensure_directory
        with mock.patch.object(installer, 'ensure_directory',
                               side_effect=lambda p, mode, _u, _g: actual_dir(p, mode, os.getuid(), os.getgid())), \
             mock.patch.object(driver, 'existing_private', side_effect=lambda p, _i: installer.read_file(p)):
            driver.materialize(task, {}, installer, {'runtime-import.env': self.raw})
            self.assertFalse(residual.exists())

            different = b'MINIMAX_API_KEY=different\n'
            residual.write_bytes(different)
            residual.chmod(0o600)
            with self.assertRaisesRegex(driver.SetupError, 'SETUP_STAGED_INPUT_DRIFT'):
                driver.materialize(task, {}, installer, {'runtime-import.env': self.raw})
            self.assertEqual(residual.read_bytes(), different)


if __name__ == '__main__':
    unittest.main()
