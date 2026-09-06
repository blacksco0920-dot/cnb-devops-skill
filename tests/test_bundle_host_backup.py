"""Opt-in PostgreSQL 16 archive checks; use a reviewed image already cached locally."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import uuid

from test_bundle_host_policy import load_host, sample_policy


@unittest.skipUnless(os.environ.get('CNB_BUNDLE_TEST_POSTGRES_IMAGE'), 'explicit cached PostgreSQL 16 image required')
class RealPostgres16BackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which('docker')
        if not cls.docker:
            raise unittest.SkipTest('Docker is required')
        image = os.environ['CNB_BUNDLE_TEST_POSTGRES_IMAGE']
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', image):
            raise ValueError('test image must be pinned by digest')
        subprocess.run([cls.docker, 'image', 'inspect', image], check=True, stdout=subprocess.DEVNULL)
        cls.container = 'cnb-backup-test-' + uuid.uuid4().hex[:12]
        created = subprocess.check_output([
            cls.docker, 'run', '--detach', '--rm', '--pull=never', '--platform=linux/amd64',
            '--network=none', '--name', cls.container, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_DB=cnb_backup_test', image,
        ], text=True).strip()
        if not re.fullmatch('[0-9a-f]{64}', created):
            raise ValueError('test container identity missing')
        cls.addClassCleanup(subprocess.run, [cls.docker, 'rm', '--force', created],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        while True:
            ready = subprocess.run([cls.docker, 'exec', cls.container, 'sh', '-ec',
                                    'test "$(cat /proc/1/comm)" = postgres; psql -U postgres -d cnb_backup_test -Atc "SHOW server_version_num"'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('test PostgreSQL did not become ready')
            time.sleep(0.2)
        version = ready.stdout.strip()
        if not version.startswith('16'):
            raise ValueError('test requires PostgreSQL 16')
        cls.archive = subprocess.check_output([cls.docker, 'exec', cls.container, 'pg_dump', '-U', 'postgres',
                                               '--format=custom', '--no-owner', '--no-privileges', 'cnb_backup_test'])

    def setUp(self):
        self.host = load_host()
        policy = sample_policy()
        policy['database'].update(container=self.container, host=self.container, name='cnb_backup_test', admin_user='postgres')
        self.host.configure_policy(policy, policy_sha256='a' * 64)
        # Bind only the local Docker transport; execute real pg_dump/pg_restore unchanged.
        for name, value in [('_docker_prefix', lambda: [self.docker]), ('BASE_ENV', dict(os.environ))]:
            patch = mock.patch.object(self.host, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name).resolve() / 'database.dump'

    def test_valid_empty_database_smaller_than_one_kib_is_backed_up_and_hashed(self):
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            digest = self.host._backup_database_at(fd, 'database.dump', os.getuid(), os.getgid())
        finally:
            os.close(fd)
        raw = self.path.read_bytes()
        self.assertGreater(len(raw), 0)
        self.assertLess(len(raw), 1024, 'fixture must reproduce the first-deployment regression')
        self.assertEqual(raw[:5], b'PGDMP')
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.host._validate_database_dump(self.path)

    def test_corrupt_and_truncated_real_archives_are_rejected(self):
        for raw in [b'BROKEN' + self.archive[6:], self.archive[:64], b'not a PostgreSQL archive']:
            with self.subTest(bytes=len(raw)):
                self.path.write_bytes(raw)
                self.path.chmod(0o600)
                with self.assertRaisesRegex(self.host.DeploymentError, '^database_backup_invalid$'):
                    self.host._validate_database_dump(self.path)

    def test_empty_file_is_rejected(self):
        self.path.touch(mode=0o600)
        with self.assertRaisesRegex(self.host.DeploymentError, '^database_backup_invalid$'):
            self.host._validate_database_dump(self.path)


if __name__ == '__main__':
    unittest.main()
