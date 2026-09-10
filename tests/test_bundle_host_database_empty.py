"""Real PostgreSQL 16 empty-baseline checks using an explicitly selected cached pgvector image."""
import os
import re
import shutil
import subprocess
import time
import unittest
from unittest import mock
import uuid

from test_bundle_host_policy import load_host, sample_policy


@unittest.skipUnless(os.environ.get('CNB_BUNDLE_TEST_PGVECTOR_IMAGE'), 'explicit cached PostgreSQL 16 pgvector image required')
class RealPostgres16EmptyDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which('docker')
        if not cls.docker:
            raise unittest.SkipTest('Docker is required')
        image = os.environ['CNB_BUNDLE_TEST_PGVECTOR_IMAGE']
        if not re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', image):
            raise ValueError('test image must be pinned by digest')
        subprocess.run([cls.docker, 'image', 'inspect', image], check=True, stdout=subprocess.DEVNULL)
        cls.container = 'cnb-empty-db-test-' + uuid.uuid4().hex[:12]
        created = subprocess.check_output([
            cls.docker, 'run', '--detach', '--rm', '--pull=never', '--platform=linux/amd64',
            '--network=none', '--name', cls.container,
            '--tmpfs', '/var/lib/postgresql/data', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', image,
        ], text=True).strip()
        if not re.fullmatch('[0-9a-f]{64}', created):
            raise ValueError('test container identity missing')
        cls.addClassCleanup(subprocess.run, [cls.docker, 'rm', '--force', created],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 45
        while True:
            ready = subprocess.run([cls.docker, 'exec', cls.container, 'sh', '-ec',
                                    'test "$(cat /proc/1/comm)" = postgres; psql -U postgres -Atc "SHOW server_version_num"'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('test PostgreSQL did not become ready')
            time.sleep(0.2)
        if not ready.stdout.strip().startswith('16'):
            raise ValueError('test requires PostgreSQL 16')

    def setUp(self):
        self.database = 'empty_check_' + uuid.uuid4().hex[:12]
        self.sql('CREATE DATABASE ' + self.database, database='postgres')
        self.host = load_host()
        policy = sample_policy()
        policy['database'].update(container=self.container, host=self.container, name=self.database)
        self.host.configure_policy(policy, policy_sha256='a' * 64)
        # Only the local transport differs; run the controller's actual SQL through real psql.
        for name, value in [('_docker_prefix', lambda: [self.docker]), ('BASE_ENV', dict(os.environ))]:
            patch = mock.patch.object(self.host, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def sql(self, sql, database=None):
        return subprocess.check_output([self.docker, 'exec', self.container, 'psql', '--no-psqlrc',
            '-U', 'postgres', '-d', database or self.database, '-At', '--set', 'ON_ERROR_STOP=1', '-c', sql])

    def test_empty_database_without_extensions_passes(self):
        self.host._assert_database_empty()

    def test_only_public_vector_and_its_automatic_array_types_pass(self):
        self.sql('CREATE EXTENSION vector WITH SCHEMA public')
        self.host._assert_database_empty()

    def test_application_objects_still_block_with_vector_installed(self):
        self.sql('CREATE EXTENSION vector WITH SCHEMA public')
        cases = [
            ('table', 'CREATE TABLE business_items (embedding vector(3))', 'DROP TABLE business_items'),
            ('function', "CREATE FUNCTION business_score(vector) RETURNS integer LANGUAGE sql AS 'SELECT 1'", 'DROP FUNCTION business_score(vector)'),
            ('domain', 'CREATE DOMAIN business_vector AS vector(3)', 'DROP DOMAIN business_vector'),
            ('type', "CREATE TYPE business_state AS ENUM ('new')", 'DROP TYPE business_state'),
            ('schema', 'CREATE SCHEMA business_data', 'DROP SCHEMA business_data'),
            ('auto_extension_dependency', "CREATE FUNCTION business_score(vector) RETURNS integer LANGUAGE sql AS 'SELECT 1'; ALTER FUNCTION business_score(vector) DEPENDS ON EXTENSION vector", 'DROP FUNCTION business_score(vector)'),
        ]
        for kind, create, drop in cases:
            with self.subTest(kind=kind):
                self.sql(create)
                with self.assertRaisesRegex(self.host.DeploymentError, '^bootstrap_database_not_empty$'):
                    self.host._assert_database_empty()
                self.sql(drop)
                self.host._assert_database_empty()

    def test_other_public_extension_is_not_ignored(self):
        self.sql('CREATE EXTENSION vector WITH SCHEMA public; CREATE EXTENSION hstore WITH SCHEMA public')
        with self.assertRaisesRegex(self.host.DeploymentError, '^bootstrap_database_not_empty$'):
            self.host._assert_database_empty()

    def test_vector_in_application_schema_is_not_ignored(self):
        self.sql('CREATE SCHEMA business_data; CREATE EXTENSION vector WITH SCHEMA business_data')
        with self.assertRaisesRegex(self.host.DeploymentError, '^bootstrap_database_not_empty$'):
            self.host._assert_database_empty()


if __name__ == '__main__':
    unittest.main()
