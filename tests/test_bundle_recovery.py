"""Recovery checks use real files and opt-in cached PostgreSQL 16 containers."""
import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock
import test_bundle_host_backup as backup_fixture
import shutil

SCRIPT = Path(__file__).parents[1] / 'assets/cnb-tcr-tat/host/recover-project.py'


class RecoveryFilesTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'the approved recovery interface is missing')
        spec = importlib.util.spec_from_file_location('recovery', SCRIPT)
        self.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.r)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_business_tree_restores_bytes_modes_and_empty_directories(self):
        source = self.root / 'uploads'
        source.mkdir()
        (source / 'empty').mkdir(mode=0o750)
        (source / 'receipt.bin').write_bytes(b'\x00private synthetic upload\xff')
        (source / 'receipt.bin').chmod(0o640)
        archive = self.root / 'uploads.tar'
        expected = self.r.pack_tree(source, archive)
        target = self.root / 'restored'
        self.r.restore_tree(archive, target)
        self.assertEqual((target / 'receipt.bin').read_bytes(), b'\x00private synthetic upload\xff')
        self.assertEqual((target / 'receipt.bin').stat().st_mode & 0o777, 0o640)
        self.assertTrue((target / 'empty').is_dir())
        self.assertEqual(self.r.tree_fingerprint(target), expected)

    def test_symlink_is_not_exported_as_business_data(self):
        source = self.root / 'uploads'
        source.mkdir()
        (source / 'outside').symlink_to('/etc/passwd')
        with self.assertRaises(self.r.RecoveryError):
            self.r.pack_tree(source, self.root / 'bad.tar')

    def test_tar_traversal_rejected_without_writing_outside_target(self):
        archive = self.root / 'bad.tar'
        with tarfile.open(archive, 'w') as tar:
            info = tarfile.TarInfo('../outside')
            tar.addfile(info)
        with self.assertRaises(self.r.RecoveryError):
            self.r.restore_tree(archive, self.root / 'restored')
        self.assertFalse((self.root / 'outside').exists())

    def test_policy_requires_every_mount_and_business_nonempty_requirement(self):
        host = {'project': 'demo', 'environment': 'production', 'app_dir': '/opt/apps/demo-production',
                'services': {'api': {'mounts': [{'source': '/opt/apps/demo-production/uploads'}]},
                             'ocr': {'mounts': [{'source': '/opt/apps/demo-production/models'}]}}}
        policy = {'schema': 'cnb-recovery-policy/v1', 'project': 'demo', 'environment': 'production',
                  'host_policy_sha256': 'a' * 64, 'mounts': {'uploads': 'backup', 'models': 'rebuild'},
                  'required_nonempty_tables': [{'schema': 'public', 'name': 'Orders', 'minimum_rows': 1}]}
        self.r.validate_recovery_policy(policy, host, 'a' * 64)
        policy['mounts'].pop('uploads')
        with self.assertRaises(self.r.RecoveryError):
            self.r.validate_recovery_policy(policy, host, 'a' * 64)

    def test_local_cli_rejects_invalid_transfer_pin_without_creating_destination(self):
        target = self.root / 'must-not-exist'
        result = subprocess.run([sys.executable, str(SCRIPT), 'restore-local', '--archive', str(self.root / 'absent.tar'),
                                 '--archive-sha256', 'invalid', '--manifest-sha256', 'a' * 64,
                                 '--destination', str(target), '--apply'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())

    def test_stale_source_journal_keeps_release_blocker_and_never_starts_containers(self):
        args = SimpleNamespace(project='demo', environment='production', export_id='exercise-one', policy_sha256='a'*64,
                               controller_sha256='b'*64, recovery_policy_sha256='c'*64)
        release = {'status': 'passed', 'images': {'api': 'registry.invalid/demo@sha256:' + 'd'*64}}
        raw = self.r.canonical(release)
        host = SimpleNamespace(RECOVERY_TRANSACTION_PATH=self.root/'marker', TRANSACTION_PATH=self.root/'absent',
                               RECOVERY_STATE_DIR=self.root, SERVICES=['api'], CONTAINERS={'api':'demo-production-api'})
        original = {'id':'e'*64,'name':'/demo-production-api','image':release['images']['api'],
                    'running':True,'paused':False,'restarting':False,'health':'healthy'}
        marker = self.r.canonical(self.r.journal_identity(args, 'f'*64, [original]))
        host.RECOVERY_TRANSACTION_PATH.write_bytes(marker)
        with mock.patch.object(self.r, 'root_read', lambda p,mode:p.read_bytes()), \
             mock.patch.object(self.r, 'source_release', return_value=(raw,release)):
            with self.assertRaisesRegex(self.r.RecoveryError, 'journal_identity_mismatch'):
                self.r.resume_source(args, host, None, None)
        self.assertEqual(host.RECOVERY_TRANSACTION_PATH.read_bytes(), marker)

    def test_unknown_transfer_manifest_cannot_be_interpreted_as_recovery(self):
        self.assertTrue(hasattr(self.r, 'verified_archive'))
        archive = self.root/'export.tar'
        raw = b'{"schema":"wrong"}\n'
        import io,hashlib
        with tarfile.open(archive,'w') as tar:
            member=tarfile.TarInfo('manifest.json'); member.size=len(raw)
            tar.addfile(member,io.BytesIO(raw))
        with self.assertRaises(self.r.RecoveryError):
            with self.r.verified_archive(archive,hashlib.sha256(archive.read_bytes()).hexdigest(),hashlib.sha256(raw).hexdigest()):
                self.fail('unknown manifest accepted')

    def test_verified_source_resume_records_evidence_before_releasing_blocker(self):
        args = SimpleNamespace(project='demo', environment='test', export_id='exercise-one', policy_sha256='a'*64,
                               controller_sha256='b'*64, recovery_policy_sha256='c'*64)
        release = {'status':'passed','images':{'api':'registry.invalid/demo@sha256:'+'d'*64}}
        raw = self.r.canonical(release)
        host = SimpleNamespace(RECOVERY_TRANSACTION_PATH=self.root/'marker', TRANSACTION_PATH=self.root/'absent',
                               RECOVERY_STATE_DIR=self.root, SERVICES=['api'], CONTAINERS={'api':'demo-test-api'}, POLICY={})
        original = {'id':'e'*64,'name':'/demo-test-api','image':release['images']['api'],'running':True,
                    'paused':False,'restarting':False,'health':'healthy','auto_remove':False}
        marker = self.r.canonical(self.r.journal_identity(args,self.r.sha(raw),[original]))
        host.RECOVERY_TRANSACTION_PATH.write_bytes(marker)
        (self.root/'journal.json').write_bytes(marker)
        state = {**original,'running':False}
        class DockerState:
            def inspect(self, reference):
                if reference != state['id']:
                    raise AssertionError('attempted another container')
                return dict(state)
            def run(self, args, **kwargs):
                if args != ['start',state['id']]:
                    raise AssertionError('attempted an unrelated operation')
                state['running']=True
        with mock.patch.object(self.r,'root_read',lambda p,mode:p.read_bytes()), \
             mock.patch.object(self.r,'source_release',return_value=(raw,release)), \
             mock.patch.object(self.r,'export_directory',return_value=self.root):
            result=self.r.resume_source(args,host,DockerState(),None)
        self.assertEqual(result['status'],'resumed')
        self.assertTrue(state['running'])
        self.assertFalse(host.RECOVERY_TRANSACTION_PATH.exists())
        self.assertEqual((self.root/'source-resumed.json').read_bytes(),self.r.canonical(result))


@unittest.skipUnless(os.environ.get('CNB_BUNDLE_TEST_POSTGRES_IMAGE'), 'explicit cached PG16 image required')
class RealRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        backup_fixture.RealPostgres16BackupTests.setUpClass.__func__(cls)
        spec = importlib.util.spec_from_file_location('real_recovery', SCRIPT)
        cls.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.r)

    def test_actual_pg_restore_reconciles_schema_data_sequences_and_detects_changed_row(self):
        self.assertTrue(hasattr(self.r, 'Postgres'), 'real database recovery is missing')
        docker = self.r.Docker([self.docker], dict(os.environ))
        pg = self.r.Postgres(docker, self.container, 'postgres', 'cnb_backup_test')
        pg.sql(b'''CREATE SCHEMA business; CREATE TABLE business.orders(id serial PRIMARY KEY, amount numeric(12,2), note text);
                  INSERT INTO business.orders(amount,note) VALUES(19.25,'synthetic'),(NULL,NULL);
                  CREATE VIEW business.order_view AS SELECT id,amount FROM business.orders;
                  SELECT setval('business.orders_id_seq',41,true);''')
        fingerprint = pg.fingerprint()
        self.assertEqual([(t['schema'], t['name'], t['rows']) for t in fingerprint['tables']], [('business', 'orders', 2)])
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp).resolve() / 'database.dump'
            pg.dump(dump)
            subprocess.run([self.docker, 'exec', self.container, 'createdb', '-U', 'postgres', 'cnb_recovery_target'], check=True)
            target = self.r.Postgres(docker, self.container, 'postgres', 'cnb_recovery_target')
            target.restore(dump)
            self.assertEqual(target.fingerprint(), fingerprint)
            target.sql(b"UPDATE business.orders SET note='changed' WHERE id=1;")
            self.assertNotEqual(target.fingerprint(), fingerprint)
            with self.assertRaises(self.r.RecoveryError):
                target.restore(dump)

    def test_resume_refuses_changed_identity_then_restarts_only_original_container(self):
        self.assertTrue(hasattr(self.r, 'resume_containers'), 'bounded source resume is missing')
        docker = self.r.Docker([self.docker], dict(os.environ))
        container = docker.run(['create', '--pull=never', '--network=none', '--tmpfs=/var/lib/postgresql/data', '--entrypoint=sleep',
                                os.environ['CNB_BUNDLE_TEST_POSTGRES_IMAGE'], '300']).decode().strip()
        self.assertRegex(container, '^[0-9a-f]{64}$')
        self.addCleanup(subprocess.run, [self.docker, 'rm', '--force', container],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        docker.run(['start', container])
        original = docker.inspect(container)
        wrong = {**original, 'image': 'registry.invalid/wrong@sha256:' + 'a' * 64}
        with self.assertRaises(self.r.RecoveryError):
            self.r.resume_containers(docker, [wrong], timeout=10)
        self.assertTrue(docker.inspect(container)['running'])
        docker.run(['stop', '--time', '10', original['id']])
        self.assertFalse(docker.inspect(container)['running'])
        self.r.resume_containers(docker, [original], timeout=10)
        self.assertTrue(docker.inspect(container)['running'])

    def test_real_database_and_upload_export_transfers_and_restores_together(self):
        docker=self.r.Docker([self.docker],dict(os.environ))
        image=os.environ['CNB_BUNDLE_TEST_POSTGRES_IMAGE']
        docker.run(['exec',self.container,'createdb','-U','postgres','cnb_export_source'])
        pg=self.r.Postgres(docker,self.container,'postgres','cnb_export_source')
        pg.sql(b"CREATE TABLE orders(id serial PRIMARY KEY,note text); INSERT INTO orders(note) VALUES('synthetic business');")
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); app_dir=root/'app'; app_dir.mkdir()
            (app_dir/'uploads').mkdir(); (app_dir/'uploads'/'proof.bin').write_bytes(b'\x00synthetic upload\xff')
            (app_dir/'uploads'/'proof.bin').chmod(0o640)
            (app_dir/'models').mkdir(); (app_dir/'models'/'cache.bin').write_bytes(b'rebuildable cache')
            declared=[{'source':str(app_dir/name),'target':'/app/'+name} for name in ('uploads','models')]
            mounts=[part for m in declared for part in ('--mount','type=bind,src='+m['source']+',dst='+m['target'])]
            app=docker.run(['create','--pull=never','--network=none','--tmpfs=/var/lib/postgresql/data',
                            *mounts,'--entrypoint=sleep',image,'300']).decode().strip()
            self.assertRegex(app,'^[0-9a-f]{64}$')
            self.addCleanup(subprocess.run,[self.docker,'rm','--force','--volumes',app],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            docker.run(['start',app]); app_name=docker.inspect(app)['name'][1:]
            raw=self.r.canonical({'status':'passed','images':{'api':image}})
            (app_dir/'.release.json').write_bytes(raw)
            policy={'database':{'container':self.container,'admin_user':'postgres','name':'cnb_export_source'},'startup_timeout_seconds':10,
                    'services':{'api':{'mounts':declared}}}
            host=SimpleNamespace(APP_DIR=app_dir,POLICY=policy,SERVICES=['api'],CONTAINERS={'api':app_name},
                                 RECOVERY_ROOT=root/'recovery',RECOVERY_STATE_DIR=root/'recovery'/'state',
                                 RECOVERY_TRANSACTION_PATH=root/'recovery'/'state'/'demo-test.transaction.json',
                                 TRANSACTION_PATH=app_dir/'.release.transaction.json',_assert_release_unblocked=lambda:None)
            args=SimpleNamespace(project='demo',environment='test',export_id='business-one',policy_sha256='a'*64,
                                 controller_sha256='b'*64,recovery_policy_sha256='c'*64,apply=True)
            recovery={'mounts':{'uploads':'backup','models':'rebuild'},
                      'required_nonempty_tables':[{'schema':'public','name':'orders','minimum_rows':1}]}
            def directory(path,mode=0o755):
                path.mkdir(parents=True,exist_ok=True); path.chmod(mode)
            # Only Linux root ownership/path entry is adapted; dump, container pause,
            # journals, transfer bytes, restore, queries, and files are real.
            with mock.patch.object(self.r,'root_directory',directory), \
                 mock.patch.object(self.r,'root_read',lambda p,mode:p.read_bytes()), \
                 mock.patch.object(self.r,'source_release',lambda *a:((app_dir/'.release.json').read_bytes(),self.r.strict_json(raw))), \
                 mock.patch.object(self.r,'export_directory',return_value=root/'export'):
                result=self.r.export_source(args,host,recovery,docker,None)
            self.assertEqual((root/'export'/'export.tar').stat().st_mode & 0o777,0o600)
            self.assertTrue(docker.inspect(app)['running'])
            self.assertFalse(host.RECOVERY_TRANSACTION_PATH.exists())
            transferred=root/'download.tar'; shutil.copyfile(root/'export'/'export.tar',transferred)
            local_target=root/'must-not-restore-on-source-daemon'
            rejected=subprocess.run([sys.executable,str(SCRIPT),'restore-local','--archive',str(transferred),
                                     '--archive-sha256',result['archive_sha256'],'--manifest-sha256',result['manifest_sha256'],
                                     '--destination',str(local_target),'--apply'],capture_output=True)
            self.assertNotEqual(rejected.returncode,0)
            self.assertIn(b'different_docker_daemon_required',rejected.stdout)
            self.assertFalse(local_target.exists())
            with self.r.verified_archive(transferred,result['archive_sha256'],result['manifest_sha256']) as (tar,manifest):
                self.assertEqual(manifest['scope']['business_mounts'],['uploads'])
                self.assertEqual(manifest['scope']['rebuildable_mounts'],['models'])
                self.assertNotIn('mounts/models.tar',manifest['files'])
                dump=root/'transferred.dump'; dump.write_bytes(tar.extractfile('database.dump').read())
                uploads=root/'uploads.tar'; uploads.write_bytes(tar.extractfile('mounts/uploads.tar').read())
            docker.run(['exec',self.container,'createdb','-U','postgres','cnb_export_target'])
            target=self.r.Postgres(docker,self.container,'postgres','cnb_export_target')
            target.restore(dump)
            self.assertEqual(target.fingerprint(),manifest['database'])
            self.r.restore_tree(uploads,root/'restored-uploads')
            self.assertEqual((root/'restored-uploads'/'proof.bin').read_bytes(),b'\x00synthetic upload\xff')
            transferred.write_bytes(transferred.read_bytes()+b'corrupt')
            with self.assertRaisesRegex(self.r.RecoveryError,'transfer_checksum_mismatch'):
                with self.r.verified_archive(transferred,result['archive_sha256'],result['manifest_sha256']):
                    self.fail('corrupt transfer accepted')


if __name__ == '__main__':
    unittest.main()
