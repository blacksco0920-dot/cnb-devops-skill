"""Bounded failed/probe repair: real filesystem transactions, simulated cloud/PG I/O."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import time
import secrets
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import test_bundle_host_transactions as ported
HOST = ported.MODULE

PATH = Path(__file__).resolve().parents[1] / 'assets/cnb-tcr-tat/host/repair-test-release.py'

def load_repair():
    spec = importlib.util.spec_from_file_location('repair_test_release', PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def sha(value):
    return hashlib.sha256(value).hexdigest()

def archive(items):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for name, content, kind in items:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(content)
                tar.addfile(item, io.BytesIO(content))
            else:
                item.linkname = content.decode()
                tar.addfile(item)
    return output.getvalue()

class RepairTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ported.PortedHostTransactionTests()
        self.fixture.setUp()
        self.repair = load_repair()
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.spec = {'schema': 'cnb-prisma-repair-inspection/v1', 'service': 'api',
                     'schema_path': 'app/prisma/schema.prisma', 'migrations_path': 'app/prisma/migrations',
                     'lock_path': 'app/prisma/migrations/migration_lock.toml'}
        self.files = {'migration_lock.toml': b'provider = "postgresql"\n',
                      '20260901000000_init/migration.sql': b'CREATE TABLE t(id int);\n'}

    def request(self):
        return {'schema':'cnb-release-request/v1', 'project':'sample', 'environment':'test',
                'controller':HOST.CONTROLLER_ID, 'git_sha':'a'*40, 'controller_commit':'a'*40,
                'build_id':'cnb-candidate-123', 'images':self.fixture.images}

    def permit(self):
        now = datetime.now(timezone.utc)
        return {'schema':'cnb-test-repair-permit/v1','permit_id':'1'*32,'project':'sample','environment':'test',
                'controller':HOST.CONTROLLER_ID,'issued_at':(now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
                'expires_at':(now+timedelta(minutes=10)).isoformat().replace('+00:00','Z'),
                **{k:'b'*64 for k in ('controller_sha256','policy_sha256','compose_sha256',
                    'recovery_policy_sha256','failed_transaction_sha256','failed_snapshot_manifest_sha256',
                    'accepted_release_sha256','source_state_sha256','migration_evidence_sha256',
                    'archive_sha256','manifest_sha256','restore_receipt_sha256')},
                'failed_snapshot':'20260901T010203Z-0123456789abcdef', 'migration_spec':self.spec,
                'request_sha256':sha(canonical(self.request()))}

    def context(self, fixture, snapshot):
        parent = self.fixture._v2_release_transaction(snapshot, git_sha='a'*40, build_id='cnb-backup-123')
        parent.update(status='failed', phase='probe', reason='release_identity_mismatch')
        parent['previous_release_sha256'] = sha(fixture['release_path'].read_bytes())
        parent_raw = canonical(parent)
        fixture['transaction_path'].write_bytes(parent_raw)
        fixture['transaction_path'].chmod(0o600)
        permit = self.permit()
        permit.update(failed_transaction_sha256=sha(parent_raw), failed_snapshot=parent['snapshot'],
                      failed_snapshot_manifest_sha256=parent['snapshot_manifest_sha256'],
                      accepted_release_sha256=parent['previous_release_sha256'])
        patch = mock.patch.object(self.repair,'revalidate_source_locked')
        patch.start()
        self.addCleanup(patch.stop)
        return {'parent':parent,'parent_raw':parent_raw,'permit':permit,'permit_raw':canonical(permit),
                'request':self.request(), 'state':{}, 'account':self.account}

    def test_permit_exact_request_expiry_and_test_only(self):
        permit = self.permit()
        self.repair.validate_permit(HOST, permit, self.request())
        for change in ({'expires_at':'2020-01-01T00:00:00Z'}, {'environment':'production'},
                       {'unexpected':True}, {'request_sha256':'c'*64}, {'permit_id':False}):
            with self.subTest(change=change), self.assertRaises(self.repair.RepairError):
                self.repair.validate_permit(HOST, {**permit, **change}, self.request())

    def test_prisma_archive_rejects_links_duplicates_and_traversal(self):
        good = archive([('migrations/'+p, b, tarfile.REGTYPE) for p,b in self.files.items()])
        self.assertEqual(self.repair.read_image_archive(good, 'migrations', directory=True), self.files)
        for bad in [('migrations/../escape',b'x',tarfile.REGTYPE),
                    ('/migrations/x',b'x',tarfile.REGTYPE), ('migrations/x',b'target',tarfile.SYMTYPE),
                    ('migrations/x',b'target',tarfile.LNKTYPE),
                    ('migrations/migration_lock.toml',b'x',tarfile.REGTYPE)]:
            with self.subTest(bad=bad), self.assertRaises(self.repair.RepairError):
                self.repair.read_image_archive(archive([('migrations/migration_lock.toml',b'x',tarfile.REGTYPE),bad]),
                                               'migrations', directory=True)

    def test_prisma_history_requires_complete_unfiltered_success_set(self):
        row = {'migration_name':'20260901000000_init', 'checksum':sha(self.files['20260901000000_init/migration.sql']),
               'finished':True, 'rolled_back':False, 'applied_steps_count':1}
        self.repair.validate_prisma_history(self.files, [row])
        cases = [[], [row,row], [{**row,'checksum':'a'*64}], [{**row,'finished':False}],
                 [{**row,'rolled_back':True}], [row,{**row,'migration_name':'extra'}],
                 [{**row,'applied_steps_count':False}]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(self.repair.RepairError):
                self.repair.validate_prisma_history(self.files, rows)

    def test_prisma_image_inspection_never_starts_image(self):
        docker = mock.Mock()
        cid = 'c'*64
        schema = b'datasource db { provider = "postgresql" }\n'
        outputs = [cid.encode(), archive([('schema.prisma',schema,tarfile.REGTYPE)]),
                   archive([('migrations/'+p,b,tarfile.REGTYPE) for p,b in self.files.items()]),
                   archive([('migration_lock.toml',self.files['migration_lock.toml'],tarfile.REGTYPE)]), b'']
        docker.run.side_effect = outputs
        observed = self.repair.inspect_prisma_image(docker, self.fixture.images['api'], self.spec)
        self.assertEqual(observed['files'], {k:sha(v) for k,v in self.files.items()})
        verbs = [call.args[0][0] for call in docker.run.call_args_list]
        self.assertEqual(verbs, ['create','cp','cp','cp','rm'])
        self.assertIn('--network=none',docker.run.call_args_list[0].args[0])

    def test_atomic_parent_archive_child_schema_and_replay_refusal(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            _, refs = self.fixture._install_v2_deploy_history(fixture, count=1)
            context = self.context(fixture, refs[0])
            transaction = self.repair.begin_locked(HOST, context, refs[0], os.getuid(), os.getgid())
            self.assertEqual(transaction['schema'],'cnb-test-release-transaction/v3')
            self.assertNotIn('previous_images',transaction)
            self.assertEqual(transaction['source_images'],context['parent']['images'])
            HOST._validate_release_transaction_model(transaction)
            history = fixture['app_dir']/'.repair-history'/sha(context['parent_raw'])
            self.assertEqual((history/'parent-transaction.json').read_bytes(),context['parent_raw'])
            self.assertEqual(fixture['transaction_path'].read_bytes(),canonical(transaction))
            with self.assertRaises(self.repair.RepairError):
                self.repair.begin_locked(HOST,context,refs[0],os.getuid(),os.getgid())

    def test_archive_interruption_preserves_parent_and_blocks_retry(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            _, refs = self.fixture._install_v2_deploy_history(fixture, count=1)
            context = self.context(fixture,refs[0])
            real_write = HOST._write_new
            def fail(path,*args):
                if path.name == 'started.json': raise OSError('simulated interrupted write')
                return real_write(path,*args)
            with mock.patch.object(HOST,'_write_new',side_effect=fail), self.assertRaises((OSError,self.repair.RepairError)):
                self.repair.begin_locked(HOST,context,refs[0],os.getuid(),os.getgid())
            self.assertEqual(fixture['transaction_path'].read_bytes(),context['parent_raw'])
            with self.assertRaises(self.repair.RepairError):
                self.repair.begin_locked(HOST,context,refs[0],os.getuid(),os.getgid())

    def test_core_repair_skips_migration_and_keeps_real_probe_gate(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
                _, refs = self.fixture._install_v2_deploy_history(fixture,count=1)
                context = self.context(fixture,refs[0])
                HOST._arguments.return_value[0].repair_required = True
                accepted = fixture['release_path'].read_bytes()
                if failed: fixture['probe_public_urls'].side_effect = HOST.DeploymentError('release_identity_mismatch')
                with mock.patch.object(HOST,'_load_repair_helper',return_value=self.repair), \
                     mock.patch.object(self.repair,'authorize_locked',return_value=context):
                    result = HOST.deploy([])
                self.assertEqual(result,1 if failed else 0,fixture['stdout'].getvalue())
                runs = [c for c in fixture['compose'].call_args_list if c.args[2][0]=='run']
                self.assertEqual(runs,[])
                history = fixture['app_dir']/'.repair-history'/sha(context['parent_raw'])
                self.assertTrue((history/'parent-transaction.json').exists())
                if failed:
                    child = json.loads(fixture['transaction_path'].read_bytes())
                    self.assertEqual((child['schema'],child['phase'],child['status']),
                                     ('cnb-test-release-transaction/v3','probe','failed'))
                    self.assertEqual(fixture['release_path'].read_bytes(),accepted)
                    self.assertFalse((history/'completed.json').exists())
                else:
                    self.assertFalse(fixture['transaction_path'].exists())
                    self.assertTrue((history/'completed.json').exists())
                    self.assertEqual(json.loads(fixture['release_path'].read_bytes())['status'],'passed')

    def test_repair_wire_is_explicit_and_production_rejects_it(self):
        request = {**self.request(), 'schema':'cnb-test-repair-request/v1'}
        def script(model):
            raw = json.dumps(model,sort_keys=True,separators=(',', ':')).encode()
            return HOST.render_tat_template(HOST.POLICY,HOST.controller_program_sha256(),HOST.POLICY_SHA256).replace(
                b'{{release_request_b64url}}',base64.urlsafe_b64encode(raw).rstrip(b'='))
        self.assertTrue(HOST.parse_tat_release_script(script(request))['repair_required'])
        self.assertNotIn('repair_required',HOST.parse_tat_release_script(script(self.request())))
        with mock.patch.dict(HOST.POLICY,environment='production'), self.assertRaises(HOST.DeploymentError):
            HOST.parse_tat_release_script(script({**request,'environment':'production'}))

    def test_repair_request_on_clean_host_never_pulls_or_migrates(self):
        for record in (None, self.fixture._canonical_bytes(self.fixture._legacy_release_record())):
            with self.subTest(record=bool(record)), tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp,previous_release_bytes=record) as fixture:
                HOST._arguments.return_value[0].repair_required = True
                self.assertEqual(HOST.deploy([]),1)
                fixture['compose'].assert_not_called()
                self.assertIn('repair_failed_transaction_required',fixture['stdout'].getvalue())

    def test_normal_request_cannot_consume_existing_repair_permit(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            _, refs = self.fixture._install_v2_deploy_history(fixture,count=1)
            context = self.context(fixture,refs[0])
            with mock.patch.object(HOST,'_load_repair_helper') as load:
                self.assertEqual(HOST.deploy([]),1)
            load.assert_not_called()
            fixture['compose'].assert_not_called()
            self.assertEqual(fixture['transaction_path'].read_bytes(),context['parent_raw'])

    def restore_receipt(self, manifest):
        return {'schema':'cnb-recovery-restore-receipt/v2','status':'verified','external_restore_verified':True,
                'archive_sha256':'a'*64,'manifest_sha256':'b'*64,'source_release_sha256':'c'*64,
                'source_docker_id_sha256':'d'*64,'target_docker_id_sha256':'e'*64,
                'postgres_image':manifest['postgres']['image'],'postgres_version_num':160015,
                'schema_equal':True,'all_table_data_equal':True,'sequences_equal':True,'business_files_equal':True,
                'file_ownership_remapped_to_local_user':True,'scope':manifest['scope'],
                'target_volume':'cnb-recovery-'+'a'*24,'target_container_id':'f'*64,
                'created_at':'2026-09-11T01:00:00Z','source_kind':'failed-test-release',
                'source_baseline_sha256':'9'*64,'public_identity_verified':False,'business_acceptance_verified':False}

    def test_actual_restore_receipt_must_bind_all_data_and_different_daemon(self):
        manifest = {'postgres':{'image':'registry.invalid/pg@sha256:'+'8'*64,'version_num':160015},
                    'scope':{'postgres':True},'source_release_sha256':'c'*64,'source_docker_id_sha256':'d'*64,
                    'source_baseline_sha256':'9'*64}
        args = SimpleNamespace(archive_sha256='a'*64,manifest_sha256='b'*64)
        receipt = self.restore_receipt(manifest)
        self.repair.validate_restore_receipt(receipt,manifest,args)
        for change in ({'schema_equal':False},{'all_table_data_equal':False},{'sequences_equal':False},
                       {'business_files_equal':False},{'target_docker_id_sha256':'d'*64},
                       {'archive_sha256':'0'*64},{'source_baseline_sha256':'0'*64},
                       {'external_restore_verified':1},{'public_identity_verified':True}):
            with self.subTest(change=change),self.assertRaises(self.repair.RepairError):
                self.repair.validate_restore_receipt({**receipt,**change},manifest,args)

    def test_authorize_rejects_source_drift_before_switch(self):
        permit = self.permit()
        permit.update(controller_sha256='c'*64, policy_sha256=HOST.POLICY_SHA256,
                      compose_sha256=HOST.CONTROLLER_COMPOSE_SHA256)
        state = {'recovery_policy_sha256':'b'*64,'database':{'tables':[{'rows':1}]}}
        permit['source_state_sha256'] = sha(canonical(state))
        parent = {'snapshot':permit['failed_snapshot'],'snapshot_manifest_sha256':permit['failed_snapshot_manifest_sha256'],
                  'previous_release_sha256':permit['accepted_release_sha256']}
        recovery = mock.Mock()
        recovery.root_read.return_value = canonical(permit)
        recovery.source_record.return_value = (b'parent',parent)
        with mock.patch.object(self.repair,'load_recovery',return_value=recovery), \
             mock.patch.object(self.repair,'require_unused'), \
             mock.patch.object(HOST,'controller_program_sha256',return_value='c'*64), \
             mock.patch.object(self.repair,'source_state',return_value={**state,'database':{'tables':[{'rows':2}]}}), \
             mock.patch.object(self.repair,'migration_evidence') as migration:
            with self.assertRaisesRegex(HOST.DeploymentError,'repair_source_drift'):
                self.repair.authorize_locked(HOST,self.request(),self.account)
            migration.assert_not_called()

    def test_source_drift_during_pull_or_backup_blocks_atomic_switch(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            _, refs = self.fixture._install_v2_deploy_history(fixture,count=1)
            context = self.context(fixture,refs[0])
            with mock.patch.object(self.repair,'revalidate_source_locked',side_effect=self.repair.RepairError('repair_source_drift')):
                with self.assertRaises(self.repair.RepairError):
                    self.repair.begin_locked(HOST,context,refs[0],os.getuid(),os.getgid())
            self.assertEqual(fixture['transaction_path'].read_bytes(),context['parent_raw'])
            self.assertFalse((fixture['app_dir']/'.repair-history').exists())

    def test_prepare_pulls_only_exact_reviewed_migration_images(self):
        docker = mock.Mock()
        docker.run.side_effect = [RuntimeError('not cached'),b'pulled',b'present']
        recovery = SimpleNamespace(RecoveryError=RuntimeError)
        images = [self.fixture.images['api'],self.fixture.images['api'],self.fixture.images['web']]
        self.repair.prepare_inspection_images(docker,recovery,images)
        calls = [call.args[0] for call in docker.run.call_args_list]
        self.assertEqual(calls,[['image','inspect','--format','{{.Id}}',images[0]],
                                ['pull',images[0]],['image','inspect','--format','{{.Id}}',images[2]]])

    def test_grant_preview_apply_repeat_and_request_change(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            _, refs = self.fixture._install_v2_deploy_history(fixture,count=1)
            context = self.context(fixture,refs[0])
            parent, raw = context['parent'],context['parent_raw']
            install = Path(temp).resolve()/'install'
            install.mkdir()
            manifest = {'postgres':{'image':'registry.invalid/pg@sha256:'+'8'*64,'version_num':160015},
                        'scope':{'postgres':True},'source_release_sha256':'c'*64,'source_docker_id_sha256':'d'*64,
                        'source_baseline_sha256':'9'*64}
            receipt = self.restore_receipt(manifest)
            for name,content in [('request.json',canonical(self.request())),('spec.json',canonical(self.spec)),
                                 ('restore.json',canonical(receipt)),('archive.tar',b'validated separately')]:
                (install/name).write_bytes(content)
                (install/name).chmod(0o600)
            args = SimpleNamespace(request=str(install/'request.json'),migration_spec=str(install/'spec.json'),
                    archive=str(install/'archive.tar'),restore_receipt=str(install/'restore.json'),
                    failed_transaction_sha256=sha(raw),archive_sha256='a'*64,manifest_sha256='b'*64,
                    restore_receipt_sha256=sha(canonical(receipt)),recovery_policy_sha256='7'*64,
                    expires_at=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat().replace('+00:00','Z'),apply=False)
            recovery = mock.Mock()
            recovery.MAX_BYTES = 1000000
            recovery.source_record.return_value = (raw,parent)
            recovery.verified_archive.side_effect = lambda *a: contextlib.nullcontext((None,manifest))
            recovery.root_directory.side_effect = lambda path: path.mkdir(mode=0o755,exist_ok=True)
            recovery.root_read.side_effect = lambda path,mode: path.read_bytes()
            def write(path,data,mode):
                fd = os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
                with os.fdopen(fd,'wb') as stream: stream.write(data)
                path.chmod(mode)
            recovery.write_new.side_effect = write
            original_write = HOST._write_new
            state = {'recovery_policy_sha256':'7'*64}
            def input_read(path,**kwargs):
                return b'' if kwargs.get('metadata_only') else path.read_bytes()
            with mock.patch.dict(HOST.POLICY,install_dir=str(install)), \
                 mock.patch.object(self.repair,'root_input',side_effect=input_read), \
                 mock.patch.object(self.repair,'source_state',return_value=state), \
                 mock.patch.object(self.repair,'validate_export_binding'), \
                 mock.patch.object(self.repair,'migration_evidence',return_value={'verified':'synthetic'}), \
                 mock.patch.object(self.repair,'prepare_inspection_images'), \
                 mock.patch.object(HOST,'_write_new',side_effect=lambda p,b,m,u,g: original_write(p,b,m,os.getuid(),os.getgid())):
                preview = self.repair.grant_locked(args,HOST,recovery,self.account)
                self.assertEqual(preview['status'],'preview')
                self.assertIsNone(preview['permit_sha256'])
                self.assertFalse((install/'test-repair').exists())
                args.apply = True
                granted = self.repair.grant_locked(args,HOST,recovery,self.account)
                active = install/'test-repair/permit.json'
                active_raw = active.read_bytes()
                self.assertEqual(granted['status'],'granted')
                self.assertEqual(granted['request_sha256'],sha(canonical(self.request())))
                self.assertEqual(granted['permit_sha256'],sha(active_raw))
                self.assertEqual(active.stat().st_mode & 0o777,0o444)
                repeated = self.repair.grant_locked(args,HOST,recovery,self.account)
                self.assertEqual(repeated['status'],'unchanged')
                self.assertEqual(active.read_bytes(),active_raw)
                changed = {**self.request(),'build_id':'cnb-other-123'}
                (install/'request.json').write_bytes(canonical(changed))
                with self.assertRaises(self.repair.RepairError):
                    self.repair.grant_locked(args,HOST,recovery,self.account)
                self.assertEqual(active.read_bytes(),active_raw)

    @unittest.skipUnless(os.environ.get('CNB_REPAIR_PRISMA_IMAGE') and os.environ.get('CNB_REPAIR_POSTGRES_IMAGE'),
                         'set cached digest images to exercise real Docker copy and PostgreSQL history')
    def test_real_stopped_image_inspection_and_postgres_history(self):
        spec = importlib.util.spec_from_file_location('repair_recovery_test',PATH.with_name('recover-project.py'))
        recovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recovery)
        docker = recovery.local_docker()
        image = os.environ['CNB_REPAIR_PRISMA_IMAGE']
        prefix = os.environ.get('CNB_REPAIR_PRISMA_ROOT','app/packages/database/prisma')
        migration_spec = {**self.spec,'schema_path':prefix+'/schema.prisma',
                          'migrations_path':prefix+'/migrations','lock_path':prefix+'/migrations/migration_lock.toml'}
        inspected = self.repair.inspect_prisma_image(docker,image,migration_spec)
        files = inspected['_contents']
        name = 'cnb-repair-test-'+secrets.token_hex(8)
        cid = docker.run(['run','--detach','--rm','--pull=never','--network=none','--name',name,
                          '--tmpfs','/var/lib/postgresql/data','--env','POSTGRES_HOST_AUTH_METHOD=trust',
                          os.environ['CNB_REPAIR_POSTGRES_IMAGE']]).decode().strip()
        try:
            pg = recovery.Postgres(docker,cid,'postgres','postgres')
            deadline = time.monotonic()+60
            while True:
                try:
                    pg.version()
                    break
                except recovery.RecoveryError:
                    self.assertLess(time.monotonic(),deadline)
                    time.sleep(.2)
            pg.sql(b'CREATE TABLE public._prisma_migrations(id text,migration_name text,checksum text,finished_at timestamptz,rolled_back_at timestamptz,applied_steps_count int);')
            for path,content in files.items():
                if path.endswith('/migration.sql'):
                    name = path.split('/')[0]
                    pg.sql(("INSERT INTO public._prisma_migrations VALUES ('"+name+"','"+name+"','"+sha(content)+"',now(),NULL,1);").encode())
            state = {'postgres':{'id':cid}}
            parent = {'images':{'api':image}}
            request = {'images':{'api':image}}
            with mock.patch.dict(HOST.POLICY,database={**HOST.POLICY['database'],'name':'postgres','admin_user':'postgres'}), \
                 mock.patch.object(recovery,'Docker',return_value=docker):
                result = self.repair.migration_evidence(HOST,recovery,state,parent,request,migration_spec)
                self.assertEqual(len(result['database_history']),len(files)-1)
                pg.sql(b"UPDATE public._prisma_migrations SET finished_at=NULL WHERE id=(SELECT min(id) FROM public._prisma_migrations);")
                with self.assertRaises(self.repair.RepairError):
                    self.repair.migration_evidence(HOST,recovery,state,parent,request,migration_spec)
        finally:
            docker.run(['rm','--force',cid],maximum=1024)

    def test_empty_accepted_baseline_survives_repair_probe_failure(self):
        for failed in (True,False):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as temp, self.fixture._empty_baseline_fixture(temp) as fixture:
                baseline_raw = fixture['release_path'].read_bytes()
                root = fixture['app_dir']/'backups/releases'
                root.mkdir(parents=True,mode=0o700)
                root.parent.chmod(0o700)
                ref = self.fixture._create_snapshot(root)[0]
                context = self.context(fixture,ref)
                context['parent']['previous_images'] = {}
                context['parent_raw'] = canonical(context['parent'])
                context['permit']['failed_transaction_sha256'] = sha(context['parent_raw'])
                context['permit_raw'] = canonical(context['permit'])
                fixture['transaction_path'].write_bytes(context['parent_raw'])
                HOST._arguments.return_value[0].repair_required = True
                fixture['database_empty'].side_effect = AssertionError('migrated DB must not be asserted empty')
                if failed: fixture['probe_public_urls'].side_effect = HOST.DeploymentError('release_identity_mismatch')
                with mock.patch.object(HOST,'_load_repair_helper',return_value=self.repair), \
                     mock.patch.object(self.repair,'authorize_locked',return_value=context):
                    self.assertEqual(HOST.deploy([]),1 if failed else 0,fixture['stdout'].getvalue())
                fixture['database_empty'].assert_not_called()
                if failed:
                    self.assertEqual(fixture['release_path'].read_bytes(),baseline_raw)
                    child = json.loads(fixture['transaction_path'].read_bytes())
                    self.assertEqual(child['accepted_release_sha256'],sha(baseline_raw))
                    self.assertEqual(child['source_images'],context['parent']['images'])
                else:
                    self.assertEqual(json.loads(fixture['release_path'].read_bytes())['status'],'passed')
                    fixture['compose'].reset_mock()
                    self.assertEqual(HOST.deploy([]),1)
                    fixture['compose'].assert_not_called()
                    self.assertIn('repair_failed_transaction_required',fixture['stdout'].getvalue())

    def test_completion_receipt_failure_retains_v3_blocker(self):
        with tempfile.TemporaryDirectory() as temp,self.fixture._deploy_fixture(temp) as fixture:
            _,refs = self.fixture._install_v2_deploy_history(fixture,count=1)
            context = self.context(fixture,refs[0])
            HOST._arguments.return_value[0].repair_required = True
            with mock.patch.object(HOST,'_load_repair_helper',return_value=self.repair), \
                 mock.patch.object(self.repair,'authorize_locked',return_value=context), \
                 mock.patch.object(self.repair,'complete_locked',side_effect=OSError('simulated fsync failure')):
                self.assertEqual(HOST.deploy([]),1)
            transaction = json.loads(fixture['transaction_path'].read_bytes())
            self.assertEqual((transaction['schema'],transaction['status'],transaction['reason']),
                             ('cnb-test-release-transaction/v3','failed','repair_completion_failed'))

    def test_source_requiring_healthcheck_rejects_absent_health(self):
        recovery = mock.Mock()
        recovery.source_record.return_value = (b'parent',{'images':self.fixture.images})
        recovery.root_read.return_value = b'{}'
        recovery.validate_recovery_policy.return_value = {'mounts':{}}
        docker = recovery.Docker.return_value
        docker.inspect.return_value = {'id':'a'*64,'health':None}
        with mock.patch.dict(HOST.POLICY['services']['api'],healthcheck=True), \
             mock.patch.object(self.repair.os.path,'lexists',return_value=False):
            with self.assertRaisesRegex(self.repair.RepairError,'repair_source_healthcheck_missing'):
                self.repair.source_state(HOST,recovery,self.account,'a'*64)

    def test_installed_helper_digest_is_checked_before_exec(self):
        lock = {'schema':'cnb-devops-artifacts/v1','version':'test','files':{
            'host/tat-deploy-test.py':'a'*64,'host-policy.json':HOST.POLICY_SHA256,
            'docker-compose.yml':HOST.CONTROLLER_COMPOSE_SHA256,'host/repair-test-release.py':'b'*64}}
        receipt = {'schema':'cnb-test-installation/v1','lock_sha256':'c'*64}
        with mock.patch.object(HOST,'read_root_owned_json',side_effect=[(lock,'c'*64),(receipt,'d'*64)]), \
             mock.patch.object(HOST,'controller_program_sha256',return_value='a'*64), \
             mock.patch.object(HOST,'_read_root_owned_bytes',return_value=b'raise AssertionError("executed unverified bytes")'):
            with self.assertRaisesRegex(HOST.DeploymentError,'repair_helper_digest_mismatch'):
                HOST._load_installed_module('repair-test-release.py')

    def test_repair_history_permanently_holds_snapshots(self):
        with tempfile.TemporaryDirectory() as temp, self.fixture._deploy_fixture(temp) as fixture:
            root, refs = self.fixture._install_v2_deploy_history(fixture,count=7)
            (fixture['app_dir']/'.repair-history').mkdir(mode=0o700)
            with mock.patch.object(HOST,'_prune_release_snapshots') as prune:
                HOST.enforce_release_snapshot_retention(root,current_snapshot=refs[-1].name,uid=os.getuid(),gid=os.getgid())
            prune.assert_not_called()

if __name__ == '__main__': unittest.main()
