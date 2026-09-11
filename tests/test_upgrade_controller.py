"""Real file-transaction tests with synthetic host ownership, Docker and SSH boundaries."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_bundle_host_installer as installer_fixtures
from test_bundle_host_policy import HOST_PATH

HOST = HOST_PATH.with_name('upgrade-controller.py')
LOCAL = HOST_PATH.parents[3] / 'scripts/upgrade-controller.py'


def load(path):
    spec = importlib.util.spec_from_file_location('upgrade_test_' + path.parent.name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class UpgradeControllerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HOST.is_file(), 'The fixed upgrade entry is missing')
        self.m = load(HOST)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.install = self.root / 'install'; self.install.mkdir(mode=0o755)
        self.app = self.root / 'app'; self.app.mkdir(mode=0o750)
        self.state = self.root / 'state'
        helper = installer_fixtures.HostInstallerTests(); helper.setUp()
        self.old_dir = self.root / 'old'; self.old_dir.mkdir()
        helper.bundle(self.old_dir, recovery=True)
        policy = json.loads((self.old_dir / 'host-policy.json').read_bytes())
        for service in policy['services'].values(): service['healthcheck'] = True
        policy_raw = self.m.canonical(policy)
        (self.old_dir / 'host-policy.json').write_bytes(policy_raw)
        recovery_policy = json.loads((self.old_dir / 'recovery-policy.json').read_bytes())
        recovery_policy['host_policy_sha256'] = hashlib.sha256(policy_raw).hexdigest()
        (self.old_dir / 'recovery-policy.json').write_bytes(self.m.canonical(recovery_policy))
        (self.old_dir / 'host/install-project.py').write_bytes(HOST.with_name('install-project.py').read_bytes())
        (self.old_dir / 'host/tat-deploy-test.py').write_bytes((self.old_dir / 'host/tat-deploy-test.py').read_bytes() + b'\n# old reviewed fixture\n')
        self.new_dir = self.root / 'new'; shutil.copytree(self.old_dir, self.new_dir)
        (self.new_dir / 'host/tat-deploy-test.py').write_bytes(HOST_PATH.read_bytes())
        (self.new_dir / 'host/upgrade-controller.py').write_bytes(HOST.read_bytes())
        (self.new_dir / 'host/repair-test-release.py').write_bytes(b'# reviewed repair fixture; never executed here\n')
        for directory in (self.old_dir, self.new_dir):
            self.relock(directory)
        self.installer = installer_fixtures.load_installer()
        self.old = self.installer.verify_bundle(self.old_dir, self.digest(self.old_dir / 'artifact-lock.json'))
        self.new = self.installer.verify_bundle(self.new_dir, self.digest(self.new_dir / 'artifact-lock.json'))
        self.accepted = self.m.canonical({'schema': 'cnb-test-installation/v1', 'lock_sha256': self.old['lock_sha256']})
        self.host = self.old['host']
        for host in (self.host, self.new['host']):
            host.APP_DIR = self.app; host.ENV_PATH = self.app / '.env'; host.COMPOSE_PATH = self.app / 'docker-compose.yml'
            host.RELEASE_PATH = self.app / '.release.json'; host.TRANSACTION_PATH = self.app / '.release.transaction.json'
            host.LOCK_PATH = self.root / '.sample-test.deploy.lock'
            host.CONTROLLER_COMPOSE_PATH = self.install / 'docker-compose.yml'
            host.RECOVERY_TRANSACTION_PATH = self.root / 'recovery/state/sample-test.transaction.json'
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=self.old['policy']['release_home'])
        for name, (raw, mode) in self.m.fixed_files(self.old, self.accepted).items():
            self.write(self.install / name, raw, mode)
        self.write(self.host.LOCK_PATH, b'', 0o600)
        self.images = {name: service['image_repository'] + '@sha256:' + '1' * 64 for name, service in self.old['policy']['services'].items()}
        env = ''.join(f'{self.host.IMAGE_KEYS[name]}={image}\n' for name, image in self.images.items()).encode()
        self.write(self.host.ENV_PATH, env, 0o600)
        self.write(self.host.COMPOSE_PATH, self.old['files']['docker-compose.yml'], 0o644)
        baseline = {'schema': self.host.EMPTY_BASELINE_SCHEMA, 'status': 'empty', 'images': {}, 'project': 'sample', 'environment': 'test',
                    'controller': self.host.CONTROLLER_ID, 'policy_sha256': self.host.POLICY_SHA256, 'database': self.host.POLICY['database'],
                    'runtime_env_sha256': hashlib.sha256(b'original bootstrap env').hexdigest(), 'controller_compose_sha256': self.host.CONTROLLER_COMPOSE_SHA256,
                    'created_at': '2026-09-11T01:00:00Z'}
        self.baseline = self.m.canonical(baseline)
        self.write(self.install / 'empty-baseline.json', self.baseline, 0o444)
        self.write(self.host.RELEASE_PATH, self.baseline, 0o600)
        root = self.app / 'backups/releases'; root.mkdir(parents=True, mode=0o700)
        def backup(fd, name, uid, gid):
            raw = b'PGDMP' + b'x' * 2048
            self.host._write_new_at(fd, name, raw, 0o600, uid, gid)
            return hashlib.sha256(raw).hexdigest()
        with mock.patch.object(self.host, '_backup_database_at', side_effect=backup):
            snap = self.host.create_release_snapshot(root, env_bytes=b'old env\n', compose_bytes=b'old compose\n', git_sha='a'*40,
                build_id='cnb-failed-fixture', created_at='2026-09-11T01:00:00Z', uid=os.getuid(), gid=os.getgid())
        tx = {'schema': self.host.TRANSACTION_SCHEMA_V2, 'status': 'failed', 'phase': 'probe', 'reason': 'release_identity_mismatch',
              'controller': self.host.CONTROLLER_ID, 'controller_program_sha256': hashlib.sha256(self.old['files']['host/tat-deploy-test.py']).hexdigest(),
              'controller_compose_sha256': self.host.CONTROLLER_COMPOSE_SHA256, 'git_sha': 'a'*40, 'build_id': 'cnb-failed-fixture',
              'images': self.images, 'previous_images': {}, 'previous_release_sha256': hashlib.sha256(self.baseline).hexdigest(),
              'snapshot': snap.name, 'snapshot_manifest_sha256': snap.manifest_sha256, 'updated_at': '2026-09-11T01:00:01Z'}
        self.tx = self.m.canonical(tx)
        self.write(self.host.TRANSACTION_PATH, self.tx, 0o600)
        self.expected = {'old_lock_sha256': self.old['lock_sha256'], 'lock_sha256': self.new['lock_sha256'],
                         'accepted_installation_sha256': hashlib.sha256(self.accepted).hexdigest(),
                         'failed_transaction_sha256': hashlib.sha256(self.tx).hexdigest(), 'target_sha256': 'c'*64}
        self.before_app = {p: (p.read_bytes(), p.stat().st_ino) for p in self.app.iterdir() if p.is_file()}

    def relock(self, directory):
        core = self.m.module((directory / 'host/tat-deploy-test.py').read_bytes(), 'bundle_fixture')
        policy_raw = (directory / 'host-policy.json').read_bytes()
        (directory / 'tat-command.sh').write_bytes(core.render_tat_template(json.loads(policy_raw), self.digest(directory / 'host/tat-deploy-test.py'), hashlib.sha256(policy_raw).hexdigest()))
        lock = {'schema':'cnb-devops-artifacts/v1','version':'0.1.0','files':{p.relative_to(directory).as_posix():self.digest(p) for p in directory.rglob('*') if p.is_file() and p.name != 'artifact-lock.json'}}
        self.write(directory / 'artifact-lock.json', self.m.canonical(lock), 0o600)

    @staticmethod
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path, raw, mode):
        if path.exists(): path.chmod(0o600)
        path.write_bytes(raw); path.chmod(mode)

    @contextlib.contextmanager
    def host_boundary(self):
        def read_root(path):
            raw = self.m.read_checked(self.host, path, 0o444)
            return json.loads(raw), hashlib.sha256(raw).hexdigest()
        docker = mock.Mock()
        docker.inspect.side_effect = lambda name: {'id':'d'*64,'name':'/'+name,'image':self.images[next(role for role,value in self.host.CONTAINERS.items() if value==name)],'running':True,'health':'healthy','auto_remove':False,'paused':False,'restarting':False}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.m, 'ROOT_IDS', (os.getuid(), os.getgid())))
            stack.enter_context(mock.patch.object(self.m, 'installation_directory', return_value=self.install))
            stack.enter_context(mock.patch.object(self.m, 'state_directory', return_value=self.state))
            stack.enter_context(mock.patch.object(self.m.os, 'geteuid', return_value=0))
            stack.enter_context(mock.patch.object(self.m.pwd, 'getpwnam', return_value=self.account))
            stack.enter_context(mock.patch.object(self.m, 'runtime_docker', return_value=docker))
            for host in (self.host, self.new['host']):
                stack.enter_context(mock.patch.object(host, 'read_root_owned_json', side_effect=read_root))
                stack.enter_context(mock.patch.object(host, '_validate_database_dump_descriptor', return_value=None))
                stack.enter_context(mock.patch.object(host, '_probe_public_urls', side_effect=AssertionError('upgrade must not probe public endpoints')))
            yield

    def apply(self): return self.m.apply_upgrade(self.old, self.new, self.accepted, self.expected)

    def assert_app_unchanged(self):
        self.assertEqual({p:(p.read_bytes(),p.stat().st_ino) for p in self.before_app}, self.before_app)
        self.assertEqual((self.install / 'empty-baseline.json').read_bytes(), self.baseline)

    def test_installs_reviewed_files_last_and_preserves_marker_and_app_bytes(self):
        with self.host_boundary():
            result = self.apply()
            self.assertEqual(result['receipt']['status'], 'verified')
            self.assertEqual((self.install / 'repair-test-release.py').stat().st_mode & 0o777, 0o555)
            self.assertEqual(json.loads((self.install / 'installation.json').read_bytes())['lock_sha256'], self.new['lock_sha256'])
            self.assert_app_unchanged()
            self.assertEqual(self.apply(), result)

    def test_interrupted_replacement_resumes_only_known_files(self):
        original = self.m.replace_known
        def interrupt(*args, **kwargs):
            original(*args, **kwargs)
            if args[1] == self.install / 'tat-deploy-test.py': raise RuntimeError('simulated power loss')
        with self.host_boundary():
            with mock.patch.object(self.m, 'replace_known', side_effect=interrupt), self.assertRaises(RuntimeError): self.apply()
            self.assertEqual((self.install / 'installation.json').read_bytes(), self.accepted)
            self.assertEqual(self.apply()['receipt']['status'], 'verified')
            self.assert_app_unchanged()

    def test_unknown_installed_bytes_are_not_overwritten(self):
        self.write(self.install / 'tat-deploy-test.py', b'unknown', 0o555)
        with self.host_boundary(), self.assertRaisesRegex(self.m.UpgradeError, 'INSTALLED_DRIFT'): self.apply()
        self.assertEqual((self.install / 'tat-deploy-test.py').read_bytes(), b'unknown')
        self.assertFalse(self.state.exists())

    def test_policy_change_and_wrong_transaction_pin_block_before_mutation(self):
        with self.host_boundary():
            raw = self.new['files']['host-policy.json']
            self.new['files']['host-policy.json'] += b'\n'
            with self.assertRaisesRegex(self.m.UpgradeError, 'POLICY_CHANGE'): self.apply()
            self.new['files']['host-policy.json'] = raw
            self.expected['failed_transaction_sha256'] = 'f'*64
            with self.assertRaisesRegex(self.m.UpgradeError, 'FAILED_TRANSACTION'): self.apply()
        self.assertFalse(self.state.exists())
        self.assert_app_unchanged()

    def test_non_probe_or_noncanonical_transaction_is_rejected(self):
        for changed in (self.tx.replace(b'"probe"', b'"starting_runtime"'), b' '+self.tx):
            self.write(self.host.TRANSACTION_PATH, changed, 0o600)
            self.expected['failed_transaction_sha256'] = hashlib.sha256(changed).hexdigest()
            with self.host_boundary(), self.assertRaises(self.m.UpgradeError): self.apply()
            self.assertFalse(self.state.exists())

    def test_existing_helper_and_foreign_journal_are_never_adopted(self):
        self.write(self.install / 'repair-test-release.py', self.new['files']['host/repair-test-release.py'], 0o555)
        with self.host_boundary(), self.assertRaisesRegex(self.m.UpgradeError, 'INSTALLED_DRIFT'): self.apply()
        (self.install / 'repair-test-release.py').unlink()
        with self.host_boundary(): self.apply()
        self.expected['target_sha256'] = 'f'*64
        with self.host_boundary(), self.assertRaisesRegex(self.m.UpgradeError, 'JOURNAL'): self.apply()

    def test_tampered_snapshot_blocks_without_replacing_control_files(self):
        tx = json.loads(self.tx)
        dump = self.app / 'backups/releases' / tx['snapshot'] / 'database.dump'
        dump.write_bytes(b'PGDMP-tampered')
        with self.host_boundary(), self.assertRaises(self.m.UpgradeError): self.apply()
        self.assertEqual((self.install / 'installation.json').read_bytes(), self.accepted)
        self.assertFalse(self.state.exists())


    def local_arguments(self):
        self.assertTrue(LOCAL.is_file(), 'The local upgrade entry is missing')
        entry = load(LOCAL)
        def private(name, raw):
            p = self.root / name; self.write(p, raw, 0o600); return p
        key = private('key', b'only synthetic SSH key bytes')
        hosts = private('known-hosts', b'fixture.invalid ssh-ed25519 synthetic')
        target = private('target.json', self.m.canonical({'host':'fixture.invalid','port':22,'user':'ubuntu','identity_file':str(key),'known_hosts_file':str(hosts)}))
        accepted = private('old-accepted.json', self.accepted)
        output = self.root / 'evidence'
        args = ['--old-bundle-dir',str(self.old_dir),'--old-lock-sha256',self.old['lock_sha256'],
                '--bundle-dir',str(self.new_dir),'--lock-sha256',self.new['lock_sha256'],
                '--accepted-installation',str(accepted),'--failed-transaction-sha256',self.expected['failed_transaction_sha256'],
                '--target',str(target),'--evidence-dir',str(output)]
        return entry,args,output

    def test_local_preview_is_offline_and_does_not_create_evidence(self):
        entry,args,output = self.local_arguments()
        text = io.StringIO()
        with mock.patch.object(entry.subprocess,'run',side_effect=AssertionError('preview connected')), contextlib.redirect_stdout(text):
            self.assertEqual(entry.main(args),0)
        self.assertEqual(json.loads(text.getvalue())['status'],'preview')
        self.assertFalse(output.exists())

    def test_local_apply_strict_transport_full_readback_and_new_accepted_receipt(self):
        entry,args,output = self.local_arguments()
        def transport(argv, **options):
            self.assertIn('StrictHostKeyChecking=yes',argv)
            self.assertIn('BatchMode=yes',argv)
            remote=shlex.split(argv[-1]); self.assertEqual(remote[:3],['/usr/bin/sudo','-n','--'])
            expected=json.loads(remote[-1])
            self.expected=expected
            with self.host_boundary(): result=self.apply()
            return subprocess.CompletedProcess(argv,0,self.m.canonical(result),b'')
        with mock.patch.object(entry.subprocess,'run',side_effect=transport), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(entry.main(args+['--apply']),0)
            self.assertEqual(entry.main(args+['--apply']),0)
        new_receipt=(output/'accepted-installation.json').read_bytes()
        self.assertEqual(json.loads(new_receipt)['lock_sha256'],self.new['lock_sha256'])
        self.assertEqual((self.root/'old-accepted.json').read_bytes(),self.accepted)
        self.assertEqual((output/'accepted-installation.json').stat().st_mode & 0o777,0o600)
        self.assert_app_unchanged()

    def test_local_incomplete_ssh_preserves_intent_and_never_retries(self):
        entry,args,output = self.local_arguments()
        with mock.patch.object(entry.subprocess,'run',side_effect=subprocess.TimeoutExpired('ssh',10)) as call:
            with self.assertRaisesRegex(entry.UpgradeError,'SSH_INCOMPLETE'): entry.main(args+['--apply'])
        self.assertEqual(call.call_count,1)
        self.assertTrue((output/'upgrade-inputs.json').is_file())
        self.assertFalse((output/'accepted-installation.json').exists())

    def test_local_rejects_missing_helper_readback_after_host_success(self):
        entry,args,output = self.local_arguments()
        def transport(argv,**options):
            self.expected=json.loads(shlex.split(argv[-1])[-1])
            with self.host_boundary(): result=self.apply()
            del result['readback']['repair-test-release.py']
            return subprocess.CompletedProcess(argv,0,self.m.canonical(result),b'')
        with mock.patch.object(entry.subprocess,'run',side_effect=transport):
            with self.assertRaisesRegex(entry.UpgradeError,'READBACK'): entry.main(args+['--apply'])
        self.assertFalse((output/'accepted-installation.json').exists())

    def test_known_journal_stage_resumes_but_unknown_stage_is_not_removed(self):
        original=self.m.replace_known
        def interrupt(host,path,old,new,mode):
            if path==self.state/'journal.json' and json.loads(new)['phase']=='prepared':
                staged=path.with_name('.'+path.name+'.upgrade-'+hashlib.sha256(new).hexdigest()[:24])
                self.write(staged,new,mode)
                raise RuntimeError('journal rename interrupted')
            return original(host,path,old,new,mode)
        with self.host_boundary():
            with mock.patch.object(self.m,'replace_known',side_effect=interrupt),self.assertRaises(RuntimeError): self.apply()
            self.assertEqual(self.apply()['receipt']['status'],'verified')
            foreign=self.state/'unknown'; self.write(foreign,b'unknown',0o600)
            with self.assertRaisesRegex(self.m.UpgradeError,'UNKNOWN'): self.apply()
            self.assertEqual(foreign.read_bytes(),b'unknown')


    def test_interruption_after_installation_receipt_only_needs_verified_resume(self):
        original=self.m.replace_known
        def interrupt(*args,**kwargs):
            original(*args,**kwargs)
            if args[1]==self.install/'installation.json': raise RuntimeError('receipt written; connection lost')
        with self.host_boundary():
            with mock.patch.object(self.m,'replace_known',side_effect=interrupt),self.assertRaises(RuntimeError): self.apply()
            self.assertEqual(json.loads((self.install/'installation.json').read_bytes())['lock_sha256'],self.new['lock_sha256'])
            self.assertEqual(self.apply()['receipt']['status'],'verified')
            self.assert_app_unchanged()

    def test_unsafe_metadata_and_unknown_control_file_are_rejected(self):
        (self.install/'tat-deploy-test.py').chmod(0o755)
        with self.host_boundary(),self.assertRaisesRegex(self.m.UpgradeError,'FILE_UNSAFE'): self.apply()
        (self.install/'tat-deploy-test.py').chmod(0o555)
        self.write(self.install/'unrecognized-control',b'unknown',0o444)
        with self.host_boundary(),self.assertRaisesRegex(self.m.UpgradeError,'UNKNOWN'): self.apply()
        self.assertFalse(self.state.exists())

    def test_only_captured_old_and_new_complete_bundles_reach_apply(self):
        entry,args,_output=self.local_arguments()
        parsed=SimpleNamespace(old_bundle_dir=self.old_dir,old_lock_sha256=self.old['lock_sha256'],bundle_dir=self.new_dir,
                               lock_sha256=self.new['lock_sha256'],accepted_installation=self.root/'old-accepted.json',
                               failed_transaction_sha256=self.expected['failed_transaction_sha256'],target=self.root/'target.json',evidence_dir=self.root/'evidence')
        setup,_driver,_old,_new,expected,_target,_evidence,files=entry.prepare(parsed)
        with mock.patch.object(self.m.os,'geteuid',return_value=0),mock.patch.object(self.m,'apply_upgrade',return_value={'checked':True}) as apply:
            self.assertEqual(self.m.upgrade_archive(setup.archive_bytes(files),expected),{'checked':True})
            self.assertEqual(apply.call_count,1)
            changed=dict(files);changed['new/host/repair-test-release.py']+=b'unknown'
            with self.assertRaisesRegex(self.m.UpgradeError,'ARTIFACT'): self.m.upgrade_archive(setup.archive_bytes(changed),expected)
            changed=dict(files);changed['unknown']=b'unknown'
            with self.assertRaisesRegex(self.m.UpgradeError,'ARCHIVE'): self.m.upgrade_archive(setup.archive_bytes(changed),expected)
            self.assertEqual(apply.call_count,1)
        self.assertFalse(self.state.exists())

    def test_archive_symlink_rejected_before_host_apply(self):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w') as archive:
            item=tarfile.TarInfo('new/host/upgrade-controller.py');item.type=tarfile.SYMTYPE;item.linkname='/tmp/foreign';archive.addfile(item)
        with mock.patch.object(self.m.os,'geteuid',return_value=0),mock.patch.object(self.m,'apply_upgrade',side_effect=AssertionError('invalid archive reached host')):
            with self.assertRaisesRegex(self.m.UpgradeError,'ARCHIVE'): self.m.upgrade_archive(output.getvalue(),self.expected)


    def test_required_container_health_cannot_be_missing(self):
        with self.host_boundary():
            docker=self.m.runtime_docker.return_value
            inspect=docker.inspect.side_effect
            def no_health(name):
                value=inspect(name);value['health']=None;return value
            docker.inspect.side_effect=no_health
            with self.assertRaisesRegex(self.m.UpgradeError,'RUNTIME_UNHEALTHY'): self.apply()
        self.assertFalse(self.state.exists())

    def test_production_is_rejected_before_installed_files_are_read(self):
        self.old['policy']['environment']=self.new['policy']['environment']='production'
        with self.host_boundary(),self.assertRaisesRegex(self.m.UpgradeError,'TEST_ONLY'): self.apply()
        self.assertFalse(self.state.exists())


if __name__ == '__main__': unittest.main()
