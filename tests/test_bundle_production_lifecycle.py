"""Real Node/OpenSSL signatures, files and flock; transaction/Docker effects are simulated.

The shared core's own production callback seam is exercised separately in
test_bundle_production_core.py. No cloud, real credentials or live containers.
"""
import copy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_bundle_production import ROOT, production

CONTRACT = (ROOT / 'assets/cnb-tcr-tat/ci/production-contract.mjs').as_uri()
FIXTURE = (ROOT / 'tests/bundle-production-fixture.mjs').as_uri()
OPENSSL = next((p for p in ['/opt/homebrew/bin/openssl', '/usr/bin/openssl'] if Path(p).exists()), None)


def put(path, raw, mode=0o600):
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(mode)


class TransactionBoundary:
    """Small fake of core effects, with real private state and a real lock."""
    RELEASE_SCHEMA_V2 = 'cnb-test-release/v2'
    SNAPSHOT_MANIFEST = 'snapshot.json'

    def __init__(self, directory, fixture, now):
        self.APP_DIR = directory / 'app'
        self.APP_DIR.mkdir(mode=0o750)
        self.ENV_PATH = self.APP_DIR / '.env'
        self.COMPOSE_PATH = self.APP_DIR / 'docker-compose.yml'
        self.RELEASE_PATH = self.APP_DIR / '.release.json'
        self.LOCK_PATH = directory / 'release.lock'
        self.POLICY = dict(project='sample', environment='production', services=fixture['config']['services'],
                           database={'container': 'sample-production-postgres'}, networks=['sample-production'])
        self.CONTROLLER_ID = fixture['config']['controller_id']
        self.SERVICES = tuple(self.POLICY['services'])
        self.CONTAINERS = {role: 'sample-production-' + role for role in self.SERVICES}
        self.PUBLIC_PROBES = tuple(sorted(p['url'] for p in fixture['config']['probes']))
        self.now, self.fixture, self.mutations = now, fixture, 0
        self.fail, self.interrupt_after_record = False, False
        self.preflight_hook = lambda: None
        put(self.ENV_PATH, b'NONSECRET_TEST_VALUE=fixture\n')
        put(self.COMPOSE_PATH, b'services: {}\n', 0o644)
        put(self.RELEASE_PATH, production.canonical({'schema': 'fixture-empty-baseline'}))
        put(self.LOCK_PATH, b'')

    def _fsync_directory(self, path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write_new(self, path, raw, mode, uid, gid):
        put(path, raw, mode)

    def _atomic_write(self, path, raw, mode, uid, gid):
        replacement = path.with_name(path.name + '.new')
        put(replacement, raw, mode)
        os.replace(replacement, path)

    def _load_private_record(self, path, **_kwargs):
        raw = production.read_file(path, 0o600, os.geteuid(), os.getegid())
        return raw, json.loads(raw)

    def load_snapshot_manifest(self, path, **_kwargs):
        value = json.loads((path / self.SNAPSHOT_MANIFEST).read_bytes())
        if production.sha((path / 'database.dump').read_bytes()) != value['files']['database.dump']['sha256']:
            raise ValueError('fixture archive integrity rejected')
        return value

    def _docker_prefix(self):
        return ['docker']

    def _run(self, args, **_kwargs):
        return b'sample-production-postgres\n' if args[1] == 'ps' else b'fixed-fixture-runtime-identity\n'

    def _read_controller_compose(self):
        return b'services: {}\n'

    def update_env_text(self, text, _images):
        return text

    def _preflight(self, *_args):
        self.preflight_hook()

    def _assert_empty_baseline_runtime(self, *_args):
        pass

    def _assert_release_unblocked(self):
        pass

    def deploy(self, *, release_override, authorize_locked):
        with self.LOCK_PATH.open('r+b') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            cached = authorize_locked(release_override)
            if cached is not None:
                return 0
            self.mutations += 1
            if self.fail:
                print('{"schema":"cnb-deploy-result/v1","status":"failed","phase":"backup","reason":"database_backup_failed"}')
                return 1
            snapshot = self.APP_DIR / 'backups/releases/fixture-snapshot'
            snapshot.mkdir(parents=True, mode=0o700)
            put(snapshot / 'database.dump', b'fixture-archive')
            manifest = {'files': {'database.dump': {'sha256': production.sha(b'fixture-archive')}}}
            put(snapshot / self.SNAPSHOT_MANIFEST, production.canonical(manifest))
            config = self.fixture['config']
            record = dict(schema=self.RELEASE_SCHEMA_V2, git_sha=release_override['git_sha'], build_id=release_override['build_id'],
                          controller=self.CONTROLLER_ID, images=release_override['images'], status='passed',
                          controller_program_sha256=config['controller_program_sha256'], controller_compose_sha256=config['controller_compose_sha256'],
                          deployed_at=production.timestamp(self.now()), snapshot=snapshot.name,
                          snapshot_manifest_sha256=production.sha(production.canonical(manifest)), probes=list(self.PUBLIC_PROBES))
            self._atomic_write(self.RELEASE_PATH, production.canonical(record), 0o600, os.geteuid(), os.getegid())
            if self.interrupt_after_record:
                raise OSError('simulated interruption after verified core success')
            return 0


class ProductionLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='cnb-production-test-keys-')
        cls.key = Path(cls.keys.name) / 'approval.pem'
        subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'ED25519', '-out', str(cls.key)], check=True, capture_output=True)
        cls.key.chmod(0o600)
        cls.public = subprocess.run([OPENSSL, 'pkey', '-in', str(cls.key), '-pubout'], check=True, capture_output=True).stdout

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cnb-production-lifecycle-')
        self.addCleanup(self.tmp.cleanup)
        self.clock = int(datetime(2026, 9, 7, tzinfo=timezone.utc).timestamp())
        self.time_patch = mock.patch.object(production.time, 'time', side_effect=lambda: self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.openssl_patch = mock.patch.object(production, 'OPENSSL', OPENSSL)
        self.openssl_patch.start()
        self.addCleanup(self.openssl_patch.stop)

    def setup_fixture(self, names=('web',), directory=None):
        source = "const {productionFixture}=await import(process.argv[1]);const f=productionFixture(JSON.parse(process.argv[2]));process.stdout.write(JSON.stringify({candidate:f.candidate,config:f.config,candidateConfig:f.candidateConfig}));"
        fixture = json.loads(subprocess.run(['node', '--input-type=module', '-e', source, FIXTURE, json.dumps(names)], check=True, capture_output=True).stdout)
        fixture['config']['approval_public_key_sha256'] = production.sha(self.public)
        core = TransactionBoundary(Path(directory or self.tmp.name), fixture, lambda: self.clock)
        authority = dict(schema='cnb-production-authority/v1', project='sample', environment='production',
                         controller_program_sha256=fixture['config']['controller_program_sha256'],
                         controller_compose_sha256=fixture['config']['controller_compose_sha256'],
                         host_policy_sha256=fixture['config']['policy_sha256'], approval_public_key_sha256=production.sha(self.public))
        runner = production.ProductionRelease(core, authority, production.canonical(authority), self.public, fixture['config']['production_entry_sha256'])
        raw = production.canonical(fixture['candidate'])
        candidate = production.validate_candidate(raw, core.POLICY)
        return core, runner, candidate, raw

    def sign(self, payload):
        source = "const fs=await import('node:fs');const crypto=await import('node:crypto');const c=await import(process.argv[1]);const payload=JSON.parse(fs.readFileSync(0,'utf8'));const key=crypto.createPrivateKey(fs.readFileSync(process.argv[2]));process.stdout.write(c.canonicalBytes(c.signApproval(payload,key)));"
        result = subprocess.run(['node', '--input-type=module', '-e', source, CONTRACT, str(self.key)], input=production.canonical(payload), capture_output=True, check=True)
        return production.parse_canonical(result.stdout)

    def approval(self, runner, candidate, raw, ready, **changes):
        payload = dict(schema='cnb-production-approval/v1', project='sample', environment='production', authorize='production-apply', approval_id='a'*32,
                       candidate_tag=candidate['candidate_tag'], candidate_manifest_sha256=candidate['manifest_sha256'], candidate_bytes_sha256=production.sha(raw),
                       application_commit=candidate['application_commit'], build_id=candidate['build_id'], authority_sha256=runner.authority_hash,
                       prepared_sha256=ready['prepared_sha256'], previous_release_sha256=ready['previous_release_sha256'],
                       issued_at=production.timestamp(self.clock), expires_at=production.timestamp(self.clock+3600))
        payload.update(changes)
        return self.sign(payload)

    def ready(self, runner, candidate, raw):
        with runner.lock():
            return runner.readiness_locked(candidate, raw)

    def test_real_node_signature_python_openssl_one_and_three_services(self):
        for names in [('web',), ('api', 'h5', 'ocr')]:
            with self.subTest(services=len(names)):
                # Each iteration has independent real filesystem/lock state.
                with tempfile.TemporaryDirectory(dir=self.tmp.name) as directory:
                    core, runner, candidate, raw = self.setup_fixture(names, directory)
                    ready = self.ready(runner, candidate, raw)
                    envelope = self.approval(runner, candidate, raw, ready)
                    self.assertEqual(production.verify_approval_signature(envelope, self.public)['candidate_bytes_sha256'], production.sha(raw))
                    result = runner.apply(candidate, raw, envelope)
                    self.assertEqual(result['release']['images'], candidate['services'])
                    self.assertEqual(result['release']['container_count'], len(names))
                    self.assertEqual(result['release']['probe_count'], len(names))
                    before = (core.APP_DIR / '.production' / ('execution-' + 'a'*32 + '.json')).read_bytes()
                    self.assertEqual(runner.apply(candidate, raw, envelope), result)
                    self.assertEqual(core.mutations, 1)
                    self.assertEqual((runner.state / ('execution-' + 'a'*32 + '.json')).read_bytes(), before)

    def test_signature_wrong_target_expiry_and_candidate_tampering_never_mutate(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner, candidate, raw)
        for changes in ({'authority_sha256':'f'*64}, {'candidate_bytes_sha256':'e'*64}, {'project':'other'},
                        {'issued_at':production.timestamp(self.clock-7200),'expires_at':production.timestamp(self.clock-3600)}):
            with self.subTest(changes=changes), self.assertRaises(production.ProductionError):
                runner.apply(candidate, raw, self.approval(runner,candidate,raw,ready,**changes))
        envelope = self.approval(runner,candidate,raw,ready)
        envelope['signature_b64url'] = 'A'*86
        with self.assertRaisesRegex(production.ProductionError, 'signature_rejected'):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(core.mutations,0)
        self.assertFalse(list(runner.state.glob('execution-*')))

    def test_expiry_during_preflight_stops_before_pending_or_mutation(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        envelope = self.approval(runner,candidate,raw,ready)
        core.preflight_hook = lambda: setattr(self,'clock',self.clock+3601)
        with self.assertRaisesRegex(production.ProductionError,'expired'):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(core.mutations,0)
        self.assertFalse(list(runner.state.glob('execution-*')))

    def test_failed_core_keeps_pending_and_blocks_new_readiness_and_retry(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        envelope = self.approval(runner,candidate,raw,ready)
        core.fail = True
        with self.assertRaisesRegex(production.ProductionError,'pending_review'):
            runner.apply(candidate,raw,envelope)
        with self.assertRaisesRegex(production.ProductionError,'pending_review'):
            self.ready(runner,candidate,raw)
        with self.assertRaisesRegex(production.ProductionError,'reconcile_required'):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(core.mutations,1)
        self.assertEqual(production.parse_canonical(next(runner.state.glob('execution-*')).read_bytes())['status'],'pending')

    def test_success_before_audit_interruption_reconciles_exact_release_without_redeploy(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        envelope = self.approval(runner,candidate,raw,ready)
        core.interrupt_after_record = True
        with self.assertRaises(OSError):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(production.parse_canonical(next(runner.state.glob('execution-*')).read_bytes())['status'],'pending')
        result = runner.apply(candidate,raw,envelope)
        self.assertEqual(result['status'],'passed')
        self.assertEqual(core.mutations,1)
        self.assertEqual(production.parse_canonical(next(runner.state.glob('execution-*')).read_bytes())['status'],'complete')

    def test_host_drift_and_release_lock_contention_block_apply(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        envelope = self.approval(runner,candidate,raw,ready)
        core.ENV_PATH.write_bytes(b'NONSECRET_TEST_VALUE=changed\n')
        with self.assertRaisesRegex(production.ProductionError,'host_drift'):
            runner.apply(candidate,raw,envelope)
        with runner.lock(), self.assertRaises(BlockingIOError):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(core.mutations,0)

    def test_unknown_completed_record_is_not_treated_as_resolved_history(self):
        _core, runner, candidate, raw = self.setup_fixture()
        self.ready(runner,candidate,raw)
        runner.write('execution-'+'b'*32+'.json', {'status':'complete'})
        with self.assertRaises(production.ProductionError):
            self.ready(runner,candidate,raw)

    def test_world_readable_release_lock_is_rejected(self):
        core, runner, candidate, raw = self.setup_fixture()
        core.LOCK_PATH.chmod(0o644)
        with self.assertRaises(production.ProductionError):
            self.ready(runner,candidate,raw)

    def test_modified_prepared_receipt_is_rejected_even_when_operator_signed_its_new_hash(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        prepared = production.parse_canonical((runner.state / ('prepared-'+ready['prepared_sha256']+'.json')).read_bytes())
        prepared['receipt']['images'] = {'unapproved':'registry.example/team/unapproved@sha256:'+'d'*64}
        changed_hash = production.sha(production.canonical(prepared))
        runner.write('prepared-'+changed_hash+'.json', prepared)
        changed_ready = dict(ready, prepared_sha256=changed_hash)
        with self.assertRaisesRegex(production.ProductionError,'prepared_scope'):
            runner.apply(candidate,raw,self.approval(runner,candidate,raw,changed_ready))
        self.assertEqual(core.mutations,0)

    def test_completed_receipt_tampering_or_new_live_record_never_justifies_cached_success(self):
        core, runner, candidate, raw = self.setup_fixture()
        ready = self.ready(runner,candidate,raw)
        envelope = self.approval(runner,candidate,raw,ready)
        runner.apply(candidate,raw,envelope)
        path = next(runner.state.glob('execution-*'))
        original = production.parse_canonical(path.read_bytes())
        changed = copy.deepcopy(original)
        changed['result']['release']['database_backup_sha256']='f'*64
        path.write_bytes(production.canonical(changed))
        with self.assertRaisesRegex(production.ProductionError,'replay_receipt_changed'):
            runner.apply(candidate,raw,envelope)
        path.write_bytes(production.canonical(original))
        record = json.loads(core.RELEASE_PATH.read_bytes())
        record['build_id']='cnb-unapproved-456'
        core.RELEASE_PATH.write_bytes(production.canonical(record))
        with self.assertRaisesRegex(production.ProductionError,'reconcile_required'):
            runner.apply(candidate,raw,envelope)
        self.assertEqual(core.mutations,1)

    def test_candidate_rehash_cannot_make_missing_or_mutable_images_and_false_evidence_valid(self):
        core, _runner, candidate, _raw = self.setup_fixture(('api','h5','ocr'))
        for problem in ('missing', 'mutable', 'environment', 'evidence'):
            changed = copy.deepcopy(candidate)
            if problem == 'missing':
                del changed['services']['api']
            if problem == 'mutable':
                changed['services']['api']='registry.example/team/sample-api:latest'
            if problem == 'environment':
                changed['environment']='production'
            if problem == 'evidence':
                changed['evidence']['runtime']['container_count']=1
            del changed['manifest_sha256']
            changed['manifest_sha256']=production.sha(production.canonical(changed)[:-1])
            with self.subTest(problem=problem), self.assertRaises(production.ProductionError):
                production.validate_candidate(production.canonical(changed),core.POLICY)


if __name__ == '__main__':
    unittest.main()
