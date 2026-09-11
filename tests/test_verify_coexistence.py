"""Read-only shared-host release comparison and evidence boundary tests."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).parents[1] / 'scripts/verify-coexistence.py'
CADDY = SCRIPT.parents[1] / 'assets/cnb-tcr-tat/host/configure-native-caddy.py'


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value, mode=0o600):
    path.write_bytes(value if isinstance(value, bytes) else encode(value))
    path.chmod(mode)
    return {'path': str(path), 'sha256': digest(path.read_bytes())}


def container(name, number=1):
    return {'name': name, 'id': str(number) * 64, 'image': 'sha256:' + 'a' * 64,
            'image_reference': 'registry.example.invalid/demo/app@sha256:' + 'b' * 64,
            'started_at': '2026-09-11T01:00:00Z', 'restart_count': 0,
            'status': 'running', 'health': 'healthy', 'oom_killed': False,
            'memory_bytes': 128 * 1024 * 1024, 'nano_cpus': 500000000,
            'cpu_period': 0, 'cpu_quota': 0, 'network_mode': 'apps',
            'networks': ['apps'], 'port_bindings': {}, 'mounts': []}


def fixture(root, roles=('api', 'web')):
    target = write(root / 'target.json', {'host': 'host.example.invalid', 'port': 22, 'user': 'ubuntu',
        'identity_file': str(root / 'identity'), 'known_hosts_file': str(root / 'known_hosts')})
    write(root / 'identity', b'PRIVATE KEY MUST NEVER ENTER OUTPUT')
    write(root / 'known_hosts', b'host.example.invalid ssh-ed25519 SAFE')
    service_map, observed = {}, {'neighbor-production-db': container('neighbor-production-db'),
                                'renamed-production-store': container('renamed-production-store', 2)}
    for role in roles:
        name = 'renamed-production-' + role
        observed[name] = container(name, 3)
        service_map[role] = {'container': name, 'resource_limits': {'memory_bytes': 134217728, 'cpu_millis': 500},
                            'networks': ['apps'], 'network_mode': 'apps', 'port_bindings': {}, 'mounts': [],
                            'health': 'healthy', 'max_restart_count': 0}
    service_map['store'] = {'container': 'renamed-production-store', 'resource_limits': {'memory_bytes': 134217728, 'cpu_millis': 500},
                          'networks': ['apps'], 'network_mode': 'apps', 'port_bindings': {}, 'mounts': [],
                          'health': 'healthy', 'max_restart_count': 0}
    probes = [{'project': 'renamed', 'service': role, 'url': f'https://{role}.example.invalid/release.json',
               'api_envelope': False, 'application_commit': 'c' * 40, 'build_id': 'cnb-new-build'} for role in roles]
    probes.append({'project': 'neighbor', 'service': 'api', 'url': 'https://neighbor.example.invalid/release.json',
                   'api_envelope': True, 'application_commit': 'd' * 40, 'build_id': 'cnb-old-build'})
    policy = write(root / 'policy.json', {'schema': 'cnb-devops-host-policy/v1', 'project': 'renamed',
        'environment': 'production', 'services': {role: {'container': service_map[role]['container'],
            'image_repository': 'registry.example.invalid/demo/app'} for role in roles},
        'database': {'container': 'renamed-production-store'},
        'identity_probes': [{key: value for key, value in p.items() if key in ('service', 'url', 'api_envelope')}
                            for p in probes if p['project'] == 'renamed'],
        'availability_probes': ['https://api.example.invalid/health']})
    candidate = write(root / 'candidate.json', {'application_commit': 'c' * 40, 'build_id': 'cnb-new-build',
        'services': {role: observed[service_map[role]['container']]['image_reference'] for role in roles}})
    old = {name: copy.deepcopy(observed[name]) for name in ('neighbor-production-db', 'renamed-production-store')}
    files = {'/opt/cnb-devops/neighbor/production/v1/host-policy.json': {'sha256': 'e' * 64, 'uid': 0, 'gid': 0, 'mode': 292},
             '/opt/cnb-devops/renamed/production/v1/host-policy.json': {'sha256': policy['sha256'], 'uid': 0, 'gid': 0, 'mode': 292}}
    caddy = {'schema': 'cnb-native-caddy-inventory/v1', 'status': 'verified', 'main_sha256': 'a' * 64,
        'base_sha256': 'b' * 64, 'running_sha256': 'c' * 64, 'sites': [
            {'project': p, 'environment': 'production', 'path': '/etc/caddy/cnb-devops/' + p + '-production.caddy',
             'site_sha256': 'f' * 64, 'policy_sha256': policy['sha256'] if p == 'renamed' else 'e' * 64,
             'domains': [p + '.example.invalid'], 'loopback_ports': [18001 + i]}
            for i, p in enumerate(('neighbor', 'renamed'))]}
    baseline = write(root / 'baseline.json', {'schema': 'cnb-coexistence-baseline/v1', 'source_target_sha256': target['sha256'],
                                             'containers': old, 'files': files, 'caddy': caddy})
    identities = []
    for probe in probes:
        identity = {'schema': 'cnb-release-identity/v1', 'service': probe['service'],
                    'git_sha': probe['application_commit'], 'build_id': probe['build_id']}
        identities.append({'project': probe['project'], 'service': probe['service'], 'url': probe['url'],
                           'http_status': 200, 'identity': identity, 'response_sha256': '9' * 64})
    observation = write(root / 'input-observation.json', {'schema': 'cnb-coexistence-observation/v1', 'status': 'collected',
        'root_gate_verified': True, 'source_target_sha256': target['sha256'], 'observed_at': '2026-09-11T02:00:00Z',
        'containers': observed, 'files': files, 'caddy': caddy, 'public_identities': identities,
        'availability': [{'url': 'https://api.example.invalid/health', 'http_status': 200, 'ok': True}]})
    spec = {'schema': 'cnb-coexistence-spec/v1', 'project': 'renamed', 'environment': 'production',
            'application_commit': 'c' * 40, 'build_id': 'cnb-new-build', 'target': target, 'policy': policy,
            'candidate': candidate, 'baseline': baseline, 'evidence_dir': str(root / 'proof'), 'services': service_map,
            'protected_containers': list(old), 'protected_files': list(files), 'identity_probes': probes,
            'availability_probes': ['https://api.example.invalid/health'], 'observation': observation,
            'caddy_helper_sha256': digest(CADDY.read_bytes())}
    write(root / 'spec.json', spec)
    return spec


class CoexistenceTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'reusable coexistence verifier must exist')
        module_spec = importlib.util.spec_from_file_location('coexistence', SCRIPT)
        self.m = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(self.m)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.spec = fixture(self.root)

    def prepare(self):
        write(self.root / 'spec.json', self.spec)
        return self.m.prepare(self.root / 'spec.json')

    def observation(self):
        return json.loads((self.root / 'input-observation.json').read_bytes())

    def test_dynamic_roles_preview_performs_no_network_or_writes(self):
        for roles in (('one',), ('one', 'two', 'three', 'four')):
            self.spec = fixture(self.root, roles)
            with mock.patch.object(self.m, 'collect', side_effect=AssertionError('network during preview')):
                with mock.patch('sys.stdout', new_callable=io.StringIO) as output:
                    self.assertEqual(self.m.main(['--spec', str(self.root / 'spec.json')]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['status'], 'preview')
            self.assertFalse(result['network_calls'])
            self.assertEqual(set(result['application_services']), set(roles))
            self.assertFalse((self.root / 'proof').exists())

    def test_expected_new_application_accepts_different_container_identity(self):
        prepared = self.prepare()
        observation = self.observation()
        observation['containers']['renamed-production-api']['id'] = 'f' * 64
        observation['containers']['renamed-production-api']['started_at'] = '2026-09-11T02:00:00Z'
        checks = self.m.compare(prepared, observation)
        self.assertTrue(checks)
        self.assertTrue(all(checks.values()), [k for k, v in checks.items() if not v])

    def test_neighbor_and_own_infrastructure_cannot_change(self):
        prepared = self.prepare()
        mutations = {'id': 'f' * 64, 'started_at': '2026-09-11T02:00:00Z', 'restart_count': 1,
            'image': 'sha256:' + 'f' * 64, 'image_reference': 'registry.example.invalid/other@sha256:' + 'f' * 64,
            'mounts': [{'type': 'bind', 'name': None, 'source': '/new', 'destination': '/data', 'rw': True}],
            'memory_bytes': 0, 'network_mode': 'host', 'port_bindings': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '80'}]}}
        for name in self.spec['protected_containers']:
            for key, value in mutations.items():
                with self.subTest(container=name, changed=key):
                    observation = self.observation()
                    observation['containers'][name][key] = value
                    self.assertFalse(all(self.m.compare(prepared, observation).values()))

    def test_controlfile_and_caddy_changes_fail(self):
        prepared = self.prepare()
        for area, key, value in [('files', self.spec['protected_files'][0], {'sha256': 'f' * 64, 'uid': 0, 'gid': 0, 'mode': 292}),
                                 ('caddy', 'base_sha256', 'f' * 64), ('caddy', 'running_sha256', 'f' * 64),
                                 ('caddy', 'main_sha256', 'f' * 64), ('caddy', 'sites', [])]:
            with self.subTest(area=area, key=key):
                observation = self.observation()
                observation[area][key] = value
                self.assertFalse(all(self.m.compare(prepared, observation).values()))

    def test_candidate_runtime_health_resources_network_and_http_fail_closed(self):
        prepared = self.prepare()
        for key, value in {'image_reference': 'registry.example.invalid/demo/app:latest', 'health': None,
            'status': 'exited', 'oom_killed': True, 'restart_count': 1, 'memory_bytes': 0, 'nano_cpus': 0,
            'networks': ['other'], 'mounts': [{'type': 'bind', 'name': None, 'source': '/etc', 'destination': '/data', 'rw': False}],
            'port_bindings': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '80'}]}}.items():
            with self.subTest(changed=key):
                observation = self.observation()
                observation['containers']['renamed-production-api'][key] = value
                self.assertFalse(all(self.m.compare(prepared, observation).values()))
        for area in ('public_identities', 'availability'):
            observation = self.observation()
            observation[area] = []
            self.assertFalse(all(self.m.compare(prepared, observation).values()))
        observation = self.observation()
        observation['public_identities'][0]['identity']['git_sha'] = 'f' * 40
        self.assertFalse(all(self.m.compare(prepared, observation).values()))

    def test_fixture_receipt_is_explicitly_historic_and_immutable(self):
        with mock.patch.object(self.m, 'collect', side_effect=AssertionError('fixture contacted host')):
            with mock.patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(self.m.main(['--spec', str(self.root / 'spec.json'), '--apply']), 0)
        receipt_path = self.root / 'proof/coexistence.receipt.json'
        receipt_raw = receipt_path.read_bytes()
        receipt = json.loads(receipt_raw)
        self.assertEqual(receipt['status'], 'verified')
        self.assertEqual(receipt['schema'], 'cnb-coexistence-verification/v1')
        self.assertEqual(receipt['observation_source'], 'fixture')
        self.assertIsNone(receipt['collection_started_at'])
        self.assertEqual(receipt['observed_at'], '2026-09-11T02:00:00Z')
        self.assertEqual(receipt['application_commit'], 'c' * 40)
        self.assertEqual(receipt['evidence']['observation']['path'], 'host-observation.json')
        self.assertEqual(receipt['observation_sha256'], digest((self.root / 'proof/host-observation.json').read_bytes()))
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'proof').stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(ValueError, 'OUTPUT_EXISTS'):
            self.m.main(['--spec', str(self.root / 'spec.json'), '--apply'])
        self.assertEqual(receipt_raw, receipt_path.read_bytes())

    def test_app_protected_overlap_and_missing_policy_role_rejected(self):
        self.spec['protected_containers'].append('renamed-production-api')
        with self.assertRaises(ValueError): self.prepare()
        self.spec = fixture(self.root)
        del self.spec['services']['api']
        with self.assertRaises(ValueError): self.prepare()

    def test_strict_paths_targets_pins_and_sensitive_filenames(self):
        mutations = [lambda s: s.update(evidence_dir='relative'), lambda s: s['policy'].update(sha256='f' * 64),
                     lambda s: s['protected_files'].append('/etc/shadow'),
                     lambda s: s['protected_files'].append('/opt/cnb-devops/renamed/production/v1/.env'),
                     lambda s: s['services']['api'].update(container='--help'),
                     lambda s: s['identity_probes'][0].update(url='https://user:password@example.invalid/release'),
                     lambda s: s['identity_probes'][0].update(url='https://example.invalid/release?token=secret')]
        for mutate in mutations:
            self.spec = fixture(self.root)
            mutate(self.spec)
            with self.subTest(mutation=mutate):
                with self.assertRaises(ValueError): self.prepare()
        for field, value in [('host', '-oProxyCommand=evil'), ('user', 'root;id'), ('port', True)]:
            self.spec = fixture(self.root)
            target = json.loads((self.root / 'target.json').read_bytes())
            target[field] = value
            self.spec['target'] = write(self.root / 'target.json', target)
            with self.assertRaises(ValueError): self.prepare()
        self.spec = fixture(self.root)
        (self.root / 'spec.json').chmod(0o644)
        with self.assertRaises(ValueError): self.m.prepare(self.root / 'spec.json')
        self.spec = fixture(self.root)
        (self.root / 'spec.json').write_text('{"schema":"a","schema":"b"}')
        with self.assertRaises(ValueError): self.m.prepare(self.root / 'spec.json')

    def test_production_control_files_and_policy_resource_constraints(self):
        for filename in ('production-authority.json', 'approval-ed25519.pub', 'empty-baseline.json'):
            self.m.control_path('/opt/cnb-devops/renamed/production/v1/' + filename)
        policy = json.loads((self.root / 'policy.json').read_bytes())
        policy['services']['api']['resource_limits'] = {'memory_bytes': 268435456, 'cpu_millis': 1000}
        self.spec['policy'] = write(self.root / 'policy.json', policy)
        baseline = json.loads((self.root / 'baseline.json').read_bytes())
        baseline['files']['/opt/cnb-devops/renamed/production/v1/host-policy.json']['sha256'] = self.spec['policy']['sha256']
        baseline['caddy']['sites'][1]['policy_sha256'] = self.spec['policy']['sha256']
        self.spec['baseline'] = write(self.root / 'baseline.json', baseline)
        with self.assertRaisesRegex(ValueError, 'SERVICE_POLICY_CONSTRAINT_MISMATCH'):
            self.prepare()

    def test_production_verifies_standard_test_candidate_without_relabeling_it(self):
        candidate = json.loads((self.root / 'candidate.json').read_bytes())
        candidate.update(schema='cnb-candidate/v1', environment='test', project='renamed')
        self.spec['candidate'] = write(self.root / 'candidate.json', candidate)
        self.assertEqual(self.prepare().candidate['environment'], 'test')
        candidate['schema'] = 'unknown'
        self.spec['candidate'] = write(self.root / 'candidate.json', candidate)
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_ENVIRONMENT_INVALID'):
            self.prepare()

    def test_legacy_baseline_omits_uncollected_oom_without_inventing_observation(self):
        baseline = json.loads((self.root / 'baseline.json').read_bytes())
        original = write(self.root / 'original-filtered-capture.json', baseline)
        baseline['original_source'] = original
        for item in baseline['containers'].values():
            del item['oom_killed']
            del item['networks']
        self.spec['baseline'] = write(self.root / 'baseline.json', baseline)
        prepared = self.prepare()
        self.assertTrue(all(self.m.compare(prepared, self.observation()).values()))
        observation = self.observation()
        observation['containers']['neighbor-production-db']['oom_killed'] = True
        self.assertFalse(all(self.m.compare(prepared, observation).values()))
        (self.root / 'original-filtered-capture.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'INPUT_PIN_MISMATCH'):
            self.prepare()

    def test_public_identity_envelopes_and_failure_output_are_safe(self):
        probe = self.spec['identity_probes'][-1]
        identity = {'schema': 'cnb-release-identity/v1', 'service': 'api', 'git_sha': 'd' * 40, 'build_id': 'cnb-old-build'}
        for data in ({'release': identity}, {'release': identity, 'service': 'api', 'status': 'ok'}):
            with mock.patch.object(self.m, 'get_public', return_value=(200, encode({'code': 0, 'message': 'ok', 'data': data}))):
                self.assertEqual(self.m.probe_identity(probe)['identity'], identity)
        for raw in (b'{"code":0,"message":"SECRET","data":{"release":{}}}',
                    b'{"schema":"cnb-release-identity/v1","Env":["SECRET"]}', b'SECRET'):
            with mock.patch.object(self.m, 'get_public', return_value=(200, raw)):
                result = self.m.probe_identity(probe)
            self.assertIsNone(result['identity'])
            self.assertEqual(result['error'], 'IDENTITY_UNVERIFIED')
            self.assertNotIn('SECRET', json.dumps(result))
        with mock.patch.object(self.m, 'get_public', side_effect=TimeoutError('SECRET')):
            self.assertFalse(self.m.probe_availability(self.spec['availability_probes'][0])['ok'])

    def test_live_receipt_marks_actual_collection_interval(self):
        del self.spec['observation']
        write(self.root / 'spec.json', self.spec)
        observation = self.observation()
        observation['observed_at'] = datetime.now(timezone.utc).isoformat()
        with mock.patch.object(self.m, 'collect', return_value=observation), mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(self.m.main(['--spec', str(self.root / 'spec.json'), '--apply']), 0)
        receipt = json.loads((self.root / 'proof/coexistence.receipt.json').read_bytes())
        self.assertEqual(receipt['observation_source'], 'live')
        self.assertIsNotNone(receipt['collection_started_at'])
        self.assertEqual(receipt['observed_at'], observation['observed_at'])

    def test_raw_secret_fields_are_rejected_before_evidence_write(self):
        observation = self.observation()
        observation['containers']['renamed-production-api']['Env'] = ['TOKEN=DO_NOT_PERSIST']
        self.spec['observation'] = write(self.root / 'input-observation.json', observation)
        write(self.root / 'spec.json', self.spec)
        with self.assertRaises(ValueError):
            self.m.main(['--spec', str(self.root / 'spec.json'), '--apply'])
        self.assertFalse((self.root / 'proof/host-observation.json').exists())

    def test_bounded_runner_kills_timeout_and_large_output_without_echo(self):
        with self.assertRaisesRegex(ValueError, 'COMMAND_TIMEOUT'):
            self.m.bounded_run([sys.executable, '-c', 'import time;time.sleep(10)'], timeout=0.05, limit=100)
        with self.assertRaisesRegex(ValueError, 'COMMAND_OUTPUT_LIMIT'):
            self.m.bounded_run([sys.executable, '-c', 'import sys;sys.stdout.write("SECRET"*100000)'], timeout=2, limit=100)
        with self.assertRaisesRegex(ValueError, 'COMMAND_FAILED') as caught:
            self.m.bounded_run([sys.executable, '-c', 'import sys;sys.stderr.write("SECRET");sys.exit(1)'], timeout=2, limit=100)
        self.assertNotIn('SECRET', str(caught.exception))

    def test_ssh_transport_uses_fixed_strict_root_gate(self):
        prepared = self.prepare()
        observation = self.observation()
        remote = {k: v for k, v in observation.items() if k not in ('public_identities', 'availability', 'observed_at', 'source_target_sha256')}
        captured = []
        def run(argv, **kwargs):
            captured.append((argv, kwargs))
            return encode(remote)
        with mock.patch.object(self.m, 'bounded_run', side_effect=run), \
             mock.patch.object(self.m, 'probe_identity', side_effect=observation['public_identities']), \
             mock.patch.object(self.m, 'probe_availability', side_effect=observation['availability']):
            result = self.m.collect(prepared)
        self.assertTrue(all(self.m.compare(prepared, result).values()))
        argv, kwargs = captured[0]
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('IdentityAgent=none', argv)
        self.assertIn('GlobalKnownHostsFile=/dev/null', argv)
        self.assertIn('/usr/bin/sudo -n --', argv[-1])
        self.assertIn('/usr/bin/python3 -I -', argv[-1])
        compile(kwargs['data'], '<fixed-readonly-ssh-payload>', 'exec')
        self.assertLessEqual(kwargs['timeout'], 300)
        self.assertNotIn('PRIVATE KEY', str(kwargs))


if __name__ == '__main__': unittest.main()
