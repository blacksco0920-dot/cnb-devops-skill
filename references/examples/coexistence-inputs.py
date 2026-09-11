#!/usr/bin/env python3
"""Create synthetic offline coexistence inputs; never connects to a host.

The output is an example fixture, not a deployable policy or live evidence.
It uses only the Python standard library and files in the public Skill.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

CADDY = Path(__file__).resolve().parents[2] / 'assets/cnb-tcr-tat/host/configure-native-caddy.py'


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
    write(root / 'identity', b'SYNTHETIC OFFLINE IDENTITY; NOT AN SSH PRIVATE KEY')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New directory for synthetic private inputs')
    parser.add_argument('--roles', nargs='+', default=['api', 'web'], help='Distinct application roles (default: api web)')
    args = parser.parse_args()
    if (len(set(args.roles)) != len(args.roles) or not args.roles
            or any(not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', role) or role == 'store' for role in args.roles)):
        parser.error('Roles must be unique lowercase identifiers; store is reserved for the database')
    root = args.output.expanduser().resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    fixture(root, tuple(args.roles))
    print(json.dumps({'status': 'synthetic_fixture_created', 'spec': str(root / 'spec.json'), 'network_calls': False}))


if __name__ == '__main__':
    main()
