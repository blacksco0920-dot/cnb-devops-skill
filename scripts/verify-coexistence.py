#!/usr/bin/env python3
"""Verify a declared shared-host baseline and independently pinned project release.

--spec is a private absolute JSON file. Preview is offline. --apply performs only
bounded read-only SSH/HTTPS collection and creates a new private evidence directory.
An optional pinned observation enables offline fixtures; these never claim live proof.
This is a point-in-time check, not a sustained availability or workload test.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from types import ModuleType, SimpleNamespace
import urllib.parse
import urllib.request

MAX_BYTES = 2 * 1024 * 1024
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
CONTAINER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
BUILD = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
IMAGE = re.compile(r'[a-z0-9][a-z0-9./:_-]{0,254}@sha256:[0-9a-f]{64}\Z')
CONTROL_NAMES = {'host-policy.json', 'docker-compose.yml', 'tat-deploy-test.py', 'tat-command.sh',
                 'recovery-policy.json', 'recover-project.py', 'production-release.py', 'production-policy.json',
                 'production-command.sh', 'production-notify.py', 'production-notify-command.sh',
                 'repair-test-release.py', 'installation.json', 'artifact-lock.json', 'bootstrap-compose.yml',
                 'configure-native-caddy.py', 'production-authority.json', 'approval-ed25519.pub', 'empty-baseline.json'}
CONTAINER_FIELDS = {'name', 'id', 'image', 'image_reference', 'started_at', 'restart_count', 'status', 'health',
                    'oom_killed', 'memory_bytes', 'nano_cpus', 'cpu_period', 'cpu_quota', 'network_mode',
                    'networks', 'port_bindings', 'mounts'}


class VerificationError(ValueError):
    pass


def require(value, code):
    if not value:
        raise VerificationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def load_module(path):
    module = ModuleType('coexistence_ssh_dependency')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


_setup = load_module(Path(__file__).with_name('setup-host.py'))
strict_json = _setup.strict_json


def absolute(value):
    require(type(value) is str and value.startswith('/') and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts and len(value) <= 4096
            and not re.search(r'[\x00-\x1f\x7f]', value), 'ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def pinned(reference, modes=None):
    require(type(reference) is dict and set(reference) == {'path', 'sha256'}
            and type(reference['sha256']) is str and HASH.fullmatch(reference['sha256']), 'REFERENCE_INVALID')
    raw = _setup.read_safe(absolute(reference['path']), modes, MAX_BYTES)
    require(sha(raw) == reference['sha256'], 'INPUT_PIN_MISMATCH')
    return raw


def named(value, pattern=NAME):
    return type(value) is str and pattern.fullmatch(value) is not None


def unique_names(value, maximum=64, pattern=CONTAINER, minimum=0):
    require(type(value) is list and minimum <= len(value) <= maximum
            and all(named(item, pattern) for item in value) and len(value) == len(set(value)), 'DECLARED_LIST_INVALID')


def url(value):
    require(type(value) is str and len(value) <= 2048 and not re.search(r'[\x00-\x20\x7f]', value), 'URL_INVALID')
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and parsed.port in (None, 443) and not parsed.query and not parsed.fragment
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', parsed.hostname), 'URL_INVALID')


def metadata(value):
    require(type(value) is dict and set(value) == {'sha256', 'uid', 'gid', 'mode'}
            and named(value['sha256'], HASH) and all(type(value[k]) is int and value[k] >= 0 for k in ('uid', 'gid', 'mode'))
            and value['uid'] == 0 and value['gid'] == 0 and value['mode'] in (0o444, 0o555, 0o644, 0o600), 'FILE_METADATA_INVALID')


def control_path(value):
    path = absolute(value)
    parts = path.parts
    require(len(parts) == 7 and parts[1:3] == ('opt', 'cnb-devops') and named(parts[3])
            and parts[4] in ('test', 'production') and parts[5] == 'v1'
            and parts[6] in CONTROL_NAMES, 'CONTROL_FILE_SCOPE_INVALID')


def mounts(value):
    require(type(value) is list and len(value) <= 64, 'MOUNTS_INVALID')
    seen = set()
    for item in value:
        require(type(item) is dict and set(item) == {'type', 'name', 'source', 'destination', 'rw'}
                and item['type'] in ('bind', 'volume', 'tmpfs') and type(item['rw']) is bool
                and (item['name'] is None or named(item['name'], CONTAINER)), 'MOUNTS_INVALID')
        absolute(item['destination'])
        require(item['destination'] not in seen and (item['source'] == '' and item['type'] == 'tmpfs'
                or bool(absolute(item['source']))), 'MOUNTS_INVALID')
        seen.add(item['destination'])
    return sorted(value, key=lambda item: item['destination'])


def ports(value):
    require(type(value) is dict and len(value) <= 64, 'PORTS_INVALID')
    result = {}
    for key, bindings in value.items():
        require(type(key) is str and re.fullmatch(r'[1-9][0-9]{0,4}/(tcp|udp)', key)
                and int(key.split('/')[0]) <= 65535 and type(bindings) is list and 1 <= len(bindings) <= 8, 'PORTS_INVALID')
        for item in bindings:
            require(type(item) is dict and set(item) == {'HostIp', 'HostPort'}
                    and item['HostIp'] in ('127.0.0.1', '::1', '0.0.0.0', '::', '')
                    and type(item['HostPort']) is str and item['HostPort'].isdigit()
                    and 1 <= int(item['HostPort']) <= 65535, 'PORTS_INVALID')
        result[key] = sorted(bindings, key=lambda item: (item['HostIp'], item['HostPort']))
    return result


def container_shape(value, name, baseline=False):
    optional = {'networks', 'oom_killed'} if baseline else set()
    require(type(value) is dict and set(value) <= CONTAINER_FIELDS and CONTAINER_FIELDS - optional <= set(value), 'CONTAINER_FIELDS_INVALID')
    require(value['name'] == name and named(value['id'], HASH) and named(value['image'], re.compile(r'sha256:[0-9a-f]{64}\Z'))
            and type(value['image_reference']) is str and 1 <= len(value['image_reference']) <= 512
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:@_-]*', value['image_reference'])
            and type(value['started_at']) is str and len(value['started_at']) <= 64
            and value['status'] in ('running', 'exited', 'created', 'paused', 'restarting', 'removing', 'dead')
            and value['health'] in ('healthy', 'unhealthy', 'starting', None)
            and ('oom_killed' not in value and baseline or type(value.get('oom_killed')) is bool),
            'CONTAINER_FIELDS_INVALID')
    for key in ('restart_count', 'memory_bytes', 'nano_cpus', 'cpu_period', 'cpu_quota'):
        require(type(value[key]) is int and value[key] >= (-1 if key == 'cpu_quota' else 0), 'CONTAINER_FIELDS_INVALID')
    require(named(value['network_mode'], CONTAINER), 'CONTAINER_FIELDS_INVALID')
    if 'networks' in value:
        unique_names(value['networks'])
    elif not baseline:
        raise VerificationError('CONTAINER_NETWORKS_REQUIRED')
    ports(value['port_bindings'] or {})
    mounts(value['mounts'])


def caddy_shape(value):
    require(type(value) is dict and set(value) == {'schema', 'status', 'main_sha256', 'base_sha256', 'running_sha256', 'sites'}
            and value['schema'] == 'cnb-native-caddy-inventory/v1' and value['status'] == 'verified'
            and all(named(value[k], HASH) for k in ('main_sha256', 'base_sha256', 'running_sha256'))
            and type(value['sites']) is list and 0 <= len(value['sites']) <= 16, 'CADDY_INVALID')
    seen = set()
    for site in value['sites']:
        require(type(site) is dict and set(site) == {'project', 'environment', 'path', 'site_sha256', 'policy_sha256', 'domains', 'loopback_ports'}
                and named(site['project']) and site['environment'] in ('test', 'production')
                and site['path'] == f"/etc/caddy/cnb-devops/{site['project']}-{site['environment']}.caddy"
                and named(site['site_sha256'], HASH) and named(site['policy_sha256'], HASH)
                and type(site['domains']) is list and 1 <= len(site['domains']) <= 16
                and all(type(x) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', x) for x in site['domains'])
                and type(site['loopback_ports']) is list and 1 <= len(site['loopback_ports']) <= 16
                and all(type(x) is int and 1024 <= x <= 65535 for x in site['loopback_ports']), 'CADDY_INVALID')
        identity = (site['project'], site['environment'])
        require(identity not in seen, 'CADDY_INVALID')
        seen.add(identity)


def prepare(spec_path):
    raw = _setup.read_safe(absolute(str(spec_path)), {0o600}, MAX_BYTES)
    spec = strict_json(raw)
    required = {'schema', 'project', 'environment', 'application_commit', 'build_id', 'target', 'policy', 'candidate',
                'baseline', 'evidence_dir', 'services', 'protected_containers', 'protected_files', 'identity_probes',
                'availability_probes', 'caddy_helper_sha256'}
    require(type(spec) is dict and required <= set(spec) and not set(spec) - required - {'observation'}
            and spec['schema'] == 'cnb-coexistence-spec/v1' and named(spec['project'])
            and spec['environment'] in ('test', 'production') and named(spec['application_commit'], COMMIT)
            and named(spec['build_id'], BUILD), 'SPEC_INVALID')
    captures = {key: pinned(spec[key], {0o600} if key in ('target', 'baseline', 'candidate') else None)
                for key in ('target', 'policy', 'candidate', 'baseline')}
    target, policy, candidate, baseline = (strict_json(captures[key]) for key in ('target', 'policy', 'candidate', 'baseline'))
    require(type(target) is dict and set(target) == {'host', 'port', 'user', 'identity_file', 'known_hosts_file'}
            and type(target['host']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', target['host'])
            and type(target['port']) is int and 1 <= target['port'] <= 65535
            and type(target['user']) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', target['user']), 'TARGET_INVALID')
    target_files = {}
    for key, modes in [('identity_file', {0o400, 0o600}), ('known_hosts_file', {0o400, 0o600, 0o644})]:
        target_files[key] = sha(_setup.read_safe(absolute(target[key]), modes, MAX_BYTES))
    output = absolute(spec['evidence_dir'])
    require(not os.path.lexists(output), 'OUTPUT_EXISTS')
    _setup.validate_output_path(output)
    require(type(policy) is dict and policy.get('schema') == 'cnb-devops-host-policy/v1'
            and (policy.get('project'), policy.get('environment')) == (spec['project'], spec['environment'])
            and type(policy.get('services')) is dict and 1 <= len(policy['services']) <= 16, 'POLICY_INVALID')
    require(type(candidate) is dict and candidate.get('application_commit') == spec['application_commit']
            and candidate.get('build_id') == spec['build_id'] and type(candidate.get('services')) is dict
            and set(candidate['services']) == set(policy['services']), 'CANDIDATE_IDENTITY_INVALID')
    for field in ('project', 'project_id'):
        require(field not in candidate or candidate[field] == spec['project'], 'CANDIDATE_PROJECT_INVALID')
    require('environment' not in candidate or candidate['environment'] == spec['environment']
            or candidate.get('schema') == 'cnb-candidate/v1' and candidate['environment'] == 'test'
            and spec['environment'] == 'production', 'CANDIDATE_ENVIRONMENT_INVALID')
    require(type(spec['services']) is dict and 1 <= len(spec['services']) <= 32
            and set(policy['services']) <= set(spec['services']), 'SERVICE_SET_INVALID')
    declared_names = []
    for role, service in spec['services'].items():
        require(named(role) and type(service) is dict and set(service) == {'container', 'resource_limits', 'networks', 'network_mode',
                'port_bindings', 'mounts', 'health', 'max_restart_count'} and named(service['container'], CONTAINER)
                and service['health'] == 'healthy' and type(service['max_restart_count']) is int
                and 0 <= service['max_restart_count'] <= 100 and named(service['network_mode'], CONTAINER), 'SERVICE_INVALID')
        cap = service['resource_limits']
        require(type(cap) is dict and set(cap) == {'memory_bytes', 'cpu_millis'}
                and type(cap['memory_bytes']) is int and 16 * 1024 * 1024 <= cap['memory_bytes'] <= 1024**4
                and type(cap['cpu_millis']) is int and 1 <= cap['cpu_millis'] <= 1024000, 'RESOURCE_LIMIT_INVALID')
        unique_names(service['networks'], minimum=1)
        ports(service['port_bindings'])
        mounts(service['mounts'])
        declared_names.append(service['container'])
        if role in policy['services']:
            approved = policy['services'][role]
            require(type(approved) is dict and service['container'] == approved.get('container')
                    and named(candidate['services'][role], IMAGE)
                    and candidate['services'][role].split('@')[0] == approved.get('image_repository'), 'SERVICE_CANDIDATE_INVALID')
            if 'resource_limits' in approved:
                require(service['resource_limits'] == approved['resource_limits'], 'SERVICE_POLICY_CONSTRAINT_MISMATCH')
            if 'networks' in approved:
                require(sorted(service['networks']) == sorted(approved['networks']), 'SERVICE_POLICY_CONSTRAINT_MISMATCH')
            if 'mounts' in approved:
                expected_mounts = [{'type': m['type'], 'source': m['source'], 'destination': m['target'], 'name': None, 'rw': True}
                                   for m in approved['mounts']]
                require(mounts(service['mounts']) == mounts(expected_mounts), 'SERVICE_POLICY_CONSTRAINT_MISMATCH')
            if 'loopback_port' in approved:
                port = approved['loopback_port']
                expected_ports = {str(port['target']) + '/' + port['protocol']:
                                  [{'HostIp': port['host_ip'], 'HostPort': str(port['published'])}]}
                require(ports(service['port_bindings']) == ports(expected_ports), 'SERVICE_POLICY_CONSTRAINT_MISMATCH')
    require(len(set(declared_names)) == len(declared_names), 'SERVICE_CONTAINERS_DUPLICATE')
    for key in ('database', 'redis'):
        if policy.get(key) is not None:
            require(type(policy[key]) is dict and policy[key].get('container') in declared_names, 'INFRASTRUCTURE_REQUIRED')
    unique_names(spec['protected_containers'], minimum=1)
    require(len(set(declared_names) | set(spec['protected_containers'])) <= 64, 'CONTAINER_BUDGET_EXCEEDED')
    applications = {spec['services'][role]['container'] for role in policy['services']}
    require(not applications.intersection(spec['protected_containers'])
            and set(declared_names) - applications <= set(spec['protected_containers']), 'PROTECTED_APPLICATION_OVERLAP')
    require(type(spec['protected_files']) is list and 1 <= len(spec['protected_files']) <= 128
            and len(spec['protected_files']) == len(set(spec['protected_files'])), 'PROTECTED_FILES_INVALID')
    for path in spec['protected_files']:
        control_path(path)
    baseline_keys = {'schema', 'source_target_sha256', 'containers', 'files', 'caddy'}
    require(type(baseline) is dict and baseline_keys <= set(baseline) and not set(baseline) - baseline_keys - {'original_source'}
            and baseline['schema'] == 'cnb-coexistence-baseline/v1'
            and baseline['source_target_sha256'] == spec['target']['sha256']
            and type(baseline['containers']) is dict and set(baseline['containers']) == set(spec['protected_containers'])
            and type(baseline['files']) is dict and set(baseline['files']) == set(spec['protected_files']), 'BASELINE_INVALID')
    if 'original_source' in baseline:
        pinned(baseline['original_source'], {0o600})
    for name, item in baseline['containers'].items():
        container_shape(item, name, baseline=True)
    for item in baseline['files'].values():
        metadata(item)
    caddy_shape(baseline['caddy'])
    own_sites = [item for item in baseline['caddy']['sites'] if (item['project'], item['environment']) == (spec['project'], spec['environment'])]
    require(len(own_sites) == 1 and own_sites[0]['policy_sha256'] == spec['policy']['sha256'], 'CADDY_POLICY_BINDING_INVALID')
    own_policy_path = f"/opt/cnb-devops/{spec['project']}/{spec['environment']}/v1/host-policy.json"
    require(baseline['files'].get(own_policy_path, {}).get('sha256') == spec['policy']['sha256'], 'POLICY_CONTROL_FILE_REQUIRED')
    probes = spec['identity_probes']
    require(type(probes) is list and 1 <= len(probes) <= 32, 'IDENTITY_PROBES_INVALID')
    probe_ids = set()
    for probe in probes:
        require(type(probe) is dict and set(probe) == {'project', 'service', 'url', 'api_envelope', 'application_commit', 'build_id'}
                and named(probe['project']) and named(probe['service']) and type(probe['api_envelope']) is bool
                and named(probe['application_commit'], COMMIT) and named(probe['build_id'], BUILD), 'IDENTITY_PROBES_INVALID')
        url(probe['url'])
        identity = (probe['project'], probe['service'])
        require(identity not in probe_ids, 'IDENTITY_PROBES_DUPLICATE')
        probe_ids.add(identity)
        if probe['project'] == spec['project']:
            require((probe['application_commit'], probe['build_id']) == (spec['application_commit'], spec['build_id']), 'IDENTITY_RELEASE_INVALID')
    own_probes = [{k: v for k, v in p.items() if k in ('service', 'url', 'api_envelope')} for p in probes if p['project'] == spec['project']]
    require({p['service'] for p in own_probes} == set(policy['services'])
            and sorted(own_probes, key=lambda p: p['service']) == sorted(policy.get('identity_probes', []), key=lambda p: p['service']), 'POLICY_PROBES_MISMATCH')
    require({site['project'] for site in baseline['caddy']['sites']} <= {p['project'] for p in probes}, 'NEIGHBOR_PROBES_REQUIRED')
    availability = spec['availability_probes']
    require(type(availability) is list and 1 <= len(availability) <= 32 and len(availability) == len(set(availability))
            and set(policy.get('availability_probes', [])) <= set(availability), 'AVAILABILITY_PROBES_INVALID')
    for value in availability:
        url(value)
    helper_path = Path(__file__).parents[1] / 'assets/cnb-tcr-tat/host/configure-native-caddy.py'
    helper = _setup.read_safe(helper_path, limit=MAX_BYTES)
    require(named(spec['caddy_helper_sha256'], HASH) and sha(helper) == spec['caddy_helper_sha256'], 'CADDY_HELPER_PIN_MISMATCH')
    observation_raw = pinned(spec['observation'], {0o600}) if 'observation' in spec else None
    return SimpleNamespace(spec=spec, spec_sha256=sha(raw), baseline=baseline, policy=policy, candidate=candidate,
                           target=target, target_files=target_files, helper=helper, output=output, observation_raw=observation_raw)


def observation_shape(observation):
    fields = {'schema', 'status', 'root_gate_verified', 'source_target_sha256', 'observed_at', 'containers', 'files',
              'caddy', 'public_identities', 'availability'}
    require(type(observation) is dict and set(observation) == fields
            and observation['schema'] == 'cnb-coexistence-observation/v1' and observation['status'] == 'collected'
            and type(observation['root_gate_verified']) is bool and named(observation['source_target_sha256'], HASH), 'OBSERVATION_INVALID')
    parse_time(observation['observed_at'])
    require(type(observation['containers']) is dict and len(observation['containers']) <= 64
            and type(observation['files']) is dict and len(observation['files']) <= 128, 'OBSERVATION_INVALID')
    for name, item in observation['containers'].items():
        require(named(name, CONTAINER), 'OBSERVATION_INVALID')
        container_shape(item, name)
    for path, item in observation['files'].items():
        control_path(path)
        metadata(item)
    caddy_shape(observation['caddy'])
    require(type(observation['public_identities']) is list and len(observation['public_identities']) <= 32
            and type(observation['availability']) is list and len(observation['availability']) <= 32, 'PROBE_OBSERVATION_INVALID')
    for item in observation['public_identities']:
        require(type(item) is dict and set(item) <= {'project', 'service', 'url', 'http_status', 'identity', 'response_sha256', 'error'}
                and {'project', 'service', 'url', 'http_status', 'identity'} <= set(item)
                and named(item['project']) and named(item['service']) and type(item['http_status']) is int
                and (item.get('error') is None or item['error'] == 'IDENTITY_UNVERIFIED')
                and ('response_sha256' not in item or named(item['response_sha256'], HASH)), 'PROBE_OBSERVATION_INVALID')
        url(item['url'])
        if item['identity'] is not None:
            validate_identity(item['identity'])
    for item in observation['availability']:
        require(type(item) is dict and set(item) == {'url', 'http_status', 'ok'}
                and type(item['http_status']) is int and type(item['ok']) is bool, 'PROBE_OBSERVATION_INVALID')
        url(item['url'])


def parse_time(value):
    require(type(value) is str and len(value) <= 64, 'OBSERVED_TIME_INVALID')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None, 'OBSERVED_TIME_INVALID')
        return parsed
    except ValueError as error:
        raise VerificationError('OBSERVED_TIME_INVALID') from error


def compare(prepared, observation):
    # Shape validation happens before evidence can be persisted; raw Docker or HTTP
    # fields, including env, args and response bodies, are never accepted as evidence.
    observation_shape(observation)
    spec, baseline = prepared.spec, prepared.baseline
    checks = {'root_gate_verified': observation['root_gate_verified'] is True,
              'target_bound': observation['source_target_sha256'] == spec['target']['sha256'],
              'declared_container_set': set(observation['containers']) == set(spec['protected_containers']) | {s['container'] for s in spec['services'].values()},
              'declared_file_set': set(observation['files']) == set(spec['protected_files'])}
    actual = observation['containers']
    for name, old in baseline['containers'].items():
        item = actual.get(name, {})
        prefix = 'protected.' + name
        keys = ('id', 'image', 'image_reference', 'name', 'restart_count', 'started_at', 'memory_bytes', 'nano_cpus', 'cpu_period', 'cpu_quota', 'network_mode')
        checks[prefix + '.identity_runtime_preserved'] = all(item.get(k) == old[k] for k in keys)
        checks[prefix + '.mounts_preserved'] = mounts(item.get('mounts', [])) == mounts(old['mounts'])
        checks[prefix + '.ports_preserved'] = ports(item.get('port_bindings') or {}) == ports(old['port_bindings'] or {})
        if 'networks' in old:
            checks[prefix + '.networks_preserved'] = sorted(item.get('networks', [])) == sorted(old['networks'])
        checks[prefix + '.healthy'] = item.get('status') == 'running' and item.get('health') == 'healthy' and item.get('oom_killed') is False
    for path, expected in baseline['files'].items():
        checks['protected.file.' + path] = observation['files'].get(path) == expected
    for role, service in spec['services'].items():
        item = actual.get(service['container'], {})
        prefix = 'project.' + role
        checks[prefix + '.healthy'] = (item.get('name') == service['container'] and item.get('status') == 'running'
            and item.get('health') == service['health'] and item.get('oom_killed') is False
            and type(item.get('restart_count')) is int and item['restart_count'] <= service['max_restart_count'])
        cpu = []
        cap = service['resource_limits']
        if item.get('nano_cpus', 0) > 0:
            cpu.append(item['nano_cpus'] == cap['cpu_millis'] * 1000000)
        if item.get('cpu_period', 0) > 0 and item.get('cpu_quota', 0) > 0:
            cpu.append(item['cpu_quota'] * 1000 == cap['cpu_millis'] * item['cpu_period'])
        checks[prefix + '.resource_limits'] = item.get('memory_bytes') == cap['memory_bytes'] and bool(cpu) and all(cpu)
        checks[prefix + '.mounts'] = mounts(item.get('mounts', [])) == mounts(service['mounts'])
        checks[prefix + '.ports'] = ports(item.get('port_bindings') or {}) == ports(service['port_bindings'])
        checks[prefix + '.networks'] = item.get('network_mode') == service['network_mode'] and sorted(item.get('networks', [])) == sorted(service['networks'])
        if role in prepared.candidate['services']:
            checks[prefix + '.candidate_digest'] = item.get('image_reference') == prepared.candidate['services'][role]
    current, previous = observation['caddy'], baseline['caddy']
    for key in ('base_sha256', 'main_sha256', 'running_sha256', 'sites'):
        checks['caddy.' + key + '.preserved'] = current[key] == previous[key]
    probes = observation['public_identities']
    checks['identity.exact_probe_set'] = (len(probes) == len(spec['identity_probes'])
        and {(p['project'], p['service'], p['url']) for p in probes} == {(p['project'], p['service'], p['url']) for p in spec['identity_probes']})
    for probe in spec['identity_probes']:
        matches = [p for p in probes if (p['project'], p['service'], p['url']) == (probe['project'], probe['service'], probe['url'])]
        expected = {'schema': 'cnb-release-identity/v1', 'service': probe['service'], 'git_sha': probe['application_commit'], 'build_id': probe['build_id']}
        checks['identity.' + probe['project'] + '.' + probe['service']] = len(matches) == 1 and matches[0]['http_status'] == 200 and matches[0]['identity'] == expected and not matches[0].get('error')
    availability = observation['availability']
    checks['availability.exact_probe_set'] = len(availability) == len(spec['availability_probes']) and {p['url'] for p in availability} == set(spec['availability_probes'])
    for index, endpoint in enumerate(spec['availability_probes']):
        matches = [p for p in availability if p['url'] == endpoint]
        checks['availability.' + str(index)] = len(matches) == 1 and matches[0]['ok'] is True and matches[0]['http_status'] == 200
    return checks


def bounded_run(argv, *, data=None, timeout=60, limit=MAX_BYTES, cwd=None):
    """Bound both pipes while running, kill the process group on failure, echo none."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, start_new_session=True,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    deadline, chunks, count, offset = time.monotonic() + timeout, [], 0, 0
    selector = selectors.DefaultSelector()
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        if data is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'COMMAND_TIMEOUT')
            for key, events in selector.select(min(remaining, 0.2)):
                stream = key.fileobj
                if events & selectors.EVENT_WRITE:
                    if offset < len(data):
                        offset += os.write(stream.fileno(), data[offset:offset + 8192])
                    if offset == len(data):
                        selector.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    count += len(chunk)
                    require(count <= limit, 'COMMAND_OUTPUT_LIMIT')
                    if stream is process.stdout:
                        chunks.append(chunk)
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'COMMAND_TIMEOUT')
        try:
            result = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise VerificationError('COMMAND_TIMEOUT') from error
        require(result == 0, 'COMMAND_FAILED')
        return b''.join(chunks)
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


# Fixed Docker format selects safe metadata. Config.Env, Config.Cmd, Args, labels,
# health logs and complete inspect output are never requested or transported.
DOCKER_FORMAT = ('{"name":{{json .Name}},"id":{{json .Id}},"image":{{json .Image}},'
    '"image_reference":{{json .Config.Image}},"started_at":{{json .State.StartedAt}},'
    '"restart_count":{{json .RestartCount}},"status":{{json .State.Status}},'
    '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},'
    '"oom_killed":{{json .State.OOMKilled}},"memory_bytes":{{json .HostConfig.Memory}},'
    '"nano_cpus":{{json .HostConfig.NanoCpus}},"cpu_period":{{json .HostConfig.CpuPeriod}},'
    '"cpu_quota":{{json .HostConfig.CpuQuota}},"network_mode":{{json .HostConfig.NetworkMode}},'
    '"port_bindings":{{json .HostConfig.PortBindings}},"networks":{{json .NetworkSettings.Networks}},'
    '"mounts":{{json .Mounts}}}')


def remote_collect(request):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    result = {'schema': 'cnb-coexistence-observation/v1', 'status': 'collected', 'root_gate_verified': True, 'containers': {}, 'files': {}}
    for name in request['containers']:
        raw = bounded_run(['/usr/bin/docker', 'inspect', '--type', 'container', '--format', DOCKER_FORMAT, name], timeout=30)
        item = json.loads(raw)
        item['name'] = item['name'].lstrip('/')
        item['networks'] = sorted(item['networks'])
        item['port_bindings'] = item['port_bindings'] or {}
        item['mounts'] = [{'type': mount['Type'], 'name': mount.get('Name') or None, 'source': mount['Source'],
                          'destination': mount['Destination'], 'rw': mount['RW']} for mount in item['mounts']]
        result['containers'][name] = item
    for path in request['files']:
        for parent in Path(path).parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'CONTROL_FILE_UNSAFE')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                    and before.st_nlink == 1 and before.st_size <= MAX_BYTES and not before.st_mode & 0o022, 'CONTROL_FILE_UNSAFE')
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_gid')
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields), 'CONTROL_FILE_CHANGED')
        result['files'][path] = {'sha256': sha(raw), 'uid': before.st_uid, 'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}
    helper_raw = base64.b64decode(request['caddy_source'], validate=True)
    require(sha(helper_raw) == request['caddy_sha256'], 'CADDY_HELPER_PIN_MISMATCH')
    module = ModuleType('coexistence_fixed_caddy_inventory')
    module.__file__ = '/coexistence-caddy-inventory.py'
    exec(compile(helper_raw, module.__file__, 'exec'), module.__dict__)
    allowed = [(['/usr/bin/systemctl', 'is-active', '--quiet', 'caddy'], False),
               (['/usr/bin/systemctl', 'show', 'caddy', '--property=MainPID', '--value'], False),
               (['/usr/bin/caddy', 'adapt', '--config', '/dev/stdin', '--adapter', 'caddyfile'], True)]
    def readonly_command(argv, data=None):
        require((argv, data is not None) in allowed, 'CADDY_COMMAND_SCOPE_INVALID')
        return bounded_run(argv, data=data, timeout=30, limit=1024 * 1024, cwd='/etc/caddy')
    module.command = readonly_command
    result['caddy'] = module.inventory()
    return result


REMOTE_FUNCTIONS = (require, sha, bounded_run, remote_collect)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_public(endpoint, body=True):
    url(endpoint)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 15
    with opener.open(urllib.request.Request(endpoint, headers={'Accept': 'application/json'}), timeout=5) as response:
        require(response.status == 200, 'PUBLIC_HTTP_INVALID')
        chunks, count = [], 0
        if body:
            while True:
                require(time.monotonic() < deadline, 'PUBLIC_TIMEOUT')
                chunk = response.read1(4096)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= 65536, 'PUBLIC_OUTPUT_LIMIT')
                chunks.append(chunk)
        return response.status, b''.join(chunks)


def validate_identity(value):
    require(type(value) is dict and set(value) == {'schema', 'service', 'git_sha', 'build_id'}
            and value['schema'] == 'cnb-release-identity/v1' and named(value['service'])
            and named(value['git_sha'], COMMIT) and named(value['build_id'], BUILD), 'IDENTITY_INVALID')
    return value


def probe_identity(probe):
    result = {'project': probe['project'], 'service': probe['service'], 'url': probe['url'], 'http_status': 0, 'identity': None}
    try:
        status, raw = get_public(probe['url'])
        result.update(http_status=status, response_sha256=sha(raw))
        value = strict_json(raw)
        if probe['api_envelope']:
            require(type(value) is dict and set(value) == {'code', 'message', 'data'} and type(value['code']) is int
                    and value['code'] == 0 and value['message'] == 'ok' and type(value['data']) is dict
                    and 'release' in value['data'] and not set(value['data']) - {'release', 'status', 'service'}, 'IDENTITY_ENVELOPE_INVALID')
            value = value['data']['release']
        result['identity'] = validate_identity(value)
    except Exception:
        result['error'] = 'IDENTITY_UNVERIFIED'
    return result


def probe_availability(endpoint):
    result = {'url': endpoint, 'http_status': 0, 'ok': False}
    try:
        status, _ = get_public(endpoint, body=False)
        result.update(http_status=status, ok=status == 200)
    except Exception:
        pass
    return result


def collect(prepared):
    for key, expected in prepared.target_files.items():
        require(sha(_setup.read_safe(prepared.target[key], limit=MAX_BYTES)) == expected, 'TARGET_FILE_CHANGED')
    request = {'containers': sorted(set(prepared.spec['protected_containers']) | {s['container'] for s in prepared.spec['services'].values()}),
               'files': sorted(prepared.spec['protected_files']), 'caddy_source': base64.b64encode(prepared.helper).decode(),
               'caddy_sha256': prepared.spec['caddy_helper_sha256']}
    source = ('import base64, hashlib, json, os, selectors, signal, stat, subprocess, time\n'
              'from pathlib import Path\nfrom types import ModuleType\n'
              'class VerificationError(ValueError): pass\n'
              f'MAX_BYTES = {MAX_BYTES}\nDOCKER_FORMAT = {DOCKER_FORMAT!r}\n')
    for function in REMOTE_FUNCTIONS:
        source += '\n' + inspect.getsource(function) + '\n'
    source += ('\ntry:\n request=json.loads(base64.b64decode(' + repr(base64.b64encode(canonical(request)).decode()) + '))\n'
               ' print(json.dumps(remote_collect(request),sort_keys=True,separators=(",",":")))\n'
               'except Exception:\n print("{\\"status\\":\\"failed\\",\\"code\\":\\"READONLY_COLLECTION_FAILED\\"}")\n raise SystemExit(1)\n')
    remote = ['/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C.UTF-8', '/usr/bin/python3', '-I', '-']
    if prepared.target['user'] != 'root':
        remote = ['/usr/bin/sudo', '-n', '--', *remote]
    raw = bounded_run(_setup.ssh_command(prepared.target, remote), data=source.encode(), timeout=300, limit=MAX_BYTES)
    result = strict_json(raw)
    # Only the fixed collector's exact subset can cross into persisted evidence.
    require(type(result) is dict and set(result) == {'schema', 'status', 'root_gate_verified', 'containers', 'files', 'caddy'}, 'REMOTE_OBSERVATION_INVALID')
    result.update(source_target_sha256=prepared.spec['target']['sha256'], observed_at=datetime.now(timezone.utc).isoformat(),
                  public_identities=[probe_identity(p) for p in prepared.spec['identity_probes']],
                  availability=[probe_availability(p) for p in prepared.spec['availability_probes']])
    result['observed_at'] = datetime.now(timezone.utc).isoformat()
    observation_shape(result)
    return result


def save_private(path, value):
    raw = canonical(value)
    require(len(raw) <= MAX_BYTES, 'EVIDENCE_TOO_LARGE')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', required=True, type=Path)
    parser.add_argument('--apply', action='store_true', help='read-only SSH/HTTPS and new private local evidence only')
    args = parser.parse_args(argv)
    prepared = prepare(args.spec)
    spec = prepared.spec
    identity = {key: spec[key] for key in ('project', 'environment', 'application_commit', 'build_id')}
    if not args.apply:
        print(json.dumps({'schema': 'cnb-coexistence-preview/v1', 'status': 'preview', **identity, 'network_calls': False,
                          'application_services': list(prepared.policy['services']), 'protected_containers': len(spec['protected_containers']),
                          'observation_source': 'fixture' if prepared.observation_raw is not None else 'live', 'spec_sha256': prepared.spec_sha256}))
        return 0
    started = None if prepared.observation_raw is not None else datetime.now(timezone.utc).isoformat()
    observation = strict_json(prepared.observation_raw) if prepared.observation_raw is not None else collect(prepared)
    checks = compare(prepared, observation)
    # Reserve a new directory only after shape validation, then create immutable files.
    _setup.validate_output_path(prepared.output)
    require(not os.path.lexists(prepared.output), 'OUTPUT_EXISTS')
    prepared.output.mkdir(mode=0o700)
    observation_sha = save_private(prepared.output / 'host-observation.json', observation)
    evidence = {'baseline': spec['baseline'], 'observation': {'path': 'host-observation.json', 'sha256': observation_sha}}
    if 'original_source' in prepared.baseline:
        evidence['original_baseline_source'] = prepared.baseline['original_source']
    receipt = {'schema': 'cnb-coexistence-verification/v1', 'status': 'verified' if all(checks.values()) else 'failed', **identity,
               'observed_at': observation['observed_at'], 'collection_started_at': started,
               'observation_source': 'fixture' if prepared.observation_raw is not None else 'live', 'checks': checks,
               'spec_sha256': prepared.spec_sha256, 'baseline_sha256': spec['baseline']['sha256'], 'observation_sha256': observation_sha,
               'target_sha256': spec['target']['sha256'], 'policy_sha256': spec['policy']['sha256'], 'candidate_sha256': spec['candidate']['sha256'],
               'caddy_helper_sha256': spec['caddy_helper_sha256'], 'candidate_environment': prepared.candidate.get('environment'), 'evidence': evidence}
    receipt_sha = save_private(prepared.output / 'coexistence.receipt.json', receipt)
    print(json.dumps({'schema': receipt['schema'], 'status': receipt['status'], **identity, 'observed_at': receipt['observed_at'],
                      'observation_source': receipt['observation_source'], 'receipt_sha256': receipt_sha,
                      'checks_total': len(checks), 'checks_passed': sum(checks.values()),
                      'failed_checks': [key for key, value in checks.items() if not value]}))
    return 0 if receipt['status'] == 'verified' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r'(?:SETUP_|CADDY_)?[A-Z][A-Z0-9_]{0,80}', code):
            code = 'READONLY_VERIFICATION_FAILED'
        print(json.dumps({'schema': 'cnb-coexistence-verification/v1', 'status': 'failed', 'code': code}))
        sys.exit(1)
