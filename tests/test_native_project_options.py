"""Native gateway selection and enforced project resource budgets."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import yaml
from jsonschema import Draft202012Validator
from test_bundle_host_policy import load_host, sample_policy

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'assets/cnb-tcr-tat'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class NativeProjectOptionsTests(unittest.TestCase):
    def setUp(self):
        self.host = load_host()
        self.render = module('native_options_render', BUNDLE / 'templates/render.py')
        self.bootstrap = module('native_options_bootstrap', BUNDLE / 'host/bootstrap-host.py')
        self.limits = {'memory_bytes': 256 * 1024 * 1024, 'cpu_millis': 400}

    def test_gateway_must_be_a_service_with_a_fixed_loopback_port(self):
        policy = sample_policy()
        policy['native_caddy_gateway'] = 'web'
        with self.assertRaises(self.host.DeploymentError):
            self.host.validate_host_policy(policy)
        policy['services']['web']['loopback_port'] = {
            'host_ip': '127.0.0.1', 'protocol': 'tcp', 'published': 13180, 'target': 80}
        self.host.validate_host_policy(policy)
        policy['native_caddy_gateway'] = 'unrelated'
        with self.assertRaises(self.host.DeploymentError):
            self.host.validate_host_policy(policy)

    def test_generated_budget_is_bound_to_policy_and_compose(self):
        config = yaml.safe_load((BUNDLE / 'project.example.yml').read_text())
        role = next(iter(config['services']))
        config['services'][role].update(expose=[3000], loopback_port=13180, resource_limits=self.limits)
        config['host']['native_caddy_gateway'] = role
        Draft202012Validator(json.loads((BUNDLE / 'project.schema.json').read_text())).validate(config)
        policy, _ci, compose_raw = self.render.model(config, 'a' * 64)
        self.host.validate_host_policy(policy)
        self.assertEqual(policy['native_caddy_gateway'], role)
        self.assertEqual(policy['services'][role]['resource_limits'], self.limits)
        service = yaml.safe_load(compose_raw)['services'][role]
        self.assertEqual(service['mem_limit'], self.limits['memory_bytes'])
        self.assertEqual(service['cpus'], 0.4)

    def test_invalid_resource_budget_and_missing_runtime_limit_are_rejected(self):
        policy = sample_policy()
        policy['services']['web']['resource_limits'] = copy.deepcopy(self.limits)
        self.host.configure_policy(policy, policy_sha256='b' * 64)
        actual = {'Memory': self.limits['memory_bytes'], 'NanoCpus': 400000000}
        self.host.validate_runtime_limits('web', actual)
        for drift in ({}, {**actual, 'Memory': 0}, {**actual, 'NanoCpus': 0}):
            with self.assertRaises(self.host.DeploymentError):
                self.host.validate_runtime_limits('web', drift)
        for bad in (True, 0, -1, 1.2):
            with self.subTest(bad=bad):
                policy['services']['web']['resource_limits']['cpu_millis'] = bad
                with self.assertRaises(self.host.DeploymentError):
                    self.host.validate_host_policy(policy)

    def test_database_budget_is_rendered_and_read_back(self):
        policy = sample_policy()
        policy['networks'] = ['sample-test']
        policy['database'].update(host='sample-test-postgres', container='sample-test-postgres')
        spec = {'schema': 'cnb-first-host/v1', 'policy_sha256': 'b' * 64,
                'images': {'postgres': 'ccr.ccs.tencentyun.com/sample/postgres@sha256:' + 'c' * 64},
                'docker_packages': {}, 'generate_env': [], 'resource_limits': {'postgres': self.limits}}
        self.bootstrap.validate_spec(spec, policy, 'b' * 64, apply=True)
        compose = self.bootstrap.compose_model(policy, spec, 'd' * 64)
        self.assertEqual(compose['services']['postgres']['mem_limit'], self.limits['memory_bytes'])
        resource = {'Config': {'Image': spec['images']['postgres'], 'Labels': self.bootstrap.labels(policy, 'd' * 64)},
                    'HostConfig': {'Privileged': False, 'PortBindings': {}, 'Memory': self.limits['memory_bytes'], 'NanoCpus': 400000000},
                    'NetworkSettings': {'Networks': {'sample-test': {}}},
                    'Mounts': [{'Type': 'volume', 'Name': 'sample-test-postgres-data', 'Destination': '/var/lib/postgresql/data'}]}
        inventory = {'container': {'sample-test-postgres': resource}}
        self.bootstrap.validate_resources(policy, spec, 'd' * 64, inventory)
        resource['HostConfig']['Memory'] = 0
        with self.assertRaises(self.bootstrap.BootstrapError):
            self.bootstrap.validate_resources(policy, spec, 'd' * 64, inventory)
        spec['resource_limits']['unrelated'] = self.limits
        with self.assertRaises(self.bootstrap.BootstrapError):
            self.bootstrap.validate_spec(spec, policy, 'b' * 64, apply=True)

    def test_vector_is_admin_provisioned_without_granting_app_superuser(self):
        policy = sample_policy()
        calls = []
        def execute(argv, **options):
            calls.append((argv, options))
            if 'bootstrap_role_verified' in argv[-1]:
                return b'bootstrap_role_verified\n'
            if 'pg_extension' in argv[-1]:
                return b'vector\n'
            if 'SELECT current_user' in ' '.join(argv):
                return (policy['database']['user'] + '\n').encode()
            return b''
        self.bootstrap.provision_database(policy, {'BOOTSTRAP_PG_APP_PASSWORD': 'synthetic-test-secret-' + 'a' * 32},
                                          execute=execute, extensions=['vector'])
        extension_calls = [argv for argv, _ in calls if 'CREATE EXTENSION' in argv[-1]]
        self.assertEqual(len(extension_calls), 1)
        self.assertEqual(extension_calls[0][extension_calls[0].index('-U') + 1], 'postgres')
        self.assertEqual(extension_calls[0][extension_calls[0].index('-d') + 1], policy['database']['name'])
        self.assertFalse(any('ALTER ROLE' in argv[-1] and 'SUPERUSER' in argv[-1] for argv, _ in calls))
        calls.clear()
        self.bootstrap.provision_database(policy, {'BOOTSTRAP_PG_APP_PASSWORD': 'synthetic-test-secret-' + 'a' * 32},
                                          execute=execute, extensions=['vector'], create=False)
        self.assertFalse(any('CREATE EXTENSION' in argv[-1] for argv, _ in calls))


if __name__ == '__main__':
    unittest.main()
