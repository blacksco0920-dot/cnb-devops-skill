import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

import jsonschema
import yaml

BUNDLE = Path(__file__).parents[1] / 'assets/cnb-tcr-tat'
spec = importlib.util.spec_from_file_location('two_environment_render', BUNDLE / 'templates/render.py')
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def project():
    config = yaml.safe_load((BUNDLE / 'project.example.yml').read_text())
    host = json.loads(json.dumps(config['host']).replace('sample_test', 'sample_production'))
    host['database']['container'] = 'sample-production-postgres'
    host['database']['host'] = 'sample-production-postgres'
    host['availability_probes'] = ['https://www.example.test/health']
    host['identity_probes'][0]['url'] = 'https://www.example.test/release.json'
    config['production'] = {'host': host, 'services': {'web': {'loopback_port': 23000}},
                            'tat_import': 'https://cnb.cool/example-team/deploy-secret/-/blob/main/sample-production.yml',
                            'approval_public_key': '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA' + 'A' * 42 + 'A=\n-----END PUBLIC KEY-----\n'}
    config['recovery'] = {'mounts': {}, 'required_nonempty_tables': [{'schema': 'public', 'name': 'Account', 'minimum_rows': 1}]}
    config['host']['required_env'].append('REDIS_URL')
    config['host']['redis'] = {'url_env': 'REDIS_URL', 'host': 'sample-test-redis', 'port': 6379,
                              'database': 0, 'container': 'sample-test-redis'}
    config['production']['host']['required_env'].append('REDIS_URL')
    config['production']['host']['redis'] = {**config['host']['redis'],
        'host': 'sample-production-redis', 'container': 'sample-production-redis'}
    return config


class TwoEnvironmentTests(unittest.TestCase):
    def test_schema_accepts_explicit_production_and_recovery_differences(self):
        jsonschema.validate(project(), json.loads((BUNDLE / 'project.schema.json').read_text()))

    def test_service_identity_is_reused_with_separate_runtime_scope(self):
        original = project()
        snapshot = copy.deepcopy(original)
        selected = render.environment_config(original, 'production')
        policy, ci, compose = render.model(selected, 'a' * 64)
        self.assertEqual(original, snapshot)
        self.assertEqual(policy['environment'], 'production')
        self.assertEqual(policy['app_dir'], '/opt/apps/sample-production')
        self.assertEqual(policy['install_dir'], '/opt/cnb-devops/sample/production/v1')
        self.assertEqual(ci['services']['web']['image_repository'], original['services']['web']['image_repository'])
        service = yaml.safe_load(compose)['services']['web']
        self.assertEqual(service['container_name'], 'sample-production-web')
        self.assertEqual(service['ports'][0]['published'], '23000')
        self.assertEqual(service['ports'][0]['host_ip'], '127.0.0.1')
        self.assertEqual(policy['database']['name'], 'sample_production')
        host_spec = importlib.util.spec_from_file_location('two_environment_host', BUNDLE / 'host/tat-deploy-test.py')
        host = importlib.util.module_from_spec(host_spec)
        host_spec.loader.exec_module(host)
        host.validate_host_policy(policy)

    def test_production_cannot_replace_image_repository_or_add_service(self):
        schema = json.loads((BUNDLE / 'project.schema.json').read_text())
        config = project()
        config['production']['services']['web']['image_repository'] = 'ccr.ccs.tencentyun.com/other/web'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(config, schema)
        config = project()
        config['production']['services']['foreign'] = {'loopback_port': 23001}
        with self.assertRaises(ValueError):
            render.environment_config(config, 'production')

    def test_production_jobs_consume_candidates_without_building_images(self):
        config = project()
        pipeline = render.pipeline(config)['sample-candidate-*']
        for phase, job in [('readiness', pipeline['web_trigger_production_readiness'][0]),
                           ('apply', pipeline['tag_deploy']['production'][0])]:
            scripts = '\n'.join(script for stage in job['stages'] for script in stage.get('script', []))
            self.assertIn('candidate_gate.py production', scripts)
            self.assertIn('--branch main', scripts)
            self.assertIn('run-production-deploy.mjs ' + phase, scripts)
            self.assertNotIn('docker build', scripts)
            self.assertNotIn('docker push', scripts)
            self.assertNotIn('private-key', scripts)
            self.assertEqual(job['lock']['key'], 'sample-production-release')
            for stage in job['stages']:
                for script in stage.get('script', []):
                    result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('verify production annotation readback', job['stages'][-1]['name'])
        ui = render.tag_deploy(True)['environments'][0]
        self.assertNotIn('尚未', json.dumps(ui, ensure_ascii=False))
        requirements = {item.get('annotation') for item in ui['require']}
        self.assertTrue({'candidate_status', 'test_runtime_status', 'test_public_status', 'production_readiness_status', 'production_approval_status'} <= requirements)


if __name__ == '__main__':
    unittest.main()
