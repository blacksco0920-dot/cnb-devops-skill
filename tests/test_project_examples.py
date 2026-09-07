"""Run the documented example inputs through the actual offline entry points."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets/cnb-tcr-tat'


class ProjectExampleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        # Generation inspects this path; no application image is built or run.
        (self.project / 'Dockerfile').write_text('FROM scratch\n')

    def prepare(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / 'scripts/prepare-project.py'),
             '--project-root', str(self.project), '--config', str(self.project / 'project.yml'), *args],
            capture_output=True, text=True,
        )

    def test_minimal_example_preserves_test_only_generation(self):
        (self.project / 'project.yml').write_bytes((ASSETS / 'project.example.yml').read_bytes())
        result = self.prepare('--apply')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        bundle = self.project / 'deploy/vendor/cnb-devops'
        self.assertTrue((bundle / 'host-policy.json').is_file())
        self.assertFalse((bundle / 'production').exists())
        self.assertFalse((bundle / 'recovery-policy.json').exists())

    def test_full_example_requires_project_key_then_generates_both_complete_environments(self):
        example = ASSETS / 'project.full.example.yml'
        self.assertTrue(example.is_file(), 'A complete dual-environment starting example is missing')
        (self.project / 'project.yml').write_bytes(example.read_bytes())
        before = {path.relative_to(self.project) for path in self.project.rglob('*')}
        rejected = self.prepare('--apply')
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(before, {path.relative_to(self.project) for path in self.project.rglob('*')})

        config = yaml.safe_load(example.read_text())
        # The private key exists only in the Node process; export only its public half.
        public = subprocess.run(
            ['node', '-e', "const {publicKey}=require('node:crypto').generateKeyPairSync('ed25519');"
             "process.stdout.write(publicKey.export({type:'spki',format:'pem'}));"],
            capture_output=True, text=True, check=True,
        ).stdout
        config['production']['approval_public_key'] = public
        (self.project / 'project.yml').write_text(yaml.safe_dump(config))
        preview = self.prepare()
        self.assertEqual(preview.returncode, 0, preview.stdout + preview.stderr)
        self.assertEqual(before, {path.relative_to(self.project) for path in self.project.rglob('*')})
        applied = self.prepare('--apply')
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        vendor = self.project / 'deploy/vendor/cnb-devops'
        generated = {path.relative_to(self.project): path.read_bytes()
                     for path in self.project.rglob('*') if path.is_file()}
        repeated = self.prepare('--apply')
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertEqual(generated, {path.relative_to(self.project): path.read_bytes()
                                    for path in self.project.rglob('*') if path.is_file()})

        pipeline = yaml.safe_load((self.project / '.cnb.yml').read_text())
        candidate = pipeline['sample-candidate-*']
        self.assertIn('web_trigger_production_readiness', candidate)
        self.assertIn('tag_deploy.production', candidate)
        for event in ('web_trigger_production_readiness', 'tag_deploy.production'):
            imports = {stage['imports'] for stage in candidate[event][0]['stages'] if 'imports' in stage}
            self.assertEqual(imports, {config['production']['tat_import']})
        self.assertEqual((vendor / 'production/approval-ed25519.pub').read_text(), public)
        test_ci = json.loads((vendor / 'ci-config.json').read_bytes())
        production_ci = json.loads((vendor / 'production/ci-config.json').read_bytes())
        self.assertEqual(test_ci['services'], production_ci['services'])
        for environment, port, domain in [('test', 13000, 'test.example.test'),
                                          ('production', 23000, 'app.example.test')]:
            with self.subTest(environment=environment):
                bundle = vendor if environment == 'test' else vendor / 'production'
                policy_path = bundle / 'host-policy.json'
                policy = json.loads(policy_path.read_bytes())
                policy_sha = hashlib.sha256(policy_path.read_bytes()).hexdigest()
                scope = 'sample-' + environment
                self.assertEqual(policy['networks'], [scope])
                self.assertEqual(policy['database']['host'], scope + '-postgres')
                self.assertEqual(policy['database']['container'], scope + '-postgres')
                self.assertEqual(policy['database']['name'], 'sample_' + environment)
                self.assertEqual(policy['database']['user'], 'sample_' + environment)
                self.assertEqual(policy['environment'], environment)
                self.assertEqual(policy['services']['web']['loopback_port'],
                                 {'host_ip': '127.0.0.1', 'protocol': 'tcp', 'published': port, 'target': 3000})
                compose = yaml.safe_load((bundle / 'docker-compose.yml').read_text())
                self.assertEqual(compose['services']['web']['networks'], [scope])
                self.assertEqual(compose['services']['web']['environment']['APP_ENV'], environment)
                self.assertEqual(compose['services']['web']['ports'],
                                 [{'host_ip': '127.0.0.1', 'protocol': 'tcp', 'published': str(port), 'target': 3000}])
                self.assertEqual(compose['services']['web']['volumes'],
                                 [{'type': 'bind', 'source': '/opt/apps/' + scope + '/uploads', 'target': '/app/uploads'}])
                caddy = runpy.run_path(str(bundle / 'host/configure-native-caddy.py'))
                site, domains = caddy['render_sites'](policy, 'sample', policy_sha, environment)
                self.assertEqual(domains, [domain])
                self.assertIn(f'reverse_proxy 127.0.0.1:{port}'.encode(), site)

                spec = {'schema': 'cnb-first-host/v1', 'policy_sha256': policy_sha,
                        'images': {'postgres': None}, 'docker_packages': {}, 'generate_env': []}
                spec_path = self.project / (environment + '-bootstrap-spec.json')
                spec_path.write_text(json.dumps(spec))
                bootstrap = subprocess.run(
                    [sys.executable, str(bundle / 'host/bootstrap-host.py'), '--bundle-dir', str(bundle),
                     '--lock-sha256', hashlib.sha256((bundle / 'artifact-lock.json').read_bytes()).hexdigest(),
                     '--spec', str(spec_path), '--spec-sha256', hashlib.sha256(spec_path.read_bytes()).hexdigest()],
                    capture_output=True, text=True,
                )
                self.assertEqual(bootstrap.returncode, 0, bootstrap.stdout + bootstrap.stderr)
                planned = json.loads(bootstrap.stdout)
                self.assertEqual((planned['status'], planned['environment']), ('preview', environment))
                self.assertEqual(planned['missing_image_pins'], ['postgres'])
                validator = runpy.run_path(str(bundle / 'host/bootstrap-host.py'))
                with self.assertRaises(validator['BootstrapError']):
                    validator['validate_spec'](spec, policy, policy_sha, apply=True)

                recovery = json.loads((bundle / 'recovery-policy.json').read_bytes())
                self.assertEqual(recovery['mounts'], {'uploads': 'backup'})
                self.assertEqual(recovery['required_nonempty_tables'],
                                 [{'schema': 'public', 'name': 'users', 'minimum_rows': 1},
                                  {'schema': 'public', 'name': 'uploaded_files', 'minimum_rows': 1}])
                recovery_api = runpy.run_path(str(bundle / 'host/recover-project.py'))
                recovery_api['validate_recovery_policy'](recovery, policy, policy_sha)


if __name__ == '__main__':
    unittest.main()
