"""Exercise the user's entry point, including ownership and resumption."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/prepare-project.py'
ASSETS = ROOT / 'assets/cnb-tcr-tat'


class PrepareProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def project(self, name='atlas', count=1):
        root = self.root / name
        root.mkdir()
        config = yaml.safe_load((ASSETS / 'project.example.yml').read_text())
        config['project'] = name
        config['cnb_repository'] = f'example-team/{name}'
        service = next(iter(config['services'].values()))
        config['services'] = {f'app{i}': copy.deepcopy(service) for i in range(count)}
        for key, item in config['services'].items():
            item['image_repository'] = f'ccr.ccs.tencentyun.com/example-team/{name}-{key}'
            item['dockerfile'] = f'{key}/Dockerfile'
            (root / key).mkdir()
            (root / item['dockerfile']).write_text('FROM scratch\n')
        config['host']['identity_probes'] = [
            {'service': key, 'url': f'https://{name}-{key}.example.test/release.json',
             'api_envelope': False} for key in config['services']]
        config['host']['availability_probes'] = [f'https://{name}.example.test/']
        config['host']['migration'] = None
        (root / 'project.yml').write_text(yaml.safe_dump(config))
        return root, config

    def run_prepare(self, root, *args, success=True):
        result = subprocess.run([sys.executable, str(SCRIPT), '--project-root', str(root),
                                 '--config', str(root / 'project.yml'), *args],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_preview_is_readonly_then_two_projects_share_identical_core(self):
        generated = []
        for name, count in [('atlas', 1), ('beacon', 3)]:
            root, _ = self.project(name, count)
            before = {p.relative_to(root) for p in root.rglob('*')}
            self.run_prepare(root)
            self.assertEqual(before, {p.relative_to(root) for p in root.rglob('*')})
            self.run_prepare(root, '--apply')
            vendor = root / 'deploy/vendor/cnb-devops'
            core = {str(p.relative_to(vendor)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for folder in ('host', 'ci', 'dependencies')
                    for p in (vendor / folder).rglob('*') if p.is_file()}
            self.assertTrue(core)
            generated.append(core)
            compose = yaml.safe_load((vendor / 'docker-compose.yml').read_text())
            self.assertEqual(count, len(compose['services']))
            pipeline = yaml.safe_load((root / '.cnb.yml').read_text())
            self.assertIn('push', pipeline['test'])
            self.assertIn(f'{name}-candidate-*', pipeline)
            self.assertTrue((root / 'docs/DEPLOYMENT.md').is_file())
            self.assertTrue((root / 'docs/PROJECT_STATUS.md').is_file())
            install_preview = subprocess.run(
                [sys.executable, str(vendor / 'host/install-project.py'), '--bundle-dir', str(vendor),
                 '--runtime-env', str(root / 'private-file-that-does-not-exist')],
                capture_output=True, text=True,
            )
            self.assertEqual(0, install_preview.returncode, install_preview.stdout + install_preview.stderr)
            self.assertEqual('preview', json.loads(install_preview.stdout)['status'])
            second = self.run_prepare(root, '--apply')
            self.assertIn('unchanged', second.stdout)
        self.assertEqual(*generated)

    def test_unrelated_cnb_job_and_existing_docs_survive(self):
        root, _ = self.project()
        existing = {'test': {'push': [{'name': 'existing-lint', 'stages': [{'script': 'true'}]}]},
                    'main': {'push': [{'name': 'existing-prod', 'stages': [{'script': 'true'}]}]}}
        (root / '.cnb.yml').write_text(yaml.safe_dump(existing))
        (root / 'docs').mkdir()
        (root / 'docs/DEPLOYMENT.md').write_text('owner documentation\n')
        self.run_prepare(root, '--apply')
        merged = yaml.safe_load((root / '.cnb.yml').read_text())
        self.assertEqual(existing['main'], merged['main'])
        self.assertEqual(existing['test']['push'][0], merged['test']['push'][0])
        self.assertEqual('owner documentation\n', (root / 'docs/DEPLOYMENT.md').read_text())
        merged['test']['push'][0]['name'] = 'owner-renamed-lint'
        (root / '.cnb.yml').write_text(yaml.safe_dump(merged))
        self.run_prepare(root, '--apply')
        self.assertEqual('owner-renamed-lint', yaml.safe_load((root / '.cnb.yml').read_text())['test']['push'][0]['name'])

    def test_existing_project_state_is_used_without_a_duplicate_status_document(self):
        root, _ = self.project()
        state = root / 'PROJECT_STATE.md'
        state.write_text('Owner-maintained current status\n')
        self.run_prepare(root, '--apply')
        self.assertEqual('Owner-maintained current status\n', state.read_text())
        self.assertFalse((root / 'docs/PROJECT_STATUS.md').exists())
        self.assertTrue((root / 'docs/DEPLOYMENT.md').is_file())

    def test_github_sync_is_explicit_and_uses_managed_branches(self):
        root, config = self.project()
        config['github_sync'] = True
        config['test_branch'] = 'preview/team'
        (root / 'project.yml').write_text(yaml.safe_dump(config))
        self.run_prepare(root, '--apply')
        workflow = root / '.github/workflows/cnb-devops-sync.yml'
        # BaseLoader keeps GitHub's `on` key as text instead of YAML 1.1 boolean.
        model = yaml.load(workflow.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(['preview/team', 'main'], model['on']['push']['branches'])
        command = model['jobs']['sync']['steps'][1]['run']
        self.assertIn('https://cnb.cool/example-team/atlas.git', command)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', command)
        self.assertNotIn('@TEST_BRANCH@', command)
        checked = subprocess.run(['bash', '-n'], input=command, capture_output=True, text=True)
        self.assertEqual(0, checked.returncode, checked.stderr)

    def test_exact_owned_nested_tag_event_upgrades_without_touching_other_jobs(self):
        spec = importlib.util.spec_from_file_location('prepare_event_upgrade', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        branch = 'atlas-candidate-*'
        job = {'name': 'production', 'stages': [{'script': ['true']}]}
        previous = {branch: {'tag_deploy': {'production': [job]}}}
        generated = {branch: {'tag_deploy.production': [job]}}
        original = copy.deepcopy(previous)
        original[branch]['web_trigger_notes'] = [{'stages': [{'script': ['echo notes']}]}]
        raw = yaml.safe_dump(original).encode()
        upgraded = module.merged_pipeline(raw, generated, previous)
        actual = yaml.safe_load(upgraded)
        self.assertNotIn('tag_deploy', actual[branch])
        self.assertEqual(actual[branch]['tag_deploy.production'], [job])
        self.assertEqual(actual[branch]['web_trigger_notes'], original[branch]['web_trigger_notes'])
        self.assertEqual(module.merged_pipeline(upgraded, generated, generated), upgraded)
        original[branch]['tag_deploy']['production'][0]['stages'][0]['script'] = ['echo drift']
        with self.assertRaises(module.PreparationError):
            module.merged_pipeline(yaml.safe_dump(original).encode(), generated, previous)

    def test_core_drift_blocks_before_writing_anything(self):
        root, config = self.project()
        self.run_prepare(root, '--apply')
        core = root / 'deploy/vendor/cnb-devops/ci/run-tat-release.mjs'
        core.write_text(core.read_text() + '\n// changed locally\n')
        before = (root / '.cnb.yml').read_bytes()
        config['ci']['verify'] = ['echo updated']
        (root / 'project.yml').write_text(yaml.safe_dump(config))
        self.run_prepare(root, '--apply', success=False)
        self.assertEqual(before, (root / '.cnb.yml').read_bytes())

    def test_invalid_config_and_symlink_are_rejected(self):
        for case in ('secret', 'mutable-image', 'missing-file', 'wrong-env', 'symlink'):
            with self.subTest(case=case):
                root, config = self.project(case)
                if case == 'secret':
                    config['host']['secret_key'] = 'must-not-be-accepted'
                elif case == 'mutable-image':
                    config['services']['app0']['image_repository'] += ':latest'
                elif case == 'missing-file':
                    config['services']['app0']['dockerfile'] = 'absent/Dockerfile'
                elif case == 'wrong-env':
                    config['environment'] = 'production'
                else:
                    destination = self.root / 'outside'
                    destination.mkdir()
                    (root / 'deploy').symlink_to(destination, target_is_directory=True)
                (root / 'project.yml').write_text(yaml.safe_dump(config))
                self.run_prepare(root, '--apply', success=False)
                self.assertFalse((root / '.cnb.yml').exists())

    def test_interrupted_apply_resumes_original_plan_and_rejects_another(self):
        root, config = self.project()
        spec = importlib.util.spec_from_file_location('prepare_under_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real_write = module.atomic_write
        calls = []

        def interrupt_after_write(*args):
            real_write(*args)
            calls.append(args[1])
            if len(calls) == 5:
                raise OSError('simulated interruption')

        argv = ['prepare-project.py', '--project-root', str(root), '--config', str(root / 'project.yml'), '--apply']
        with mock.patch.object(module, 'atomic_write', interrupt_after_write), mock.patch.object(sys, 'argv', argv), mock.patch('sys.stdout', io.StringIO()):
            with self.assertRaises(OSError):
                module.main()
        self.assertTrue((root / module.JOURNAL).is_file())
        altered = copy.deepcopy(config)
        altered['ci']['verify'] = ['echo changed-plan']
        (root / 'project.yml').write_text(yaml.safe_dump(altered))
        self.run_prepare(root, '--apply', success=False)
        (root / 'project.yml').write_text(yaml.safe_dump(config))
        self.run_prepare(root, '--apply')
        self.assertFalse((root / module.JOURNAL).exists())
        self.assertIn('unchanged', self.run_prepare(root, '--apply').stdout)


if __name__ == '__main__':
    unittest.main()
