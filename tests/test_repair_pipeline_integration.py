"""Run the repair wire and generated prepare stage locally, without SDK or cloud."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets/cnb-tcr-tat'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepairPipelineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        if not cls.node:
            raise AssertionError('Node.js is required for the real repair CI integration')
        cls.render = load_module('repair_integration_render', ASSETS / 'templates/render.py')
        cls.host = load_module('repair_integration_host', ASSETS / 'host/tat-deploy-test.py')
        cls.repair = load_module('repair_integration_helper', ASSETS / 'host/repair-test-release.py')
        cls.candidate = load_module('repair_integration_candidate', ASSETS / 'ci/candidate_manifest.py')
        cls.config = yaml.safe_load((ASSETS / 'project.example.yml').read_text())
        cls.policy, cls.ci, _ = cls.render.model(cls.config, cls.host.controller_program_sha256())
        cls.config_raw = cls.render.json_bytes(cls.ci).decode()
        cls.host.configure_policy(cls.policy, policy_sha256=cls.ci['policy_sha256'])
        cls.request = {
            'schema': 'cnb-release-request/v1', 'project': cls.ci['project'],
            'environment': 'test', 'controller': cls.ci['controller_id'],
            'git_sha': 'a' * 40, 'controller_commit': 'a' * 40, 'build_id': 'cnb-source-one',
            'images': {name: service['image_repository'] + '@sha256:' + 'b' * 64
                       for name, service in cls.ci['services'].items()},
        }
        cls.execution_build = 'cnb-repair-execution'
        cls.wire = cls.node_json("""(() => {
          const config = JSON.parse(input.configRaw);
          const handoff = repair.createBuildHandoff({configRaw: input.configRaw,
            gitSha: input.request.git_sha, buildId: input.request.build_id, images: input.request.images});
          const request = repair.parseBuildHandoff(handoff, input.configRaw, input.request.git_sha).request;
          return {handoff, repair: repair.renderRepairRequest(request, config),
            normal: normal.renderReleaseRequest(request, config), canonical: repair.canonical(request) + '\\n'};
        })()""", configRaw=cls.config_raw, request=cls.request)

    @classmethod
    def node_json(cls, expression, **values):
        source = (
            "import fs from 'node:fs';\n"
            f"import * as repair from {json.dumps((ASSETS / 'ci/test-repair.mjs').as_uri())};\n"
            f"import * as normal from {json.dumps((ASSETS / 'ci/release-request.mjs').as_uri())};\n"
            "const input = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
            f"process.stdout.write(JSON.stringify({expression}));\n"
        )
        result = subprocess.run([cls.node, '--input-type=module', '-e', source],
                                input=json.dumps(values), text=True, capture_output=True, timeout=15,
                                env={'PATH': str(Path(cls.node).parent) + os.pathsep + os.defpath})
        if result.returncode:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    def parse_host_wire(self, encoded):
        template = self.host.render_tat_template(
            self.policy, self.host.controller_program_sha256(), self.ci['policy_sha256'])
        return self.host.parse_tat_release_script(
            template.replace(b'{{release_request_b64url}}', encoded.encode()))

    def assemble_candidate(self, build_id):
        probes = sorted({probe['url'] for probe in self.ci['probes']})
        receipt = {
            **self.request, 'schema': 'cnb-deploy-result/v1', 'status': 'passed',
            'controller_program_sha256': self.ci['controller_program_sha256'],
            'controller_compose_sha256': self.ci['controller_compose_sha256'],
            'policy_sha256': self.ci['policy_sha256'], 'database_backup_sha256': 'c' * 64,
            'container_count': len(self.ci['services']), 'probe_count': len(probes), 'probes': probes,
        }
        raw = (json.dumps(receipt, separators=(',', ':')) + '\n').encode()
        return json.loads(self.candidate.assemble_candidate(
            raw, self.ci, receipt_sha256=hashlib.sha256(raw).hexdigest(),
            invocation_id='inv-review123456', completed_at='2026-09-11T00:00:00Z',
            commit=self.request['git_sha'], build_id=build_id))

    def test_javascript_wire_distinguishes_repair_from_normal_in_real_host_parser(self):
        repair = self.parse_host_wire(self.wire['repair'])
        normal = self.parse_host_wire(self.wire['normal'])
        self.assertIs(repair.pop('repair_required'), True)
        self.assertNotIn('repair_required', normal)
        self.assertEqual(repair, normal)
        self.assertEqual(repair['build_id'], self.request['build_id'])
        self.assertEqual(repair['images'], self.request['images'])

    def test_javascript_request_hash_matches_python_permit_canonical_bytes(self):
        self.assertEqual(self.wire['canonical'].encode(), self.repair.canonical(self.request))

    def test_handoff_binds_original_config_bytes_and_rejects_changed_bytes(self):
        encoded = self.wire['handoff']
        handoff = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        self.assertEqual(handoff['request'], self.request)
        self.assertEqual(handoff['ci_config_sha256'], hashlib.sha256(self.config_raw.encode()).hexdigest())
        rejected = self.node_json("""(() => {
          try { repair.parseBuildHandoff(input.handoff, input.configRaw, input.commit); return false; }
          catch { return true; }
        })()""", handoff=encoded, configRaw=self.config_raw + '\n', commit=self.request['git_sha'])
        self.assertTrue(rejected)

    def test_candidate_keeps_source_build_identity_and_digest_set(self):
        candidate = self.assemble_candidate(self.request['build_id'])
        self.assertEqual(candidate['build_id'], self.request['build_id'])
        self.assertEqual(candidate['candidate_tag'], self.ci['candidate_prefix'] + self.request['build_id'])
        self.assertEqual(candidate['services'], self.request['images'])
        self.assertTrue(candidate['build_url'].endswith('/' + self.request['build_id']))

    def test_candidate_rejects_execution_build_in_place_of_source_build(self):
        with self.assertRaisesRegex(self.candidate.CandidateError, 'receipt build_id mismatch'):
            self.assemble_candidate(self.execution_build)

    def test_generated_prepare_shell_exports_source_build_and_rejects_reused_execution_id(self):
        stage = self.render.pipeline(self.config)[self.config['test_branch']]['api_trigger_repair_test'][0]['stages'][0]
        self.assertEqual(stage['exports'], {'source_build_id': 'RELEASE_SOURCE_BUILD_ID'})
        self.assertEqual(len(stage['script']), 1)
        for execution_id, expected_success in ((self.execution_build, True), (self.request['build_id'], False)):
            with self.subTest(execution_id=execution_id), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                vendor = workspace / self.render.VENDOR
                # Current CI sources are sufficient: prepare must not load the Tencent SDK.
                shutil.copytree(ASSETS / 'ci', vendor / 'ci')
                (vendor / 'ci-config.json').write_text(self.config_raw)
                result = subprocess.run(['/bin/sh', '-c', stage['script'][0]], cwd=workspace,
                                        text=True, capture_output=True, timeout=15, env={
                                            'PATH': str(Path(self.node).parent) + os.pathsep + os.defpath,
                                            'CNB_BRANCH': self.config['test_branch'],
                                            'CNB_COMMIT': self.request['git_sha'],
                                            'CNB_BUILD_ID': execution_id,
                                            'CNB_TEST_REPAIR_BUILD': self.wire['handoff'],
                                        })
                evidence = workspace / '.cnb-release/repair-execution.json'
                if expected_success:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, f"##[set-output source_build_id={self.request['build_id']}]\n")
                    self.assertEqual(json.loads(evidence.read_bytes()), {
                        'schema': 'cnb-test-repair-execution/v1', 'source_build_id': self.request['build_id'],
                        'execution_build_id': execution_id,
                        'request_sha256': hashlib.sha256(self.repair.canonical(self.request)).hexdigest(),
                    })
                    self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stderr, 'TEST_REPAIR_FAILED\n')
                    self.assertNotIn('set-output', result.stdout)
                    self.assertFalse(evidence.exists())


if __name__ == '__main__':
    unittest.main()
