import importlib.util
from pathlib import Path
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('repair_pipeline',ROOT/'assets/cnb-tcr-tat/templates/render.py')
render=importlib.util.module_from_spec(spec);spec.loader.exec_module(render)

class RepairPipelineTests(unittest.TestCase):
    def setUp(self):
        self.config=yaml.safe_load((ROOT/'assets/cnb-tcr-tat/project.example.yml').read_text())
        self.events=render.pipeline(self.config)[self.config['test_branch']]

    def test_prepare_event_verifies_and_builds_without_deploying(self):
        self.assertIn('api_trigger_prepare_repair',self.events)
        stages=self.events['api_trigger_prepare_repair'][0]['stages']
        names=[s['name'] for s in stages]
        self.assertIn('verify project',names)
        self.assertTrue(all('build and push '+role in names for role in self.config['services']))
        self.assertEqual(names[-1],'record digests and remove push credentials')
        self.assertNotIn('deploy and verify test through TAT',names)
        self.assertIn('CNB_PROJECT_VERIFIED',next(s for s in stages if s['name']=='verify project')['script'][0])

    def test_repair_event_reuses_source_identity_and_keeps_candidate_gates(self):
        self.assertIn('api_trigger_repair_test',self.events)
        stages=self.events['api_trigger_repair_test'][0]['stages']
        self.assertFalse(any(s['name']=='verify project' or s['name'].startswith('build and push ') for s in stages))
        first=stages[0]
        self.assertEqual(first['exports']['source_build_id'],'RELEASE_SOURCE_BUILD_ID')
        self.assertIn('--action=prepare',first['script'][0])
        self.assertEqual(first['script'][0].count('set-output source_build_id='),0)
        deploy=next(s for s in stages if s['name']=='deploy and verify test through TAT')
        self.assertIn('--action=deploy',deploy['script'][0])
        candidate=next(s for s in stages if s['name']=='assemble verified candidate')
        self.assertIn('--build-id "$RELEASE_SOURCE_BUILD_ID"',candidate['script'][0])
        self.assertEqual(stages[-1]['name'],'verify ready evidence')

    def test_normal_push_still_builds_and_deploys_and_exports_its_own_build(self):
        stages=self.events['push'][0]['stages']
        self.assertIn('set-output source_build_id=%s',stages[0]['script'][0])
        self.assertIn('deploy and verify test through TAT',[s['name'] for s in stages])
        record=next(s for s in stages if s['name']=='record digests and remove push credentials')
        self.assertIn('--action=record',record['script'][0])

if __name__=='__main__':unittest.main()
