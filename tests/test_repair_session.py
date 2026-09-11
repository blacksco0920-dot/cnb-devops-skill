import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import yaml
from test_bundle_host_policy import load_host,sample_policy

SCRIPT=Path(__file__).parents[1]/'scripts/repair-session.py'
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()

class RepairBuildTests(unittest.TestCase):
    def setUp(self):
        if not SCRIPT.exists(): self.fail('fixed repair-session collector is missing')
        spec=importlib.util.spec_from_file_location('repair_session',SCRIPT)
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        host=load_host();host.configure_policy(sample_policy(('api','web')),policy_sha256='a'*64)
        self.bundle={'host':host,'policy':host.POLICY,'files':{'ci-config.json':b'{"test":"fixed"}\n'}}
        self.sha='a'*40;self.build='cnb-source-one';self.repo='team/sample';self.branch='test'
        self.request={'schema':'cnb-release-request/v1','project':host.POLICY['project'],'environment':'test',
          'controller':host.CONTROLLER_ID,'git_sha':self.sha,'controller_commit':self.sha,'build_id':self.build,
          'images':{role:host.POLICY['services'][role]['image_repository']+'@sha256:'+'b'*64 for role in host.SERVICES}}
        self.handoff={'schema':'cnb-test-build-handoff/v1','request':self.request,
          'ci_config_sha256':hashlib.sha256(self.bundle['files']['ci-config.json']).hexdigest()}
        self.encoded=base64.urlsafe_b64encode(canonical(self.handoff).rstrip(b'\n')).decode().rstrip('=')
        self.builds={'data':{'data':[{'sn':self.build,'sha':self.sha,'slug':self.repo,'sourceSlug':self.repo,
          'sourceRef':'test','targetRef':'test','event':'push'}]}}
        names=['validate release identity','install pinned deployment dependencies','verify project','configure TCR push credentials',
          *['build and push '+r for r in host.SERVICES],'record digests and remove push credentials']
        self.stages={str(i):{'id':str(i),'name':n,'status':'success','error':'','startTime':1,'endTime':2,'duration':1,'content':[]} for i,n in enumerate(names)}
        self.stages['2']['content']=['CNB_PROJECT_VERIFIED='+self.sha]
        self.stages[str(len(names)-1)]['content']=['CNB_TEST_BUILD_HANDOFF='+self.encoded]
        self.status={'data':{'status':'success','pipelinesStatus':{self.build+'-001':{
          'id':self.build+'-001','name':'cnb-devops-'+host.POLICY['project']+'-test','status':'success','stages':list(self.stages.values())}}}}
    def validate(self):
        return self.m.validate_build_evidence(self.bundle,self.sha,self.build,self.branch,self.repo,self.builds,self.status,self.stages)
    def test_complete_source_preserves_exact_request(self):
        self.assertEqual(self.validate()['handoff'],self.encoded)
        self.assertEqual(self.validate()['request'],self.request)
    def test_success_status_without_final_verification_marker_is_not_accepted(self):
        self.stages['2']['content']=['build interrupted']
        with self.assertRaisesRegex(ValueError,'VERIFICATION'):self.validate()
    def test_incomplete_build_or_changed_repository_or_source_commit_is_rejected(self):
        original=copy.deepcopy(self.builds)
        for key,value in [('sha','e'*40),('slug','other/sample'),('sourceRef','main'),('event','api_trigger_repair_test')]:
            self.builds=copy.deepcopy(original);self.builds['data']['data'][0][key]=value
            with self.assertRaises(ValueError):self.validate()
        self.builds=original;self.stages['4']['status']='skipped'
        with self.assertRaises(ValueError):self.validate()
    def test_ambiguous_or_changed_handoff_does_not_make_release_request(self):
        stage=self.stages[str(len(self.stages)-1)]
        stage['content']*=2
        with self.assertRaises(ValueError):self.validate()
        stage['content']=['CNB_TEST_BUILD_HANDOFF='+base64.urlsafe_b64encode(canonical({**self.handoff,'ci_config_sha256':'f'*64}).rstrip(b'\n')).decode().rstrip('=')]
        with self.assertRaises(ValueError):self.validate()

    def test_first_collection_creates_private_evidence_before_writing_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary).resolve();os.chmod(parent,0o700)
            args=SimpleNamespace(bundle_dir=parent/'bundle',lock_sha256='a'*64,git_sha=self.sha,
              build_id=self.build,test_branch='test',project_dir=parent,cnb_cli=parent/'cnb',
              evidence_dir=parent/'new-evidence',apply=True)
            bundle=copy.copy(self.bundle);bundle['files']={'ci-config.json':canonical({'cnb_repository':self.repo})}
            answers=[self.builds,self.status,{'data':self.stages['2']},{'data':self.stages[str(len(self.stages)-1)]}]
            with mock.patch.object(self.m,'load_bundle',return_value=bundle), \
                 mock.patch.object(self.m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'captured')), \
                 mock.patch.object(self.m,'verify_source_files',return_value={'test_branch':'test','pipeline_verified':True,'files':{}}), \
                 mock.patch.object(self.m,'cli_json',side_effect=answers), \
                 mock.patch.object(self.m,'validate_build_evidence',return_value={'request':self.request,'handoff':self.encoded}):
                self.assertEqual(self.m.collect(args)['status'],'verified')
            self.assertEqual((args.evidence_dir.stat().st_mode & 0o777),0o700)
            self.assertEqual((args.evidence_dir/'request.json').read_bytes(),canonical(self.request))
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in args.evidence_dir.iterdir()))

    def test_source_pipeline_and_helpers_are_pinned_not_just_stage_names(self):
        root=SCRIPT.parents[1]
        renderer_raw=(root/'assets/cnb-tcr-tat/templates/render.py').read_bytes()
        renderer=SimpleNamespace()
        exec(compile(renderer_raw,'render.py','exec'),renderer.__dict__)
        config=yaml.safe_load((root/'assets/cnb-tcr-tat/project.example.yml').read_text())
        policy,ci,_=renderer.model(config,'a'*64)
        bundle={'policy':policy,'files':{'ci-config.json':renderer.json_bytes(ci),
          'host-policy.json':renderer.json_bytes(policy),'ci/test-repair.mjs':b'fixed helper',
          'bundle.json':canonical({'files':{'templates/render.py':hashlib.sha256(renderer_raw).hexdigest()}})}}
        files={'deploy/vendor/cnb-devops/'+name:raw for name,raw in bundle['files'].items()}
        files['deploy/project.yml']=yaml.safe_dump(config,sort_keys=False).encode()
        files['.cnb.yml']=yaml.safe_dump(renderer.pipeline(config)).encode()
        self.assertTrue(self.m.verify_source_files(bundle,files)['pipeline_verified'])
        changed=copy.deepcopy(files);pipeline=yaml.safe_load(changed['.cnb.yml'])
        pipeline[config['test_branch']]['push'][0]['stages'][2]['script']=['echo skipped']
        changed['.cnb.yml']=yaml.safe_dump(pipeline).encode()
        with self.assertRaisesRegex(ValueError,'PIPELINE'):self.m.verify_source_files(bundle,changed)
        changed=copy.deepcopy(files);changed['deploy/vendor/cnb-devops/ci/test-repair.mjs']=b'changed'
        with self.assertRaisesRegex(ValueError,'ARTIFACT'):self.m.verify_source_files(bundle,changed)

if __name__=='__main__':unittest.main()
