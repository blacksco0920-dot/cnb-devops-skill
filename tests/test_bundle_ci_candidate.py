import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / 'assets/cnb-tcr-tat/ci'

def load(name):
    spec=importlib.util.spec_from_file_location(name, CI / (name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def fixture(names):
    config={'schema':'cnb-devops-ci/v1','project':'sample','environment':'test','controller_id':'sample-test-v1','candidate_prefix':'sample-candidate-','cnb_repository':'example/sample','services':{name:{'image_repository':f'registry.example/team/sample-{name}','image_env':f'RELEASE_{name.upper()}_IMAGE'} for name in names},'probes':[{'url':f'https://{name}.example/health'} for name in names]}
    config.update(controller_program_sha256='c'*64,controller_compose_sha256='d'*64,policy_sha256='e'*64)
    receipt={'schema':'cnb-deploy-result/v1','status':'passed','project':'sample','environment':'test','controller':'sample-test-v1','git_sha':'a'*40,'controller_commit':'a'*40,'build_id':'cnb-build-123','images':{name:f'registry.example/team/sample-{name}@sha256:'+('b'*64) for name in names},'controller_program_sha256':'c'*64,'controller_compose_sha256':'d'*64,'policy_sha256':'e'*64,'database_backup_sha256':'f'*64,'container_count':len(names),'probe_count':len(names),'probes':sorted(f'https://{name}.example/health' for name in names)}
    return config,receipt

class CandidateTests(unittest.TestCase):
    def setUp(self): self.m=load('candidate_manifest')
    def assemble(self,config,receipt):
        raw=(json.dumps(receipt)+'\n').encode()
        return self.m.assemble_candidate(raw,config,receipt_sha256=hashlib.sha256(raw).hexdigest(),invocation_id='inv-example123',completed_at='2026-09-06T00:00:00Z',build_id='cnb-build-123',commit='a'*40)
    def test_one_and_three_services_round_trip(self):
        for names in [('web',),('api','portal','worker')]:
            with self.subTest(names=names):
                config,receipt=fixture(names);raw=self.assemble(config,receipt);model=self.m.parse_manifest(raw,config)
                self.assertEqual(model['services'],receipt['images']);self.assertEqual(model['evidence']['runtime']['container_count'],len(names));self.assertEqual(model['evidence']['public']['probe_count'],len(names))
                self.assertEqual(model['candidate_tag'],'sample-candidate-cnb-build-123')
    def test_negative_receipts_do_not_form_candidate(self):
        for names in [('web',),('api','portal','worker')]:
            for kind in ('wrong-environment','missing-image','mutable-tag','wrong-build','wrong-probe','wrong-count','stale-controller','stale-compose','stale-policy'):
                with self.subTest(names=names,kind=kind):
                    config,receipt=fixture(names)
                    if kind=='wrong-environment': receipt['environment']='production'
                    if kind=='missing-image': del receipt['images'][names[0]]
                    if kind=='mutable-tag': receipt['images'][names[0]]='registry.example/team/sample:latest'
                    if kind=='wrong-build': receipt['build_id']='cnb-wrong-123'
                    if kind=='wrong-probe': receipt['probes'][0]='https://unexpected.example/'
                    if kind=='wrong-count': receipt['container_count']=9
                    if kind=='stale-controller': receipt['controller_program_sha256']='9'*64
                    if kind=='stale-compose': receipt['controller_compose_sha256']='9'*64
                    if kind=='stale-policy': receipt['policy_sha256']='9'*64
                    with self.assertRaises(ValueError): self.assemble(config,receipt)
    def test_receipt_hash_cannot_be_replaced(self):
        config,receipt=fixture(('web',));raw=json.dumps(receipt).encode()
        with self.assertRaises(ValueError):self.m.assemble_candidate(raw,config,receipt_sha256='0'*64,invocation_id='inv-example123',completed_at='2026-09-06T00:00:00Z',build_id='cnb-build-123',commit='a'*40)
    def test_duplicate_and_noncanonical_manifest_are_rejected(self):
        config,receipt=fixture(('web',));raw=self.assemble(config,receipt)
        for bad in (b' '+raw,raw.replace(b'"project":"sample"',b'"project":"sample","project":"sample"')):
            with self.assertRaises(ValueError):self.m.parse_manifest(bad,config)
    def test_ready_last_rejects_incomplete_and_wrong_annotations(self):
        import sys
        sys.path.insert(0,str(CI));gate=load('candidate_gate')
        try:
            config,receipt=fixture(('web',));model=self.m.parse_manifest(self.assemble(config,receipt),config)
            expected=gate.candidate_annotation_values(model)
            gate.validate_publication_annotations({},model)
            gate.validate_publication_annotations({k:v for k,v in expected.items() if k!='candidate_status'},model,require_non_ready_complete=True)
            gate.validate_publication_annotations(expected,model,require_ready_complete=True)
            for bad in ({'candidate_status':'ready'},{'candidate_commit':model['application_commit']},{**expected,'surprise':'value'},{**expected,'candidate_manifest_sha256':'0'*64}):
                with self.assertRaises(ValueError):gate.validate_publication_annotations(bad,model)
        finally:sys.path.pop(0)
    def test_tag_publication_is_create_only_and_compares_exact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);work=root/'work';bare=root/'remote.git'
            subprocess.run(['git','init','-q',str(work)],check=True);subprocess.run(['git','init','-q','--bare',str(bare)],check=True)
            subprocess.run(['git','-C',str(work),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-q','--allow-empty','-m','initial'],check=True)
            commit=subprocess.check_output(['git','-C',str(work),'rev-parse','HEAD'],text=True).strip()
            config,receipt=fixture(('web',));receipt['git_sha']=commit;receipt['controller_commit']=commit
            raw=json.dumps(receipt).encode();manifest=self.m.assemble_candidate(raw,config,receipt_sha256=hashlib.sha256(raw).hexdigest(),invocation_id='inv-example123',completed_at='2026-09-06T00:00:00Z',build_id='cnb-build-123',commit=commit)
            (root/'config.json').write_text(json.dumps(config));(root/'manifest.json').write_bytes(manifest)
            args=['bash',str(CI/'publish-candidate-tag.sh'),f'--config={root}/config.json',f'--manifest={root}/manifest.json','--tag=sample-candidate-cnb-build-123',f'--commit={commit}',f'--remote={bare}']
            env={**os.environ,'CNB_CANDIDATE_TAG_ALLOW_LOCAL_BARE_REMOTE_FOR_TESTS':'1'}
            for expected in ('created','existing'):
                result=subprocess.run(args,cwd=work,env=env,text=True,capture_output=True);self.assertEqual(result.returncode,0,result.stderr);self.assertIn('status='+expected,result.stdout)
            original=subprocess.check_output(['git','--git-dir='+str(bare),'rev-parse','refs/tags/sample-candidate-cnb-build-123'],text=True)
            model=self.m.parse_manifest(manifest,config);model.pop('manifest_sha256');model['services']['web']='registry.example/team/sample-web@sha256:'+('9'*64);(root/'manifest.json').write_bytes(self.m.create_manifest(model,config))
            self.assertNotEqual(subprocess.run(args,cwd=work,env=env,capture_output=True).returncode,0)
            self.assertEqual(subprocess.check_output(['git','--git-dir='+str(bare),'rev-parse','refs/tags/sample-candidate-cnb-build-123'],text=True),original)

class PushDigestTests(unittest.TestCase):
    def test_accepts_one_exact_digest_and_rejects_ambiguous_output(self):
        digest='sha256:'+('a'*64)
        cases=[('tag: digest: '+digest+' size: 123\n',True),('digest: '+digest+'\n',True),('digest: '+digest+'\ndigest: '+digest+'\n',False),('digest: sha256:bad\n',False),('pushed layer\n',False)]
        for output,valid in cases:
            with self.subTest(output=output):
                result=subprocess.run(['bash',str(CI/'extract-docker-push-digest.sh')],input=output,text=True,capture_output=True)
                self.assertEqual(result.returncode==0,valid,result.stderr)
                self.assertEqual(result.stdout,digest+'\n' if valid else '')

class GithubSyncTests(unittest.TestCase):
    def test_generated_workflow_blocks_unmanaged_refs_and_wrong_sha_before_network(self):
        import yaml
        template=ROOT/'assets/cnb-tcr-tat/templates/github-sync.yml.tmpl'
        text=template.read_text().replace('@TEST_BRANCH@','staging').replace('@PRODUCTION_BRANCH@','production').replace('@CNB_REPOSITORY@','example-team/sample')
        model=yaml.load(text,Loader=yaml.BaseLoader)
        self.assertEqual(model['on']['push']['branches'],['staging','production'])
        script=model['jobs']['sync']['steps'][1]['run']
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);git=base/'git';network=base/'network-called'
            git.write_text('#!/bin/sh\nif [ "$1" = rev-parse ] && [ "$2" = HEAD ]; then printf "%s\\n" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; else : > "$NETWORK_MARKER"; exit 99; fi\n');git.chmod(0o755)
            env={**os.environ,'PATH':str(base)+os.pathsep+os.environ['PATH'],'CNB_PUSH_TOKEN':'fixture-token','GITHUB_SHA':'b'*40,'NETWORK_MARKER':str(network)}
            for ref in ('refs/tags/release','refs/heads/staging'):
                result=subprocess.run(['bash','-c',script],env={**env,'GITHUB_REF':ref},cwd=base,text=True,capture_output=True)
                self.assertNotEqual(result.returncode,0);self.assertFalse(network.exists())
