"""Exercise generated artifacts at their real local command boundaries; no cloud calls."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[1]
ASSETS=ROOT/'assets/cnb-tcr-tat'

def imported(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def outputs(text):
    return dict(re.findall(r'^##\[set-output ([a-z0-9_]+)=([^\r\n]*)\]$',text,re.M))

class GeneratedCiIntegration(unittest.TestCase):
    def test_one_and_three_services_request_host_receipt_candidate_and_gates(self):
        for names in [('web',),('api','portal','worker')]:
            with self.subTest(names=names),tempfile.TemporaryDirectory() as td:
                root=Path(td);config=yaml.safe_load((ASSETS/'project.example.yml').read_text())
                config['project']='atlas' if len(names)==1 else 'beacon';config['cnb_repository']='example-team/'+config['project']
                source=next(iter(config['services'].values()));config['services']={name:copy.deepcopy(source) for name in names}
                for name,spec in config['services'].items():
                    spec['dockerfile']=name+'/Dockerfile';spec['image_repository']=f'ccr.ccs.tencentyun.com/example-team/{config["project"]}-{name}';(root/name).mkdir();(root/spec['dockerfile']).write_text('FROM scratch\n')
                config['host']['identity_probes']=[{'service':name,'url':f'https://{name}.example.test/release.json','api_envelope':False} for name in names]
                config['host']['availability_probes']=['https://app.example.test/health'];config['host']['migration']=None
                config['host']['database']['name']=config['project']+'_test';config['host']['database']['user']=config['project']+'_test'
                (root/'project.yml').write_text(yaml.safe_dump(config))
                prepared=subprocess.run([sys.executable,str(ROOT/'scripts/prepare-project.py'),'--project-root',str(root),'--config',str(root/'project.yml'),'--apply'],text=True,capture_output=True)
                self.assertEqual(prepared.returncode,0,prepared.stderr)
                vendor=root/'deploy/vendor/cnb-devops';ci=json.loads((vendor/'ci-config.json').read_text());policy_raw=(vendor/'host-policy.json').read_bytes();policy=json.loads(policy_raw)
                invalid_tat=subprocess.run(['node',str(vendor/'ci/run-tat-release.mjs')],text=True,capture_output=True)
                self.assertNotEqual(invalid_tat.returncode,0,'TAT CLI must execute its validation even through a symlinked temporary path')
                pipeline=yaml.safe_load((root/'.cnb.yml').read_text());stages=pipeline[config['test_branch']]['push'][0]['stages'];stage={v['name']:v for v in stages}
                env={**os.environ,'HOME':str(root/'home'),'CNB_COMMIT':'a'*40,'CNB_BUILD_ID':'cnb-build-123','CNB_BRANCH':config['test_branch']}
                images={name:ci['services'][name]['image_repository']+'@sha256:'+('b'*64) for name in names}
                env.update({'RELEASE_IMAGE_'+name.upper().replace('-','_'):image for name,image in images.items()})
                def run_stage(name):
                    result=subprocess.run(['bash','-eu','-c','\n'.join(stage[name]['script'])],cwd=root,env=env,text=True,capture_output=True)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    for key,value in outputs(result.stdout).items():
                        if key in stage[name].get('exports',{}):env[stage[name]['exports'][key]]=value
                    return result
                for entry in stages:
                    for command in entry.get('script',[]):
                        self.assertEqual(subprocess.run(['bash','-n'],input=command,text=True,capture_output=True).returncode,0,entry['name'])
                run_stage('validate release identity');run_stage('record digests and remove push credentials')
                self.assertEqual(json.loads((root/'.cnb-release/images.json').read_text()),images)
                js="""import{readFileSync}from'node:fs';import{pathToFileURL}from'node:url';const config=JSON.parse(readFileSync(process.argv[1]));const{renderReleaseRequest}=await import(pathToFileURL(process.argv[2]).href);console.log(renderReleaseRequest({schema:'cnb-release-request/v1',project:config.project,environment:config.environment,controller:config.controller_id,git_sha:process.env.CNB_COMMIT,controller_commit:process.env.CNB_COMMIT,build_id:process.env.CNB_BUILD_ID,images:JSON.parse(readFileSync(process.argv[3]))},config));"""
                result=subprocess.run(['node','--input-type=module','-e',js,str(vendor/'ci-config.json'),str(vendor/'ci/release-request.mjs'),str(root/'.cnb-release/images.json')],env=env,text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr);encoded=result.stdout.strip().encode()
                host=imported(vendor/'host/tat-deploy-test.py','generated_host');policy_hash=hashlib.sha256(policy_raw).hexdigest();host.configure_policy(policy,policy_sha256=policy_hash)
                parsed=host.parse_tat_release_script((vendor/'tat-command.sh').read_bytes().replace(b'{{release_request_b64url}}',encoded))
                self.assertEqual(parsed['images'],images)
                # Compose config expands actual generated substitutions without starting Docker.
                runtime_values={'DATABASE_URL':'postgresql://fixture:fixture@database.example/fixture'}
                runtime_file=root/'.runtime.env';runtime_file.write_text('DATABASE_URL='+runtime_values['DATABASE_URL']+'\n')
                compose_env={**env,'HOME':os.environ.get('HOME',''),**runtime_values,'CNB_RUNTIME_ENV_FILE':str(runtime_file),**{spec['image_env']:images[name] for name,spec in ci['services'].items()}}
                docker=Path('/usr/local/bin/docker')
                if not docker.is_file():
                    import shutil
                    found=shutil.which('docker')
                    self.assertIsNotNone(found,'Docker Compose is required for generated artifact integration')
                    docker=Path(found)
                composed=subprocess.run([str(docker),'compose','--file',str(vendor/'docker-compose.yml'),'config','--format','json'],env=compose_env,text=True,capture_output=True)
                self.assertEqual(composed.returncode,0,composed.stderr)
                host.validate_compose_model(json.loads(composed.stdout),images,runtime_values)
                for name in names:
                    identity=root/(name+'-identity.json')
                    generated=subprocess.run(['node',str(vendor/'ci/release-identity.mjs'),'--service='+name,'--git-sha='+env['CNB_COMMIT'],'--build-id='+env['CNB_BUILD_ID'],'--output='+str(identity)],text=True,capture_output=True)
                    self.assertEqual(generated.returncode,0,generated.stderr)
                    host.validate_public_release_identity(name,identity.read_bytes(),env['CNB_COMMIT'],env['CNB_BUILD_ID'])
                receipt={'schema':'cnb-deploy-result/v1','status':'passed','project':config['project'],'environment':'test','controller':ci['controller_id'],'git_sha':env['CNB_COMMIT'],'controller_commit':env['CNB_COMMIT'],'build_id':env['CNB_BUILD_ID'],'images':images,'controller_program_sha256':hashlib.sha256((vendor/'host/tat-deploy-test.py').read_bytes()).hexdigest(),'controller_compose_sha256':hashlib.sha256((vendor/'docker-compose.yml').read_bytes()).hexdigest(),'policy_sha256':policy_hash,'database_backup_sha256':'c'*64,'container_count':len(names),'probe_count':len(host.PUBLIC_PROBES),'probes':list(host.PUBLIC_PROBES)}
                receipt_raw=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode();(root/'.cnb-release/receipt.json').write_bytes(receipt_raw)
                env.update(RELEASE_TEST_RECEIPT_SHA256=hashlib.sha256(receipt_raw).hexdigest(),RELEASE_TEST_INVOCATION_ID='inv-example123',RELEASE_TEST_COMPLETED_AT='2026-09-06T00:00:00Z')
                run_stage('assemble verified candidate');self.assertEqual(env['RELEASE_CANDIDATE_TAG'],config['project']+'-candidate-cnb-build-123')
                run_stage('initialize annotation readback');run_stage('verify existing annotation state')
                annotation_data=stage['write non-ready evidence']['settings']['data']
                for name,value in env.items():annotation_data=annotation_data.replace('${'+name+'}',value)
                nonready=dict(line.split('=',1) for line in annotation_data.splitlines());(root/'.cnb-release/non-ready.json').write_text(json.dumps(nonready));run_stage('verify non-ready evidence')
                (root/'.cnb-release/ready.json').write_text(json.dumps({**nonready,'candidate_status':'ready'}));run_stage('verify ready evidence')
                candidate=json.loads((root/'.cnb-release/candidate.json').read_text());self.assertEqual(candidate['services'],images);self.assertEqual(candidate['evidence']['public']['probe_count'],len(names)+1)
                # Corrupting an actual receipt after its verified SHA is exported must stop assembly.
                (root/'.cnb-release/candidate.json').unlink();receipt['environment']='production';(root/'.cnb-release/receipt.json').write_text(json.dumps(receipt))
                bad=subprocess.run(['bash','-eu','-c','\n'.join(stage['assemble verified candidate']['script'])],cwd=root,env=env,text=True,capture_output=True)
                self.assertNotEqual(bad.returncode,0);self.assertFalse((root/'.cnb-release/candidate.json').exists())
