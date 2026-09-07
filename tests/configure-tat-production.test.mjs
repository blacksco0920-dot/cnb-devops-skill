import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { configureTat } from '../scripts/configure-tat.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const wrapper=fileURLToPath(new URL('../assets/cnb-tcr-tat/host/production-release.py',import.meta.url));
function fixture() {
  const authority={schema:'cnb-production-authority/v1',project:'sample',environment:'production',controller_program_sha256:'a'.repeat(64),host_policy_sha256:'b'.repeat(64),controller_compose_sha256:'c'.repeat(64),approval_public_key_sha256:'d'.repeat(64)};
  const raw=Buffer.from(JSON.stringify(authority,null,2)+'\n'),entry='e'.repeat(64);
  const rendered=spawnSync(process.env.CNB_BUNDLE_TEST_PYTHON||'python3',['-c','import runpy,sys; m=runpy.run_path(sys.argv[1]); sys.stdout.buffer.write(m["render_tat_template"]({"install_dir":"/opt/cnb-devops/sample/production/v1"},sys.argv[2],sys.argv[3]))',wrapper,entry,hash(raw)],{encoding:'utf8'});
  assert.equal(rendered.status,0,rendered.stderr);
  return {authority,raw,spec:{schema_version:1,project:'sample',environment:'production',version:'0.2.0-preview.1',target:{region:'ap-example',instance_id:'lhins-demo'},
    expected_artifacts:{program_sha256:entry,policy_sha256:authority.host_policy_sha256,compose_sha256:authority.controller_compose_sha256},production_authority_b64url:raw.toString('base64url'),
    expectedCommand:{CommandName:'sample-production-v0.2.0-preview.1',Description:'Pinned project production release',CommandType:'SHELL',Content:rendered.stdout,Username:'ubuntu',WorkingDirectory:'/home/ubuntu',Timeout:3600,EnableParameter:true,DefaultParameters:{release_request_b64url:'INVALID'},DefaultParameterConfs:[{ParameterName:'release_request_b64url',ParameterValue:'INVALID',ParameterDescription:''}]}}};
}

test('actual production template pins the full authority bytes while retaining the three binding hashes',async()=>{
  const f=fixture(),binding=await configureTat({spec:f.spec});
  for(const [key,value] of Object.entries(f.spec.expected_artifacts))assert.equal(binding[key],value);
  assert.equal(binding.status,'planned');assert.equal(binding.target_verified,false);
  assert.equal(Object.hasOwn(binding,'production_authority_b64url'),false);
});

test('production authority rejects changed scope/hash, duplicate JSON, alternate bytes or altered fixed tuple before network',async()=>{
  for(const problem of ['project','environment','policy','compose','core-hash','key-hash','extra-key','duplicate','raw-bytes','entry-tuple','authority-tuple','missing-authority','test-scope']) {
    const f=fixture(),s=f.spec,a=f.authority;
    if(problem==='project')a.project='other';
    if(problem==='environment')a.environment='test';
    if(problem==='policy')a.host_policy_sha256='f'.repeat(64);
    if(problem==='compose')a.controller_compose_sha256='f'.repeat(64);
    if(problem==='core-hash')a.controller_program_sha256='latest';
    if(problem==='key-hash')a.approval_public_key_sha256='latest';
    if(problem==='extra-key')a.unused=true;
    if(['project','environment','policy','compose','core-hash','key-hash','extra-key'].includes(problem))s.production_authority_b64url=Buffer.from(JSON.stringify(a,null,2)+'\n').toString('base64url');
    if(problem==='duplicate')s.production_authority_b64url=Buffer.from(f.raw.toString().replace('"project": "sample"','"project": "other", "project": "sample"')).toString('base64url');
    if(problem==='raw-bytes')s.production_authority_b64url=Buffer.from(JSON.stringify(a)+'\n').toString('base64url');
    if(problem==='entry-tuple')s.expectedCommand.Content=s.expectedCommand.Content.replace("'e"+'e'.repeat(63)+"', 0o555","'f"+'f'.repeat(63)+"', 0o555");
    if(problem==='authority-tuple')s.expectedCommand.Content=s.expectedCommand.Content.replace(hash(f.raw),'f'.repeat(64));
    if(problem==='missing-authority')delete s.production_authority_b64url;
    if(problem==='test-scope')s.environment='test';
    await assert.rejects(configureTat({spec:s}),undefined,problem);
  }
});
