import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
const module = await import('../assets/cnb-tcr-tat/ci/test-repair.mjs').catch(e => {
  if (e.code === 'ERR_MODULE_NOT_FOUND') return {}; throw e;
});
const configRaw = JSON.stringify({schema:'cnb-devops-ci/v1', project:'sample', environment:'test',
  controller_id:'sample-test-controller-v1', cnb_repository:'team/sample',
  services:{api:{image_repository:'registry.invalid/sample/api',image_env:'IMAGE_API'}},
  controller_program_sha256:'a'.repeat(64), controller_compose_sha256:'b'.repeat(64), policy_sha256:'c'.repeat(64),
  probes:[{url:'https://sample.invalid/health'}]});
const commit='d'.repeat(40), buildId='cnb-source-build';
const images={api:'registry.invalid/sample/api@sha256:'+'e'.repeat(64)};

test('build handoff preserves original build identity and every immutable digest',()=>{
  assert.equal(typeof module.createBuildHandoff,'function','verified build handoff missing');
  const encoded=module.createBuildHandoff({configRaw,gitSha:commit,buildId,images});
  const handoff=module.parseBuildHandoff(encoded,configRaw,commit);
  assert.equal(handoff.request.build_id,buildId);
  assert.deepEqual(handoff.request.images,images);
  assert.equal(handoff.ci_config_sha256,createHash('sha256').update(configRaw).digest('hex'));
});
test('wrong commit, changed config, mutable or incomplete images fail',()=>{
  const encoded=module.createBuildHandoff({configRaw,gitSha:commit,buildId,images});
  assert.throws(()=>module.parseBuildHandoff(encoded,configRaw,'f'.repeat(40)));
  assert.throws(()=>module.parseBuildHandoff(encoded,configRaw+'\n',commit));
  for(const bad of [{}, {api:'registry.invalid/sample/api:latest'}, {...images,extra:images.api}]) {
    assert.throws(()=>module.createBuildHandoff({configRaw,gitSha:commit,buildId,images:bad}));
  }
});
test('noncanonical or duplicate-key handoff, unknown fields and production are rejected',()=>{
  const encoded=module.createBuildHandoff({configRaw,gitSha:commit,buildId,images});
  const raw=Buffer.from(encoded,'base64url').toString();
  for(const bad of [raw+'\n', raw.replace('{','{"schema":"fake",'),JSON.stringify({...JSON.parse(raw),extra:true})]) {
    assert.throws(()=>module.parseBuildHandoff(Buffer.from(bad).toString('base64url'),configRaw,commit));
  }
  assert.throws(()=>module.createBuildHandoff({configRaw:configRaw.replace('"test"','"production"'),gitSha:commit,buildId,images}));
});

test('repair wire is explicitly distinct from ordinary release and keeps the original authorization identity',()=>{
  assert.equal(typeof module.renderRepairRequest,'function','repair-only wire discriminator missing');
  const config=JSON.parse(configRaw);
  const request=module.parseBuildHandoff(module.createBuildHandoff({configRaw,gitSha:commit,buildId,images}),configRaw,commit).request;
  const encoded=module.renderRepairRequest(request,config);
  const wire=JSON.parse(Buffer.from(encoded,'base64url').toString());
  assert.equal(wire.schema,'cnb-test-repair-request/v1');
  assert.deepEqual(module.parseRepairRequest(encoded,config),request);
  assert.throws(()=>module.parseRepairRequest(Buffer.from(module.canonical(request)).toString('base64url'),config));
  assert.throws(()=>module.parseRepairRequest(encoded,{...config,environment:'production'}));
});
