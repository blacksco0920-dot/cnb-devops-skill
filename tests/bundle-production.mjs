import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, rm, realpath, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson } from '../assets/cnb-tcr-tat/ci/run-production-deploy.mjs';
import { canonicalBytes, parseCanonical, signApproval, verifyApproval, approvalPayload, sha256, parseCandidate } from '../assets/cnb-tcr-tat/ci/production-contract.mjs';
import { productionFixture } from './bundle-production-fixture.mjs';
import { runProductionTat } from '../assets/cnb-tcr-tat/ci/run-production-deploy.mjs';
import { approveProduction } from '../assets/cnb-tcr-tat/admin/sign-production-approval.mjs';

test('production canonical bytes reject duplicate, float and alternate framing', () => {
  assert.equal(canonicalBytes({z:1,a:true}).toString(), '{"a":true,"z":1}\n');
  for (const raw of ['{"a":1,"a":2}\n','{"a":1.0}\n','{"a":1}','{"a":NaN}\n']) {
    assert.throws(() => parseCanonical(Buffer.from(raw)));
  }
});

for(const names of [['web'],['api','h5','ocr']]) {
  test(`${names.length} immutable services pass readiness and signed production apply using the exact task receipt`,async()=>{
    const fixture=productionFixture(names);
    for(const action of ['readiness','apply']) {
      const remote=fixture.clientFor(action);
      const actual=await runProductionTat({...fixture,action,client:remote.client,approval:action==='apply'?fixture.approval:null});
      assert.deepEqual(actual.receipt,action==='apply'?fixture.result:fixture.readiness);
      assert.equal(remote.invoked(),1);
    }
  });
  for(const problem of ['mutable-image','missing-service','wrong-environment','wrong-evidence-count']) {
    test(`${names.length} candidate ${problem} is blocked even with a fresh manifest hash`,()=>{
      const f=productionFixture(names),candidate=structuredClone(f.candidate);
      if(problem==='mutable-image')candidate.services[names[0]]=f.config.services[names[0]].image_repository+':latest';
      if(problem==='missing-service')delete candidate.services[names[0]];
      if(problem==='wrong-environment')candidate.environment='production';
      if(problem==='wrong-evidence-count')candidate.evidence.runtime.container_count++;
      delete candidate.manifest_sha256;candidate.manifest_sha256=sha256(canonicalBytes(candidate).subarray(0,-1));
      assert.throws(()=>parseCandidate(canonicalBytes(candidate),f.candidateConfig));
    });
  }
  for(const problem of ['signature','expired','target','digest','prepared','receipt-image','receipt-probe']) {
    test(`${names.length} production rejects ${problem} without repeating Invoke`,async()=>{
      const f=productionFixture(names),remote=f.clientFor('apply');
      if(problem==='signature')f.approval.signature_b64url='A'.repeat(86);
      if(problem==='expired'){f.payload.issued_at=new Date(f.instant-7200000).toISOString().replace('.000Z','Z');f.payload.expires_at=new Date(f.instant-3600000).toISOString().replace('.000Z','Z');f.approval=signApproval(f.payload,f.privateKey);}
      if(problem==='target'){f.payload.authority_sha256='f'.repeat(64);f.approval=signApproval(f.payload,f.privateKey);}
      if(problem==='digest'){f.payload.candidate_bytes_sha256='f'.repeat(64);f.approval=signApproval(f.payload,f.privateKey);}
      if(problem==='prepared'){f.payload.prepared_sha256='f'.repeat(64);f.approval=signApproval(f.payload,f.privateKey);}
      if(problem==='receipt-image'){f.result.release.images={...f.result.release.images,[names[0]]:f.config.services[names[0]].image_repository+'@sha256:'+'f'.repeat(64)};remote.task.TaskResult.Output=canonicalBytes(f.result).toString('base64');}
      if(problem==='receipt-probe'){f.result.release.probes=['https://wrong.example/health'];remote.task.TaskResult.Output=canonicalBytes(f.result).toString('base64');}
      await assert.rejects(runProductionTat({...f,action:'apply',client:remote.client}));
      assert.equal(remote.invoked(),problem.startsWith('receipt-')?1:0);
    });
  }
}

test('administrator signs only after independently verifying the exact readiness task; the private key stays local',async()=>{
  const f=productionFixture(['api','h5','ocr']),remote=f.clientFor();delete remote.client.InvokeCommand;
  const directory=await realpath(await mkdtemp(join(tmpdir(),'cnb-local-approval-')));
  try {
    const key=join(directory,'private.pem'),output=join(directory,'approval.json');
    await writeFile(key,f.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
    const result=await approveProduction({...f,client:remote.client,invocationId:'inv-DEMO1234',privateKeyPath:key,output,authorized:true});
    const envelope=parseCanonical(await readFile(output)),payload=verifyApproval(envelope,f.publicKey);
    assert.equal(payload.prepared_sha256,f.readiness.prepared_sha256);assert.equal(payload.candidate_bytes_sha256,sha256(f.candidateRaw));
    assert.equal(result.production_approval_b64url,canonicalBytes(envelope).toString('base64url'));assert.equal(remote.invoked(),0);assert.equal(remote.described(),1);
    await assert.rejects(approveProduction({...f,client:remote.client,invocationId:'inv-DEMO1234',privateKeyPath:key,output,authorized:true}),/EEXIST/);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('forged readiness output or missing authorization cannot reach private-key access',async()=>{
  const f=productionFixture(),remote=f.clientFor();remote.task.CommandDocument.Username='root';
  // This nonexistent path would produce ENOENT if key access ran first.
  const args={...f,client:remote.client,invocationId:'inv-DEMO1234',privateKeyPath:'/does-not-exist/private.pem',output:'/does-not-exist/approval.json'};
  await assert.rejects(approveProduction({...args,authorized:true}),/executed TAT command/);
  await assert.rejects(approveProduction({...args,authorized:false}),/local production authorization/);
  assert.equal(remote.invoked(),0);
});

test('administrator rejects a readable private key and never writes an approval',async()=>{
  const f=productionFixture(),remote=f.clientFor(),directory=await realpath(await mkdtemp(join(tmpdir(),'cnb-local-key-mode-')));
  try {
    const key=join(directory,'private.pem'),output=join(directory,'approval.json');
    await writeFile(key,f.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});await chmod(key,0o644);
    await assert.rejects(approveProduction({...f,client:remote.client,invocationId:'inv-DEMO1234',privateKeyPath:key,output,authorized:true}),/private key metadata/);
    await assert.rejects(readFile(output),/ENOENT/);assert.equal(remote.invoked(),0);
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('pretty printed production config rejects duplicate keys rather than adopting the last value', async () => {
  const directory=await mkdtemp(join(tmpdir(),'cnb-production-json-'));
  try {
    const path=join(directory,'config.json');
    await writeFile(path,'{ "environment": "test", "environment": "production" }\n');
    await assert.rejects(readJson(path));
    await writeFile(path,'{ "environment": "production", "count": 3 }\n');
    assert.deepEqual(await readJson(path),{environment:'production',count:3});
  } finally {await rm(directory,{recursive:true,force:true});}
});

test('Ed25519 approval binds canonical payload and rejects changed signature or candidate', () => {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const payload = {schema:'cnb-production-approval/v1',project:'sample',environment:'production',authorize:'production-apply',
    approval_id:'a'.repeat(32),candidate_tag:'sample-candidate-cnb-demo-one',candidate_manifest_sha256:'b'.repeat(64),
    candidate_bytes_sha256:'c'.repeat(64),application_commit:'d'.repeat(40),build_id:'cnb-demo-one',
    authority_sha256:'e'.repeat(64),prepared_sha256:'f'.repeat(64),previous_release_sha256:'1'.repeat(64),
    issued_at:'2026-09-07T00:00:00Z',expires_at:'2026-09-07T01:00:00Z'};
  const signed = signApproval(payload, privateKey);
  assert.deepEqual(verifyApproval(signed, publicKey), payload);
  const altered = structuredClone(payload);altered.candidate_bytes_sha256='2'.repeat(64);
  assert.throws(() => verifyApproval({...signed,payload_b64url:canonicalBytes(altered).toString('base64url')},publicKey));
  assert.throws(() => verifyApproval({...signed,signature_b64url:'A'.repeat(86)},publicKey));
  assert.throws(() => approvalPayload({...payload,environment:'test'}));
});
