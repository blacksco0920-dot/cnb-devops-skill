import assert from 'node:assert/strict';
import test from 'node:test';
import { productionFixture } from './bundle-production-fixture.mjs';
import { canonicalBytes, sha256 } from '../assets/cnb-tcr-tat/ci/production-contract.mjs';
import { publishProductionApproval, expectedApprovalAnnotations } from '../assets/cnb-tcr-tat/admin/publish-production-approval.mjs';

function remote(fixture,changes={}) {
  const expected=expectedApprovalAnnotations({...fixture,invocationId:'inv-DEMO1234'});
  const annotations={...expected.prerequisites,'platform-unrelated':'keep',...changes},events=[];
  const fetchImpl=async(url,options)=>{
    assert.equal(url,'https://api.cnb.cool/example/sample/-/git/tag-annotations/sample-candidate-cnb-example-123');
    assert.equal(options.redirect,'error');assert.equal(options.headers.Authorization,'Bearer local-test-token');
    assert.equal(options.headers.Accept,'application/vnd.cnb.api+json');
    if(options.method==='PUT') {
      const body=JSON.parse(options.body);events.push(['PUT',body]);
      for(const {key,value} of body.annotations)annotations[key]=value;
      return new Response('{}',{status:200});
    }
    events.push(['GET']);
    return new Response(JSON.stringify(Object.entries(annotations).map(([key,value])=>({key,value,created_at:'ignored-provider-metadata'}))),{status:200});
  };
  return {expected,annotations,events,fetchImpl};
}

test('actual signed approval previews offline then publishes only owned fields with signed-last readback',async()=>{
  const f=productionFixture(['api','h5','ocr']),r=remote(f),inputs={...f,invocationId:'inv-DEMO1234',fetchImpl:r.fetchImpl,token:'local-test-token'};
  const preview=await publishProductionApproval(inputs);assert.equal(preview.status,'preview');assert.deepEqual(r.events,[]);
  const result=await publishProductionApproval({...inputs,apply:true});assert.equal(result.status,'signed');
  assert.deepEqual(r.events.map(e=>e[0]),['GET','PUT','GET','PUT','GET','PUT','GET']);
  assert.deepEqual(r.events[1][1],{annotations:[{key:'production_approval_status',value:'pending'}]});
  assert.deepEqual(r.events[3][1],{annotations:[{key:'production_approval_b64url',value:canonicalBytes(f.approval).toString('base64url')},{key:'production_approval_sha256',value:sha256(canonicalBytes(f.approval))}]});
  assert.deepEqual(r.events[5][1],{annotations:[{key:'production_approval_status',value:'signed'}]});
  assert.equal(r.annotations['platform-unrelated'],'keep');
  r.events.length=0;
  assert.equal((await publishProductionApproval({...inputs,apply:true})).status,'signed');assert.deepEqual(r.events,[['GET']]);
});

test('invalid signature or mismatched remote candidate/readiness never sends PUT',async()=>{
  for(const change of [{candidate_commit:'f'.repeat(40)},{production_prepared_sha256:'f'.repeat(64)},{production_readiness_invocation_id:'inv-DIFF1234'},{production_readiness_status:'pending'}]) {
    const f=productionFixture(),r=remote(f,change);
    await assert.rejects(publishProductionApproval({...f,invocationId:'inv-DEMO1234',fetchImpl:r.fetchImpl,token:'local-test-token',apply:true}));
    assert.deepEqual(r.events,[['GET']]);
  }
  const f=productionFixture(),r=remote(f);f.approval.signature_b64url='A'.repeat(86);
  await assert.rejects(publishProductionApproval({...f,invocationId:'inv-DEMO1234',fetchImpl:r.fetchImpl,token:'local-test-token',apply:true}));
  assert.deepEqual(r.events,[]);
});
