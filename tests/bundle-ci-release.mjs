import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { renderReleaseRequest, parseReleaseRequest, validateReleaseReceipt } from '../assets/cnb-tcr-tat/ci/release-request.mjs';
import { runTatRelease } from '../assets/cnb-tcr-tat/ci/run-tat-release.mjs';

const sha = 'a'.repeat(40);
const command = '#!/bin/sh\nrequest="{{release_request_b64url}}"\nexec /opt/release/command\n';
const hash = (text) => createHash('sha256').update(text).digest('hex');
function fixture(names) {
  const config = {schema:'cnb-devops-ci/v1',project:'sample',environment:'test',controller_id:'sample-test-v1',candidate_prefix:'sample-candidate-',cnb_repository:'example/sample',services:Object.fromEntries(names.map(name=>[name,{image_repository:`registry.example/team/sample-${name}`,image_env:`RELEASE_${name.toUpperCase()}_IMAGE`}])),probes:names.map(name=>({url:`https://${name}.example/health`}))};
  Object.assign(config,{controller_program_sha256:'c'.repeat(64),controller_compose_sha256:'d'.repeat(64),policy_sha256:'e'.repeat(64)});
  const values={schema:'cnb-release-request/v1',project:'sample',environment:'test',controller:'sample-test-v1',git_sha:sha,controller_commit:sha,build_id:'cnb-build-123',images:Object.fromEntries(names.map(name=>[name,`registry.example/team/sample-${name}@sha256:${'b'.repeat(64)}`]))};
  const binding={schema:'cnb-tat-binding/v1',project:'sample',environment:'test',region:'ap-guangzhou',instance_id:'lhins-demo-1234',command_id:'cmd-example123',command_sha256:hash(command),username:'release',working_directory:'/home/release',timeout:3600,program_sha256:'c'.repeat(64),compose_sha256:'d'.repeat(64),policy_sha256:'e'.repeat(64)};
  const receipt={schema:'cnb-deploy-result/v1',status:'passed',project:'sample',environment:'test',controller:'sample-test-v1',git_sha:sha,controller_commit:sha,build_id:'cnb-build-123',images:values.images,controller_program_sha256:binding.program_sha256,controller_compose_sha256:binding.compose_sha256,policy_sha256:binding.policy_sha256,database_backup_sha256:'f'.repeat(64),container_count:names.length,probe_count:names.length,probes:names.map(name=>`https://${name}.example/health`).sort()};
  return {config,values,binding,receipt};
}
test('production request retains exact environment and same immutable application commit',()=>{
  const {config,values}=fixture(['web']);
  config.environment='production'; values.environment='production';
  config.controller_id='sample-production-v1';values.controller=config.controller_id;
  assert.deepEqual(parseReleaseRequest(renderReleaseRequest(values,config),config),values);
  assert.throws(()=>renderReleaseRequest({...values,environment:'test'},config));
  assert.throws(()=>renderReleaseRequest({...values,controller_commit:'f'.repeat(40)},config));
});
for (const names of [['web'],['api','portal','worker']]) {
  test(`${names.length} services request and receipt bind full deployment`,()=>{
    const {config,values,binding,receipt}=fixture(names);
    const encoded=renderReleaseRequest(values,config);
    assert.deepEqual(JSON.parse(Buffer.from(encoded,'base64url').toString('utf8')),values);
    assert.deepEqual(parseReleaseRequest(encoded,config),values);
    assert.deepEqual(validateReleaseReceipt(receipt,values,config,binding),receipt);
  });
  for (const kind of ['mutable-tag','missing-image','wrong-environment','wrong-controller-commit','unknown-target']) {
    test(`${names.length} services reject ${kind}`,()=>{
      const {config,values}=fixture(names);
      if(kind==='mutable-tag') values.images[names[0]]=`registry.example/team/sample-${names[0]}:latest`;
      if(kind==='missing-image') delete values.images[names[0]];
      if(kind==='wrong-environment') values.environment='production';
      if(kind==='wrong-controller-commit') values.controller_commit='f'.repeat(40);
      if(kind==='unknown-target') values.instance_id='lhins-diff-1234';
      assert.throws(()=>renderReleaseRequest(values,config));
    });
  }
  for (const kind of ['wrong-image','wrong-project','wrong-probe','wrong-hash','missing-field']) {
    test(`${names.length} services reject receipt ${kind}`,()=>{
      const {config,values,binding,receipt}=fixture(names);
      receipt.images={...receipt.images};
      if(kind==='wrong-image') receipt.images[names[0]]=`registry.example/team/sample-${names[0]}@sha256:${'f'.repeat(64)}`;
      if(kind==='wrong-project') receipt.project='other';
      if(kind==='wrong-probe') receipt.probes[0]='https://unapproved.example/health';
      if(kind==='wrong-hash') receipt.policy_sha256='f'.repeat(64);
      if(kind==='missing-field') delete receipt.images;
      assert.throws(()=>validateReleaseReceipt(receipt,values,config,binding));
    });
  }
}
function clientFixture(receipt, binding) {
  let parameters;
  let invoked=0;
  const invocation='inv-example123';
  return {get invoked(){return invoked;},DescribeCommands:async()=>({TotalCount:1,CommandSet:[{CommandId:binding.command_id,Content:Buffer.from(command).toString('base64'),CommandType:'SHELL',WorkingDirectory:'/home/release',Timeout:3600,EnableParameter:true,DefaultParameters:JSON.stringify({release_request_b64url:'INVALID'}),CreatedBy:'USER',Username:'release'}]}),InvokeCommand:async args=>{invoked++; parameters=args.Parameters; assert.deepEqual(args.InstanceIds,[binding.instance_id]);return {InvocationId:invocation};},DescribeInvocations:async()=>({InvocationSet:[{InvocationId:invocation,CommandId:binding.command_id,Parameters:parameters,InvocationTaskBasicInfoSet:[{InstanceId:binding.instance_id}],InvocationStatus:'SUCCESS'}]}),DescribeInvocationTasks:async args=>{assert.deepEqual(args,{Filters:[{Name:'invocation-id',Values:[invocation]}],HideOutput:false,Limit:1,Offset:0});return {TotalCount:1,InvocationTaskSet:[{InvocationId:invocation,InstanceId:binding.instance_id,TaskStatus:'SUCCESS',CommandId:binding.command_id,CommandDocument:{Content:Buffer.from(command.replace('{{release_request_b64url}}',JSON.parse(parameters).release_request_b64url)).toString('base64'),CommandType:'SHELL',Username:binding.username,WorkingDirectory:binding.working_directory,Timeout:binding.timeout,OutputCOSBucketUrl:'',OutputCOSKeyPrefix:''},TaskResult:{ExitCode:0,Output:Buffer.from(JSON.stringify(receipt)+'\n').toString('base64'),Dropped:0}}]};}};
}
test('TAT exact command and result readback yields verified receipt',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);
 const result=await runTatRelease({client,request:renderReleaseRequest(values,config),config,binding,now:()=>Date.parse('2026-09-06T00:00:00Z')});
 assert.equal(result.invocationId,'inv-example123');assert.deepEqual(result.receipt,receipt);
});
test('TAT accepts the real conf-only Saved Command response before invocation',async()=>{
 for(const legacy of ['',JSON.stringify({release_request_b64url:'INVALID'})]) {
  const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);
  const describe=client.DescribeCommands;client.DescribeCommands=async()=>{const response=await describe();Object.assign(response.CommandSet[0],{
   DefaultParameters:legacy,DefaultParameterConfs:[{ParameterName:'release_request_b64url',ParameterValue:'INVALID',ParameterDescription:''}]});return response;};
  const result=await runTatRelease({client,request:renderReleaseRequest(values,config),config,binding});
  assert.deepEqual(result.receipt,receipt);assert.equal(client.invoked,1);
 }
});
test('TAT rejects conflicting or extra Saved Command defaults before invocation',async()=>{
 const conf={ParameterName:'release_request_b64url',ParameterValue:'INVALID',ParameterDescription:''};
 const invalidConfs=[undefined,null,[],[conf,conf],[conf,{...conf,ParameterName:'extra'}],
  [{...conf,ParameterValue:'OTHER'}],[{...conf,ParameterDescription:'changed'}],[{...conf,Unknown:''}],{}];
 for(const legacy of ['',JSON.stringify({release_request_b64url:'INVALID'})]) {
  for(const confs of invalidConfs) {
   if(legacy && (confs==null || (Array.isArray(confs)&&confs.length===0)))continue;
   const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);
   const describe=client.DescribeCommands;client.DescribeCommands=async()=>{const response=await describe();Object.assign(response.CommandSet[0],{DefaultParameters:legacy,DefaultParameterConfs:confs});return response;};
   await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}),/saved TAT command configuration is invalid/);
   assert.equal(client.invoked,0);
  }
 }
 for(const legacy of ['{"release_request_b64url":"OTHER"}','{"release_request_b64url":"INVALID","extra":"INVALID"}',null,undefined]) {
  const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);
  const describe=client.DescribeCommands;client.DescribeCommands=async()=>{const response=await describe();Object.assign(response.CommandSet[0],{DefaultParameters:legacy,DefaultParameterConfs:[conf]});return response;};
  await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}),/saved TAT command configuration is invalid/);
  assert.equal(client.invoked,0);
 }
});
test('TAT task-only client waits through delivery states without DescribeInvocations permission',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);
 delete client.DescribeInvocations;
 const readTask=client.DescribeInvocationTasks;
 const statuses=['PENDING','DELIVERING','DELIVER_DELAYED','RUNNING','SUCCESS'];
 let tick=0;
 client.DescribeInvocationTasks=async args=>{const result=await readTask(args);result.InvocationTaskSet[0].TaskStatus=statuses.shift();return result;};
 const result=await runTatRelease({client,request:renderReleaseRequest(values,config),config,binding,now:()=>Date.parse('2026-09-06T00:00:00Z')+tick,sleep:async ms=>{tick+=ms;}});
 assert.deepEqual(result.receipt,receipt);assert.equal(client.invoked,1);assert.deepEqual(statuses,[]);
});
for(const status of ['DELIVER_FAILED','START_FAILED','FAILED','TIMEOUT','TASK_TIMEOUT','CANCELLING','CANCELLED','TERMINATED','UNRECOGNIZED']) {
 test(`TAT task ${status} never yields a verified receipt`,async()=>{
  const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);delete client.DescribeInvocations;
  const readTask=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await readTask(args);result.InvocationTaskSet[0].TaskStatus=status;return result;};
  await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}),error=>error.invocationId==='inv-example123'&&/did not succeed|unknown terminal status/.test(error.message));
  assert.equal(client.invoked,1);
 });
}
for(const mismatch of ['invocation','command','instance','multiple','missing','truncated-count']) {
 test(`TAT polling rejects ${mismatch} task identity before accepting status`,async()=>{
  const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);delete client.DescribeInvocations;
  const readTask=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await readTask(args);const task=result.InvocationTaskSet[0];
   if(mismatch==='invocation')task.InvocationId='inv-different123';if(mismatch==='command')task.CommandId='cmd-different123';if(mismatch==='instance')task.InstanceId='lhins-diff';
   if(mismatch==='multiple'){result.InvocationTaskSet.push({...task});result.TotalCount=2;}if(mismatch==='missing')result.InvocationTaskSet=[];if(mismatch==='truncated-count')result.TotalCount=2;
   return result;};
  await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}),error=>error.invocationId==='inv-example123'&&/exact invocation task/.test(error.message));
  assert.equal(client.invoked,1);
 });
}
test('TAT task query failures stop after three reads without repeating invoke',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);delete client.DescribeInvocations;
 let reads=0;client.DescribeInvocationTasks=async()=>{reads++;throw Error('query unavailable');};
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding,sleep:async()=>{}}),error=>error.invocationId==='inv-example123'&&/status query failed/.test(error.message));
 assert.equal(reads,3);assert.equal(client.invoked,1);
});
test('TAT task polling deadline preserves invocation identity without repeating invoke',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);delete client.DescribeInvocations;
 let tick=0;const readTask=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await readTask(args);result.InvocationTaskSet[0].TaskStatus='RUNNING';return result;};
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding,deadlineMs:1000,pollIntervalMs:500,now:()=>tick,sleep:async ms=>{tick+=ms;}}),error=>error.invocationId==='inv-example123'&&/deadline exceeded/.test(error.message));
 assert.equal(client.invoked,1);
});
test('TAT altered Saved Command is blocked before invoke',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);binding.command_sha256='f'.repeat(64);
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));assert.equal(client.invoked,0);
});
test('TAT SUCCESS with mismatched receipt is not release success',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);receipt.build_id='cnb-wrong-123';const client=clientFixture(receipt,binding);
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));
});

test('TAT rejects truncated SDK task output',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);const original=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await original(args);result.InvocationTaskSet[0].TaskResult.Dropped=8;return result;};
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));
});

test('sixteen services fit the shared 16 KiB request bound',()=>{
 const {config,values}=fixture(Array.from({length:16},(_,i)=>`service-${i}`));
 for(const name of Object.keys(config.services)){config.services[name].image_repository='registry.example/team/'+('a'.repeat(100))+'-'+name;values.images[name]=config.services[name].image_repository+'@sha256:'+('b'.repeat(64));}
 assert.equal(Object.keys(parseReleaseRequest(renderReleaseRequest(values,config),config).images).length,16);
});
test('oversized release request is rejected before TAT',()=>{
 const {config,values}=fixture(['web']);config.services.web.image_repository='registry.example/team/'+('a'.repeat(17000));values.images.web=config.services.web.image_repository+'@sha256:'+('b'.repeat(64));
 assert.throws(()=>renderReleaseRequest(values,config));
});

test('TAT rejects duplicate JSON keys in receipt output',async()=>{
 const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);const original=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await original(args);const raw=JSON.stringify(receipt).replace('"status":"passed"','"status":"failed","status":"passed"')+'\n';result.InvocationTaskSet[0].TaskResult.Output=Buffer.from(raw).toString('base64');return result;};
 await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));
});

test('request bytes match the host canonical JSON contract',()=>{
 const {config,values}=fixture(['web']);
 const expected=`{"build_id":"cnb-build-123","controller":"sample-test-v1","controller_commit":"${'a'.repeat(40)}","environment":"test","git_sha":"${'a'.repeat(40)}","images":{"web":"registry.example/team/sample-web@sha256:${'b'.repeat(64)}"},"project":"sample","schema":"cnb-release-request/v1"}`;
 assert.equal(Buffer.from(renderReleaseRequest(values,config),'base64url').toString('utf8'),expected);
});

for(const mismatch of ['content','username','working-directory','timeout','output-destination']) {
 test(`TAT rejects changed executed command ${mismatch} despite valid receipt`,async()=>{
  const {config,values,binding,receipt}=fixture(['web']);const client=clientFixture(receipt,binding);const original=client.DescribeInvocationTasks;client.DescribeInvocationTasks=async args=>{const result=await original(args);const doc=result.InvocationTaskSet[0].CommandDocument;if(mismatch==='content')doc.Content=Buffer.from('#!/bin/sh\necho forged\n').toString('base64');if(mismatch==='username')doc.Username='root';if(mismatch==='working-directory')doc.WorkingDirectory='/tmp';if(mismatch==='timeout')doc.Timeout=1;if(mismatch==='output-destination')doc.OutputCOSBucketUrl='https://other.example';return result;};
  await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));
 });
}

for(const field of ['program_sha256','compose_sha256','policy_sha256']) {
 test(`TAT rejects stale protected binding ${field} before Invoke`,async()=>{
  const {config,values,binding,receipt}=fixture(['web']);binding[field]='9'.repeat(64);const client=clientFixture(receipt,binding);
  // Match the old host receipt too: the mismatch is against newly generated configuration.
  receipt[({program_sha256:'controller_program_sha256',compose_sha256:'controller_compose_sha256',policy_sha256:'policy_sha256'})[field]]=binding[field];
  await assert.rejects(runTatRelease({client,request:renderReleaseRequest(values,config),config,binding}));assert.equal(client.invoked,0);
 });
}
