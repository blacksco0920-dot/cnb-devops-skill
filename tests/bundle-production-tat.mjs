import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { runTatCommand, verifyTatInvocation } from '../assets/cnb-tcr-tat/ci/run-tat-release.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture() {
  const template='#!/bin/sh\n# {{release_request_b64url}}\n';
  const config={project:'sample',environment:'production',controller_program_sha256:'a'.repeat(64),production_entry_sha256:'b'.repeat(64),controller_compose_sha256:'c'.repeat(64),policy_sha256:'d'.repeat(64)};
  const binding={schema:'cnb-tat-binding/v1',project:'sample',environment:'production',region:'ap-guangzhou',instance_id:'lhins-DEMO1234',command_id:'cmd-DEMO1234',command_sha256:hash(template),program_sha256:config.production_entry_sha256,compose_sha256:config.controller_compose_sha256,policy_sha256:config.policy_sha256,username:'ubuntu',working_directory:'/home/ubuntu',timeout:120};
  const request=Buffer.from('{"action":"readiness"}\n').toString('base64url');let invoked=0;
  const metadata={CommandId:binding.command_id,CommandType:'SHELL',Username:binding.username,WorkingDirectory:binding.working_directory,Timeout:binding.timeout};
  const task={InvocationId:'inv-DEMO1234',CommandId:binding.command_id,InstanceId:binding.instance_id,TaskStatus:'SUCCESS',CommandDocument:{...metadata,Content:Buffer.from(template.replace('{{release_request_b64url}}',request)).toString('base64')},TaskResult:{ExitCode:0,Dropped:0,Output:Buffer.from('{"ready":true}\n').toString('base64')}};
  const client={DescribeCommands:async()=>({TotalCount:1,CommandSet:[{...metadata,CreatedBy:'USER',EnableParameter:true,DefaultParameters:'{"release_request_b64url":"INVALID"}',Content:Buffer.from(template).toString('base64')}]}),InvokeCommand:async()=>{invoked++;return {InvocationId:task.InvocationId};},DescribeInvocationTasks:async()=>({TotalCount:1,InvocationTaskSet:[task]})};
  const options={client,request,config,binding,parseRequest:value=>JSON.parse(Buffer.from(value,'base64url')),receiptValidator:receipt=>{assert.deepEqual(receipt,{ready:true});return receipt;}};
  return {options,task,invoked:()=>invoked};
}
test('production transport invokes once and attests executed request',async()=>{
  const f=fixture();const r=await runTatCommand(f.options);assert.deepEqual(r.receipt,{ready:true});assert.equal(f.invoked(),1);
});
test('administrator readiness verification only reads and never invokes',async()=>{
  const f=fixture();delete f.options.client.InvokeCommand;
  const r=await verifyTatInvocation({...f.options,invocationId:'inv-DEMO1234'});assert.deepEqual(r.receipt,{ready:true});assert.equal(f.invoked(),0);
  f.task.CommandDocument.Username='root';await assert.rejects(verifyTatInvocation({...f.options,invocationId:'inv-DEMO1234'}),/executed TAT command/);
});
test('stale production entry hash blocks before Invoke',async()=>{
  const f=fixture();f.options.config.production_entry_sha256='e'.repeat(64);
  await assert.rejects(runTatCommand(f.options),/protected binding/);assert.equal(f.invoked(),0);
});
