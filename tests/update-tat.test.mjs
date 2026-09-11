import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as tat from '../scripts/configure-tat.mjs';

function spec(digit = 'a') {
  return { schema_version: 1, project: 'sample', environment: 'test', version: '0.2.0',
    target: {region: 'ap-guangzhou', instance_id: 'lhins-' + 'example1'},
    expected_artifacts: {program_sha256: digit.repeat(64), compose_sha256: 'b'.repeat(64), policy_sha256: 'c'.repeat(64)},
    expectedCommand: {CommandName: 'sample-test-v0.2.0', Description: 'fixed test release', CommandType: 'SHELL',
      Content: `#!/bin/sh\ncontroller_sha256='${digit.repeat(64)}'\npolicy_sha256='${'c'.repeat(64)}'\nexit 0\n`,
      Username: 'sample-release', WorkingDirectory: '/home/sample-release', Timeout: 3600, EnableParameter: true,
      DefaultParameters: {release_request_b64url: 'INVALID'},
      DefaultParameterConfs: [{ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: ''}]}};
}
function command(input) {
  const c = input.expectedCommand;
  return {...c, CommandId: 'cmd-example1', Content: Buffer.from(c.Content).toString('base64'),
    DefaultParameters: JSON.stringify(c.DefaultParameters), CreatedBy: 'USER', Tags: [], Scenes: [],
    OutputCOSBucketUrl: '', OutputCOSKeyPrefix: ''};
}
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'tat-update-'));
  fs.chmodSync(dir, 0o700); t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const old = spec(), next = spec('d');
  const client = {region: 'ap-guangzhou', state: command(old), writes: [], mode: 'normal',
    async DescribeCommands(request) {
      const rows=[this.state].filter(row=>(!request.CommandIds||request.CommandIds.includes(row.CommandId)) &&
        (!request.Filters||request.Filters.every(filter=>filter.Name==='command-name'&&filter.Values.includes(row.CommandName))));
      return {TotalCount:rows.length,CommandSet:rows};
    },
    async DescribeInstances() {return {TotalCount: 1, InstanceSet: [{InstanceId: old.target.instance_id, InstanceState: 'RUNNING'}], RequestId: 'instance-query'};},
    async DescribeAutomationAgentStatus() {return {TotalCount: 1, AutomationAgentSet: [{InstanceId: old.target.instance_id, AgentStatus: 'Online', Environment: 'Linux'}], RequestId: 'agent-query'};},
    async ModifyCommand(request) {
      assert.equal(fs.existsSync(path.join(dir, 'binding.json.update-intent.json')), true, 'intent must be durable before write');
      this.writes.push(request);
      if (this.mode !== 'timeout-before') this.state = {...this.state, ...request, Timeout: request.Timeout ?? 60};
      if (this.mode.startsWith('timeout')) throw Error('private SDK body must not escape');
      return {RequestId: 'modify-request'};
    }};
  const previousBinding = await tat.configureTat({spec: old, client, apply: true, output: path.join(dir, 'old.json')});
  return {spec: next, previousSpec: old, previousBinding, client, output: path.join(dir, 'binding.json'), dir};
}

test('preview validates a scoped update without cloud or disk mutations', async t => {
  const f = await fixture(t);
  assert.equal(typeof tat.updateTat, 'function', 'reviewed update entry is missing');
  const result = await tat.updateTat({...f, client: undefined});
  assert.equal(result.status, 'planned');
  assert.equal(fs.existsSync(f.output), false);
  assert.equal(fs.existsSync(f.output + '.update-intent.json'), false);
});

test('reviewed update modifies only fixed content/name/description and reads it back', async t => {
  const f = await fixture(t);
  const result = await tat.updateTat({...f, apply: true});
  assert.equal(result.status, 'verified');
  assert.equal(result.command_id, f.previousBinding.command_id);
  assert.equal(result.program_sha256, 'd'.repeat(64));
  assert.deepEqual(f.client.writes, [{CommandId: 'cmd-example1', Content: command(f.spec).Content,
    CommandName: f.spec.expectedCommand.CommandName, Description: f.spec.expectedCommand.Description, Timeout: 3600}]);
  assert.equal(fs.statSync(f.output).mode & 0o777, 0o600);
  assert.equal(result.deployment_ready, false);
});

test('timeout after a successful remote update resumes by readback without another write', async t => {
  const f = await fixture(t); f.client.mode = 'timeout-after';
  await assert.rejects(tat.updateTat({...f, apply: true}), /TAT_UPDATE_UNCERTAIN/);
  assert.equal(fs.existsSync(f.output), false);
  const result = await tat.updateTat({...f, apply: true});
  assert.equal(result.status, 'verified');
  assert.equal(f.client.writes.length, 1);
  await tat.updateTat({...f, apply: true});
  assert.equal(f.client.writes.length, 1);
});

test('renamed command timeout resumes by ID and new-name readback without duplicating it',async t=>{
  const f=await fixture(t);f.spec.version='0.3.0';f.spec.expectedCommand.CommandName='sample-test-v0.3.0';f.client.mode='timeout-after';
  await assert.rejects(tat.updateTat({...f,apply:true}),/TAT_UPDATE_UNCERTAIN/);
  assert.equal(f.client.state.CommandName,f.spec.expectedCommand.CommandName);
  const result=await tat.updateTat({...f,apply:true});
  assert.equal(result.command_id,f.previousBinding.command_id);
  assert.equal(f.client.writes.length,1);
});

test('uncertain update still showing old bytes is retained for review, never repeated', async t => {
  const f = await fixture(t); f.client.mode = 'timeout-before';
  await assert.rejects(tat.updateTat({...f, apply: true}), /TAT_UPDATE_UNCERTAIN/);
  await assert.rejects(tat.updateTat({...f, apply: true}), /TAT_UPDATE_UNCERTAIN_REVIEW_REQUIRED/);
  assert.equal(f.client.writes.length, 1);
});

test('scope, policy, command metadata, and original binding drift reject before mutation', async t => {
  for (const change of [f => {f.spec.environment = 'production';},
    f => {f.spec.target.instance_id = 'lhins-' + 'other123';},
    f => {f.spec.expectedCommand.Username = 'root';},
    f => {f.spec.expected_artifacts.compose_sha256 = 'e'.repeat(64);},
    f => {f.previousBinding.command_sha256 = 'e'.repeat(64);},
    f => {f.client.state.Content = Buffer.from('changed').toString('base64');}]) {
    const f = await fixture(t); change(f);
    await assert.rejects(tat.updateTat({...f, apply: true}));
    assert.equal(f.client.writes.length, 0);
  }
});

test('a changed retry or unjournaled new remote command cannot be silently adopted', async t => {
  const f = await fixture(t); f.client.mode = 'timeout-after';
  await assert.rejects(tat.updateTat({...f, apply: true}), /TAT_UPDATE_UNCERTAIN/);
  await assert.rejects(tat.updateTat({...f, spec: spec('e'), apply: true}), /TAT_UPDATE_INTENT_MISMATCH/);
  const g = await fixture(t); g.client.state = command(g.spec);
  await assert.rejects(tat.updateTat({...g, apply: true}), /TAT_COMMAND_DRIFT/);
  assert.equal(g.client.writes.length, 0);
});

test('ambiguous destination name is rejected before the update intent or mutation',async t=>{
  const f=await fixture(t);
  f.client.DescribeCommands=async request=>request.Filters ? {TotalCount:2,CommandSet:[f.client.state,{...f.client.state,CommandId:'cmd-other123'}]} : {TotalCount:1,CommandSet:[f.client.state]};
  await assert.rejects(tat.updateTat({...f,apply:true}),/TAT_QUERY_AMBIGUOUS/);
  assert.equal(f.client.writes.length,0);
  assert.equal(fs.existsSync(f.output+'.update-intent.json'),false);
});
