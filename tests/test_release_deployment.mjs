import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { productionFixture } from './bundle-production-fixture.mjs';
import * as contract from '../assets/cnb-tcr-tat/ci/production-contract.mjs';
import * as runner from '../assets/cnb-tcr-tat/ci/run-production-deploy.mjs';
import * as tat from '../assets/cnb-tcr-tat/ci/run-tat-release.mjs';
import * as publisher from '../assets/cnb-tcr-tat/admin/publish-production-approval.mjs';

const entry = new URL('../scripts/release-deployment.mjs', import.meta.url);
const stamp = value => new Date(value).toISOString().replace('.000Z', 'Z');
async function loaded() {
  assert.equal(await access(entry).then(() => true, () => false), true, 'fixed deployment verifier must exist');
  return import(entry);
}
function fixture() {
  const f = productionFixture(['web', 'worker']);
  const wire = f.clientFor('apply');
  wire.task.TaskResult.ExecStartTime = stamp(f.instant + 1000);
  wire.task.TaskResult.ExecEndTime = stamp(f.instant + 60000);
  const plan = publisher.expectedApprovalAnnotations({ ...f, invocationId: 'inv-READY1234', now: f.instant });
  const annotations = { ...plan.prerequisites, ...plan.payload, production_approval_status: 'signed',
    production_deploy_status: 'passed', production_receipt_sha256: contract.sha256(contract.canonicalBytes(f.result)) };
  const options = { ...f, contract, runner, tat, publisher, readinessRaw: contract.canonicalBytes(f.readiness), approvalRaw: contract.canonicalBytes(f.approval),
    readinessInvocationId: 'inv-READY1234', invocationId: 'inv-DEMO1234', now: () => f.instant + 90000000 };
  return { ...f, wire, annotations, options, async evidence() {
    return { 'describe-commands.json': Buffer.from(JSON.stringify(await wire.client.DescribeCommands({}))),
      'describe-invocation-tasks.json': Buffer.from(JSON.stringify(await wire.client.DescribeInvocationTasks({}))),
      'annotations-response.json': Buffer.from(JSON.stringify(Object.entries(annotations).map(([key, value]) => ({ key, value })))) };
  } };
}

test('standard production validators prove a completed actual command window after approval and readiness expire', async () => {
  const verifier = await loaded(), f = fixture();
  const result = await verifier.verifyDeploymentEvidence({ ...f.options, evidence: await f.evidence() });
  assert.equal(result.schema, 'cnb-deployment-verification/v1');
  assert.equal(result.status, 'verified'); assert.equal(result.environment, 'production');
  assert.equal(result.build_id, 'cnb-example-123'); assert.equal(result.invocation_id, 'inv-DEMO1234');
  assert.equal(result.images.worker, 'registry.example/team/sample-worker@sha256:' + '4'.repeat(64));
  assert.equal(result.execution_started_at, stamp(f.instant + 1000));
  assert.equal(result.execution_finished_at, stamp(f.instant + 60000));
  assert.equal(result.current_runtime_verified, false); assert.equal(f.wire.invoked(), 0);
});

for (const [name, mutate] of [
  ['wrong instance', f => { f.wire.task.InstanceId = 'lhins-OTHER1234'; }],
  ['wrong command', f => { f.wire.task.CommandId = 'cmd-OTHER1234'; }],
  ['wrong invocation', f => { f.wire.task.InvocationId = 'inv-OTHER1234'; }],
  ['changed executed request', f => { f.wire.task.CommandDocument.Content = Buffer.from('#!/bin/sh\necho forged\n').toString('base64'); }],
  ['wrong result digest', f => { f.result.release.images.web = 'registry.example/team/sample-web@sha256:' + '0'.repeat(64); }],
  ['wrong approval signature', f => { f.options.approvalRaw = contract.canonicalBytes({ ...f.approval, signature_b64url: 'A'.repeat(86) }); }],
  ['wrong annotation digest', f => { f.annotations.production_receipt_sha256 = '0'.repeat(64); }],
  ['wrong annotation approval', f => { f.annotations.production_approval_b64url = 'e30K'; }],
  ['wrong annotation readiness', f => { f.annotations.production_readiness_b64url = 'e30K'; }],
  ['wrong candidate annotations', f => { f.annotations.candidate_commit = '0'.repeat(40); }],
  ['dropped output', f => { f.wire.task.TaskResult.Dropped = 1; }],
  ['nonzero exit', f => { f.wire.task.TaskResult.ExitCode = 1; }],
  ['incomplete task', f => { f.wire.task.TaskStatus = 'RUNNING'; }],
  ['missing actual start', f => { delete f.wire.task.TaskResult.ExecStartTime; }],
  ['missing actual end', f => { delete f.wire.task.TaskResult.ExecEndTime; }],
  ['end at approval expiry', f => { f.wire.task.TaskResult.ExecEndTime = f.payload.expires_at; }],
  ['start before approval', f => { f.wire.task.TaskResult.ExecStartTime = stamp(f.instant - 1000); }],
  ['reversed command window', f => { f.wire.task.TaskResult.ExecEndTime = stamp(f.instant); }],
  ['future command end', f => { f.options.now = () => f.instant + 10000; }],
]) test(`verification rejects ${name} without invoking TAT`, async () => {
  const verifier = await loaded(), f = fixture(); mutate(f);
  if (name === 'wrong result digest') f.wire.task.TaskResult.Output = contract.canonicalBytes(f.result).toString('base64');
  await assert.rejects(verifier.verifyDeploymentEvidence({ ...f.options, evidence: await f.evidence() }));
  assert.equal(f.wire.invoked(), 0);
});
