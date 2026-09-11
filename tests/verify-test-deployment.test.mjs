import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, statSync, watch } from 'node:fs';
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { renderReleaseRequest } from '../assets/cnb-tcr-tat/ci/release-request.mjs';
import { productionFixture } from './bundle-production-fixture.mjs';

const execute = promisify(execFile), root = dirname(dirname(fileURLToPath(import.meta.url)));
const entry = join(root, 'scripts/verify-test-deployment.mjs');
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object'
  ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const bytes = value => Buffer.from(JSON.stringify(value) + '\n');
async function put(path, value) { await writeFile(path, Buffer.isBuffer(value) ? value : bytes(value), { mode: 0o600 }); }
async function ref(path) { return { path, sha256: hash(await readFile(path)) }; }
async function moduleUnderTest() {
  await assert.doesNotReject(access(entry), 'fixed test-deployment verification entry is missing');
  return import(pathToFileURL(entry));
}
async function fixture(t) {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'verify-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const project = join(directory, 'project'), privateDir = join(directory, 'private'), bundle = join(project, 'bundle');
  await mkdir(project, { mode: 0o700 }); await mkdir(privateDir, { mode: 0o700 }); await mkdir(bundle, { mode: 0o700 });
  await mkdir(join(bundle, 'ci'), { mode: 0o700 }); await mkdir(join(bundle, 'dependencies'), { mode: 0o700 });
  const f = productionFixture(), config = f.candidateConfig;
  const template = '#!/bin/sh\nexec /opt/release {{release_request_b64url}}\n';
  const binding = { ...f.binding, environment: 'test', command_sha256: hash(template), program_sha256: config.controller_program_sha256,
    compose_sha256: config.controller_compose_sha256, policy_sha256: config.policy_sha256 };
  const receipt = { ...f.result.release, environment: 'test', controller: config.controller_id,
    controller_program_sha256: config.controller_program_sha256, controller_compose_sha256: config.controller_compose_sha256,
    policy_sha256: config.policy_sha256, probes: config.probes.map(p => p.url).sort() };
  const receiptRaw = bytes(receipt), candidate = { ...f.candidate, created_at: '2026-09-11T04:30:05Z', release_receipt_sha256: hash(receiptRaw) };
  for (const plane of Object.values(candidate.evidence)) plane.verified_at = candidate.created_at;
  delete candidate.manifest_sha256;
  candidate.manifest_sha256 = hash(canonical(candidate));
  const candidateRaw = Buffer.from(canonical(candidate) + '\n');
  const request = renderReleaseRequest({ schema: 'cnb-release-request/v1', project: 'sample', environment: 'test', controller: config.controller_id,
    git_sha: candidate.application_commit, controller_commit: candidate.controller_commit, build_id: candidate.build_id, images: candidate.services }, config);
  const metadata = { CommandId: binding.command_id, CommandType: 'SHELL', Username: binding.username, WorkingDirectory: binding.working_directory, Timeout: binding.timeout };
  const commands = { TotalCount: 1, CommandSet: [{ ...metadata, Content: Buffer.from(template).toString('base64'), CreatedBy: 'USER', EnableParameter: true,
    DefaultParameters: '', DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }] }] };
  const task = { InvocationId: 'inv-DEMO1234', CommandId: binding.command_id, InstanceId: binding.instance_id, TaskStatus: 'SUCCESS',
    CommandDocument: { ...metadata, Content: Buffer.from(template.replace('{{release_request_b64url}}', request)).toString('base64') },
    TaskResult: { ExitCode: 0, Dropped: 0, Output: receiptRaw.toString('base64'), ExecStartTime: '2026-09-11T04:28:00Z', ExecEndTime: '2026-09-11T04:30:00Z' } };
  const tasks = { TotalCount: 1, InvocationTaskSet: [task] };
  const tag = Buffer.concat([Buffer.from(`object ${candidate.application_commit}\ntype commit\ntag ${candidate.candidate_tag}\ntagger CI <ci@example.invalid> ${Date.parse("2026-09-11T04:30:05Z") / 1000} +0000\n\n`), candidateRaw]);
  const files = ['ci/candidate_manifest.py', 'ci/release-request.mjs', 'ci/run-tat-release.mjs', 'dependencies/package.json', 'dependencies/package-lock.json'];
  for (const name of files) await copyFile(join(root, 'assets/cnb-tcr-tat', name), join(bundle, name));
  await put(join(bundle, 'ci-config.json'), config); files.push('ci-config.json');
  const locked = {}; for (const name of files) locked[name] = hash(await readFile(join(bundle, name)));
  await put(join(bundle, 'artifact-lock.json'), { schema: 'cnb-devops-artifacts/v1', version: 'test', files: locked });
  await put(join(privateDir, 'candidate.json'), candidateRaw); await put(join(privateDir, 'candidate-tag.raw'), tag);
  await put(join(privateDir, 'binding.json'), binding); await put(join(privateDir, 'credentials.json'), { secretId: 'AKIDSYNTHETIC', secretKey: 'SYNTHETIC_SECRET_DO_NOT_LOG' });
  const spec = { schema: 'cnb-test-deployment-verification-spec/v1', project: 'sample', environment: 'test', project_dir: project, bundle_dir: bundle,
    bundle_lock_sha256: hash(await readFile(join(bundle, 'artifact-lock.json'))), output_dir: join(privateDir, 'verification'),
    candidate_tag: candidate.candidate_tag, application_commit: candidate.application_commit, invocation_id: task.InvocationId,
    candidate: await ref(join(privateDir, 'candidate.json')), tag_object: await ref(join(privateDir, 'candidate-tag.raw')),
    binding: await ref(join(privateDir, 'binding.json')), tat_credentials_file: join(privateDir, 'credentials.json') };
  const specPath = join(privateDir, 'spec.json'); await put(specPath, spec);
  const calls = [], client = { DescribeCommands: async input => { calls.push('DescribeCommands'); assert.deepEqual(input, { CommandIds: [binding.command_id], Limit: 1, Offset: 0 }); return commands; },
    DescribeInvocationTasks: async input => { calls.push('DescribeInvocationTasks'); assert.deepEqual(input, { Filters: [{ Name: 'invocation-id', Values: [spec.invocation_id] }], HideOutput: false, Limit: 1, Offset: 0 }); return tasks; },
    InvokeCommand: async () => assert.fail('verification must never deploy') };
  return { directory, privateDir, bundle, spec, specPath, config, binding, receipt, candidate, candidateRaw, tag, commands, tasks, task, calls, client,
    now: () => Date.parse('2026-09-11T05:00:00Z'), saveSpec: () => put(specPath, spec) };
}

test('offline CLI preview verifies bound inputs without cloud calls or local writes', async t => {
  const { verifyTestDeployment } = await moduleUnderTest(), f = await fixture(t);
  const before = await readdir(f.privateDir);
  const result = await verifyTestDeployment({ specPath: f.specPath, client: f.client, now: f.now });
  assert.equal(result.status, 'preview'); assert.equal(result.current_annotations_status, 'not_checked');
  assert.deepEqual(f.calls, []); assert.deepEqual(await readdir(f.privateDir), before);
  const cli = await execute(process.execPath, [entry, '--spec', f.specPath]);
  assert.equal(JSON.parse(cli.stdout).status, 'preview'); assert(!cli.stdout.includes(f.privateDir));
  assert.deepEqual(await readdir(f.privateDir), before);
  const linkedEntry = join(f.directory, 'installed-verifier.mjs'); await symlink(entry, linkedEntry);
  const installed = await execute(process.execPath, [linkedEntry, '--spec', f.specPath]);
  assert.equal(installed.stdout, cli.stdout, 'an installed symlink must run the same CLI');
});

test('apply saves exact inputs and TAT output then both repeat modes reverify offline without writes', async t => {
  const { verifyTestDeployment } = await moduleUnderTest(), f = await fixture(t);
  const result = await verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now });
  assert.equal(result.status, 'verified'); assert.equal(result.receipt.schema, 'cnb-test-deployment-verification/v1');
  assert.equal(result.receipt.environment, 'test'); assert.equal(result.receipt.current_runtime_verified, false);
  assert.equal(result.receipt.saved_tag_verified, true); assert.equal(result.receipt.current_tag_status, 'not_checked');
  assert.equal(result.receipt.current_annotations_status, 'not_checked'); assert.equal(result.receipt.execution_finished_at, '2026-09-11T04:30:00Z');
  assert.equal(result.receipt.candidate_created_at, '2026-09-11T04:30:05Z');
  assert.deepEqual(f.calls, ['DescribeCommands', 'DescribeInvocationTasks']);
  assert((await readFile(join(f.spec.output_dir, 'candidate-tag.raw'))).equals(f.tag));
  assert((await readFile(join(f.spec.output_dir, 'release-receipt.json'))).equals(bytes(f.receipt)));
  const names = await readdir(f.spec.output_dir), before = await Promise.all(names.map(async name => [name, await readFile(join(f.spec.output_dir, name)), (await stat(join(f.spec.output_dir, name))).mtimeMs]));
  const offline = { DescribeCommands: () => assert.fail('existing evidence is offline'), DescribeInvocationTasks: () => assert.fail('existing evidence is offline') };
  for (const apply of [false, true]) {
    const again = await verifyTestDeployment({ specPath: f.specPath, apply, client: offline, now: f.now });
    assert.equal(again.reused, true); assert.deepEqual(again.receipt, result.receipt);
  }
  const cli = await execute(process.execPath, [entry, '--spec', f.specPath, '--apply']);
  assert.equal(JSON.parse(cli.stdout).reused, true); assert(!cli.stdout.includes(f.privateDir));
  assert.deepEqual(await Promise.all(names.map(async name => [name, await readFile(join(f.spec.output_dir, name)), (await stat(join(f.spec.output_dir, name))).mtimeMs])), before);
  assert.equal((await stat(f.spec.output_dir)).mode & 0o777, 0o700);
  for (const name of names) assert.equal((await stat(join(f.spec.output_dir, name))).mode & 0o777, 0o600);
  const document = join(f.spec.project_dir, 'PROJECT_STATE.md'), state = join(f.privateDir, 'state.json'), closeout = join(f.privateDir, 'closeout-spec.json');
  await put(document, Buffer.from('# Human notes\n'));
  await put(state, { project: 'sample', environments: { production: { status: 'unchanged' } } });
  await put(closeout, { schema: 'cnb-project-closeout/v1', project: 'sample', environment: 'test', project_dir: f.spec.project_dir,
    state_file: state, status_document: document, output_dir: join(f.privateDir, 'closeout'), deployment: await ref(join(f.spec.output_dir, 'receipt.json')),
    required_checks: ['business'], checks: {}, resource_refs: {} });
  const reconciled = await execute('python3', ['-B', join(root, 'scripts/reconcile-project-state.py'), '--spec', closeout, '--apply']);
  assert.equal(JSON.parse(reconciled.stdout).current.status, 'deployment_verified');
  const currentState = JSON.parse(await readFile(state));
  assert.deepEqual(currentState.environments.production, { status: 'unchanged' });
  assert.equal(currentState.environments.test.current.invocation_id, 'inv-DEMO1234');
  assert.deepEqual(currentState.environments.test.current.pending_checks, ['business']);
});

test('candidate and saved annotated tag reject changed bytes, wrong headers and invocation before cloud access', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  for (const mutation of ['hash', 'tag_object', 'tag_type', 'tag_name', 'tag_message', 'candidate_scope', 'candidate_invocation', 'bundle']) {
    await t.test(mutation, async t => {
      const f = await fixture(t);
      if (mutation === 'hash') f.spec.candidate.sha256 = '0'.repeat(64);
      else if (mutation === 'bundle') await put(join(f.bundle, 'ci-config.json'), { ...f.config, project: 'other' });
      else if (mutation.startsWith('tag_')) {
        let raw = f.tag.toString();
        if (mutation === 'tag_object') raw = raw.replace('object ' + f.candidate.application_commit, 'object ' + 'b'.repeat(40));
        if (mutation === 'tag_type') raw = raw.replace('type commit', 'type tag');
        if (mutation === 'tag_name') raw = raw.replace('tag ' + f.candidate.candidate_tag, 'tag another-candidate');
        if (mutation === 'tag_message') raw += '\n';
        await put(f.spec.tag_object.path, Buffer.from(raw)); f.spec.tag_object = await ref(f.spec.tag_object.path);
      } else {
        if (mutation === 'candidate_scope') f.candidate.environment = 'production';
        else for (const k of ['runtime', 'public']) f.candidate.evidence[k].reference = 'tat:inv-OTHER1234';
        delete f.candidate.manifest_sha256; f.candidate.manifest_sha256 = hash(canonical(f.candidate));
        const changed = Buffer.from(canonical(f.candidate) + '\n');
        await put(f.spec.candidate.path, changed); f.spec.candidate = await ref(f.spec.candidate.path);
        await put(f.spec.tag_object.path, Buffer.concat([f.tag.subarray(0, f.tag.indexOf('\n\n') + 2), changed])); f.spec.tag_object = await ref(f.spec.tag_object.path);
      }
      await f.saveSpec();
      await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }));
      assert.deepEqual(f.calls, []); await assert.rejects(access(f.spec.output_dir));
    });
  }
});

test('readback rejects wrong task, command, parameters, target, image, digest, truncation and timing', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  const changes = {
    multiple: f => { f.tasks.TotalCount = 2; f.tasks.InvocationTaskSet.push(structuredClone(f.task)); },
    task: f => { f.task.InvocationId = 'inv-OTHER1234'; },
    command: f => { f.task.CommandId = 'cmd-OTHER1234'; },
    instance: f => { f.task.InstanceId = 'lhins-OTHER1234'; },
    content: f => { f.commands.CommandSet[0].Content = Buffer.from('wrong {{release_request_b64url}}').toString('base64'); },
    defaults: f => { f.commands.CommandSet[0].DefaultParameterConfs[0].ParameterValue = 'ALLOW'; },
    parameters: f => { f.task.CommandDocument.Content = Buffer.from('wrong parameters').toString('base64'); },
    dropped: f => { f.task.TaskResult.Dropped = 1; },
    failed: f => { f.task.TaskStatus = 'FAILED'; },
    exit: f => { f.task.TaskResult.ExitCode = 1; },
    image: f => { f.receipt.images.web = f.receipt.images.web.replace('@sha256:', ':other@sha256:'); f.task.TaskResult.Output = bytes(f.receipt).toString('base64'); },
    digest: f => { f.receipt.database_backup_sha256 = 'e'.repeat(64); f.task.TaskResult.Output = bytes(f.receipt).toString('base64'); },
    reverse_time: f => { f.task.TaskResult.ExecStartTime = '2026-09-11T04:31:00Z'; },
    future_candidate: f => { f.now = () => Date.parse('2026-09-11T04:30:03Z'); },
    end_after_candidate: f => { f.task.TaskResult.ExecEndTime = '2026-09-11T04:30:06Z'; },
    invalid_date: f => { f.task.TaskResult.ExecEndTime = '2026-02-30T04:30:00Z'; },
  };
  for (const [name, change] of Object.entries(changes)) await t.test(name, async t => {
    const f = await fixture(t); change(f);
    await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }));
    await assert.rejects(access(f.spec.output_dir));
  });
});

test('existing receipt and evidence tampering cannot be replaced or accepted', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  for (const mutation of ['summary', 'raw', 'invocation', 'schema', 'receipt_bytes']) await t.test(mutation, async t => {
    const f = await fixture(t); await verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now });
    const path = join(f.spec.output_dir, mutation === 'raw' ? 'describe-invocation-tasks.json' : 'receipt.json');
    if (mutation === 'raw') await put(path, { ...f.tasks, TotalCount: 7 });
    else if (mutation === 'invocation') { f.spec.invocation_id = 'inv-OTHER1234'; await f.saveSpec(); }
    else if (mutation === 'receipt_bytes') await put(path, Buffer.concat([await readFile(path), Buffer.from('\n')]));
    else { const receipt = JSON.parse(await readFile(path)); if (mutation === 'schema') receipt.schema = 'cnb-deployment-verification/v1'; else receipt.images.web = 'registry.invalid/wrong@sha256:' + 'd'.repeat(64); await put(path, receipt); }
    const before = await readFile(path); f.calls.length = 0;
    for (const apply of [false, true]) await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply, client: f.client, now: f.now }));
    assert.deepEqual(f.calls, []); assert((await readFile(path)).equals(before));
  });
});

test('concurrent apply cannot query or replace another verifier evidence', async t => {
  const { verifyTestDeployment } = await moduleUnderTest(), f = await fixture(t);
  let entered, resume;
  const started = new Promise(done => { entered = done; }), blocked = new Promise(done => { resume = done; });
  const original = f.client.DescribeCommands;
  f.client.DescribeCommands = async input => { entered(); await blocked; return original(input); };
  const first = verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now });
  await started;
  await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }), /VERIFICATION_LOCKED/);
  resume(); assert.equal((await first).status, 'verified');
  assert.deepEqual(f.calls, ['DescribeCommands', 'DescribeInvocationTasks']);
});

test('source changes during readback and incomplete existing evidence stop without publishing or remote retry', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  for (const mutation of ['source_changed', 'incomplete']) await t.test(mutation, async t => {
    const f = await fixture(t);
    if (mutation === 'incomplete') { await mkdir(f.spec.output_dir, { mode: 0o700 }); await put(join(f.spec.output_dir, 'receipt.json'), { status: 'verified' }); }
    else { const original = f.client.DescribeInvocationTasks; f.client.DescribeInvocationTasks = async input => {
      const value = await original(input); await put(f.spec.candidate.path, Buffer.concat([f.candidateRaw, Buffer.from('\n')])); return value;
    }; }
    await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }));
    if (mutation === 'incomplete') { assert.deepEqual(f.calls, []); assert.deepEqual(await readdir(f.spec.output_dir), ['receipt.json']); }
    else await assert.rejects(access(f.spec.output_dir));
  });
});

test('unsafe private input and output locations fail before network or mutation and CLI errors redact secrets', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  for (const mutation of ['mode', 'link', 'in_project', 'production']) await t.test(mutation, async t => {
    const f = await fixture(t);
    if (mutation === 'mode') await chmod(f.spec.candidate.path, 0o644);
    if (mutation === 'link') { const original = f.spec.candidate.path; await symlink(original, join(f.privateDir, 'link.json')); f.spec.candidate.path = join(f.privateDir, 'link.json'); }
    if (mutation === 'in_project') f.spec.output_dir = join(f.spec.project_dir, 'private-output');
    if (mutation === 'production') f.spec.environment = 'production';
    await f.saveSpec();
    await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }));
    assert.deepEqual(f.calls, []);
    try { await execute(process.execPath, [entry, '--spec', f.specPath, '--apply']); assert.fail('unsafe input was accepted'); }
    catch (error) { assert(!error.stderr.includes(f.privateDir)); assert(!error.stderr.includes('SYNTHETIC_SECRET')); assert.equal(JSON.parse(error.stderr).status, 'stopped'); }
  });
});

test('bundle must be inside the project and an explicit SDK path must be absolute even in preview', async t => {
  const { verifyTestDeployment } = await moduleUnderTest();
  await t.test('parent bundle', async t => {
    const f = await fixture(t);
    for (const name of await readdir(f.bundle)) await rename(join(f.bundle, name), join(f.directory, name));
    f.spec.bundle_dir = f.directory; await f.saveSpec();
    await assert.rejects(verifyTestDeployment({ specPath: f.specPath, client: f.client, now: f.now }), /BUNDLE_OUTSIDE_PROJECT/);
    assert.deepEqual(f.calls, []);
  });
  await t.test('empty SDK root', async t => {
    const f = await fixture(t); f.spec.sdk_root = ''; await f.saveSpec();
    await assert.rejects(verifyTestDeployment({ specPath: f.specPath, client: f.client, now: f.now }), /PATH_INVALID/);
    assert.deepEqual(f.calls, []);
  });
});

test('in-process reuse refuses a newly pinned bundle at a path whose verifier modules were already imported', async t => {
  const { verifyTestDeployment } = await moduleUnderTest(), f = await fixture(t);
  await verifyTestDeployment({ specPath: f.specPath, now: f.now });
  const program = join(f.bundle, 'ci/run-tat-release.mjs');
  await put(program, Buffer.from((await readFile(program, 'utf8')).replace('export function validateBinding(binding, config) {',
    'export function validateBinding(binding, config) { throw new Error("new program must run");')));
  const lockPath = join(f.bundle, 'artifact-lock.json'), lock = JSON.parse(await readFile(lockPath));
  lock.files['ci/run-tat-release.mjs'] = hash(await readFile(program)); await put(lockPath, lock);
  f.spec.bundle_lock_sha256 = hash(await readFile(lockPath)); await f.saveSpec();
  await assert.rejects(verifyTestDeployment({ specPath: f.specPath, client: f.client, now: f.now }), /BUNDLE_CHANGED/);
  assert.deepEqual(f.calls, []);
});

test('publishing never replaces an output directory created while evidence is staging', async t => {
  const { verifyTestDeployment } = await moduleUnderTest(), f = await fixture(t);
  let occupied;
  const watcher = watch(f.privateDir, (_, name) => {
    if (name?.endsWith('.pending') && !occupied) { mkdirSync(f.spec.output_dir, { mode: 0o700 }); occupied = statSync(f.spec.output_dir).ino; }
  });
  t.after(() => watcher.close());
  await assert.rejects(verifyTestDeployment({ specPath: f.specPath, apply: true, client: f.client, now: f.now }));
  assert(occupied, 'fixture must reserve the directory during staging');
  assert.equal((await stat(f.spec.output_dir)).ino, occupied); assert.deepEqual(await readdir(f.spec.output_dir), []);
});

test('CLI reports missing installed SDK as actionable SDK_UNAVAILABLE without installing or exposing private data', async t => {
  await moduleUnderTest(); const f = await fixture(t);
  try { await execute(process.execPath, [entry, '--spec', f.specPath, '--apply']); assert.fail('missing SDK was accepted'); }
  catch (error) { assert.equal(JSON.parse(error.stderr).code, 'SDK_UNAVAILABLE'); assert(!error.stderr.includes(f.privateDir)); }
  await assert.rejects(access(f.spec.output_dir));
  await assert.rejects(access(join(f.bundle, 'dependencies/node_modules')));
});

test('CLI apply uses protected file credentials and pinned SDK for only the two Describe operations', async t => {
  await moduleUnderTest(); const f = await fixture(t), sdkRoot = join(f.privateDir, 'sdk');
  const sdkPackage = join(sdkRoot, 'node_modules/tencentcloud-sdk-nodejs-tat');
  await mkdir(sdkPackage, { recursive: true, mode: 0o700 });
  await put(join(sdkRoot, 'package.json'), { dependencies: { 'tencentcloud-sdk-nodejs-tat': '4.1.241' } });
  await put(join(sdkRoot, 'package-lock.json'), { packages: { 'node_modules/tencentcloud-sdk-nodejs-tat': { version: '4.1.241' } } });
  await put(join(sdkPackage, 'package.json'), { name: 'tencentcloud-sdk-nodejs-tat', version: '4.1.241', main: 'index.cjs' });
  await put(join(sdkRoot, 'commands.json'), f.commands); await put(join(sdkRoot, 'tasks.json'), f.tasks);
  await put(join(sdkPackage, 'index.cjs'), Buffer.from(`const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'../..');
module.exports={tat:{v20201028:{Client:class {
 constructor(options){assert.deepEqual(options.credential,{secretId:'AKIDSYNTHETIC',secretKey:'SYNTHETIC_SECRET_DO_NOT_LOG'});assert.equal(options.region,'ap-guangzhou');assert.equal(options.profile.httpProfile.endpoint,'tat.tencentcloudapi.com');}
 DescribeCommands(input){assert.deepEqual(input,{CommandIds:['cmd-DEMO1234'],Limit:1,Offset:0});fs.appendFileSync(path.join(root,'calls.txt'),'DescribeCommands\\n',{mode:0o600});return JSON.parse(fs.readFileSync(path.join(root,'commands.json')));}
 DescribeInvocationTasks(input){assert.deepEqual(input,{Filters:[{Name:'invocation-id',Values:['inv-DEMO1234']}],HideOutput:false,Limit:1,Offset:0});fs.appendFileSync(path.join(root,'calls.txt'),'DescribeInvocationTasks\\n');return JSON.parse(fs.readFileSync(path.join(root,'tasks.json')));}
 InvokeCommand(){throw Error('verification must never invoke');}
}}}};\n`));
  f.spec.sdk_root = sdkRoot; await f.saveSpec();
  const env = { ...process.env, TENCENTCLOUD_SECRET_ID: 'WRONG_AMBIENT_ID', TENCENTCLOUD_SECRET_KEY: 'WRONG_AMBIENT_KEY' };
  for (const [name, value] of [['NODE_DEBUG', 'https'], ['NODE_DEBUG_NATIVE', 'http'], ['NODE_OPTIONS', '--no-warnings']]) {
    const blocked = await execute(process.execPath, [entry, '--spec', f.specPath, '--apply'], { env: { ...env, [name]: value } }).then(
      result => ({ ...result, code: 0 }), error => error);
    assert.equal(blocked.code, 1, `${name} must prevent online verification`);
    assert.equal(JSON.parse(blocked.stderr).code, 'TAT_DEBUG_ENV_REFUSED');
    assert(!blocked.stderr.includes('SYNTHETIC_SECRET')); assert(!blocked.stdout.includes('SYNTHETIC_SECRET'));
    await assert.rejects(access(join(sdkRoot, 'calls.txt'))); await assert.rejects(access(f.spec.output_dir));
  }
  const first = await execute(process.execPath, [entry, '--spec', f.specPath, '--apply'], { env });
  assert.equal(JSON.parse(first.stdout).status, 'verified'); assert(!first.stdout.includes('SYNTHETIC_SECRET'));
  assert.equal(await readFile(join(sdkRoot, 'calls.txt'), 'utf8'), 'DescribeCommands\nDescribeInvocationTasks\n');
  await rm(sdkRoot, { recursive: true }); await rm(f.spec.tat_credentials_file);
  const repeated = await execute(process.execPath, [entry, '--spec', f.specPath, '--apply'], { env });
  assert.equal(JSON.parse(repeated.stdout).reused, true);
});
