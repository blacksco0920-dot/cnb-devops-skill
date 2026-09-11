import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, cp, writeFile, readFile, readdir, rm, chmod, access, symlink, stat } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { tmpdir, hostname } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { productionFixture } from './bundle-production-fixture.mjs';
import { canonicalBytes, sha256, signApproval, createProductionRequest } from '../assets/cnb-tcr-tat/ci/production-contract.mjs';

const execute = promisify(execFile), ROOT = resolve(import.meta.dirname, '..');
const entry = join(ROOT, 'scripts/release-session.mjs');
const loaded = () => import(pathToFileURL(entry));
const put = (file, value) => writeFile(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value), { mode: 0o600 });
const exists = async path => { try { await access(path); return true; } catch { return false; } };

async function fixture(t) {
  const root = await mkdtemp(join(await import('node:fs/promises').then(m => m.realpath(tmpdir())), 'release-session-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = join(root, 'project'), privateDir = join(root, 'private'), session = join(privateDir, 'session');
  await mkdir(project); await mkdir(privateDir, { mode: 0o700 }); await mkdir(session, { mode: 0o700 });
  await execute('git', ['init', '-q', '-b', 'main', project]);
  await execute('git', ['-C', project, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-qm', 'candidate']);
  const commit = (await execute('git', ['-C', project, 'rev-parse', 'HEAD'])).stdout.trim();
  const f = productionFixture();
  f.config.production_branch = 'main';
  f.candidate.application_commit = commit; f.candidate.controller_commit = commit;
  delete f.candidate.manifest_sha256;
  f.candidate.manifest_sha256 = sha256(canonicalBytes(f.candidate).subarray(0, -1));
  f.candidateRaw = canonicalBytes(f.candidate);
  Object.assign(f.readiness, { application_commit: commit, candidate_manifest_sha256: f.candidate.manifest_sha256, candidate_bytes_sha256: sha256(f.candidateRaw) });
  Object.assign(f.payload, { application_commit: commit, candidate_manifest_sha256: f.candidate.manifest_sha256, candidate_bytes_sha256: sha256(f.candidateRaw) });
  f.approval = signApproval(f.payload, f.privateKey);
  const message = join(privateDir, 'tag-message'); await put(message, f.candidateRaw);
  await execute('git', ['-C', project, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'tag', '-a', f.candidate.candidate_tag, '-F', message, '--cleanup=verbatim']);
  const bundle = join(project, 'deploy/vendor/cnb-devops'); await mkdir(bundle, { recursive: true });
  async function bundleAt(base, config) {
    await mkdir(base, { recursive: true });
    for (const name of ['ci', 'admin', 'dependencies']) await cp(join(ROOT, 'assets/cnb-tcr-tat', name), join(base, name), { recursive: true, filter: path => !path.includes('node_modules') && !path.includes('__pycache__') });
    await put(join(base, 'ci-config.json'), config);
    await put(join(base, 'approval-ed25519.pub'), f.publicPem);
    const files = {};
    async function walk(dir, prefix = '') { for (const item of await readdir(dir, { withFileTypes: true })) { const name = prefix + item.name; if (item.isDirectory()) await walk(join(dir, item.name), name + '/'); else files[name] = sha256(await readFile(join(dir, item.name))); } }
    await walk(base);
    const raw = JSON.stringify({ schema: 'cnb-devops-artifacts/v1', version: 'test', files });
    await put(join(base, 'artifact-lock.json'), raw); return sha256(raw);
  }
  const bundleHash = await bundleAt(bundle, f.candidateConfig), productionHash = await bundleAt(join(bundle, 'production'), f.config);
  const spec = { schema: 'cnb-release-session/v1', project_dir: project, bundle_dir: bundle, session_dir: session,
    bundle_lock_sha256: bundleHash, production_lock_sha256: productionHash,
    candidate_tag: f.candidate.candidate_tag, application_commit: commit,
    production_binding: join(privateDir, 'binding.json'), approval_private_key: join(privateDir, 'key.pem'),
    cnb_token_file: join(privateDir, 'cnb-token'), tat_credentials_file: join(privateDir, 'tat.json') };
  await put(spec.production_binding, f.binding); await put(spec.approval_private_key, f.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await put(spec.cnb_token_file, 'TEST-PAT-MUST-NOT-LEAK\n'); await put(spec.tat_credentials_file, { secretId: 'AKID' + 'a'.repeat(32), secretKey: 'TAT-SECRET-MUST-NOT-LEAK', token: 'TEMP-TOKEN' });
  const specPath = join(privateDir, 'spec.json'); await put(specPath, spec);
  const annotations = { candidate_format: 'cnb-candidate/v1', candidate_manifest_sha256: f.candidate.manifest_sha256, candidate_commit: commit,
    test_build_status: 'passed', test_runtime_status: 'passed', test_public_status: 'passed', candidate_status: 'ready',
    production_readiness_status: 'passed', production_readiness_b64url: canonicalBytes(f.readiness).toString('base64url'),
    production_prepared_sha256: f.readiness.prepared_sha256, production_readiness_invocation_id: 'inv-DEMO1234' };
  let npmCalls = 0, writes = 0, reads = 0;
  const dependencies = {
    async execute(bin, args, options) {
      if (bin === 'npm') {
        npmCalls++; assert.deepEqual(args, ['ci', '--ignore-scripts', '--prefix', join(bundle, 'production/dependencies')]);
        assert.equal(options.env.CNB_TOKEN, undefined); assert.equal(options.env.TENCENTCLOUD_SECRET_KEY, undefined);
        const sdk = join(bundle, 'production/dependencies/node_modules/tencentcloud-sdk-nodejs-tat'); await mkdir(sdk, { recursive: true });
        await put(join(sdk, 'package.json'), { name: 'tencentcloud-sdk-nodejs-tat', version: '4.1.241', main: 'index.js' });
        await put(join(sdk, 'index.js'), 'module.exports={tat:{v20201028:{Client:class{}}}};'); return { stdout: '', stderr: '' };
      }
      return execute(bin, args, { ...options, env: { ...options.env, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: `url.file://${project}.insteadOf`, GIT_CONFIG_VALUE_0: 'https://cnb.cool/example/sample.git', GIT_ALLOW_PROTOCOL: 'file' } });
    },
    async fetchImpl(url, options) {
      assert.equal(url, `https://api.cnb.cool/example/sample/-/git/tag-annotations/${f.candidate.candidate_tag}`);
      assert.equal(options.headers.Authorization, 'Bearer TEST-PAT-MUST-NOT-LEAK');
      if (options.method === 'PUT') { writes++; for (const item of JSON.parse(options.body).annotations) annotations[item.key] = item.value; return new Response(''); }
      reads++; return new Response(JSON.stringify(Object.entries(annotations).map(([key, value]) => ({ key, value }))));
    },
    createClient(credentials) {
      assert.equal(credentials.token, 'TEMP-TOKEN');
      const wire = f.clientFor();
      wire.task.CommandDocument.Content = Buffer.from('#!/bin/sh\n# production ' + createProductionRequest('readiness', f.candidateRaw) + '\n').toString('base64');
      return wire.client;
    },
  };
  const run = async (action, options = {}, overrides = {}) => (await loaded()).runSession({ action, specPath, ...options }, { ...dependencies, ...overrides });
  return { ...f, root, spec, specPath, run, dependencies, annotations, npmCalls: () => npmCalls, writes: () => writes, reads: () => reads };
}

test('entry provides a bounded CLI instead of requiring inline shell assembly', async () => {
  assert.equal(await exists(entry), true, 'release-session CLI must exist');
  const result = await execute(process.execPath, [entry, '--help']);
  assert.match(result.stdout, /prepare\|candidate\|sign\|publish\|status/);
});

test('installed symlink entry runs the CLI while an imported entry remains silent', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'release-session-link-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const installed = join(directory, 'skill');
  await symlink(ROOT, installed, 'dir');
  const linkedEntry = join(installed, 'scripts/release-session.mjs');
  const help = await execute(process.execPath, [linkedEntry, '--help']);
  assert.match(help.stdout, /prepare\|candidate\|sign\|publish\|status/);
  const imported = await execute(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(pathToFileURL(linkedEntry).href)})`]);
  assert.equal(imported.stdout, ''); assert.equal(imported.stderr, '');
});

test('prepare is offline in preview, installs production dependencies once and never reads private key or credentials', async t => {
  const f = await fixture(t);
  for (const path of [f.spec.approval_private_key, f.spec.cnb_token_file, f.spec.tat_credentials_file]) await rm(path);
  assert.equal((await f.run('prepare')).status, 'preview'); assert.equal(f.npmCalls(), 0);
  assert.equal(await exists(join(f.spec.session_dir, 'state.json')), false);
  assert.equal((await f.run('prepare', { apply: true })).status, 'prepared');
  assert.equal((await f.run('prepare', { apply: true })).status, 'prepared'); assert.equal(f.npmCalls(), 1);
  assert.equal((await f.run('status')).next_action, 'candidate');
});

test('candidate uses real Git annotated Tag gate, preserves bytes and resumes after a failed GET', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true });
  await assert.rejects(f.run('candidate', { apply: true }, { fetchImpl: async () => { throw Error('TEST-PAT-MUST-NOT-LEAK'); } }), /CANDIDATE_FETCH_FAILED/);
  const result = await f.run('candidate', { apply: true }); assert.equal(result.status, 'candidate');
  assert.deepEqual(await readFile(join(f.spec.session_dir, 'candidate/candidate.json')), f.candidateRaw);
  assert.deepEqual(await readFile(join(f.spec.session_dir, 'candidate/readiness.json')), canonicalBytes(f.readiness));
  const reads = f.reads(); assert.equal((await f.run('candidate', { apply: true })).status, 'candidate'); assert.equal(f.reads(), reads);
  assert.equal((await f.run('status')).next_action, 'sign');
});

test('sign requires explicit authorization and publisher retries by exact envelope with real readback', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true }); await f.run('candidate', { apply: true });
  await assert.rejects(f.run('sign', { apply: true }), /PRODUCTION_AUTHORIZATION_REQUIRED/);
  assert.equal((await f.run('sign', { apply: true, authorized: true })).status, 'signed');
  const raw = await readFile(join(f.spec.session_dir, 'approval.json'));
  assert.equal((await f.run('sign', { apply: true, authorized: true })).status, 'signed');
  assert.deepEqual(await readFile(join(f.spec.session_dir, 'approval.json')), raw);
  assert.equal((await f.run('publish')).status, 'preview'); assert.equal(f.writes(), 0);
  assert.equal((await f.run('publish', { apply: true })).status, 'signed'); assert.equal(f.writes(), 3);
  const originalPublication = await readFile(join(f.spec.session_dir, 'publication-result.json'));
  const reads = f.reads(); await f.run('publish', { apply: true }); assert.equal(f.writes(), 3); assert.ok(f.reads() > reads);
  assert.deepEqual(await readFile(join(f.spec.session_dir, 'publication-result.json')), originalPublication);
  const serialized = JSON.stringify(await f.run('status')); assert.doesNotMatch(serialized, /TEST-PAT|TAT-SECRET|TEMP-TOKEN|privateKey/);
});

test('a signer failure without a local envelope safely retries, while an invalid envelope is preserved', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true }); await f.run('candidate', { apply: true });
  await assert.rejects(f.run('sign', { apply: true, authorized: true }, { createClient() { throw Error('secret failure'); } }), /SIGN_FAILED/);
  assert.equal((await f.run('sign', { apply: true, authorized: true })).status, 'signed');
  await put(join(f.spec.session_dir, 'approval.json'), '{}\n');
  await assert.rejects(f.run('sign', { apply: true, authorized: true }), /EVIDENCE_CHANGED|APPROVAL_INVALID/);
  assert.equal(await readFile(join(f.spec.session_dir, 'approval.json'), 'utf8'), '{}\n');
});

test('expiry, bundle drift, evidence tampering and a concurrent lock block reuse', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true }); await f.run('candidate', { apply: true });
  await f.run('sign', { apply: true, authorized: true });
  await assert.rejects(f.run('publish', { apply: true }, { now: () => f.instant + 7200000 }), /APPROVAL_EXPIRED/);
  const expired = await f.run('status', {}, { now: () => f.instant + 7200000 });
  assert.equal(expired.status, 'blocked'); assert.equal(expired.next_action, 'refresh_readiness_new_session');
  await put(join(f.spec.session_dir, '.lock'), { pid: process.pid });
  await assert.rejects(f.run('publish', { apply: true }), /SESSION_LOCKED/); await rm(join(f.spec.session_dir, '.lock'));
  await put(join(f.spec.session_dir, 'candidate/candidate.json'), '{}\n');
  await assert.rejects(f.run('status'), /EVIDENCE_CHANGED/);
  await put(join(f.spec.bundle_dir, 'production/admin/sign-production-approval.mjs'), '// changed');
  await assert.rejects(f.run('prepare', { apply: true }), /BUNDLE_CHANGED/);
});

test('strict spec and protected storage reject cross-project or public state', async t => {
  const f = await fixture(t);
  await put(f.specPath, { ...f.spec, command: 'arbitrary' }); await assert.rejects(f.run('prepare'), /SPEC_INVALID/);
  await put(f.specPath, { ...f.spec, session_dir: f.spec.project_dir }); await assert.rejects(f.run('prepare'), /PRIVATE_PATH_IN_PROJECT|PRIVATE_DIRECTORY_UNSAFE/);
  await put(f.specPath, f.spec); await chmod(f.specPath, 0o644); await assert.rejects(f.run('status'), /PRIVATE_FILE_UNSAFE/);
});

test('bad readiness annotations remain in a disposable attempt and allow a correct candidate retry', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true });
  f.annotations.production_readiness_invocation_id = 'invalid';
  await assert.rejects(f.run('candidate', { apply: true }), /READINESS_INVALID/);
  assert.equal(await exists(join(f.spec.session_dir, 'candidate')), false);
  f.annotations.production_readiness_invocation_id = 'inv-DEMO1234';
  assert.equal((await f.run('candidate', { apply: true })).status, 'candidate');
});

test('a stale same-host lock is recoverable, while live or ambiguous owners block', async t => {
  const f = await fixture(t);
  const child = await execute(process.execPath, ['-e', 'process.stdout.write(String(process.pid))']);
  const deadPid = Number(child.stdout); assert.throws(() => process.kill(deadPid, 0), { code: 'ESRCH' });
  const path = join(f.spec.session_dir, '.lock');
  await put(path, { schema: 'cnb-release-session-lock/v1', pid: deadPid, hostname: hostname(), id: 'dead-owner', started_at: new Date().toISOString() });
  assert.equal((await f.run('prepare', { apply: true })).status, 'prepared');
  await put(path, { schema: 'cnb-release-session-lock/v1', pid: process.pid, hostname: hostname(), id: 'live-owner', started_at: new Date().toISOString() });
  await assert.rejects(f.run('prepare', { apply: true }), /SESSION_LOCKED/);
  await rm(path); await put(path, { schema: 'cnb-release-session-lock/v1', pid: deadPid, hostname: 'another-host.invalid', id: 'foreign-owner', started_at: new Date().toISOString() });
  await assert.rejects(f.run('prepare', { apply: true }), /SESSION_LOCKED/);
});

test('lost publisher response resumes exact server readback without another approval', async t => {
  const f = await fixture(t); await f.run('prepare', { apply: true }); await f.run('candidate', { apply: true }); await f.run('sign', { apply: true, authorized: true });
  const approval = await readFile(join(f.spec.session_dir, 'approval.json'));
  let interrupted = false;
  await assert.rejects(f.run('publish', { apply: true }, { fetchImpl: async (url, options) => {
    const response = await f.dependencies.fetchImpl(url, options);
    if (options.method === 'PUT' && !interrupted) { interrupted = true; throw Error('response lost'); }
    return response;
  } }), /PUBLICATION_FAILED/);
  assert.equal((await f.run('publish', { apply: true })).status, 'signed');
  assert.deepEqual(await readFile(join(f.spec.session_dir, 'approval.json')), approval);
});

async function completedDeployment(t) {
  const f = await fixture(t), current = { now: () => f.instant };
  await f.run('prepare', { apply: true }, current); await f.run('candidate', { apply: true }, current);
  await f.run('sign', { apply: true, authorized: true }, current); await f.run('publish', { apply: true }, current);
  const approval = JSON.parse(await readFile(join(f.spec.session_dir, 'approval.json')));
  const payload = JSON.parse(Buffer.from(approval.payload_b64url, 'base64url'));
  const result = { ...f.result, approval_id: payload.approval_id, approval_sha256: sha256(canonicalBytes(approval)),
    candidate_manifest_sha256: f.candidate.manifest_sha256, candidate_bytes_sha256: sha256(f.candidateRaw),
    release: { ...f.result.release, git_sha: f.candidate.application_commit, controller_commit: f.candidate.controller_commit } };
  f.annotations.production_deploy_status = 'passed'; f.annotations.production_receipt_sha256 = sha256(canonicalBytes(result));
  const wire = f.clientFor('apply');
  wire.task.CommandDocument.Content = Buffer.from('#!/bin/sh\n# production ' + createProductionRequest('apply', f.candidateRaw, approval) + '\n').toString('base64');
  Object.assign(wire.task.TaskResult, { Output: canonicalBytes(result).toString('base64'),
    ExecStartTime: new Date(f.instant + 1000).toISOString().replace('.000Z', 'Z'),
    ExecEndTime: new Date(f.instant + 60000).toISOString().replace('.000Z', 'Z') });
  let commandReads = 0, taskReads = 0;
  const originalCommands = wire.client.DescribeCommands, originalTasks = wire.client.DescribeInvocationTasks;
  wire.client.DescribeCommands = async args => {
    assert.deepEqual(args, { CommandIds: ['cmd-DEMO1234'], Limit: 1, Offset: 0 }); commandReads++; return originalCommands(args);
  };
  wire.client.DescribeInvocationTasks = async args => {
    assert.deepEqual(args, { Filters: [{ Name: 'invocation-id', Values: ['inv-DEMO1234'] }], HideOutput: false, Limit: 1, Offset: 0 });
    taskReads++; return originalTasks(args);
  };
  return { ...f, wire, commandReads: () => commandReads, taskReads: () => taskReads,
    verification: { now: () => f.instant + 90000000, createClient: () => wire.client } };
}

test('verify keeps historical proof after expiry, saves owner-only evidence, and remains read-only on retry', async t => {
  const f = await completedDeployment(t), input = { invocationId: 'inv-DEMO1234' }, writes = f.writes(), reads = f.reads();
  assert.equal((await f.run('verify', input, f.verification)).status, 'preview');
  assert.equal(f.reads(), reads); assert.equal(f.commandReads(), 0);
  const result = await f.run('verify', { ...input, apply: true }, f.verification);
  assert.equal(result.status, 'verified'); assert.equal(result.next_action, 'none');
  const path = join(f.spec.session_dir, 'deployment-verification/receipt.json'), raw = await readFile(path);
  const receipt = JSON.parse(raw);
  assert.equal(receipt.schema, 'cnb-deployment-verification/v1'); assert.equal(receipt.build_id, 'cnb-example-123');
  assert.equal(receipt.application_commit, f.spec.application_commit); assert.equal(receipt.current_runtime_verified, false);
  assert.equal(receipt.evidence_base, 'receipt_directory'); assert.equal(receipt.evidence.length, 7);
  assert.equal((await stat(dirname(path))).mode & 0o777, 0o700);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  for (const ref of receipt.evidence) {
    const evidencePath = join(dirname(path), ref.path);
    assert.equal(sha256(await readFile(evidencePath)), ref.sha256); assert.equal((await stat(evidencePath)).mode & 0o777, 0o600);
  }
  await f.run('verify', { ...input, apply: true }, { ...f.verification, now: () => f.instant + 91000000 });
  assert.deepEqual(await readFile(path), raw); assert.equal(f.writes(), writes); assert.equal(f.wire.invoked(), 0);
  assert.equal(f.commandReads(), 2); assert.equal(f.taskReads(), 2); assert.equal(f.reads(), reads + 2);
  for (const action of ['sign', 'publish']) await assert.rejects(f.run(action, { apply: true, authorized: action === 'sign' }, f.verification), /READINESS_EXPIRED|APPROVAL_EXPIRED/);
  for (const path of [f.spec.cnb_token_file, f.spec.tat_credentials_file, f.spec.approval_private_key]) await rm(path);
  const status = await f.run('status', {}, { now: f.verification.now });
  assert.equal(status.status, 'verified'); assert.equal(status.next_action, 'none');
  assert.equal(status.deployment.current_runtime_verified, false);
  assert.doesNotMatch(JSON.stringify(status), /TEST-PAT|TAT-SECRET|TEMP-TOKEN|privateKey/);
});

test('failed readback keeps bounded partial evidence and retries without promoting a partial receipt', async t => {
  const f = await completedDeployment(t), args = { apply: true, invocationId: 'inv-DEMO1234' };
  await assert.rejects(f.run('verify', args, { ...f.verification, fetchImpl: async () => { throw Error('TEST-PAT-MUST-NOT-LEAK'); } }), /DEPLOYMENT_/);
  const final = join(f.spec.session_dir, 'deployment-verification'), pending = join(f.spec.session_dir, '.deployment-verification-pending');
  assert.equal(await exists(join(final, 'receipt.json')), false);
  assert.equal(await exists(join(pending, 'describe-invocation-tasks.json')), true);
  assert.notEqual((await f.run('status', {}, f.verification)).status, 'verified');
  assert.equal((await f.run('verify', args, f.verification)).status, 'verified');
  assert.equal(await exists(pending), false); assert.equal(f.wire.invoked(), 0);
});

test('verified status revalidates raw execution and receipt rather than trusting a terminal state flag', async t => {
  const f = await completedDeployment(t), args = { apply: true, invocationId: 'inv-DEMO1234' };
  await f.run('verify', args, f.verification);
  const statePath = join(f.spec.session_dir, 'state.json'), state = JSON.parse(await readFile(statePath));
  const path = join(f.spec.session_dir, 'deployment-verification/describe-invocation-tasks.json');
  const task = JSON.parse(await readFile(path)); task.InvocationTaskSet[0].TaskResult.ExecEndTime = new Date(f.instant + 7200000).toISOString().replace('.000Z', 'Z');
  await put(path, task);
  state.files['deployment-verification/describe-invocation-tasks.json'] = sha256(await readFile(path)); await put(statePath, state);
  await assert.rejects(f.run('status', {}, f.verification), /DEPLOYMENT_|EVIDENCE_CHANGED/);
});

test('verify requires one exact invocation and refuses options on unrelated actions', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run('verify'), /ARGUMENTS_INVALID/);
  await assert.rejects(f.run('verify', { invocationId: 'inv-../../wrong' }), /ARGUMENTS_INVALID/);
  await assert.rejects(f.run('prepare', { invocationId: 'inv-DEMO1234' }), /ARGUMENTS_INVALID/);
  await assert.rejects(f.run('verify', { invocationId: 'inv-DEMO1234', authorized: true }), /ARGUMENTS_INVALID/);
});

test('verified preview refuses replacing the already bound invocation', async t => {
  const f = await completedDeployment(t);
  await f.run('verify', { apply: true, invocationId: 'inv-DEMO1234' }, f.verification);
  await assert.rejects(f.run('verify', { invocationId: 'inv-OTHER1234' }, f.verification), /DEPLOYMENT_INVOCATION_CHANGED/);
});

test('a completed atomic receipt recovers a missing state update but a terminal flag without receipt never proves deployment', async t => {
  const f = await completedDeployment(t), statePath = join(f.spec.session_dir, 'state.json');
  const before = JSON.parse(await readFile(statePath)); before.steps.verify = 'complete'; await put(statePath, before);
  assert.notEqual((await f.run('status', {}, f.verification)).status, 'verified');
  await f.run('verify', { apply: true, invocationId: 'inv-DEMO1234' }, f.verification);
  before.steps.verify = 'pending'; await put(statePath, before);
  assert.equal((await f.run('status', {}, f.verification)).status, 'verified');
  assert.equal((await f.run('verify', { apply: true, invocationId: 'inv-DEMO1234' }, f.verification)).status, 'verified');
  assert.equal(f.wire.invoked(), 0);
});

test('a forged public summary cannot bypass raw standard validation even when local file hashes are rewritten', async t => {
  const f = await completedDeployment(t);
  await f.run('verify', { apply: true, invocationId: 'inv-DEMO1234' }, f.verification);
  const directory = join(f.spec.session_dir, 'deployment-verification'), receiptPath = join(directory, 'receipt.json');
  const receipt = JSON.parse(await readFile(receiptPath)); receipt.current_runtime_verified = true; await put(receiptPath, receipt);
  const statePath = join(f.spec.session_dir, 'state.json'), state = JSON.parse(await readFile(statePath));
  state.files['deployment-verification/receipt.json'] = sha256(await readFile(receiptPath)); await put(statePath, state);
  await assert.rejects(f.run('status', {}, f.verification), /DEPLOYMENT_RECEIPT_INVALID/);
});

test('failed live retry preserves historical proof while reporting that the new observation failed', async t => {
  const f = await completedDeployment(t), args = { apply: true, invocationId: 'inv-DEMO1234' };
  await f.run('verify', args, f.verification);
  const path = join(f.spec.session_dir, 'deployment-verification/receipt.json'), raw = await readFile(path);
  f.annotations.production_deploy_status = 'failed';
  await assert.rejects(f.run('verify', args, f.verification), /DEPLOYMENT_VERIFICATION_FAILED/);
  assert.deepEqual(await readFile(path), raw);
  const status = await f.run('status', {}, f.verification);
  assert.equal(status.status, 'verified'); assert.equal(status.deployment.current_runtime_verified, false);
  assert.equal(status.next_action, 'none'); assert.equal(f.wire.invoked(), 0);
});

test('verify preflight validates the protected TAT binding before transport is available', async t => {
  const f = await fixture(t);
  await put(f.spec.production_binding, { ...f.binding, command_id: 'cmd-PENDING0' });
  await f.run('prepare', { apply: true }); await f.run('candidate', { apply: true });
  await put(join(f.spec.session_dir, 'approval.json'), canonicalBytes(f.approval));
  await assert.rejects(f.run('verify', { invocationId: 'inv-DEMO1234' }), /DEPLOYMENT_INPUT_INVALID/);
});
