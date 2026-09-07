import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const module = await import('../scripts/configure-cam.mjs').catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {};
  throw error;
});
const spec = () => ({ schema_version: 1, project: 'sample', environment: 'test',
  account_id: '90001', user_name: 'sample-test-ci', policy_name: 'sample-test-release',
  target: { region: 'ap-example', instance_id: 'lhins-demo', command_ids: ['cmd-example1', 'cmd-example2'] } });
function fake(input, changes = {}) {
  const state = { user: null, policy: null, attachments: [], keys: [], groups: [], writes: [], ...changes };
  const client = { async request(action, request) {
    if (action === 'ListPolicies') return { TotalNum: state.policy ? 1 : 0, List: state.policy ? [{ PolicyId: 123, PolicyName: input.policy_name }] : [] };
    if (action === 'GetPolicy') return state.policy;
    if (action === 'GetUser') {
      if (!state.user) throw Object.assign(new Error('private diagnostic'), { code: 'ResourceNotFound.UserNotExist' });
      return state.user;
    }
    if (action === 'ListGroupsForUser') return { TotalNum: state.groups.length, GroupInfo: state.groups };
    if (action === 'ListAttachedUserAllPolicies') {
      assert.equal(request.AttachType, 0);
      return { TotalNum: state.attachments.length, PolicyList: state.attachments };
    }
    if (action === 'ListAccessKeys') return { AccessKeys: state.keys };
    state.writes.push([action, request]);
    if (action === 'CreatePolicy') {
      state.policy = { PolicyName: request.PolicyName, Description: request.Description, Type: 1,
        IsServiceLinkedRolePolicy: 0, PolicyDocument: request.PolicyDocument };
      return { PolicyId: 123 };
    }
    if (action === 'AddUser') {
      assert.equal(request.ConsoleLogin, 0); assert.equal(request.UseApi, 0);
      state.user = { Uin: 90002, Name: request.Name, Remark: request.Remark, ConsoleLogin: 0 };
      return state.user;
    }
    if (action === 'AttachUserPolicy') {
      assert.deepEqual(request, { PolicyId: 123, AttachUin: 90002 });
      state.attachments = [{ PolicyId: '123', PolicyName: input.policy_name, Groups: [] }];
      return {};
    }
    throw new Error(`unexpected API: ${action}`);
  } };
  const identityClient = { async request(action, request) {
    assert.equal(action, 'GetCallerIdentity'); assert.deepEqual(request, {});
    return { AccountId: input.account_id };
  } };
  return { state, client, identityClient };
}

test('preview creates a bounded TAT policy offline and refuses arbitrary permissions or targets', async () => {
  assert.equal(typeof module.configureCam, 'function');
  const input = spec(), result = await module.configureCam({ spec: input });
  assert.equal(result.status, 'planned'); assert.equal(result.credential_status, 'not_created');
  assert.deepEqual(result.policy, { version: '2.0', statement: [
    { effect: 'allow', action: ['tat:InvokeCommand', 'tat:DescribeInvocationTasks'], resource: [
      'qcs::tat:ap-example:uin/90001:command/cmd-example1',
      'qcs::tat:ap-example:uin/90001:command/cmd-example2',
      'qcs::lighthouse:ap-example:uin/90001:instance/lhins-demo'] },
    { effect: 'allow', action: ['tat:DescribeCommands'], resource: [
      'qcs::tat:ap-example:uin/90001:command/cmd-example1',
      'qcs::tat:ap-example:uin/90001:command/cmd-example2'] },
  ] });
  for (const edit of [s => s.policy = {}, s => s.target.command_ids = ['*'], s => s.target.command_ids.push('cmd-example3'),
    s => s.user_name = 'administrator', s => s.target.instance_id = '*', s => s.account_id = '*']) {
    const bad = spec(); edit(bad);
    await assert.rejects(module.configureCam({ spec: bad }), { message: 'CAM_SPEC_INVALID' });
  }
});

test('apply creates only the scoped policy and programmatic identity, verifies attachment and reuses without mutation', async () => {
  const input = spec(), f = fake(input);
  const first = await module.configureCam({ spec: input, apply: true, ...f });
  assert.equal(first.status, 'verified'); assert.equal(first.user_uin, 90002);
  assert.equal(first.credential_status, 'not_created'); assert.equal(first.deployment_ready, false);
  assert.deepEqual(f.state.writes.map(([action]) => action), ['CreatePolicy', 'AddUser', 'AttachUserPolicy']);
  f.state.writes.length = 0;
  const second = await module.configureCam({ spec: input, apply: true, ...f });
  assert.deepEqual(second, first); assert.deepEqual(f.state.writes, []);
});

test('existing identity, policy, inherited permissions, keys and owner mismatches fail before any mutation', async () => {
  for (const kind of ['console', 'remark', 'policy', 'group', 'attached', 'key', 'account']) {
    const input = spec(), f = fake(input);
    await module.configureCam({ spec: input, apply: true, ...f });
    f.state.writes.length = 0;
    if (kind === 'console') f.state.user.ConsoleLogin = 1;
    if (kind === 'remark') f.state.user.Remark = 'unmanaged';
    if (kind === 'policy') f.state.policy.PolicyDocument = '{"version":"2.0","statement":[]}';
    if (kind === 'group') f.state.groups = [{ GroupId: 999 }];
    if (kind === 'attached') f.state.attachments.push({ PolicyId: '999', PolicyName: 'AdministratorAccess' });
    if (kind === 'key') f.state.keys = [{ AccessKeyId: 'never-print-this', Status: 'Active' }];
    if (kind === 'account') f.identityClient.request = async () => ({ AccountId: '90099' });
    await assert.rejects(module.configureCam({ spec: input, apply: true, ...f }),
      { message: kind === 'key' ? 'CAM_CREDENTIAL_RECOVERY_REQUIRED' : kind === 'account' ? 'CAM_ACCOUNT_MISMATCH' : 'CAM_RESOURCE_CONFLICT' });
    assert.deepEqual(f.state.writes, [], kind);
  }
});

test('ambiguous reads and uncertain writes stop with fixed errors and never create a key or retry a mutation', async () => {
  const input = spec(), f = fake(input), original = f.client.request;
  f.client.request = async (action, request) => {
    if (action === 'ListPolicies') return { TotalNum: 201, List: [] };
    return original(action, request);
  };
  await assert.rejects(module.configureCam({ spec: input, apply: true, ...f }), { message: 'CAM_QUERY_INCOMPLETE' });
  assert.deepEqual(f.state.writes, []);
  f.client.request = async (action, request) => {
    if (action === 'AddUser') {
      f.state.writes.push([action, request]);
      throw new Error('private diagnostic');
    }
    return original(action, request);
  };
  await assert.rejects(module.configureCam({ spec: input, apply: true, ...f }), { message: 'CAM_WRITE_UNCERTAIN' });
  assert.deepEqual(f.state.writes.map(([action]) => action), ['CreatePolicy', 'AddUser']);
});


test('CLI preview is offline and apply uses the pinned SDK with private credentials and fixed CAM/STS endpoints', t => {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'configure-cam-cli-'));
  fs.chmodSync(dir, 0o700); t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  const input = spec(), specFile = path.join(dir, 'spec.json'), script = fileURLToPath(new URL('../scripts/configure-cam.mjs', import.meta.url));
  fs.writeFileSync(specFile, JSON.stringify(input), { mode: 0o600 });
  const run = args => spawnSync(process.execPath, [script, '--spec', specFile, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  const preview = run(['--credentials', path.join(dir, 'missing'), '--sdk-root', path.join(dir, 'missing-sdk')]);
  assert.equal(preview.status, 0, preview.stderr); assert.equal(JSON.parse(preview.stdout).status, 'planned');
  assert.deepEqual(fs.readdirSync(dir), ['spec.json']);
  const root = path.join(dir, 'sdk'), common = path.join(root, 'node_modules/tencentcloud-sdk-nodejs-common');
  fs.mkdirSync(common, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/tencentcloud-sdk-nodejs-common': { version: '4.1.220' } } }));
  fs.writeFileSync(path.join(common, 'package.json'), JSON.stringify({ main: 'index.js', version: '4.1.220' }));
  fs.writeFileSync(path.join(common, 'index.js'), `
const assert = require('node:assert/strict');
const f = (${fake.toString()})(${JSON.stringify(input)});
module.exports = { AbstractClient: class {
  constructor(endpoint, version, config) {
    assert.ok(['cam.tencentcloudapi.com', 'sts.tencentcloudapi.com'].includes(endpoint));
    assert.equal(version, endpoint.startsWith('cam.') ? '2019-01-16' : '2018-08-13');
    assert.equal(config.region, 'ap-example');
    assert.equal(config.profile.httpProfile.endpoint, endpoint);
    assert.equal(config.profile.httpProfile.protocol, 'https://');
    assert.deepEqual(config.credential, { secretId: 'test-id', secretKey: 'test-private-value', token: 'test-token' });
    this.client = endpoint.startsWith('cam.') ? f.client : f.identityClient;
  }
  request(action, request) { return this.client.request(action, request); }
} };
`);
  const credentials = path.join(dir, 'credentials.json');
  fs.writeFileSync(credentials, JSON.stringify({ secretId: 'test-id', secretKey: 'test-private-value', token: 'test-token' }), { mode: 0o600 });
  const result = run(['--apply', '--sdk-root', root, '--credentials', credentials]);
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).credential_status, 'not_created');
  assert.equal(result.stdout.includes('test-private-value'), false); assert.equal(result.stdout.includes('test-token'), false);
  fs.chmodSync(credentials, 0o644);
  const rejected = run(['--apply', '--sdk-root', root, '--credentials', credentials]);
  assert.equal(rejected.status, 1); assert.equal(rejected.stdout, ''); assert.equal(rejected.stderr, 'CAM_INPUT_UNSAFE\n');
});

test('final readback refuses a replacement user even when its name and managed fields match', async () => {
  const input = spec(), f = fake(input), original = f.client.request;
  let reads = 0;
  f.client.request = async (action, request) => {
    const result = await original(action, request);
    if (action === 'GetUser' && result && ++reads === 2) return { ...result, Uin: 90003 };
    return result;
  };
  await assert.rejects(module.configureCam({ spec: input, apply: true, ...f }), { message: 'CAM_RESOURCE_CONFLICT' });
});
