import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const source = new URL('../scripts/configure-tat.mjs', import.meta.url);
const module = await import(source).catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {};
  throw error;
});
const text = '#!/bin/sh\nexec /usr/local/lib/example/deploy --request {{release_request_b64url}}\n';
const spec = () => ({
  schema_version: 1, project: 'example', environment: 'staging', version: '0.1.0',
  target: { region: 'ap-example', instance_id: 'lhins-demo' },
  expectedCommand: { CommandName: 'example-staging-v0.1.0', Description: 'Reviewed staging entry',
    CommandType: 'SHELL', Content: text, Username: 'ubuntu', WorkingDirectory: '/home/ubuntu',
    Timeout: 3600, EnableParameter: true, DefaultParameters: { release_request_b64url: 'INVALID' } },
});
const remote = (changes = {}) => ({
  CommandId: 'cmd-example1', CommandName: 'example-staging-v0.1.0', Description: 'Reviewed staging entry',
  CommandType: 'SHELL', Content: Buffer.from(text).toString('base64'), Username: 'ubuntu',
  WorkingDirectory: '/home/ubuntu', Timeout: 3600, EnableParameter: true,
  DefaultParameters: '{"release_request_b64url":"INVALID"}', DefaultParameterConfs: [],
  CreatedBy: 'USER', Tags: [], Scenes: [], FormattedDescription: '',
  OutputCOSBucketUrl: '', OutputCOSKeyPrefix: '', CreatedTime: '2026-01-01T00:00:00Z',
  UpdatedTime: '2026-01-01T00:00:00Z', ...changes,
});
const response = commands => ({ TotalCount: commands.length, CommandSet: commands, RequestId: 'synthetic-request' });
function folder(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'configure-tat-'));
  fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function clientWith(replies) {
  const requests = [];
  return { requests, async DescribeCommands(request) {
    requests.push(['DescribeCommands', request]);
    const result = replies.shift();
    if (result instanceof Error) throw result;
    assert.ok(result, 'unexpected additional cloud request');
    return result;
  }, async CreateCommand(request) {
    requests.push(['CreateCommand', request]);
    return { CommandId: 'cmd-example1', RequestId: 'synthetic-create' };
  } };
}

test('default preview validates the spec without a client or cloud side effects', async () => {
  assert.equal(typeof module.configureTat, 'function', 'configureTat is implemented');
  const result = await module.configureTat({ spec: spec() });
  assert.equal(result.status, 'planned');
  assert.equal(result.command_sha256, createHash('sha256').update(text).digest('hex'));
  assert.equal(result.command_id, undefined);
  assert.equal(result.target_verified, false);
});

test('expected artifact hashes flow into the binding without claiming a verified host', async t => {
  const input = spec();
  input.expected_artifacts = { program_sha256: 'a'.repeat(64), compose_sha256: 'b'.repeat(64), policy_sha256: 'c'.repeat(64) };
  input.expectedCommand.Content = `#!/bin/sh\ncontroller_sha256='${'a'.repeat(64)}'\npolicy_sha256='${'c'.repeat(64)}'\nexit 0\n`;
  const actual = remote({ Content: Buffer.from(input.expectedCommand.Content).toString('base64') });
  const result = await module.configureTat({ spec: input, apply: true,
    client: clientWith([response([actual])]), output: path.join(folder(t), 'binding.json') });
  assert.equal(result.program_sha256, 'a'.repeat(64));
  assert.equal(result.compose_sha256, 'b'.repeat(64));
  assert.equal(result.policy_sha256, 'c'.repeat(64));
  assert.equal(result.artifacts_status, 'expected_not_host_verified');
  assert.equal(result.configuration_only, true);
  assert.equal(result.target_verified, false);
  assert.equal(result.deployment_ready, false);
});

test('missing artifacts are explicitly not a deployable binding; malformed or unbound artifacts fail offline', async () => {
  const result = await module.configureTat({ spec: spec() });
  assert.equal(result.deployment_ready, false);
  assert.equal(result.artifacts_status, 'not_supplied');
  for (const artifacts of [null, {}, { program_sha256: 'a'.repeat(64), compose_sha256: 'b'.repeat(64), policy_sha256: 'bad' },
    { program_sha256: 'a'.repeat(64), compose_sha256: 'b'.repeat(64), policy_sha256: 'c'.repeat(64), unknown: 'x' },
    { program_sha256: 'a'.repeat(64), compose_sha256: 'b'.repeat(64), policy_sha256: 'c'.repeat(64) }]) {
    await assert.rejects(module.configureTat({ spec: { ...spec(), expected_artifacts: artifacts } }));
  }
});

test('project names accepted by the bundle through 63 characters remain configurable', async () => {
  const input = spec(); input.project = 'p'.repeat(63);
  assert.equal((await module.configureTat({ spec: input })).project, input.project);
  input.project += 'p';
  await assert.rejects(module.configureTat({ spec: input }));
});

test('matching existing name is reused without mutation and produces a private binding', async t => {
  const output = path.join(folder(t), 'binding.json');
  const client = clientWith([response([remote()])]);
  const result = await module.configureTat({ spec: spec(), apply: true, client, output });
  assert.deepEqual(client.requests, [['DescribeCommands', {
    Filters: [{ Name: 'command-name', Values: ['example-staging-v0.1.0'] }], Limit: 100, Offset: 0,
  }]]);
  assert.equal(result.status, 'verified');
  assert.equal(result.command_id, 'cmd-example1');
  assert.equal(result.schema, 'cnb-tat-binding/v1');
  assert.equal(result.username, 'ubuntu');
  assert.equal(result.timeout, 3600);
  assert.equal(result.target_verified, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(output)), result);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
});

test('new version sends exact Base64/API metadata then verifies ID and unique name', async t => {
  const input = spec();
  input.version = '0.2.0';
  input.expectedCommand.CommandName = 'example-staging-v0.2.0';
  const actual = remote({ CommandName: 'example-staging-v0.2.0' });
  const client = clientWith([response([]), response([actual]), response([actual])]);
  const result = await module.configureTat({ spec: input, apply: true, client,
    output: path.join(folder(t), 'binding.json') });
  assert.equal(result.command_id, 'cmd-example1');
  assert.deepEqual(client.requests[1], ['CreateCommand', {
    CommandName: 'example-staging-v0.2.0', Description: 'Reviewed staging entry', CommandType: 'SHELL',
    Content: Buffer.from(text).toString('base64'), Username: 'ubuntu', WorkingDirectory: '/home/ubuntu',
    Timeout: 3600, EnableParameter: true, DefaultParameters: '{"release_request_b64url":"INVALID"}',
  }]);
  assert.deepEqual(client.requests[2], ['DescribeCommands', { CommandIds: ['cmd-example1'], Limit: 100, Offset: 0 }]);
  assert.equal(client.requests[3][1].Filters[0].Values[0], 'example-staging-v0.2.0');
});

test('disabled template parameters are explicitly supported without DefaultParameters API input', async t => {
  const input = spec();
  Object.assign(input.expectedCommand, { Content: '#!/bin/sh\nexec /opt/example/readiness\n',
    EnableParameter: false, DefaultParameters: {}, Username: 'root', WorkingDirectory: '/' });
  const actual = remote({ ...input.expectedCommand,
    Content: Buffer.from(input.expectedCommand.Content).toString('base64'), DefaultParameters: '' });
  const client = clientWith([response([]), response([actual]), response([actual])]);
  await module.configureTat({ spec: input, apply: true, client, output: path.join(folder(t), 'binding.json') });
  assert.equal(client.requests[1][1].EnableParameter, false);
  assert.equal(Object.hasOwn(client.requests[1][1], 'DefaultParameters'), false);
});

test('same-name content or metadata drift and nonempty logging/parameter settings stop before create', async t => {
  for (const change of [ { Content: Buffer.from('changed').toString('base64') }, { Timeout: 60 },
    { Description: 'different' }, { Username: 'root' }, { WorkingDirectory: '/' },
    { DefaultParameters: '{"release_request_b64url":"OTHER"}' },
    { DefaultParameters: '{"release_request_b64url": "INVALID"}' }, { CreatedBy: 'TAT' },
    { OutputCOSBucketUrl: 'https://unexpected.example' }, { Tags: [{ Key: 'other', Value: 'value' }] },
    { DefaultParameterConfs: [{ ParameterName: 'extra' }] } ]) {
    const client = clientWith([response([remote(change)])]);
    await assert.rejects(module.configureTat({ spec: spec(), apply: true, client,
      output: path.join(folder(t), 'binding.json') }), { message: 'TAT_COMMAND_DRIFT' });
    assert.equal(client.requests.length, 1);
  }
});

test('ambiguous, truncated, or wrong-name query results never choose a command or create', async t => {
  for (const answer of [response([remote(), remote({ CommandId: 'cmd-example2' })]),
    { ...response([remote()]), TotalCount: 101 }, { ...response([]), TotalCount: 1 },
    response([remote({ CommandName: 'unrelated-v0.1.0' })])]) {
    const client = clientWith([answer]);
    await assert.rejects(module.configureTat({ spec: spec(), apply: true, client,
      output: path.join(folder(t), 'binding.json') }));
    assert.equal(client.requests.length, 1);
  }
});

test('uncertain create is not retried; next run resumes by exact query', async t => {
  const output = path.join(folder(t), 'binding.json');
  const client = clientWith([response([])]);
  client.CreateCommand = async request => {
    client.requests.push(['CreateCommand', request]);
    throw new Error('synthetic secret must never be returned');
  };
  await assert.rejects(module.configureTat({ spec: spec(), apply: true, client, output }), { message: 'TAT_CREATE_UNCERTAIN' });
  assert.equal(client.requests.length, 2);
  assert.equal(fs.existsSync(output), false);
  const retry = clientWith([response([remote()])]);
  assert.equal((await module.configureTat({ spec: spec(), apply: true, client: retry, output })).status, 'verified');
  assert.equal(retry.requests.length, 1);
});

test('failed or drifting create readback produces no binding and performs no cleanup mutation', async t => {
  for (const answer of [response([]), response([remote({ Timeout: 3 })]), new Error('private transport detail')]) {
    const output = path.join(folder(t), 'binding.json');
    const client = clientWith([response([]), answer]);
    await assert.rejects(module.configureTat({ spec: spec(), apply: true, client, output }));
    assert.equal(fs.existsSync(output), false);
    assert.equal(client.requests.length, 3);
  }
});

test('existing output and symlink are refused before any remote side effect', async t => {
  const dir = folder(t), output = path.join(dir, 'binding.json');
  fs.writeFileSync(output, 'keep', { mode: 0o600 });
  const client = clientWith([]);
  await assert.rejects(module.configureTat({ spec: spec(), apply: true, client, output }), { message: 'TAT_OUTPUT_EXISTS' });
  assert.equal(fs.readFileSync(output, 'utf8'), 'keep');
  fs.symlinkSync(output, path.join(dir, 'link.json'));
  await assert.rejects(module.configureTat({ spec: spec(), apply: true, client, output: path.join(dir, 'link.json') }));
  assert.equal(client.requests.length, 0);
});

test('private child of the root-owned sticky system temp directory is usable', async t => {
  const parent = fs.realpathSync('/tmp'), info = fs.statSync(parent);
  if (info.uid !== 0 || !(info.mode & 0o1000)) return t.skip('system temp has no root-owned sticky ancestor');
  const dir = fs.mkdtempSync(path.join(parent, 'configure-tat-sticky-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.chmodSync(dir, 0o700);
  const output = path.join(dir, 'binding.json');
  await module.configureTat({ spec: spec(), apply: true, client: clientWith([response([remote()])]), output });
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  fs.chmodSync(dir, 0o777);
  await assert.rejects(module.configureTat({ spec: spec(), output: path.join(dir, 'unsafe.json') }), { message: 'TAT_PATH_UNSAFE' });
});

test('an output created during readback is not replaced', async t => {
  const output = path.join(folder(t), 'binding.json');
  const client = { async DescribeCommands() {
    fs.writeFileSync(output, 'concurrent owner', { flag: 'wx', mode: 0o600 });
    return response([remote()]);
  } };
  await assert.rejects(module.configureTat({ spec: spec(), apply: true, client, output }));
  assert.equal(fs.readFileSync(output, 'utf8'), 'concurrent owner');
});

test('invalid version, template defaults, paths, target, and unknown fields are rejected offline', async () => {
  for (const edit of [s => s.version = '0.2.0', s => s.unexpected = true,
    s => s.target.endpoint = 'https://other.example', s => s.target.instance_id = '*',
    s => s.expectedCommand.Timeout = 0, s => s.expectedCommand.WorkingDirectory = '/home/../root',
    s => s.expectedCommand.DefaultParameters.release_request_b64url = 'live-request',
    s => s.expectedCommand.Content += '\0', s => s.expectedCommand.Username = 'root;id']) {
    const input = spec(); edit(input);
    await assert.rejects(module.configureTat({ spec: input }));
  }
});
