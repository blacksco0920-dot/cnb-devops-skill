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
    Timeout: 3600, EnableParameter: true, DefaultParameters: { release_request_b64url: 'INVALID' }, DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }] },
});
const remote = (changes = {}) => ({
  CommandId: 'cmd-example1', CommandName: 'example-staging-v0.1.0', Description: 'Reviewed staging entry',
  CommandType: 'SHELL', Content: Buffer.from(text).toString('base64'), Username: 'ubuntu',
  WorkingDirectory: '/home/ubuntu', Timeout: 3600, EnableParameter: true,
  DefaultParameters: '{"release_request_b64url":"INVALID"}', DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }],
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
  return { requests, region: 'ap-example',
    async DescribeInstances(request) { return { TotalCount: 1, InstanceSet: [{ InstanceId: request.InstanceIds[0], InstanceState: 'RUNNING' }], RequestId: 'instance-query' }; },
    async DescribeAutomationAgentStatus(request) { return { TotalCount: 1, AutomationAgentSet: [{ InstanceId: request.InstanceIds[0], AgentStatus: 'Online', Environment: 'Linux' }], RequestId: 'agent-query' }; },
    async DescribeCommands(request) {
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
  assert.equal(result.target_verified, true);
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
  assert.equal(result.target_verified, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(output)), result);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
});

test('parameter readback permits only the declared name, INVALID value and empty description', async t => {
  const expected = [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }];
  for (const confs of [[], null, undefined, [...expected, ...expected],
    [{ ...expected[0], ParameterName: 'extra' }], [{ ...expected[0], ParameterValue: 'live-request' }],
    [{ ...expected[0], ParameterDescription: 'changed' }], [{ ...expected[0], Unknown: '' }]]) {
    const client = clientWith([response([remote({ DefaultParameterConfs: confs })])]);
    await assert.rejects(module.configureTat({ spec: spec(), apply: true, client,
      output: path.join(folder(t), 'binding.json') }), { message: 'TAT_COMMAND_DRIFT' });
    assert.equal(client.requests.length, 1);
    const input = spec(); input.expectedCommand.DefaultParameterConfs = confs;
    await assert.rejects(module.configureTat({ spec: input }), { message: 'TAT_SPEC_INVALID' });
  }
});

test('API conf-only defaults are verified after create and on reuse with the same binding metadata', async t => {
  const actual = remote({ DefaultParameters: '' });
  const created = await module.configureTat({ spec: spec(), apply: true,
    client: clientWith([response([]), response([actual]), response([actual])]),
    output: path.join(folder(t), 'binding.json') });
  const reusedClient = clientWith([response([actual])]);
  const reused = await module.configureTat({ spec: spec(), apply: true, client: reusedClient,
    output: path.join(folder(t), 'binding.json') });
  assert.equal(created.status, 'verified');
  assert.deepEqual(reused, created);
  assert.deepEqual(reused.metadata.DefaultParameters, { release_request_b64url: 'INVALID' });
  const preview = await module.configureTat({ spec: spec() });
  assert.deepEqual(reused.metadata, preview.metadata);
  assert.equal(reused.command_metadata_sha256, preview.command_metadata_sha256);
  assert.equal(reusedClient.requests.length, 1);
});

test('empty legacy defaults cannot hide missing, duplicate, extra or changed confs', async t => {
  const expected = { ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' };
  for (const confs of [undefined, null, [], [expected, expected], [expected, { ...expected, ParameterName: 'extra' }],
    [{ ...expected, ParameterValue: 'live-request' }], [{ ...expected, ParameterDescription: 'changed' }],
    [{ ...expected, Unknown: '' }]]) {
    const output = path.join(folder(t), 'binding.json');
    await assert.rejects(module.configureTat({ spec: spec(), apply: true,
      client: clientWith([response([remote({ DefaultParameters: '', DefaultParameterConfs: confs })])]), output }),
    { message: 'TAT_COMMAND_DRIFT' });
    assert.equal(fs.existsSync(output), false);
  }
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
  assert.equal(result.target_verified, true);
  assert.deepEqual(client.requests[1], ['CreateCommand', {
    CommandName: 'example-staging-v0.2.0', Description: 'Reviewed staging entry', CommandType: 'SHELL',
    Content: Buffer.from(text).toString('base64'), Username: 'ubuntu', WorkingDirectory: '/home/ubuntu',
    Timeout: 3600, EnableParameter: true, DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }],
  }]);
  assert.deepEqual(client.requests[2], ['DescribeCommands', { CommandIds: ['cmd-example1'], Limit: 100, Offset: 0 }]);
  assert.equal(client.requests[3][1].Filters[0].Values[0], 'example-staging-v0.2.0');
});

test('disabled template parameters are explicitly supported without DefaultParameters API input', async t => {
  const input = spec();
  Object.assign(input.expectedCommand, { Content: '#!/bin/sh\nexec /opt/example/readiness\n',
    EnableParameter: false, DefaultParameters: {}, DefaultParameterConfs: [], Username: 'root', WorkingDirectory: '/' });
  const actual = remote({ ...input.expectedCommand,
    Content: Buffer.from(input.expectedCommand.Content).toString('base64'), DefaultParameters: '' });
  const client = clientWith([response([]), response([actual]), response([actual])]);
  await module.configureTat({ spec: input, apply: true, client, output: path.join(folder(t), 'binding.json') });
  assert.equal(client.requests[1][1].EnableParameter, false);
  assert.equal(Object.hasOwn(client.requests[1][1], 'DefaultParameters'), false);
  assert.equal(Object.hasOwn(client.requests[1][1], 'DefaultParameterConfs'), false);
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
  const client = { ...clientWith([]), async DescribeCommands() {
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

function targetClients(input, { instanceState = 'RUNNING', agentStatus = 'Online', instanceId = input.target.instance_id,
  agentId = input.target.instance_id, count = 1, region = input.target.region, environment = 'Linux' } = {}) {
  const client = clientWith([response([remote()])]);
  client.region = input.target.region;
  client.DescribeAutomationAgentStatus = async request => {
    assert.deepEqual(request, { InstanceIds: [input.target.instance_id], Limit: 1, Offset: 0 });
    return { TotalCount: 1, AutomationAgentSet: [{ InstanceId: agentId, AgentStatus: agentStatus,
      Environment: environment, Version: '1.0', LastHeartbeatTime: '2026-01-01T00:00:00Z' }], RequestId: 'agent-query' };
  };
  const instanceClient = { region, async DescribeInstances(request) {
    assert.deepEqual(request, { InstanceIds: [input.target.instance_id], Limit: 1, Offset: 0 });
    return { TotalCount: count, InstanceSet: count ? [{ InstanceId: instanceId, InstanceState: instanceState }] : [], RequestId: 'instance-query' };
  } };
  return { client, instanceClient };
}

test('apply verifies the exact running CVM or Lighthouse target and online Linux agent without attesting host artifacts', async t => {
  for (const [instance_id, service] of [['ins-demo', 'cvm'], ['lhins-demo', 'lighthouse']]) {
    const input = spec(); input.target.instance_id = instance_id;
    const output = path.join(folder(t), 'binding.json');
    const result = await module.configureTat({ spec: input, apply: true, output, ...targetClients(input) });
    assert.equal(result.target_verified, true);
    assert.deepEqual(result.target_status, { scope: 'cloud_instance_and_agent', service,
      region: 'ap-example', instance_id, instance_state: 'RUNNING', agent_status: 'Online',
      instance_request_id: 'instance-query', agent_request_id: 'agent-query' });
    assert.equal(result.configuration_only, true);
    assert.equal(result.deployment_ready, false);
    assert.deepEqual(JSON.parse(fs.readFileSync(output)), result);
  }
});

test('missing, mismatched, stopped or offline targets never publish a successful binding', async t => {
  for (const [change, code] of [[{ count: 0 }, 'TAT_TARGET_NOT_FOUND'], [{ count: 2 }, 'TAT_TARGET_RESPONSE_INVALID'],
    [{ instanceId: 'lhins-other' }, 'TAT_TARGET_RESPONSE_INVALID'], [{ instanceState: 'STOPPED' }, 'TAT_TARGET_NOT_RUNNING'],
    [{ agentId: 'lhins-other' }, 'TAT_AGENT_RESPONSE_INVALID'], [{ agentStatus: 'Offline' }, 'TAT_AGENT_NOT_ONLINE'],
    [{ environment: 'Windows' }, 'TAT_AGENT_ENVIRONMENT_MISMATCH'], [{ region: 'ap-other' }, 'TAT_TARGET_REGION_MISMATCH']]) {
    const input = spec(), output = path.join(folder(t), 'binding.json');
    await assert.rejects(module.configureTat({ spec: input, apply: true, output, ...targetClients(input, change) }), { message: code });
    assert.equal(fs.existsSync(output), false);
  }
});

test('an offline new target fails before creating its saved command', async t => {
  const input = spec(), output = path.join(folder(t), 'binding.json');
  const client = clientWith([response([]), response([remote()]), response([remote()])]);
  client.DescribeAutomationAgentStatus = async () => ({TotalCount: 1, RequestId: 'agent-query',
    AutomationAgentSet: [{InstanceId: input.target.instance_id, AgentStatus: 'Offline', Environment: 'Linux'}]});
  await assert.rejects(module.configureTat({spec: input, apply: true, output, client}), /TAT_AGENT_NOT_ONLINE/);
  assert.equal(client.requests.some(([action]) => action === 'CreateCommand'), false);
});

test('readiness query errors expose fixed codes and leave the existing command reusable', async t => {
  for (const [side, action, code] of [['instanceClient', 'DescribeInstances', 'TAT_TARGET_QUERY_FAILED'],
    ['client', 'DescribeAutomationAgentStatus', 'TAT_AGENT_QUERY_FAILED']]) {
    const input = spec(), output = path.join(folder(t), 'binding.json'), clients = targetClients(input);
    clients[side][action] = async () => { throw new Error('synthetic-private-transport'); };
    await assert.rejects(module.configureTat({ spec: input, apply: true, output, ...clients }), { message: code });
    assert.equal(fs.existsSync(output), false);
    assert.equal(clients.client.requests.some(([action]) => action !== 'DescribeCommands'), false);
  }
});
