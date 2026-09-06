import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/configure-tat.mjs', import.meta.url));
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'configure-tat-cli-'));
  fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  const spec = { schema_version: 1, project: 'example', environment: 'staging', version: '0.1.0',
    target: { region: 'ap-example', instance_id: 'lhins-demo' },
    expectedCommand: { CommandName: 'example-staging-v0.1.0', Description: '', CommandType: 'SHELL',
      Content: '#!/bin/sh\nexit 0\n', Username: 'ubuntu', WorkingDirectory: '/home/ubuntu',
      Timeout: 3600, EnableParameter: true, DefaultParameters: { release_request_b64url: 'INVALID' }, DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }] } };
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(spec), { mode: 0o600 });
  return { dir, spec, run(args = [], env = {}) {
    return spawnSync(process.execPath, [script, '--spec', path.join(dir, 'spec.json'), ...args], {
      encoding: 'utf8', env: { PATH: process.env.PATH, ...env },
    });
  } };
}
function sdkFixture(dir, spec, version = '4.1.241') {
  const sdkRoot = path.join(dir, 'dependencies'), name = 'tencentcloud-sdk-nodejs-tat';
  const installed = path.join(sdkRoot, 'node_modules', name);
  fs.mkdirSync(installed, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(sdkRoot, 'package.json'), JSON.stringify({ dependencies: { [name]: version } }));
  fs.writeFileSync(path.join(sdkRoot, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3,
    packages: { [`node_modules/${name}`]: { version } } }));
  fs.writeFileSync(path.join(installed, 'package.json'), JSON.stringify({ name, version, main: 'index.js' }));
  const command = { ...spec.expectedCommand, CommandId: 'cmd-example1', CreatedBy: 'USER',
    Content: Buffer.from(spec.expectedCommand.Content).toString('base64'),
    DefaultParameters: '{"release_request_b64url":"INVALID"}', DefaultParameterConfs: [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }],
    Tags: [], Scenes: [], OutputCOSBucketUrl: '', OutputCOSKeyPrefix: '' };
  fs.writeFileSync(path.join(installed, 'index.js'), `
const fs = require('node:fs');
module.exports = { tat: { v20201028: { Client: class {
  constructor(config) {
    fs.writeFileSync(${JSON.stringify(path.join(dir, 'client.json'))}, JSON.stringify({
      region: config.region, profile: config.profile,
      credentialMatches: config.credential.secretId === 'synthetic-id' && config.credential.secretKey === 'synthetic-private-key'
    }));
  }
  async DescribeCommands(request) {
    fs.writeFileSync(${JSON.stringify(path.join(dir, 'request.json'))}, JSON.stringify(request));
    return ${JSON.stringify({ TotalCount: 1, CommandSet: [command], RequestId: 'synthetic' })};
  }
} } } };
`);
  return sdkRoot;
}

test('CLI preview needs no installed SDK or credentials and no output file', t => {
  const f = fixture(t);
  const result = f.run(['--credentials', path.join(f.dir, 'missing-secret'), '--sdk-root', path.join(f.dir, 'missing-sdk')]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, 'planned');
  assert.deepEqual(fs.readdirSync(f.dir), ['spec.json']);
});

test('CLI apply resolves pinned bundle SDK and uses fixed endpoint without exposing credentials', t => {
  const f = fixture(t), sdk = sdkFixture(f.dir, f.spec);
  const credentials = path.join(f.dir, 'credential.json'), output = path.join(f.dir, 'binding.json');
  fs.writeFileSync(credentials, JSON.stringify({ secretId: 'synthetic-id', secretKey: 'synthetic-private-key' }), { mode: 0o600 });
  const result = f.run(['--apply', '--sdk-root', sdk, '--credentials', credentials, '--output', output]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).command_id, 'cmd-example1');
  assert.equal(result.stdout.includes('synthetic-private-key'), false);
  assert.equal(fs.readFileSync(output, 'utf8').includes('synthetic-private-key'), false);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.dir, 'client.json'))), {
    region: 'ap-example', credentialMatches: true, profile: { signMethod: 'TC3-HMAC-SHA256',
      httpProfile: { endpoint: 'tat.tencentcloudapi.com', protocol: 'https://', reqMethod: 'POST', reqTimeout: 30 } },
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.dir, 'request.json'))), {
    Filters: [{ Name: 'command-name', Values: ['example-staging-v0.1.0'] }], Limit: 100, Offset: 0,
  });
});

test('unsafe credential file fails before client creation and reveals only a fixed code', t => {
  const f = fixture(t), sdk = sdkFixture(f.dir, f.spec), credentials = path.join(f.dir, 'credential.json');
  fs.writeFileSync(credentials, '{"secretId":"synthetic-id","secretKey":"synthetic-private-key"}', { mode: 0o644 });
  const result = f.run(['--apply', '--sdk-root', sdk, '--credentials', credentials, '--output', path.join(f.dir, 'binding.json')]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'TAT_INPUT_UNSAFE\n');
  assert.equal(fs.existsSync(path.join(f.dir, 'client.json')), false);
});

test('SDK version drift is refused before reading even a missing credential file', t => {
  const f = fixture(t), sdk = sdkFixture(f.dir, f.spec, '4.1.240');
  const result = f.run(['--apply', '--sdk-root', sdk, '--credentials', path.join(f.dir, 'missing-secret'),
    '--output', path.join(f.dir, 'binding.json')]);
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'TAT_SDK_VERSION_MISMATCH\n');
  assert.equal(fs.existsSync(path.join(f.dir, 'client.json')), false);
});

test('debug environments and unknown CLI flags are rejected with no credential output', t => {
  const f = fixture(t);
  const debug = f.run(['--apply', '--output', path.join(f.dir, 'binding.json')], { NODE_DEBUG: 'http' });
  assert.equal(debug.status, 1);
  assert.equal(debug.stderr, 'TAT_DEBUG_ENV_REFUSED\n');
  const unknown = f.run(['--secret-key', 'synthetic-private-key']);
  assert.equal(unknown.status, 1);
  assert.equal(unknown.stdout, '');
  assert.equal(unknown.stderr, 'TAT_ARGUMENTS_INVALID\n');
});
