import assert from 'node:assert/strict';
import test from 'node:test';
import { createTatClientOptions, createTatClientFromEnvironment } from '../assets/cnb-tcr-tat/ci/run-tat-release.mjs';

const credentials = {secretId: 'AK' + 'IDexample', secretKey: 'example-key', region: 'ap-guangzhou'};
test('temporary credential token reaches the signed SDK request configuration', () => {
  assert.deepEqual(createTatClientOptions({...credentials, token: 'temporary-token'}).credential,
    {secretId: credentials.secretId, secretKey: credentials.secretKey, token: 'temporary-token'});
  assert.deepEqual(createTatClientOptions(credentials).credential,
    {secretId: credentials.secretId, secretKey: credentials.secretKey});
  for (const token of ['', 'bad\ntoken', null]) {
    assert.throws(() => createTatClientOptions({...credentials, token}), /credentials/);
  }
});

test('environment adapter consumes the complete temporary credential triple and rejects conflicting aliases', () => {
  const names = ['TENCENTCLOUD_SECRET_ID','TENCENTCLOUD_SECRET_KEY','TENCENTCLOUD_TOKEN','TENCENTCLOUD_SECURITY_TOKEN'];
  const old = Object.fromEntries(names.map(name => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    Object.assign(process.env, {TENCENTCLOUD_SECRET_ID: credentials.secretId, TENCENTCLOUD_SECRET_KEY: credentials.secretKey,
      TENCENTCLOUD_TOKEN: 'first-token', TENCENTCLOUD_SECURITY_TOKEN: 'other-token'});
    assert.throws(() => createTatClientFromEnvironment(credentials.region), /credentials/);
    for (const name of names) assert.equal(process.env[name], undefined);
  } finally {
    for (const name of names) {if (old[name] === undefined) delete process.env[name]; else process.env[name] = old[name];}
  }
});
