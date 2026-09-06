import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configureTat } from '../scripts/configure-tat.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('actual generated spec, exact mock query, and generated CI binding validation agree', async t => {
  const project = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'tat-bundle-integration-'));
  fs.chmodSync(project, 0o700);
  t.after(() => fs.rmSync(project, { recursive: true, force: true }));
  fs.writeFileSync(path.join(project, 'Dockerfile'), 'FROM scratch\n');
  fs.copyFileSync(path.join(root, 'assets/cnb-tcr-tat/project.example.yml'), path.join(project, 'input.yml'));
  const generated = spawnSync(process.env.CNB_BUNDLE_TEST_PYTHON || 'python3', [path.join(root, 'scripts/prepare-project.py'),
    '--project-root', project, '--config', path.join(project, 'input.yml'), '--apply'], { encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const vendor = path.join(project, 'deploy/vendor/cnb-devops');
  const spec = JSON.parse(fs.readFileSync(path.join(vendor, 'tat-spec.template.json')));
  assert.deepEqual(spec.target, { region: null, instance_id: null });
  await assert.rejects(configureTat({ spec }), { message: 'TAT_SPEC_INVALID' });
  const expected = {
    program_sha256: sha(fs.readFileSync(path.join(vendor, 'host/tat-deploy-test.py'))),
    compose_sha256: sha(fs.readFileSync(path.join(vendor, 'docker-compose.yml'))),
    policy_sha256: sha(fs.readFileSync(path.join(vendor, 'host-policy.json'))),
  };
  assert.deepEqual(spec.expected_artifacts, expected);
  assert.equal(JSON.parse(fs.readFileSync(path.join(vendor, 'host-policy.json'))).compose_sha256, expected.compose_sha256);
  assert.equal(spec.expectedCommand.Content, fs.readFileSync(path.join(vendor, 'tat-command.sh'), 'utf8'));
  // Shape-valid, visibly synthetic IDs constructed only in the test; no cloud target.
  spec.target = { region: 'ap-example', instance_id: `lhins-${'d'.repeat(8)}` };
  assert.equal((await configureTat({ spec })).status, 'planned');
  const requests = [];
  const commandId = `cmd-${'c'.repeat(8)}`;
  const client = { async DescribeCommands(request) {
    requests.push(request);
    return { TotalCount: 1, CommandSet: [{ ...spec.expectedCommand,
      CommandId: commandId, CreatedBy: 'USER',
      Content: Buffer.from(spec.expectedCommand.Content).toString('base64'),
      DefaultParameters: '{"release_request_b64url":"INVALID"}',
      DefaultParameterConfs: [], Tags: [], Scenes: [], OutputCOSBucketUrl: '', OutputCOSKeyPrefix: '' }],
    RequestId: 'synthetic-query-only' };
  } };
  const binding = await configureTat({ spec, apply: true, client, output: path.join(project, 'binding.json') });
  assert.deepEqual(requests, [{ Filters: [{ Name: 'command-name', Values: [spec.expectedCommand.CommandName] }], Limit: 100, Offset: 0 }]);
  for (const [field, value] of Object.entries(expected)) assert.equal(binding[field], value);
  const ci = await import(pathToFileURL(path.join(vendor, 'ci/run-tat-release.mjs')));
  const config = JSON.parse(fs.readFileSync(path.join(vendor, 'ci-config.json')));
  assert.equal(ci.validateBinding(binding, config).command_id, commandId);
  const incomplete = { ...binding }; delete incomplete.program_sha256;
  assert.throws(() => ci.validateBinding(incomplete, config));
  assert.equal(binding.target_verified, false);
  assert.equal(binding.deployment_ready, false);
});
