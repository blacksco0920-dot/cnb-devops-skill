import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

let api;
try { api = await import('../scripts/configure-cnb.mjs'); } catch (error) {
  if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}
test('the executable exposes a reusable initialization operation', () => {
  assert.equal(typeof api?.configureCnb, 'function');
});

const settings = { auto_trigger: false, auto_trigger_by_npc: true, cron_auto_trigger: true, forked_repo_auto_trigger: false };
const spec = () => ({ schema_version: 1, repositories: [
  { slug: 'team/app', visibility: 'private', build_settings: { auto_trigger: true, cron_auto_trigger: false } },
  { slug: 'team/secrets', visibility: 'secret' },
] });
const repo = (path, visibility) => ({ id: `id:${path}`, path, visibility_level: visibility, access: 'Master', freeze: false });

// A stateful external boundary: the production reconciler still performs planning,
// schema mapping, all reads/writes, persistence and readback comparisons.
function service(initial = {}) {
  const repos = new Map(Object.entries(initial));
  const builds = new Map([...repos.keys()].map(k => [k, { ...settings }]));
  const writes = [];
  return { repos, builds, writes,
    async getGroup(slug) { return { path: slug, access_role: 'Owner', freeze: false }; },
    async getRepo(slug) { return repos.get(slug) ?? null; },
    async listGroupRepos(group, page) {
      return [...repos.values()].filter(item => item.path.slice(0, item.path.lastIndexOf('/')) === group).slice((page - 1) * 100, page * 100);
    },
    async createRepo(group, body) {
      assert.deepEqual(Object.keys(body).sort(), ['name', 'visibility']);
      const slug = `${group}/${body.name}`;
      if (repos.has(slug)) throw new Error('duplicate creation');
      writes.push(['create', slug, body.visibility]);
      repos.set(slug, repo(slug, body.visibility === 'private' ? 'Private' : 'Secret'));
      builds.set(slug, { ...settings });
    },
    async getBuildSettings(slug) { return structuredClone(builds.get(slug)); },
    async putBuildSettings(slug, body) { writes.push(['settings', slug, body]); builds.set(slug, structuredClone(body)); },
  };
}
async function fixture(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'configure-cnb-test-'));
  await chmod(dir, 0o700);
  try { await fn(dir, new api.FileJournal(join(dir, 'state.json'))); }
  finally { await rm(dir, { recursive: true, force: true }); }
}

test('preview lists concrete creates and changes without mutation or a state file', { skip: !api }, async () => fixture(async (dir, journal) => {
  const client = service({ 'team/app': repo('team/app', 'Private') });
  const result = await api.configureCnb({ spec: spec(), client, journal });
  assert.equal(result.status, 'preview');
  assert.deepEqual(result.plan.map(x => x.action), ['update_build_settings', 'create_repository']);
  assert.deepEqual(result.plan[0].changes, { auto_trigger: { from: false, to: true }, cron_auto_trigger: { from: true, to: false } });
  assert.deepEqual(client.writes, []);
  await assert.rejects(readFile(join(dir, 'state.json')), { code: 'ENOENT' });
}));

test('apply creates exact private/secret types, preserves unrequested flags and reuses on rerun', { skip: !api }, async () => fixture(async (dir, journal) => {
  const client = service();
  const first = await api.configureCnb({ spec: spec(), client, journal, apply: true });
  assert.equal(first.status, 'applied');
  assert.deepEqual(client.writes, [
    ['create', 'team/app', 'private'],
    ['settings', 'team/app', { ...settings, auto_trigger: true, cron_auto_trigger: false }],
    ['create', 'team/secrets', 'secret'],
  ]);
  assert.ok(first.manual_actions[0].url.startsWith('https://cnb.cool/team/secrets'));
  const second = await api.configureCnb({ spec: spec(), client, journal, apply: true });
  assert.equal(second.status, 'unchanged');
  assert.equal(client.writes.length, 3);
  assert.equal(JSON.parse(await readFile(join(dir, 'state.json'))).creates['team/secrets'].status, 'verified');
}));

test('all requested repository identities are checked before any mutation', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service({ 'team/secrets': repo('team/secrets', 'Private') });
  await assert.rejects(api.configureCnb({ spec: spec(), client, journal, apply: true }), { code: 'REPOSITORY_TYPE_MISMATCH' });
  assert.equal(client.writes.length, 0);
}));

test('Secret metadata uses complete public group pagination and explicit parent authority', { skip: !api }, async () => fixture(async (_, journal) => {
  const pages = [], rows = Array.from({ length: 100 }, (_, index) => ({ ...repo(`team/repo-${index}`, 'Private'), id: String(index) }));
  rows.push({ ...repo('team/secrets', 'Secret'), id: 'secret-id', access: 'Unknown' });
  const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => {
    if (args[0] === '--version') return { stdout: '1.15.18' };
    if (args[1] === 'get-group') return { stdout: JSON.stringify({ status: 200, data: { path: 'team', access_role: 'Owner' } }) };
    if (args[1] === 'get-group-sub-repos') {
      assert.equal(args[args.indexOf('--slug') + 1], 'team');
      assert.equal(args[args.indexOf('--descendant') + 1], 'sub');
      assert.equal(args[args.indexOf('--page-size') + 1], '100');
      assert.equal(args[args.indexOf('--order-by') + 1], 'slug_path');
      assert.ok(!args.includes('--filter-type') && !args.includes('--search') && !args.includes('--status'));
      const page = Number(args[args.indexOf('--page') + 1]); pages.push(page);
      return { stdout: JSON.stringify({ status: 200, data: rows.slice((page - 1) * 100, page * 100) }) };
    }
    throw new Error('Secret single-repo GET or a write must not be used');
  } });
  const result = await api.configureCnb({ spec: { schema_version: 1, repositories: [spec().repositories[1]] }, client, journal, apply: true });
  assert.equal(result.status, 'unchanged');
  assert.deepEqual(pages, [1, 2]);
  assert.deepEqual(result.verified[0].permission_basis, { kind: 'parent_group', slug: 'team', role: 'Owner' });
}));

test('Secret creation readback and reentry never require the forbidden single-repo endpoint', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service();
  client.getRepo = async () => { throw new Error('Secret repos do not support token access.'); };
  const create = client.createRepo;
  client.createRepo = async (...args) => { await create(...args); client.repos.get('team/secrets').access = 'Unknown'; };
  const input = { schema_version: 1, repositories: [spec().repositories[1]] };
  assert.equal((await api.configureCnb({ spec: input, client, journal, apply: true })).status, 'applied');
  assert.equal((await api.configureCnb({ spec: input, client, journal, apply: true })).status, 'unchanged');
  assert.deepEqual(client.writes, [['create', 'team/secrets', 'secret']]);
  assert.equal((await journal.load()).creates['team/secrets'].status, 'verified');
}));

test('Secret listing rejects incomplete pages, wrong group identities and insufficient parent authority before writes', { skip: !api }, async () => {
  for (const failure of ['later-page', 'foreign-path', 'wrong-parent', 'denied-parent', 'duplicate-page']) await fixture(async (_, journal) => {
    const client = service({ 'team/secrets': { ...repo('team/secrets', 'Secret'), access: 'Unknown' } });
    if (failure === 'wrong-parent') client.getGroup = async () => ({ path: 'other', access_role: 'Owner' });
    else if (failure === 'denied-parent') client.getGroup = async () => ({ path: 'team', access_role: 'Developer' });
    else if (failure === 'foreign-path') client.listGroupRepos = async () => [repo('other/secrets', 'Secret')];
    else client.listGroupRepos = async (_, page) => {
      if (page > 1 && failure === 'later-page') throw new Error('later page denied');
      return Array.from({ length: 100 }, (_, index) => ({ ...repo(index ? `team/repo-${index}` : 'team/secrets', index ? 'Private' : 'Secret'), id: String(index), access: 'Unknown' }));
    };
    const code = failure === 'later-page' ? 'CNB_OPERATION_FAILED'
      : ['wrong-parent', 'denied-parent'].includes(failure) ? 'GROUP_PERMISSION_REQUIRED' : 'REPOSITORY_LIST_INVALID';
    await assert.rejects(api.configureCnb({ spec: { schema_version: 1, repositories: [spec().repositories[1]] }, client, journal, apply: true }), { code });
    assert.equal(client.writes.length, 0);
  });
});

test('a lost create response is persisted and cannot cause blind creation on reentry', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service(); let attempts = 0;
  client.createRepo = async () => { attempts++; throw new Error('Bearer do-not-output-secret body'); };
  await assert.rejects(api.configureCnb({ spec: spec(), client, journal, apply: true }), error => error.code === 'CREATE_RESULT_UNCERTAIN' && !error.message.includes('secret body'));
  await assert.rejects(api.configureCnb({ spec: spec(), client, journal, apply: true }), { code: 'CREATE_RECONCILIATION_REQUIRED' });
  assert.equal(attempts, 1);
  client.repos.set('team/app', repo('team/app', 'Private'));
  client.builds.set('team/app', { ...settings });
  client.createRepo = service().createRepo;
  const one = { schema_version: 1, repositories: [spec().repositories[0]] };
  assert.equal((await api.configureCnb({ spec: one, client, journal, apply: true })).status, 'applied');
  assert.equal(attempts, 1);
}));

test('confirmed CNB 400/403 rejection leaves no pending create and can resume after correction', { skip: !api }, async () => {
  for (const status of [400, 403]) for (const visibility of ['private', 'secret']) await fixture(async (_, journal) => {
    let denied = true, exists = false, posts = 0;
    const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => {
      if (args[0] === '--version') return { stdout: '1.15.18' };
      let response;
      if (args[1] === 'get-by-id') response = { status: exists ? 200 : 404, data: exists ? repo('team/app', 'Private') : { errcode: 404, errmsg: 'missing' } };
      else if (args[1] === 'get-group-sub-repos') response = { status: 200, data: exists ? [{ ...repo('team/app', 'Secret'), access: 'Unknown' }] : [] };
      else if (args[1] === 'get-group') response = { status: 200, data: { path: 'team', access_role: 'Owner' } };
      else if (args[1] === 'create-repo') {
        posts++;
        if (denied) response = { status, data: { errcode: status, errmsg: 'private response must not escape', errparam: {} } };
        else { exists = true; response = { status: 201, data: null }; }
      } else throw new Error('unexpected operation');
      return { stdout: JSON.stringify(response) };
    } });
    const input = { schema_version: 1, repositories: [{ slug: 'team/app', visibility }] };
    await assert.rejects(api.configureCnb({ spec: input, client, journal, apply: true }), error => error.code === `CNB_HTTP_${status}` && !error.message.includes('private response'));
    assert.equal((await journal.load()).creates['team/app'], undefined);
    assert.equal(posts, 1, 'no retry in the rejected operation');
    denied = false;
    assert.equal((await api.configureCnb({ spec: input, client, journal, apply: true })).status, 'applied');
    assert.equal((await journal.load()).creates['team/app'].status, 'verified');
    assert.equal(posts, 2);
    assert.equal((await api.configureCnb({ spec: input, client, journal, apply: true })).status, 'unchanged');
    assert.equal(posts, 2);
  });
});

test('timeout, 5xx and unknown 4xx bodies remain pending and never repeat POST', { skip: !api }, async () => {
  for (const failure of ['timeout', 'server', 'unknown-body', 'malformed-body', 'unconfirmed-absence']) for (const visibility of ['private', 'secret']) await fixture(async (_, journal) => {
    let posts = 0;
    const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => {
      if (args[0] === '--version') return { stdout: '1.15.18' };
      let response;
      if (args[1] === 'get-by-id') {
        if (failure === 'unconfirmed-absence' && posts) response = { status: 403, data: { errcode: 403, errmsg: 'cannot confirm' } };
        else response = { status: 404, data: { errcode: 404, errmsg: 'missing' } };
      } else if (args[1] === 'get-group-sub-repos') {
        response = failure === 'unconfirmed-absence' && posts ? { status: 403, data: { errcode: 403, errmsg: 'cannot confirm' } } : { status: 200, data: [] };
      } else if (args[1] === 'get-group') response = { status: 200, data: { path: 'team', access_role: 'Owner' } };
      else if (args[1] === 'create-repo') {
        posts++;
        if (failure === 'timeout') {
          try { await promisify(execFile)(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], { timeout: 30 }); }
          catch (error) { assert.equal(error.killed, true); throw error; }
          assert.fail('the controlled process must time out');
        }
        response = failure === 'server' ? { status: 503, data: { errcode: 503, errmsg: 'private service error' } }
          : failure === 'unknown-body' ? { status: 403, data: 'private gateway response' }
          : failure === 'malformed-body' ? { status: 400, data: { errcode: 'unknown', errmsg: 'private error' } }
          : { status: 403, data: { errcode: 403, errmsg: 'denied' } };
      } else throw new Error('unexpected operation');
      return { stdout: JSON.stringify(response) };
    } });
    const input = { schema_version: 1, repositories: [{ slug: 'team/app', visibility }] };
    await assert.rejects(api.configureCnb({ spec: input, client, journal, apply: true }), { code: 'CREATE_RESULT_UNCERTAIN' });
    assert.equal((await journal.load()).creates['team/app'].status, 'pending');
    await assert.rejects(api.configureCnb({ spec: input, client, journal, apply: true }));
    assert.equal(posts, 1);
  });
});

test('creation and settings must be verified by readback', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service({ 'team/app': repo('team/app', 'Private'), 'team/secrets': repo('team/secrets', 'Secret') });
  client.putBuildSettings = async () => {};
  await assert.rejects(api.configureCnb({ spec: spec(), client, journal, apply: true }), { code: 'SETTINGS_READBACK_MISMATCH' });
  const missing = service(); missing.createRepo = async () => {};
  await assert.rejects(api.configureCnb({ spec: spec(), client: missing, journal, apply: true }), { code: 'CREATE_RESULT_UNCERTAIN' });
}));

test('invalid or secret-bearing inputs fail before contacting the service', { skip: !api }, async () => {
  for (const bad of [
    { schema_version: 1, repositories: [{ slug: 'team/app', visibility: 'public' }] },
    { schema_version: 1, repositories: [{ slug: 'team/app', visibility: 'private', token: 'do-not-output' }] },
    { schema_version: 1, repositories: [{ slug: '../app', visibility: 'private' }] },
    { schema_version: 1, repositories: [{ slug: 'team/app', visibility: 'private', build_settings: { auto_trigger: 'false' } }] },
    { schema_version: 1, repositories: [spec().repositories[0], spec().repositories[0]] },
  ]) await assert.rejects(api.configureCnb({ spec: bad, client: {} }), { code: 'INVALID_SPEC' });
});

test('CLI client maps real commands and JSON false fields, checks HTTP status and suppresses bodies', { skip: !api }, async () => {
  const calls = [];
  const client = new api.CnbCliClient('/explicit/cnb', { run: async (file, args) => {
    calls.push([file, args]);
    if (args[0] === '--version') return { stdout: '1.15.18\n' };
    if (args[1] === 'get-by-id') return { stdout: JSON.stringify({ status: 404, data: { private: 'must-not-leak' } }) };
    return { stdout: JSON.stringify({ status: 200, data: settings }) };
  } });
  assert.equal(await client.getRepo('team/app'), null);
  await client.putBuildSettings('team/app', { ...settings, auto_trigger: false });
  assert.deepEqual(calls[1][1], ['repositories', 'get-by-id', '--repo', 'team/app', '--verbose']);
  assert.deepEqual(calls[2][1], ['git-settings', 'put-pipeline-settings', '--repo', 'team/app', '--data', JSON.stringify(settings), '--verbose']);
  const denied = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => ({ stdout: args[0] === '--version' ? '1.15.18' : JSON.stringify({ status: 403, data: 'Bearer secret' }) }) });
  await assert.rejects(denied.getRepo('team/app'), error => error.code === 'CNB_HTTP_403' && !error.message.includes('Bearer'));
});

const scopeMessage = scopes => `The token's authorization scope does not match this request. Missing required scopes: ${scopes}`;
test('read and PUT scope denials expose only allowlisted permission names', { skip: !api }, async () => {
  for (const [scope, operation] of [
    ['repo-basic-info:r', client => client.getRepo('team/app')],
    ['repo-manage:rw', client => client.putBuildSettings('team/app', settings)],
  ]) {
    const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => ({ stdout: args[0] === '--version' ? '1.15.18'
      : JSON.stringify({ status: 403, data: { errcode: 10023, errmsg: scopeMessage(scope), errparam: { private: 'never-export' } } }) }) });
    await assert.rejects(operation(client), error => {
      assert.equal(error.code, 'CNB_SCOPE_REQUIRED');
      assert.equal(error.message, 'CNB_SCOPE_REQUIRED');
      assert.deepEqual(error.required_scopes, [scope]);
      assert.ok(!JSON.stringify(error).includes('never-export'));
      return true;
    });
  }
  for (const data of [
    { errcode: 10023, errmsg: scopeMessage('repo-manage:rw, private-payload:r') },
    { errcode: 10023, errmsg: `${scopeMessage('repo-manage:rw')} private-payload` },
    { errcode: 10023, errmsg: 'Missing required scopes: repo-manage:rw' },
    { errcode: 7, errmsg: scopeMessage('repo-manage:rw') },
  ]) {
    const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => ({ stdout: args[0] === '--version' ? '1.15.18' : JSON.stringify({ status: 403, data }) }) });
    await assert.rejects(client.getRepo('team/app'), error => error.code === 'CNB_HTTP_403' && error.required_scopes === undefined);
  }
});

test('create scope denial preserves safe diagnosis and confirmed-absence recovery', { skip: !api }, async () => fixture(async (_, journal) => {
  let denied = true, exists = false, posts = 0;
  const client = new api.CnbCliClient('/explicit/cnb', { run: async (_, args) => {
    if (args[0] === '--version') return { stdout: '1.15.18' };
    let response;
    if (args[1] === 'get-by-id') response = { status: exists ? 200 : 404, data: exists ? repo('team/app', 'Private') : null };
    else if (args[1] === 'get-group') response = { status: 200, data: { path: 'team', access_role: 'Owner' } };
    else if (args[1] === 'create-repo') {
      posts++;
      if (denied) response = { status: 403, data: { errcode: 10023, errmsg: scopeMessage('group-resource:rw') } };
      else { exists = true; response = { status: 201, data: null }; }
    } else throw new Error('unexpected operation');
    return { stdout: JSON.stringify(response) };
  } });
  const input = { schema_version: 1, repositories: [{ slug: 'team/app', visibility: 'private' }] };
  await assert.rejects(api.configureCnb({ spec: input, client, journal, apply: true }), error => error.code === 'CNB_SCOPE_REQUIRED' && assert.deepEqual(error.required_scopes, ['group-resource:rw']) === undefined);
  assert.deepEqual((await journal.load()).creates, {});
  assert.equal(posts, 1);
  denied = false;
  assert.equal((await api.configureCnb({ spec: input, client, journal, apply: true })).status, 'applied');
  assert.equal(posts, 2);
}));

test('wrong CLI version and process failures cannot leak output or reach an API call', { skip: !api }, async () => {
  let calls = 0;
  const client = new api.CnbCliClient('/explicit/cnb', { run: async () => { calls++; return { stdout: '1.15.17' }; } });
  await assert.rejects(client.getRepo('team/app'), { code: 'CNB_CLI_VERSION_MISMATCH' });
  assert.equal(calls, 1);
  const failed = new api.CnbCliClient('/explicit/cnb', { run: async () => { throw new Error('private output'); } });
  await assert.rejects(failed.getRepo('team/app'), error => error.code === 'CNB_CLI_FAILED' && !error.message.includes('private output'));
});

test('journal rejects unsafe permissions and concurrent mutation holders', { skip: !api }, async () => fixture(async (dir, journal) => {
  const release = await journal.acquire();
  await assert.rejects(journal.acquire(), { code: 'STATE_LOCKED' });
  await release();
  await writeFile(join(dir, 'state.json'), '{}', { mode: 0o644 });
  await assert.rejects(journal.load(), { code: 'UNSAFE_STATE_PATH' });
}));

test('unreadable groups, wrong resource paths and unknown build flags prevent all writes', { skip: !api }, async () => fixture(async (_, journal) => {
  const denied = service();
  denied.getGroup = async slug => ({ path: slug, access_role: 'Developer' });
  await assert.rejects(api.configureCnb({ spec: spec(), client: denied, journal, apply: true }), { code: 'GROUP_PERMISSION_REQUIRED' });
  assert.equal(denied.writes.length, 0);
  const wrong = service({ 'team/app': repo('other/app', 'Private') });
  await assert.rejects(api.configureCnb({ spec: spec(), client: wrong, journal, apply: true }), { code: 'REPOSITORY_IDENTITY_INVALID' });
  assert.equal(wrong.writes.length, 0);
  const future = service({ 'team/app': repo('team/app', 'Private') });
  future.builds.set('team/app', { ...settings, future_flag: true });
  await assert.rejects(api.configureCnb({ spec: spec(), client: future, journal, apply: true }), { code: 'SETTINGS_RESPONSE_INVALID' });
  assert.equal(future.writes.length, 0);
}));

test('settings read immediately before PUT preserve changes made since preflight', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service({ 'team/app': repo('team/app', 'Private'), 'team/secrets': repo('team/secrets', 'Secret') });
  const result = await api.configureCnb({ spec: spec(), client, journal, apply: true,
    onPlan() { client.builds.get('team/app').auto_trigger_by_npc = false; },
  });
  assert.equal(result.verified[0].build_settings.auto_trigger_by_npc, false);
  assert.equal(client.builds.get('team/app').auto_trigger_by_npc, false);
}));

test('a requested flag changed after preflight is restored and reported as applied', { skip: !api }, async () => fixture(async (_, journal) => {
  const client = service({ 'team/app': repo('team/app', 'Private') });
  const input = { schema_version: 1, repositories: [{ slug: 'team/app', visibility: 'private', build_settings: { auto_trigger: false } }] };
  const result = await api.configureCnb({ spec: input, client, journal, apply: true,
    onPlan() { client.builds.get('team/app').auto_trigger = true; },
  });
  assert.equal(client.builds.get('team/app').auto_trigger, false);
  assert.equal(result.status, 'applied');
}));

test('executable rejects denied HTTP envelopes without forwarding stdout, stderr or ambient tokens', { skip: !api }, async () => fixture(async (dir) => {
  const bin = join(dir, 'cnb');
  await mkdir(join(dir, '.cnb'), { mode: 0o700 });
  await writeFile(join(dir, '.cnb', 'token'), JSON.stringify({ login_host: 'https://api.cnb.cool', platform_url: 'https://cnb.cool', client_id: 'cnb_cli', access_token: 'synthetic-profile-token' }), { mode: 0o600 });
  const denial = { status: 403, data: { errcode: 10023, errmsg: scopeMessage('repo-basic-info:r'), errparam: { private: 'body-private-token' } } };
  await writeFile(bin, `#!/usr/bin/env node\nif(process.env.CNB_TOKEN || process.env.CNB_TOKEN_FOR_CODEBUDDY || process.env.AGENTOS_RUNTIME_ID || process.env.WORKBUDDY_TOKEN_URL_CNB_APP || process.env.CNB_NPC_NAME) process.exit(9);\nif(process.argv.includes('--version')) console.log('1.15.18');\nelse { console.error('stderr-private-token'); console.log(JSON.stringify(${JSON.stringify(denial)})); }\n`, { mode: 0o700 });
  const input = join(dir, 'spec.json');
  await writeFile(input, JSON.stringify(spec()));
  await assert.rejects(promisify(execFile)(process.execPath, [new URL('../scripts/configure-cnb.mjs', import.meta.url).pathname, '--spec', input, '--cnb-bin', bin, '--state', join(dir, 'state.json')],
    { env: { ...process.env, HOME: dir, CNB_TOKEN: 'ambient-private-token', CNB_TOKEN_FOR_CODEBUDDY: 'ambient-agent-token', AGENTOS_RUNTIME_ID: 'synthetic-agent', WORKBUDDY_TOKEN_URL_CNB_APP: 'https://untrusted.example/token', CNB_NPC_NAME: 'CodeBuddy' } }), error => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, '');
      assert.deepEqual(JSON.parse(error.stderr), { status: 'failed', code: 'CNB_SCOPE_REQUIRED', required_scopes: ['repo-basic-info:r'] });
      return true;
    });
}));

test('profile metadata must select the official API and OAuth issuer without exporting credentials', { skip: !api }, async () => fixture(async (dir) => {
  const profile = join(dir, 'token');
  const value = { login_host: 'https://api.cnb.cool', platform_url: 'https://cnb.cool', client_id: 'cnb_cli', access_token: 'synthetic-private-token', refresh_token: 'synthetic-private-refresh' };
  await writeFile(profile, JSON.stringify(value), { mode: 0o600 });
  assert.equal(await api.verifyCnbProfile(profile), undefined);
  for (const change of [{ login_host: 'https://api.unrelated.example' }, { platform_url: 'http://cnb.cool' }, { client_id: 'different-app' }]) {
    await writeFile(profile, JSON.stringify({ ...value, ...change }));
    await assert.rejects(api.verifyCnbProfile(profile), error => error.code === 'CNB_PROFILE_HOST_MISMATCH' && !error.message.includes('private-token'));
  }
  await writeFile(profile, JSON.stringify(value));
  await chmod(profile, 0o644);
  await assert.rejects(api.verifyCnbProfile(profile), { code: 'CNB_PROFILE_NOT_PRIVATE' });
  await chmod(profile, 0o600);
  const link = join(dir, 'linked-token'); await symlink(profile, link);
  await assert.rejects(api.verifyCnbProfile(link), { code: 'CNB_PROFILE_NOT_PRIVATE' });
}));
