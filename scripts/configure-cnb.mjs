#!/usr/bin/env node
/** Reconcile explicitly selected CNB repositories using @cnbcool/cnb-cli 1.15.18.
 * AI supplies the non-secret spec; the user supplies decisions and authorizes scope.
 * Login is a separate, interactive `cnb login --host cnb.cool` operation.
 * No Secret content input, credential output, login, installation or internal APIs.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, lstat, open, readFile, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

const execute = promisify(execFile);
const VERSION = '1.15.18';
const BUILD_KEYS = ['auto_trigger', 'auto_trigger_by_npc', 'cron_auto_trigger', 'forked_repo_auto_trigger'];
const ADMIN = new Set(['Owner', 'Master']);
const API_SCOPES = new Set(['group-resource:r', 'group-resource:rw', 'repo-basic-info:r', 'repo-manage:r', 'repo-manage:rw']);
class CnbFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new CnbFailure(code); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const only = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
const slugOK = slug => typeof slug === 'string' && slug.length <= 255 && /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)+$/.test(slug) && !slug.endsWith('.git');

function requiredScopes(response) {
  const prefix = "The token's authorization scope does not match this request. Missing required scopes: ";
  if (response.status !== 403 || response.data?.errcode !== 10023 || typeof response.data.errmsg !== 'string' || !response.data.errmsg.startsWith(prefix)) return null;
  const scopes = response.data.errmsg.slice(prefix.length).replace(/\.$/, '').split(',').map(scope => scope.trim());
  return scopes.length && scopes.every(scope => API_SCOPES.has(scope)) ? [...new Set(scopes)] : null;
}

/** Inspect only the profile's destination metadata; credential use and refresh
 * remain inside the official CLI. CNB_API_ENDPOINT cannot override login_host.
 */
export async function verifyCnbProfile(filename) {
  let handle;
  try {
    const parent = await lstat(dirname(filename));
    if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o022)) fail('CNB_PROFILE_NOT_PRIVATE');
    handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.uid !== process.getuid() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600 || info.size > 65536) fail('CNB_PROFILE_NOT_PRIVATE');
    let metadata;
    try { metadata = JSON.parse(await handle.readFile('utf8')); } catch { fail('CNB_PROFILE_INVALID'); }
    if (!object(metadata) || metadata.login_host !== 'https://api.cnb.cool' || metadata.platform_url !== 'https://cnb.cool' || metadata.client_id !== 'cnb_cli') fail('CNB_PROFILE_HOST_MISMATCH');
  } catch (error) {
    if (error instanceof CnbFailure) throw error;
    fail(error.code === 'ENOENT' ? 'CNB_PROFILE_LOGIN_REQUIRED' : 'CNB_PROFILE_NOT_PRIVATE');
  } finally { if (handle) await handle.close(); }
}

export function validateSpec(spec) {
  if (!only(spec, ['schema_version', 'repositories']) || spec.schema_version !== 1 || !Array.isArray(spec.repositories) || !spec.repositories.length || spec.repositories.length > 20) fail('INVALID_SPEC');
  const slugs = new Set();
  for (const item of spec.repositories) {
    if (!only(item, ['slug', 'visibility', 'build_settings']) || !slugOK(item.slug) || !['private', 'secret'].includes(item.visibility) || slugs.has(item.slug)) fail('INVALID_SPEC');
    slugs.add(item.slug);
    if (Object.hasOwn(item, 'build_settings') && (item.visibility !== 'private' || !only(item.build_settings, BUILD_KEYS) || !Object.keys(item.build_settings).length || Object.values(item.build_settings).some(value => typeof value !== 'boolean'))) fail('INVALID_SPEC');
  }
  return structuredClone(spec);
}

/** No retries; stderr and response bodies never escape this boundary. */
export class CnbCliClient {
  constructor(bin, { run } = {}) {
    if (!isAbsolute(bin || '')) fail('CNB_BIN_MUST_BE_ABSOLUTE');
    this.bin = bin;
    this.run = run || (async (file, args) => {
      await access(file, constants.X_OK);
      if (args[0] !== '--version') await verifyCnbProfile(join(homedir(), '.cnb', 'token'));
      const env = { ...process.env, CNB_API_ENDPOINT: 'https://api.cnb.cool', NO_COLOR: '1' };
      // Reuse the CLI's authenticated profile and refresh logic, not an incidental
      // pipeline/agent token. Metadata checks never replace CLI credential refresh.
      delete env.CNB_TOKEN;
      delete env.CNB_TOKEN_FOR_CODEBUDDY;
      delete env.AGENTOS_RUNTIME_ID;
      delete env.CNB_NPC_NAME;
      delete env.CNB_NPC_SLUG;
      delete env.OAUTH2_CLIENT_ID;
      for (const key of Object.keys(env)) if (key.startsWith('WORKBUDDY_TOKEN_URL_')) delete env[key];
      return execute(file, args, { env, timeout: 60_000, maxBuffer: 2 * 1024 * 1024, windowsHide: true });
    });
    this.checked = false;
  }
  async invoke(args) {
    let result;
    try { result = await this.run(this.bin, args); } catch (error) { if (error instanceof CnbFailure) throw error; fail('CNB_CLI_FAILED'); }
    if (typeof result?.stdout !== 'string') fail('CNB_CLI_RESPONSE_INVALID');
    return result.stdout;
  }
  async request(args, { missing = false, creating = false } = {}) {
    if (!this.checked) {
      if ((await this.invoke(['--version'])).trim() !== VERSION) fail('CNB_CLI_VERSION_MISMATCH');
      this.checked = true;
    }
    let response;
    try { response = JSON.parse(await this.invoke([...args, '--verbose'])); }
    catch (error) { if (error instanceof CnbFailure) throw error; fail('CNB_CLI_RESPONSE_INVALID'); }
    if (!object(response) || !Number.isInteger(response.status) || response.status < 100 || response.status > 599 || !Object.hasOwn(response, 'data')) fail('CNB_CLI_RESPONSE_INVALID');
    if (missing && response.status === 404) return null;
    if (response.status < 200 || response.status >= 300) {
      const scopes = requiredScopes(response);
      const error = new CnbFailure(scopes ? 'CNB_SCOPE_REQUIRED' : `CNB_HTTP_${response.status}`);
      if (scopes) error.required_scopes = scopes;
      // Only standard CNB validation/auth rejection envelopes establish that POST
      // was refused. Gateway text, timeouts, conflicts and 5xx remain uncertain.
      error.rejectedCreate = creating && [400, 401, 403, 422].includes(response.status)
        && object(response.data) && Number.isInteger(response.data.errcode) && response.data.errcode !== 0
        && typeof response.data.errmsg === 'string' && response.data.errmsg.length > 0
        && (!Object.hasOwn(response.data, 'errparam') || object(response.data.errparam));
      throw error;
    }
    return response.data;
  }
  getGroup(slug) { return this.request(['organizations', 'get-group', '--group', slug]); }
  getRepo(slug) { return this.request(['repositories', 'get-by-id', '--repo', slug], { missing: true }); }
  listGroupRepos(group, page) { return this.request(['repositories', 'get-group-sub-repos', '--slug', group, '--descendant', 'sub', '--page', String(page), '--page-size', '100', '--order-by', 'slug_path']); }
  createRepo(group, body) { return this.request(['repositories', 'create-repo', '--slug', group, '--data', JSON.stringify(body)], { creating: true }); }
  getBuildSettings(slug) { return this.request(['git-settings', 'get-pipeline-settings', '--repo', slug]); }
  putBuildSettings(slug, body) { return this.request(['git-settings', 'put-pipeline-settings', '--repo', slug, '--data', JSON.stringify(body)]); }
}

/** Keep this state across retries. Deleting it discards uncertainty protection. */
export class FileJournal {
  constructor(path) { if (!isAbsolute(path || '')) fail('STATE_PATH_MUST_BE_ABSOLUTE'); this.path = path; }
  async checkPath() {
    try {
      const parent = await lstat(dirname(this.path));
      if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) || parent.uid !== process.getuid()) fail('UNSAFE_STATE_PATH');
      try {
        const file = await lstat(this.path);
        if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) || file.uid !== process.getuid()) fail('UNSAFE_STATE_PATH');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    } catch (error) { if (error instanceof CnbFailure) throw error; fail('UNSAFE_STATE_PATH'); }
  }
  async load() {
    await this.checkPath();
    let state;
    try { state = JSON.parse(await readFile(this.path, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return { schema_version: 1, creates: {} }; fail('STATE_INVALID'); }
    if (!only(state, ['schema_version', 'creates']) || state.schema_version !== 1 || !object(state.creates)) fail('STATE_INVALID');
    for (const [slug, entry] of Object.entries(state.creates)) {
      if (!slugOK(slug) || !only(entry, ['visibility', 'status']) || !['private', 'secret'].includes(entry.visibility) || !['pending', 'verified'].includes(entry.status)) fail('STATE_INVALID');
    }
    return state;
  }
  async save(state) {
    await this.checkPath();
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`); await handle.sync(); }
      finally { await handle.close(); }
      await rename(temporary, this.path);
      const directory = await open(dirname(this.path), 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    } catch { fail('STATE_WRITE_FAILED'); }
    finally { await unlink(temporary).catch(() => {}); }
  }
  async acquire() {
    await this.checkPath();
    let lock;
    try { lock = await open(`${this.path}.lock`, 'wx', 0o600); }
    catch (error) { fail(error.code === 'EEXIST' ? 'STATE_LOCKED' : 'STATE_WRITE_FAILED'); }
    return async () => { await lock.close(); await unlink(`${this.path}.lock`); };
  }
}

function checkGroup(info, group) {
  if (!object(info) || info.path !== group || info.freeze === true || !ADMIN.has(info.access_role)) fail('GROUP_PERMISSION_REQUIRED');
}
function checkRepo(actual, desired, group) {
  if (!object(actual) || actual.path !== desired.slug || typeof actual.id !== 'string' || !actual.id || actual.freeze === true) fail('REPOSITORY_IDENTITY_INVALID');
  if (actual.visibility_level !== (desired.visibility === 'private' ? 'Private' : 'Secret')) fail('REPOSITORY_TYPE_MISMATCH');
  if (desired.visibility === 'secret') checkGroup(group, desired.slug.slice(0, desired.slug.lastIndexOf('/')));
  if (desired.build_settings && !ADMIN.has(actual.access)) fail('REPOSITORY_PERMISSION_REQUIRED');
}
async function discoverRepo(client, desired) {
  if (desired.visibility !== 'secret') return { actual: await client.getRepo(desired.slug) };
  // Secret's single-repo endpoint rejects OAuth tokens; the public organization
  // listing returns metadata, but access may be Unknown. Keep parent authority
  // explicit, without inventing a repository role or treating a 403 as absence.
  const parent = desired.slug.slice(0, desired.slug.lastIndexOf('/'));
  const group = await client.getGroup(parent);
  checkGroup(group, parent);
  const paths = new Set(), ids = new Set();
  let actual = null;
  for (let page = 1; page <= 100; page++) {
    const rows = await client.listGroupRepos(parent, page);
    if (!Array.isArray(rows) || rows.length > 100) fail('REPOSITORY_LIST_INVALID');
    for (const item of rows) {
      if (!object(item) || !slugOK(item.path) || item.path.slice(0, item.path.lastIndexOf('/')) !== parent
        || typeof item.id !== 'string' || !item.id || paths.has(item.path) || ids.has(item.id)) fail('REPOSITORY_LIST_INVALID');
      paths.add(item.path); ids.add(item.id);
      if (item.path === desired.slug) actual = item;
    }
    // Even a found target is not trusted before the complete listing finishes.
    if (rows.length < 100) return { actual, group };
  }
  fail('REPOSITORY_LIST_INCOMPLETE');
}
function checkedSettings(value) {
  if (!only(value, BUILD_KEYS) || BUILD_KEYS.some(key => typeof value[key] !== 'boolean')) fail('SETTINGS_RESPONSE_INVALID');
  return structuredClone(value);
}
const changesFor = (current, requested) => Object.fromEntries(Object.entries(requested || {}).filter(([key, value]) => current[key] !== value).map(([key, value]) => [key, { from: current[key], to: value }]));
async function call(fn) {
  try { return await fn(); } catch (error) { if (error instanceof CnbFailure) throw error; fail('CNB_OPERATION_FAILED'); }
}

export async function configureCnb({ spec, client, journal, apply = false, onPlan = () => {} }) {
  spec = validateSpec(spec);
  if (apply && !journal) fail('STATE_REQUIRED');
  const release = apply ? await journal.acquire() : null;
  try {
    const state = journal ? await journal.load() : { schema_version: 1, creates: {} };
    const discovered = [], plan = [], groups = new Set();
    // Complete all preflight discovery before the first write, including later repos.
    for (const desired of spec.repositories) {
      const { actual, group: authority } = await call(() => discoverRepo(client, desired));
      const remembered = state.creates[desired.slug];
      if (remembered && remembered.visibility !== desired.visibility) fail('STATE_TARGET_MISMATCH');
      if (actual === null) {
        if (remembered) fail('CREATE_RECONCILIATION_REQUIRED');
        const group = desired.slug.slice(0, desired.slug.lastIndexOf('/'));
        if (!groups.has(group)) {
          const info = authority || await call(() => client.getGroup(group));
          checkGroup(info, group);
          groups.add(group);
        }
        plan.push({ action: 'create_repository', slug: desired.slug, visibility: desired.visibility, requested_build_settings: desired.build_settings || {} });
        discovered.push({ desired, actual: null, authority });
      } else {
        checkRepo(actual, desired, authority);
        const current = desired.build_settings ? checkedSettings(await call(() => client.getBuildSettings(desired.slug))) : null;
        const changes = current ? changesFor(current, desired.build_settings) : {};
        if (Object.keys(changes).length) plan.push({ action: 'update_build_settings', slug: desired.slug, changes });
        discovered.push({ desired, actual, current, authority });
      }
    }
    const manual_actions = spec.repositories.filter(repo => repo.visibility === 'secret').map(repo => ({
      action: 'edit_secret_files_in_official_web_ui', slug: repo.slug, url: `https://cnb.cool/${repo.slug}`,
      guidance: 'AI prepares the file names, variable keys and allow_* scope. Use the official Web editor; no Secret file was written by this executor.',
    }));
    const preview = { schema_version: 1, status: 'preview', cli_version: VERSION, plan, manual_actions,
      permission_check: 'Read access and returned roles checked; write token scopes are enforced by CNB on apply.' };
    await onPlan(preview);
    if (!apply) return preview;
    const verified = [];
    let writes = 0;
    for (const item of discovered) {
      const { desired } = item;
      let actual = item.actual;
      let authority = item.authority;
      if (!actual) {
        state.creates[desired.slug] = { visibility: desired.visibility, status: 'pending' };
        await journal.save(state); // durable before POST, including a lost response/crash
        const split = desired.slug.lastIndexOf('/');
        try {
          await client.createRepo(desired.slug.slice(0, split), { name: desired.slug.slice(split + 1), visibility: desired.visibility });
          writes++;
        } catch (error) {
          if (error instanceof CnbFailure && error.rejectedCreate) {
            // Reconfirm absence before releasing this POST's pending marker.
            // A read failure or an existing resource cannot justify another POST.
            let absent = false;
            try { absent = (await discoverRepo(client, desired)).actual === null; } catch {}
            if (absent) {
              delete state.creates[desired.slug];
              await journal.save(state);
              throw error;
            }
          }
          fail('CREATE_RESULT_UNCERTAIN');
        }
        try {
          ({ actual, group: authority } = await discoverRepo(client, desired));
          checkRepo(actual, desired, authority);
        } catch { fail('CREATE_RESULT_UNCERTAIN'); }
      }
      if (state.creates[desired.slug]) {
        state.creates[desired.slug].status = 'verified';
        await journal.save(state);
      }
      let build_settings;
      if (desired.build_settings) {
        // Re-read immediately before PUT to preserve all unspecified current flags.
        const current = checkedSettings(await call(() => client.getBuildSettings(desired.slug)));
        const target = { ...current, ...desired.build_settings };
        if (Object.keys(changesFor(current, desired.build_settings)).length) {
          await call(() => client.putBuildSettings(desired.slug, target));
          writes++;
          const readback = checkedSettings(await call(() => client.getBuildSettings(desired.slug)));
          if (BUILD_KEYS.some(key => readback[key] !== target[key])) fail('SETTINGS_READBACK_MISMATCH');
          build_settings = readback;
        } else build_settings = current;
      }
      verified.push({ slug: desired.slug, id: actual.id, visibility: desired.visibility,
        ...(authority ? { permission_basis: { kind: 'parent_group', slug: authority.path, role: authority.access_role } } : {}),
        ...(build_settings ? { build_settings } : {}) });
    }
    return { ...preview, status: writes ? 'applied' : 'unchanged', verified };
  } finally { if (release) await release(); }
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/configure-cnb.mjs --spec <AI-generated JSON> --cnb-bin <absolute cnb 1.15.18> --state <protected persistent JSON> [--apply]\nRequires prior cnb login --host cnb.cool. Preview only reads CNB. Keep the same state file across retries.\nSpec: {"schema_version":1,"repositories":[{"slug":"group/app","visibility":"private","build_settings":{"auto_trigger":true}},{"slug":"group/secrets","visibility":"secret"}]}');
    return;
  }
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (!['--spec', '--cnb-bin', '--state', '--apply'].includes(key) || Object.hasOwn(options, key)) fail('INVALID_ARGUMENTS');
    options[key] = key === '--apply' ? true : args[++i];
    if (options[key] === undefined || (typeof options[key] === 'string' && options[key].startsWith('--'))) fail('INVALID_ARGUMENTS');
  }
  if (!options['--spec'] || !options['--state'] || !options['--cnb-bin']) fail('INVALID_ARGUMENTS');
  let spec;
  try { spec = JSON.parse(await readFile(options['--spec'], 'utf8')); } catch { fail('INVALID_SPEC'); }
  const result = await configureCnb({ spec, client: new CnbCliClient(options['--cnb-bin']), journal: new FileJournal(resolve(options['--state'])), apply: options['--apply'] === true,
    onPlan: options['--apply'] ? plan => console.log(JSON.stringify(plan)) : undefined });
  console.log(JSON.stringify(result));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => {
    console.error(JSON.stringify({ status: 'failed', code: error instanceof CnbFailure ? error.code : 'CNB_CONFIGURATION_FAILED',
      ...(error instanceof CnbFailure && error.code === 'CNB_SCOPE_REQUIRED' ? { required_scopes: error.required_scopes } : {}) }));
    process.exitCode = 1;
  });
}
