#!/usr/bin/env node
/** Fixed local orchestration for an already reviewed, tested production bundle.
 * State records evidence; it never grants authorization or replaces live gates.
 */
import { constants } from 'node:fs';
import { lstat, realpath, open, readFile, writeFile, mkdir, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { hostname } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';

const executeFile = promisify(execFile), SDK = 'tencentcloud-sdk-nodejs-tat';
const ACTIONS = ['prepare', 'candidate', 'sign', 'publish', 'status'];
const SPEC_KEYS = ['schema', 'project_dir', 'bundle_dir', 'session_dir', 'bundle_lock_sha256', 'production_lock_sha256',
  'candidate_tag', 'application_commit', 'production_binding', 'approval_private_key', 'cnb_token_file', 'tat_credentials_file'];
const PATH_KEYS = ['project_dir', 'bundle_dir', 'session_dir', 'production_binding', 'approval_private_key', 'cnb_token_file', 'tat_credentials_file'];
const hash = raw => createHash('sha256').update(raw).digest('hex');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
class SessionError extends Error { constructor(code) { super(code); this.code = code; } }
const fail = code => { throw new SessionError(code); };
const check = (value, code) => { if (!value) fail(code); };
const json = raw => { try { return parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(raw), { maxBytes: 512 * 1024 }); } catch { fail('JSON_INVALID'); } };
const stamp = now => new Date(now()).toISOString();
const exists = async path => { try { await lstat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

async function safeDirectory(path, privateMode = false) {
  check(isAbsolute(path) && resolve(path) === path && await realpath(path) === path, 'DIRECTORY_UNSAFE');
  for (let current = path; ; current = dirname(current)) {
    const info = await lstat(current), sticky = current !== path && info.uid === 0 && (info.mode & 0o1000) !== 0;
    check(info.isDirectory() && !info.isSymbolicLink() && [0, process.getuid()].includes(info.uid)
      && (!(info.mode & 0o022) || sticky), 'DIRECTORY_UNSAFE');
    if (current === path && privateMode) check(info.uid === process.getuid() && (info.mode & 0o7777) === 0o700, 'PRIVATE_DIRECTORY_UNSAFE');
    if (current === parse(current).root) break;
  }
}

async function safeRead(path, privateMode = false, maxBytes = 512 * 1024) {
  await safeDirectory(dirname(path), privateMode);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await handle.stat();
    check(before.isFile() && before.nlink === 1 && [0, process.getuid()].includes(before.uid)
      && !(before.mode & 0o022) && before.size > 0 && before.size <= maxBytes, privateMode ? 'PRIVATE_FILE_UNSAFE' : 'FILE_UNSAFE');
    if (privateMode) check(before.uid === process.getuid() && (before.mode & 0o7777) === 0o600, 'PRIVATE_FILE_UNSAFE');
    const raw = await handle.readFile(), after = await handle.stat(), named = await lstat(path);
    check(!named.isSymbolicLink() && before.ino === named.ino && before.dev === named.dev && before.size === raw.length
      && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'FILE_CHANGED');
    return raw;
  } finally { await handle?.close(); }
}

async function atomicJson(path, value) {
  const temp = `${path}.${randomUUID()}.tmp`, handle = await open(temp, 'wx', 0o600);
  try { await handle.writeFile(JSON.stringify(value) + '\n'); await handle.sync(); } finally { await handle.close(); }
  try {
    await rename(temp, path);
    const directory = await open(dirname(path), 'r'); try { await directory.sync(); } finally { await directory.close(); }
  } finally { await unlink(temp).catch(() => {}); }
}

function privateLocation(path, project) {
  const name = relative(project, path);
  check(name.startsWith('../') || name === '.git' || name.startsWith('.git/'), 'PRIVATE_PATH_IN_PROJECT');
}

async function verifyBundle(base, expected, required) {
  const raw = await safeRead(join(base, 'artifact-lock.json'));
  check(hash(raw) === expected, 'BUNDLE_CHANGED');
  const lock = json(raw);
  check(exact(lock, ['schema', 'version', 'files']) && lock.schema === 'cnb-devops-artifacts/v1' && object(lock.files)
    && required.every(name => Object.hasOwn(lock.files, name)), 'BUNDLE_LOCK_INVALID');
  for (const [name, digest] of Object.entries(lock.files)) {
    check(/^[A-Za-z0-9._/-]+$/.test(name) && name.split('/').every(part => part && part !== '.' && part !== '..')
      && !isAbsolute(name) && /^[0-9a-f]{64}$/.test(digest), 'BUNDLE_LOCK_INVALID');
    check(hash(await safeRead(join(base, name), false, 8 * 1024 * 1024)) === digest, 'BUNDLE_CHANGED');
  }
}

function cleanEnvironment() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(CNB|TENCENT|TC_|AWS_|GOOGLE_|AZURE_|GIT_CONFIG|GIT_ASKPASS|GIT_SSH|NODE_OPTIONS|NODE_PATH|npm_config_)/i.test(key)) delete env[key];
  env.PYTHONDONTWRITEBYTECODE = '1'; env.GIT_TERMINAL_PROMPT = '0';
  return env;
}

// flock serializes owner changes, including simultaneous stale-lock recovery.
// The PID belongs to this Node process, not the short-lived Python helper.
const LOCK_HELPER = `import fcntl,json,os,stat,sys
path,mode,owner_raw=sys.argv[1:]
owner=json.loads(owner_raw)
fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 info=os.fstat(fd); named=os.stat(path,follow_symlinks=False)
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600
 assert (info.st_ino,info.st_dev)==(named.st_ino,named.st_dev) and info.st_size<=4096
 raw=os.read(fd,4097)
 current=json.loads(raw) if raw else None
 if mode=='release':
  assert current==owner
  os.unlink(path)
 else:
  if current is not None:
   assert set(current)=={'schema','pid','hostname','id','started_at'} and current['schema']=='cnb-release-session-lock/v1'
   assert current['hostname']==owner['hostname'] and type(current['pid']) is int and current['pid']>0
   try: os.kill(current['pid'],0)
   except ProcessLookupError: pass
   else: raise ValueError('owner active')
  os.ftruncate(fd,0); os.lseek(fd,0,os.SEEK_SET); os.write(fd,owner_raw.encode()); os.fsync(fd)
finally: os.close(fd)
`;

async function changeLock(path, mode, owner) {
  try { await executeFile('python3', ['-c', LOCK_HELPER, path, mode, JSON.stringify(owner)], { env: cleanEnvironment(), timeout: 10000, maxBuffer: 65536 }); }
  catch { fail(mode === 'release' ? 'SESSION_LOCK_RELEASE_FAILED' : 'SESSION_LOCKED'); }
}

async function lockActive(path) {
  if (!await exists(path)) return false;
  try {
    const current = json(await safeRead(path, true, 4096));
    if (current.hostname !== hostname() || !Number.isSafeInteger(current.pid) || current.pid <= 0) return true;
    try { process.kill(current.pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
  } catch { return true; }
}

async function tokenFrom(path) {
  const raw = await safeRead(path, true, 8194);
  try { const token = raw.toString('latin1').replace(/\r?\n$/, ''); check(token.length <= 8192 && /^[A-Za-z0-9._~+/-]+=*$/.test(token), 'CNB_TOKEN_INVALID'); return token; }
  finally { raw.fill(0); }
}

async function credentialsFrom(path) {
  const raw = await safeRead(path, true, 65536);
  try {
    const value = json(raw);
    check(object(value) && Object.keys(value).every(key => ['secretId', 'secretKey', 'token'].includes(key))
      && ['secretId', 'secretKey'].every(key => typeof value[key] === 'string' && value[key].length > 0 && value[key].length <= 16384 && !/[\s\0]/.test(value[key]))
      && (value.token === undefined || typeof value.token === 'string' && value.token.length > 0 && value.token.length <= 16384 && !/[\s\0]/.test(value.token)), 'TAT_CREDENTIALS_INVALID');
    return value;
  } finally { raw.fill(0); }
}

async function sdkInstalled(base) {
  const root = join(base, 'dependencies'), manifest = json(await safeRead(join(root, 'package.json'))), lock = json(await safeRead(join(root, 'package-lock.json')));
  const expected = manifest.dependencies?.[SDK];
  check(typeof expected === 'string' && /^\d+\.\d+\.\d+$/.test(expected) && lock.packages?.[`node_modules/${SDK}`]?.version === expected, 'SDK_LOCK_INVALID');
  const packagePath = join(root, 'node_modules', SDK, 'package.json');
  if (!await exists(packagePath)) return false;
  const actual = json(await safeRead(packagePath)), require = createRequire(join(root, 'package.json'));
  check(actual.version === expected && await realpath(require.resolve(`${SDK}/package.json`)) === packagePath, 'SDK_VERSION_MISMATCH');
  return true;
}

async function loadContext(specPath) {
  check(typeof specPath === 'string' && isAbsolute(specPath) && resolve(specPath) === specPath, 'SPEC_PATH_INVALID');
  const specRaw = await safeRead(specPath, true), spec = json(specRaw);
  check(exact(spec, SPEC_KEYS) && spec.schema === 'cnb-release-session/v1' && PATH_KEYS.every(key => typeof spec[key] === 'string'
    && isAbsolute(spec[key]) && resolve(spec[key]) === spec[key] && !/[\r\n\0]/.test(spec[key]))
    && ['bundle_lock_sha256', 'production_lock_sha256'].every(key => /^[0-9a-f]{64}$/.test(spec[key]))
    && /^[0-9a-f]{40}$/.test(spec.application_commit) && /^[a-z][a-z0-9-]{0,191}$/.test(spec.candidate_tag), 'SPEC_INVALID');
  await safeDirectory(spec.project_dir); await safeDirectory(spec.session_dir, true);
  for (const path of [specPath, spec.session_dir, spec.production_binding, spec.approval_private_key, spec.cnb_token_file, spec.tat_credentials_file]) privateLocation(path, spec.project_dir);
  check(relative(spec.project_dir, spec.bundle_dir).split('/').every(part => part !== '..') && spec.bundle_dir !== spec.project_dir, 'BUNDLE_OUTSIDE_PROJECT');
  const production = join(spec.bundle_dir, 'production');
  await verifyBundle(spec.bundle_dir, spec.bundle_lock_sha256, ['ci-config.json', 'ci/candidate_gate.py', 'ci/candidate_manifest.py']);
  await verifyBundle(production, spec.production_lock_sha256, ['ci-config.json', 'approval-ed25519.pub', 'ci/production-contract.mjs', 'ci/run-production-deploy.mjs',
    'ci/run-tat-release.mjs', 'admin/sign-production-approval.mjs', 'admin/publish-production-approval.mjs', 'dependencies/package.json', 'dependencies/package-lock.json']);
  const contract = await import(pathToFileURL(join(production, 'ci/production-contract.mjs')));
  const runner = await import(pathToFileURL(join(production, 'ci/run-production-deploy.mjs')));
  const signer = await import(pathToFileURL(join(production, 'admin/sign-production-approval.mjs')));
  const publisher = await import(pathToFileURL(join(production, 'admin/publish-production-approval.mjs')));
  const tat = await import(pathToFileURL(join(production, 'ci/run-tat-release.mjs')));
  const config = json(await safeRead(join(production, 'ci-config.json'))), candidateConfig = json(await safeRead(join(spec.bundle_dir, 'ci-config.json')));
  const bindingRaw = await safeRead(spec.production_binding, true), binding = json(bindingRaw);
  check(config.environment === 'production' && candidateConfig.environment === 'test' && config.project === candidateConfig.project
    && binding.project === config.project && binding.environment === 'production'
    && /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*){1,7}$/.test(candidateConfig.cnb_repository)
    && /^[a-zA-Z0-9][a-zA-Z0-9_/-]*$/.test(config.production_branch)
    && spec.candidate_tag.startsWith(candidateConfig.candidate_prefix) && /^cnb-[a-z0-9][a-z0-9-]{2,127}$/.test(spec.candidate_tag.slice(candidateConfig.candidate_prefix.length)), 'INPUT_SCOPE_INVALID');
  const publicKey = await runner.readPublicKey(join(production, 'approval-ed25519.pub'), config.approval_public_key_sha256);
  return { spec, production, contract, runner, signer, publisher, tat, config, candidateConfig, binding, publicKey,
    inputHash: hash(Buffer.concat([specRaw, Buffer.from(hash(bindingRaw))])) };
}

async function loadState(context, now) {
  const { spec, inputHash } = context, path = join(spec.session_dir, 'state.json');
  let state = { schema: 'cnb-release-session-state/v1', input_sha256: inputHash, started_at: stamp(now), updated_at: stamp(now), steps: {}, files: {}, events: [] };
  if (await exists(path)) {
    state = json(await safeRead(path, true));
    check(exact(state, ['schema', 'input_sha256', 'started_at', 'updated_at', 'steps', 'files', 'events']) && state.schema === 'cnb-release-session-state/v1'
      && state.input_sha256 === inputHash && object(state.steps) && object(state.files) && Array.isArray(state.events), 'SESSION_INPUT_CHANGED');
    for (const [name, digest] of Object.entries(state.files)) {
      check(['candidate/annotations.json', 'candidate/candidate.json', 'candidate/readiness.json', 'approval.json', 'sign-result.json', 'publication-result.json'].includes(name)
        && /^[0-9a-f]{64}$/.test(digest), 'STATE_INVALID');
      check(await exists(join(spec.session_dir, name)) && hash(await safeRead(join(spec.session_dir, name), true)) === digest, 'EVIDENCE_CHANGED');
    }
  }
  return state;
}

async function materials(context, now, requireApproval = false, directory = join(context.spec.session_dir, 'candidate')) {
  const { spec, contract, config, candidateConfig, publicKey } = context;
  const candidateRaw = await safeRead(join(directory, 'candidate.json'), true), readinessRaw = await safeRead(join(directory, 'readiness.json'), true);
  let candidate, readiness;
  try { candidate = contract.validateProductionContext(candidateRaw, candidateConfig, config); } catch { fail('CANDIDATE_INVALID'); }
  try { readiness = contract.parseCanonical(readinessRaw); } catch { fail('READINESS_INVALID'); }
  check(candidate.candidate_tag === spec.candidate_tag && candidate.application_commit === spec.application_commit, 'CANDIDATE_CHANGED');
  check(!(Date.parse(readiness.prepared_expires_at) <= now()), 'READINESS_EXPIRED');
  try { contract.validateReadiness(readiness, candidate, candidateRaw, config, now()); } catch { fail('READINESS_INVALID'); }
  const annotations = json(await safeRead(join(directory, 'annotations.json'), true));
  const invocationId = annotations.production_readiness_invocation_id;
  check(/^inv-[A-Za-z0-9-]{8,64}$/.test(invocationId) && annotations.production_readiness_status === 'passed'
    && annotations.production_readiness_b64url === readinessRaw.toString('base64url')
    && annotations.production_prepared_sha256 === readiness.prepared_sha256, 'READINESS_INVALID');
  let approval;
  if (requireApproval) {
    try {
      approval = contract.parseCanonical(await safeRead(join(spec.session_dir, 'approval.json'), true));
      const payload = contract.verifyApproval(approval, publicKey);
      check(!(Date.parse(payload.expires_at) <= now()), 'APPROVAL_EXPIRED');
      contract.validateApprovedSelection(approval, publicKey, candidate, candidateRaw, readiness, config, now());
    } catch (error) { if (error instanceof SessionError && error.code === 'APPROVAL_EXPIRED') throw error; fail('APPROVAL_INVALID'); }
  }
  return { config, candidateConfig, candidateRaw, readiness, approval, publicKey, invocationId };
}

async function annotationGet(context, fetchImpl) {
  let raw;
  try {
    const token = await tokenFrom(context.spec.cnb_token_file);
    const response = await fetchImpl(`https://api.cnb.cool/${context.candidateConfig.cnb_repository}/-/git/tag-annotations/${encodeURIComponent(context.spec.candidate_tag)}`,
      { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15000), headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.cnb.api+json' } });
    check(response.ok && response.body, 'CANDIDATE_FETCH_FAILED');
    const chunks = []; let size = 0;
    for await (const chunk of response.body) { size += chunk.length; check(size <= 256 * 1024, 'CANDIDATE_FETCH_FAILED'); chunks.push(Buffer.from(chunk)); }
    raw = Buffer.concat(chunks);
  } catch { fail('CANDIDATE_FETCH_FAILED'); }
  const rows = json(raw), values = Object.create(null);
  check(Array.isArray(rows) && rows.length <= 1024, 'ANNOTATIONS_INVALID');
  for (const item of rows) { check(object(item) && typeof item.key === 'string' && typeof item.value === 'string' && !Object.hasOwn(values, item.key), 'ANNOTATIONS_INVALID'); values[item.key] = item.value; }
  check(values.production_readiness_status === 'passed' && values.candidate_commit === context.spec.application_commit, 'READINESS_REQUIRED');
  return values;
}

async function productionClient(context, createClient) {
  const credentials = await credentialsFrom(context.spec.tat_credentials_file);
  if (createClient) return createClient(credentials, context.binding.region, context.production);
  const options = context.tat.createTatClientOptions({ ...credentials, region: context.binding.region });
  const require = createRequire(join(context.production, 'dependencies/package.json')), sdk = require(SDK);
  const Client = sdk?.tat?.v20201028?.Client ?? sdk?.default?.tat?.v20201028?.Client;
  check(typeof Client === 'function', 'SDK_INVALID'); return new Client(options);
}

/** External effects are injectable at process, HTTP and SDK boundaries for local rehearsal. */
export async function runSession({ action, specPath, apply = false, authorized = false }, { execute = executeFile, fetchImpl = globalThis.fetch, now = Date.now, createClient } = {}) {
  check(ACTIONS.includes(action) && typeof apply === 'boolean' && typeof authorized === 'boolean' && !(action === 'status' && apply), 'ARGUMENTS_INVALID');
  check(process.versions.node.split('.')[0] === '22' && typeof process.getuid === 'function' && process.env.CNB !== 'true', 'LOCAL_NODE_22_REQUIRED');
  const context = await loadContext(specPath), { spec } = context;
  const statePath = join(spec.session_dir, 'state.json'), lockPath = join(spec.session_dir, '.lock');
  let lock, state;
  try {
    if (apply) {
      const owner = { schema: 'cnb-release-session-lock/v1', pid: process.pid, hostname: hostname(), id: randomUUID(), started_at: stamp(now) };
      await changeLock(lockPath, 'acquire', owner); lock = owner;
    }
    state = await loadState(context, now);
    const record = async names => { for (const name of names) state.files[name] = hash(await safeRead(join(spec.session_dir, name), true)); };
    const save = async () => { state.updated_at = stamp(now); await atomicJson(statePath, state); };
    const start = async () => { check(state.events.length < 1000, 'SESSION_EVENT_LIMIT'); state.steps[action] = 'pending'; state.events.push({ action, status: 'started', at: stamp(now) }); await save(); };
    const finish = async (status, details = {}) => { state.steps[action] = 'complete'; state.events.push({ action, status, at: stamp(now) }); await save(); return { schema: 'cnb-release-session-result/v1', status, ...details }; };
    const hasCandidate = await exists(join(spec.session_dir, 'candidate'));
    const hasApproval = await exists(join(spec.session_dir, 'approval.json'));
    if (hasCandidate) {
      try { await materials(context, now, hasApproval); }
      catch (error) {
        if (action !== 'status') throw error;
        const code = error instanceof SessionError ? error.code : 'EVIDENCE_INVALID';
        return { schema: 'cnb-release-session-result/v1', status: 'blocked', code, steps: state.steps,
          next_action: ['APPROVAL_EXPIRED', 'READINESS_EXPIRED'].includes(code) ? 'refresh_readiness_new_session' : 'inspect_evidence' };
      }
    }
    if (action === 'status') {
      const next = hasApproval ? state.steps.publish === 'complete' ? 'native-production-approval' : 'publish' : hasCandidate ? 'sign' : state.steps.prepare === 'complete' ? 'candidate' : 'prepare';
      return { schema: 'cnb-release-session-result/v1', status: 'observed', steps: state.steps, next_action: next,
        candidate_tag: spec.candidate_tag, application_commit: spec.application_commit, started_at: state.started_at, updated_at: state.updated_at, locked: await lockActive(lockPath) };
    }
    if (!apply) {
      if (action === 'sign') check(hasCandidate, 'CANDIDATE_REQUIRED');
      if (action === 'publish') return { ...await context.publisher.publishProductionApproval({ ...await materials(context, now, true), now }), next_action: 'publish --apply' };
      return { schema: 'cnb-release-session-result/v1', status: 'preview', action, candidate_tag: spec.candidate_tag,
        ...(action === 'prepare' ? { production_dependencies_ready: await sdkInstalled(context.production) } : {}) };
    }
    if (action === 'prepare') {
      await start();
      const child = { cwd: spec.project_dir, env: cleanEnvironment(), timeout: 120000, maxBuffer: 1024 * 1024 };
      await execute('python3', ['-c', 'import sys; assert sys.version_info >= (3,11)'], child);
      await execute('git', ['--version'], child);
      if (!await sdkInstalled(context.production)) await execute('npm', ['ci', '--ignore-scripts', '--prefix', join(context.production, 'dependencies')], { ...child, timeout: 300000 });
      check(await sdkInstalled(context.production), 'SDK_INSTALL_FAILED');
      return finish('prepared');
    }
    check(state.steps.prepare === 'complete' && await sdkInstalled(context.production), 'PREPARE_REQUIRED');
    if (action === 'candidate') {
      if (hasCandidate && state.steps.candidate === 'complete') return { schema: 'cnb-release-session-result/v1', status: 'candidate', reused: true };
      await start();
      const scratch = join(spec.session_dir, `.candidate-${randomUUID()}`); await mkdir(scratch, { mode: 0o700 });
      const annotations = hasCandidate ? json(await safeRead(join(spec.session_dir, 'candidate/annotations.json'), true)) : await annotationGet(context, fetchImpl);
      await writeFile(join(scratch, 'annotations.json'), JSON.stringify(annotations), { mode: 0o600, flag: 'wx' });
      const token = await tokenFrom(spec.cnb_token_file);
      await execute('python3', [join(spec.bundle_dir, 'ci/candidate_gate.py'), 'production', '--config', join(spec.bundle_dir, 'ci-config.json'),
        '--tag', spec.candidate_tag, '--commit', spec.application_commit, '--branch', context.config.production_branch,
        '--annotations', join(scratch, 'annotations.json'), '--output-dir', scratch, '--phase', 'readiness'],
      { cwd: spec.project_dir, env: { ...cleanEnvironment(), CNB_TOKEN: token }, timeout: 150000, maxBuffer: 1024 * 1024 });
      const raw = context.contract.decodeBase64url(annotations.production_readiness_b64url);
      await writeFile(join(scratch, 'readiness.json'), raw, { mode: 0o600, flag: 'wx' });
      // Validate before publishing the directory, retaining canonical raw bytes.
      const { candidateRaw } = await materials(context, now, false, scratch);
      if (hasCandidate) check((await safeRead(join(spec.session_dir, 'candidate/candidate.json'), true)).equals(candidateRaw), 'CANDIDATE_CHANGED');
      else await rename(scratch, join(spec.session_dir, 'candidate'));
      await materials(context, now);
      await record(['candidate/annotations.json', 'candidate/candidate.json', 'candidate/readiness.json']); return finish('candidate');
    }
    check(hasCandidate, 'CANDIDATE_REQUIRED');
    if (action === 'sign') {
      check(authorized, 'PRODUCTION_AUTHORIZATION_REQUIRED');
      // The signer performs only a TAT read and a create-only local write. With
      // no envelope under this lock, retrying still re-verifies live readiness.
      const inputs = await materials(context, now, hasApproval); await start();
      let result;
      try {
        const client = await productionClient(context, createClient);
        if (hasApproval) {
          const verified = await context.runner.verifyProductionReadiness({ ...inputs, binding: context.binding, client });
          check(context.contract.canonicalBytes(verified.receipt).equals(context.contract.canonicalBytes(inputs.readiness)), 'READINESS_CHANGED');
          const approvalRaw = await safeRead(join(spec.session_dir, 'approval.json'), true);
          result = { approval_id: context.contract.verifyApproval(inputs.approval, context.publicKey).approval_id, approval_sha256: hash(approvalRaw), readiness_invocation_id: inputs.invocationId };
        } else {
          const signed = await context.signer.approveProduction({ ...inputs, binding: context.binding, client, privateKeyPath: spec.approval_private_key,
            output: join(spec.session_dir, 'approval.json'), authorized, now });
          result = { approval_id: signed.approval_id, approval_sha256: signed.approval_sha256, readiness_invocation_id: signed.readiness_invocation_id };
        }
        await materials(context, now, true);
      } catch { fail('SIGN_FAILED'); }
      await atomicJson(join(spec.session_dir, 'sign-result.json'), result); await record(['approval.json', 'sign-result.json']); return finish('signed', result);
    }
    const inputs = await materials(context, now, true);
    // Even an already published state must pass the standard live readback.
    await start();
    let result;
    try { result = await context.publisher.publishProductionApproval({ ...inputs, now, apply: true, token: await tokenFrom(spec.cnb_token_file), fetchImpl }); }
    catch { fail('PUBLICATION_FAILED'); }
    const publicationPath = join(spec.session_dir, 'publication-result.json');
    if (await exists(publicationPath)) {
      const previous = json(await safeRead(publicationPath, true));
      check(['schema', 'status', 'candidate_tag', 'approval_id', 'approval_sha256', 'endpoint'].every(key => previous[key] === result[key]), 'PUBLICATION_EVIDENCE_CHANGED');
    } else await atomicJson(publicationPath, result);
    // Preserve the first successful receipt across later zero-write readbacks;
    // otherwise a crash between receipt replacement and state save creates drift.
    await record(['publication-result.json']); return finish(result.status, { approval_id: result.approval_id, writes: result.writes });
  } catch (error) {
    const safe = error instanceof SessionError ? error : new SessionError('SESSION_STEP_FAILED');
    if (apply && lock && state) { state.events.push({ action, status: 'stopped', code: safe.code, at: stamp(now) }); state.updated_at = stamp(now); await atomicJson(statePath, state).catch(() => {}); }
    throw safe;
  } finally { if (lock) await changeLock(lockPath, 'release', lock); }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') { process.stdout.write('Usage: node scripts/release-session.mjs <prepare|candidate|sign|publish|status> --spec <absolute protected JSON> [--apply] [--authorize-production-apply]\nDefault preview is offline. sign --apply requires explicit production authorization. Keep the same spec and session directory across retries.\n'); return; }
  const action = args.shift(), options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i]; check(['--spec', '--apply', '--authorize-production-apply'].includes(key) && !Object.hasOwn(options, key), 'ARGUMENTS_INVALID');
    options[key] = key === '--spec' ? args[++i] : true;
  }
  check(!options['--authorize-production-apply'] || action === 'sign' && options['--apply'], 'ARGUMENTS_INVALID');
  const result = await runSession({ action, specPath: options['--spec'], apply: options['--apply'] === true, authorized: options['--authorize-production-apply'] === true });
  process.stdout.write(JSON.stringify(result) + '\n');
}
const invokedPath = process.argv[1] ? await realpath(resolve(process.argv[1])).catch(() => null) : null;
if (invokedPath === await realpath(fileURLToPath(import.meta.url))) main().catch(error => {
  process.stderr.write(JSON.stringify({ status: 'stopped', code: error instanceof SessionError ? error.code : 'SESSION_INPUT_INVALID' }) + '\n'); process.exitCode = 1;
});
