#!/usr/bin/env node
/** Historical test proof from a locked candidate bundle and read-only TAT APIs.
 * The saved annotated Tag is evidence; no current CNB ref or annotation is read.
 */
import { constants } from 'node:fs';
import { lstat, realpath, open, mkdir, link, unlink, rm, readdir } from 'node:fs/promises';
import { dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';

const SDK = 'tencentcloud-sdk-nodejs-tat';
const SPEC_KEYS = ['schema', 'project', 'environment', 'project_dir', 'bundle_dir', 'bundle_lock_sha256', 'output_dir',
  'candidate_tag', 'application_commit', 'invocation_id', 'candidate', 'tag_object', 'binding', 'tat_credentials_file'];
const FILES = ['candidate.json', 'candidate-tag.raw', 'binding.json', 'describe-commands.json', 'describe-invocation-tasks.json', 'release-receipt.json'];
const REQUIRED_BUNDLE = ['ci-config.json', 'ci/candidate_manifest.py', 'ci/release-request.mjs', 'ci/run-tat-release.mjs',
  'dependencies/package.json', 'dependencies/package-lock.json'];
const loadedBundles = new Map();
const digest = raw => createHash('sha256').update(raw).digest('hex');
const bytes = value => Buffer.from(JSON.stringify(value) + '\n');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value);
class VerificationError extends Error { constructor(code) { super(code); this.code = code; } }
const check = (value, code) => { if (!value) throw new VerificationError(code); };
function json(raw) {
  try { return parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(raw), { maxBytes: 2 * 1024 * 1024 }); }
  catch { throw new VerificationError('JSON_INVALID'); }
}
function absolute(value) {
  check(matches(value, /^[^\x00-\x1f\x7f]{1,4096}$/) && isAbsolute(value) && resolve(value) === value, 'PATH_INVALID');
  return value;
}
const within = (base, path) => {
  const name = relative(base, path);
  return name === '' || name !== '..' && !name.startsWith('../') && !isAbsolute(name);
};
const exists = async path => { try { await lstat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };

async function directory(path, privateMode = false) {
  check(await realpath(absolute(path)) === path, 'DIRECTORY_UNSAFE');
  for (let current = path; ; current = dirname(current)) {
    const info = await lstat(current), sticky = current !== path && info.uid === 0 && (info.mode & 0o1000) !== 0;
    check(info.isDirectory() && !info.isSymbolicLink() && [0, process.getuid()].includes(info.uid)
      && (!(info.mode & 0o022) || sticky), 'DIRECTORY_UNSAFE');
    if (current === path && privateMode) check(info.uid === process.getuid() && (info.mode & 0o7777) === 0o700, 'PRIVATE_DIRECTORY_UNSAFE');
    if (current === parse(current).root) break;
  }
}

async function read(path, privateMode = true, limit = 2 * 1024 * 1024) {
  absolute(path); await directory(dirname(path), privateMode);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await handle.stat();
    check(before.isFile() && before.nlink === 1 && [0, process.getuid()].includes(before.uid) && !(before.mode & 0o022)
      && before.size > 0 && before.size <= limit, 'FILE_UNSAFE');
    if (privateMode) check(before.uid === process.getuid() && (before.mode & 0o7777) === 0o600, 'PRIVATE_FILE_UNSAFE');
    const raw = await handle.readFile(), after = await handle.stat(), named = await lstat(path);
    check(!named.isSymbolicLink() && before.ino === named.ino && before.dev === named.dev && before.size === raw.length
      && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'FILE_CHANGED');
    return raw;
  } finally { await handle?.close(); }
}

async function writeNew(path, raw) {
  const handle = await open(path, 'wx', 0o600);
  try { await handle.writeFile(raw); await handle.sync(); } finally { await handle.close(); }
}
async function syncDirectory(path) {
  const handle = await open(path, 'r'); try { await handle.sync(); } finally { await handle.close(); }
}

async function verifyBundle(spec) {
  const base = spec.bundle_dir, lockRaw = await read(join(base, 'artifact-lock.json'), false);
  check(digest(lockRaw) === spec.bundle_lock_sha256, 'BUNDLE_CHANGED');
  const lock = json(lockRaw);
  check(exact(lock, ['schema', 'version', 'files']) && lock.schema === 'cnb-devops-artifacts/v1' && object(lock.files)
    && REQUIRED_BUNDLE.every(name => Object.hasOwn(lock.files, name)), 'BUNDLE_LOCK_INVALID');
  for (const [name, hash] of Object.entries(lock.files)) {
    check(matches(name, /^[A-Za-z0-9._/-]+$/) && !isAbsolute(name) && name.split('/').every(part => part && part !== '.' && part !== '..')
      && matches(hash, /^[0-9a-f]{64}$/), 'BUNDLE_LOCK_INVALID');
    check(digest(await read(join(base, name), false, 8 * 1024 * 1024)) === hash, 'BUNDLE_CHANGED');
  }
}

// The pinned Python validator consumes the already checked bytes on stdin.
// No candidate/private content is placed in process arguments or error output.
const CANDIDATE_CHECK = `import base64,importlib.util,json,sys
spec=importlib.util.spec_from_file_location('candidate_manifest',sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
value=json.load(sys.stdin)
module.parse_manifest(base64.b64decode(value['candidate']),json.loads(base64.b64decode(value['config'])),value['tag'],value['commit'])
`;
async function validateCandidate(spec, candidateRaw, configRaw) {
  await new Promise((done, reject) => {
    const child = spawn('python3', ['-I', '-B', '-c', CANDIDATE_CHECK, join(spec.bundle_dir, 'ci/candidate_manifest.py')],
      { stdio: ['pipe', 'ignore', 'ignore'], env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: '1' } });
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    child.once('error', () => { clearTimeout(timer); reject(new VerificationError('CANDIDATE_INVALID')); });
    child.once('exit', code => { clearTimeout(timer); code === 0 ? done() : reject(new VerificationError('CANDIDATE_INVALID')); });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify({ candidate: candidateRaw.toString('base64'), config: configRaw.toString('base64'), tag: spec.candidate_tag, commit: spec.application_commit }));
  });
}

function savedTag(raw, candidateRaw, spec) {
  const split = raw.indexOf('\n\n');
  check(split > 0 && raw.subarray(split + 2).equals(candidateRaw), 'SAVED_TAG_MESSAGE_MISMATCH');
  const header = raw.subarray(0, split), text = header.toString('utf8');
  check(Buffer.from(text).equals(header) && !/[\x00-\x09\x0b-\x1f\x7f]/.test(text), 'SAVED_TAG_INVALID');
  const lines = text.split('\n');
  check((lines.length === 3 || lines.length === 4) && lines[0] === `object ${spec.application_commit}` && lines[1] === 'type commit'
    && lines[2] === `tag ${spec.candidate_tag}` && (lines.length === 3 || /^tagger .+$/.test(lines[3])), 'SAVED_TAG_IDENTITY_MISMATCH');
}

function utc(value) {
  check(matches(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/), 'EXECUTION_TIME_INVALID');
  const time = Date.parse(value);
  check(Number.isFinite(time) && new Date(time).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z'), 'EXECUTION_TIME_INVALID');
  return time;
}

async function context(specPath) {
  const specRaw = await read(absolute(specPath)), spec = json(specRaw);
  check(exact(spec, [...SPEC_KEYS, ...(Object.hasOwn(spec, 'sdk_root') ? ['sdk_root'] : [])])
    && spec.schema === 'cnb-test-deployment-verification-spec/v1' && spec.environment === 'test'
    && matches(spec.project, /^[a-z][a-z0-9-]{0,62}$/) && matches(spec.application_commit, /^[0-9a-f]{40}$/)
    && matches(spec.bundle_lock_sha256, /^[0-9a-f]{64}$/) && matches(spec.candidate_tag, /^[a-z][a-z0-9-]{0,191}$/)
    && matches(spec.invocation_id, /^inv-[A-Za-z0-9-]{8,64}$/), 'SPEC_INVALID');
  for (const key of ['project_dir', 'bundle_dir', 'output_dir', 'tat_credentials_file', ...(Object.hasOwn(spec, 'sdk_root') ? ['sdk_root'] : [])]) absolute(spec[key]);
  await directory(spec.project_dir);
  check(spec.bundle_dir !== spec.project_dir && within(spec.project_dir, spec.bundle_dir), 'BUNDLE_OUTSIDE_PROJECT');
  const inputPaths = [specPath, spec.tat_credentials_file], raw = {};
  for (const [key, name] of [['candidate', 'candidate.json'], ['tag_object', 'candidate-tag.raw'], ['binding', 'binding.json']]) {
    const reference = spec[key];
    check(exact(reference, ['path', 'sha256']) && matches(reference.sha256, /^[0-9a-f]{64}$/), 'REFERENCE_INVALID');
    inputPaths.push(absolute(reference.path));
    raw[name] = await read(reference.path);
    check(digest(raw[name]) === reference.sha256, 'EVIDENCE_HASH_MISMATCH');
  }
  check(new Set([...inputPaths, spec.output_dir]).size === inputPaths.length + 1
    && [...inputPaths, spec.output_dir].every(path => !within(spec.project_dir, path))
    && inputPaths.every(path => !within(spec.output_dir, path)), 'PRIVATE_PATH_CONFLICT');
  await directory(await exists(spec.output_dir) ? spec.output_dir : dirname(spec.output_dir), true);
  await verifyBundle(spec);
  const configRaw = await read(join(spec.bundle_dir, 'ci-config.json'), false), config = json(configRaw);
  check(config.project === spec.project && config.environment === 'test', 'INPUT_SCOPE_INVALID');
  await validateCandidate(spec, raw['candidate.json'], configRaw);
  savedTag(raw['candidate-tag.raw'], raw['candidate.json'], spec);
  const candidate = json(raw['candidate.json']), binding = json(raw['binding.json']);
  check(['runtime', 'public'].every(key => candidate.evidence[key].reference === `tat:${spec.invocation_id}`), 'CANDIDATE_INVOCATION_MISMATCH');
  // ESM caches the complete dependency graph by file URL. A caller must start a
  // fresh process to use different pinned bytes at an already imported path.
  check(!loadedBundles.has(spec.bundle_dir) || loadedBundles.get(spec.bundle_dir) === spec.bundle_lock_sha256, 'BUNDLE_CHANGED');
  loadedBundles.set(spec.bundle_dir, spec.bundle_lock_sha256);
  const request = await import(pathToFileURL(join(spec.bundle_dir, 'ci/release-request.mjs')));
  const tat = await import(pathToFileURL(join(spec.bundle_dir, 'ci/run-tat-release.mjs')));
  try { tat.validateBinding(binding, config); } catch { throw new VerificationError('BINDING_INVALID'); }
  const encoded = request.renderReleaseRequest({ schema: 'cnb-release-request/v1', project: spec.project, environment: 'test', controller: candidate.controller,
    git_sha: spec.application_commit, controller_commit: spec.application_commit, build_id: candidate.build_id, images: candidate.services }, config);
  const inputHash = digest(bytes({ spec_sha256: digest(specRaw), candidate: spec.candidate.sha256, tag_object: spec.tag_object.sha256, binding: spec.binding.sha256 }));
  return { spec, specRaw, specPath, raw, candidate, binding, config, request, tat, encoded, inputHash };
}

async function verifyEvidence(ctx, evidence, verifiedAt, now) {
  const { spec, candidate, binding, config, request, tat } = ctx;
  const commands = json(evidence['describe-commands.json']), tasks = json(evidence['describe-invocation-tasks.json']);
  const task = tasks?.InvocationTaskSet?.[0], start = utc(task?.TaskResult?.ExecStartTime), end = utc(task?.TaskResult?.ExecEndTime);
  const created = utc(candidate.created_at), verified = utc(verifiedAt);
  check(start <= end && end <= created && created <= verified && verified <= now && Number.isFinite(now), 'EXECUTION_WINDOW_INVALID');
  let result;
  try {
    result = await tat.verifyTatInvocation({ client: { DescribeCommands: async () => commands, DescribeInvocationTasks: async () => tasks },
      request: ctx.encoded, config, binding, invocationId: spec.invocation_id,
      parseRequest: request.parseReleaseRequest, receiptValidator: request.validateReleaseReceipt });
  } catch { throw new VerificationError('TAT_EVIDENCE_INVALID'); }
  const releaseRaw = Buffer.from(task.TaskResult.Output, 'base64');
  check(releaseRaw.equals(evidence['release-receipt.json']) && digest(releaseRaw) === candidate.release_receipt_sha256, 'RELEASE_RECEIPT_HASH_MISMATCH');
  check(bytes(result.receipt).equals(releaseRaw), 'RELEASE_RECEIPT_ENCODING_INVALID');
  return { schema: 'cnb-test-deployment-verification/v1', status: 'verified', project: spec.project, environment: 'test',
    application_commit: candidate.application_commit, build_id: candidate.build_id, candidate_tag: candidate.candidate_tag,
    invocation_id: spec.invocation_id, verified_at: verifiedAt, images: candidate.services, controller: candidate.controller,
    verification_scope: 'historical_completed_deployment', current_runtime_verified: false,
    execution_started_at: task.TaskResult.ExecStartTime, execution_finished_at: task.TaskResult.ExecEndTime, candidate_created_at: candidate.created_at,
    region: binding.region, instance_id: binding.instance_id, command_id: binding.command_id,
    candidate_manifest_sha256: candidate.manifest_sha256, candidate_bytes_sha256: digest(ctx.raw['candidate.json']),
    tag_object_sha256: digest(ctx.raw['candidate-tag.raw']), binding_sha256: digest(ctx.raw['binding.json']), release_receipt_sha256: digest(releaseRaw),
    controller_program_sha256: config.controller_program_sha256, controller_compose_sha256: config.controller_compose_sha256, policy_sha256: config.policy_sha256,
    bundle_lock_sha256: spec.bundle_lock_sha256, verification_spec_sha256: digest(ctx.specRaw), input_sha256: ctx.inputHash,
    saved_tag_verified: true, current_tag_status: 'not_checked', current_annotations_status: 'not_checked', evidence_base: 'receipt_directory',
    evidence: FILES.map(path => ({ path, sha256: digest(evidence[path]) })) };
}

async function existing(ctx, now) {
  const out = ctx.spec.output_dir;
  check(isDeepStrictEqual((await readdir(out)).sort(), [...FILES, 'receipt.json'].sort()), 'EVIDENCE_FILES_CHANGED');
  const receiptRaw = await read(join(out, 'receipt.json')), receipt = json(receiptRaw), evidence = {};
  for (const name of FILES) evidence[name] = await read(join(out, name));
  for (const name of Object.keys(ctx.raw)) check(evidence[name].equals(ctx.raw[name]), 'EVIDENCE_CHANGED');
  const expected = await verifyEvidence(ctx, evidence, receipt.verified_at, now);
  check(isDeepStrictEqual(receipt, expected) && bytes(expected).equals(receiptRaw), 'VERIFICATION_RECEIPT_CHANGED');
  return { status: 'verified', reused: true, receipt };
}

async function cloudClient(ctx) {
  const { spec, tat, binding } = ctx, raw = await read(spec.tat_credentials_file, true, 65536);
  let credential;
  try {
    credential = json(raw);
    check(object(credential) && Object.keys(credential).every(k => ['secretId', 'secretKey', 'token'].includes(k)), 'TAT_CREDENTIALS_INVALID');
    tat.createTatClientOptions({ ...credential, region: binding.region });
  } finally { raw.fill(0); }
  try {
    const base = spec.sdk_root ?? join(spec.bundle_dir, 'dependencies');
    const pinned = json(await read(join(spec.bundle_dir, 'dependencies/package.json'), false));
    const manifest = json(await read(join(base, 'package.json'), false)), lock = json(await read(join(base, 'package-lock.json'), false));
    const version = pinned.dependencies?.[SDK];
    check(matches(version, /^\d+\.\d+\.\d+$/) && manifest.dependencies?.[SDK] === version
      && lock.packages?.[`node_modules/${SDK}`]?.version === version, 'SDK_LOCK_INVALID');
    const require = createRequire(join(base, 'package.json')), packagePath = join(base, 'node_modules', SDK, 'package.json');
    check(await realpath(require.resolve(`${SDK}/package.json`)) === packagePath
      && json(await read(packagePath, false)).version === version, 'SDK_VERSION_MISMATCH');
    const Client = require(SDK)?.tat?.v20201028?.Client;
    check(typeof Client === 'function', 'SDK_UNAVAILABLE');
    return new Client(tat.createTatClientOptions({ ...credential, region: binding.region }));
  } catch (error) {
    if (['MODULE_NOT_FOUND', 'ENOENT'].includes(error.code)) throw new VerificationError('SDK_UNAVAILABLE');
    throw error;
  }
}

/** client is injectable at the external API boundary; the CLI always pins its SDK. */
export async function verifyTestDeployment({ specPath, apply = false, client, now = Date.now }) {
  const ctx = await context(specPath), { spec } = ctx;
  if (await exists(spec.output_dir)) return existing(ctx, now());
  if (!apply) return { status: 'preview', reused: false, project: spec.project, environment: 'test',
    application_commit: spec.application_commit, candidate_tag: spec.candidate_tag, invocation_id: spec.invocation_id,
    current_tag_status: 'not_checked', current_annotations_status: 'not_checked', current_runtime_verified: false };
  check(!process.env.NODE_DEBUG && !process.env.NODE_DEBUG_NATIVE && !process.env.NODE_OPTIONS, 'TAT_DEBUG_ENV_REFUSED');
  const lockPath = join(dirname(spec.output_dir), '.' + parse(spec.output_dir).base + '.verification.lock');
  let lock, staging;
  try {
    try { lock = await open(lockPath, 'wx', 0o600); } catch { throw new VerificationError('VERIFICATION_LOCKED'); }
    if (await exists(spec.output_dir)) return existing(ctx, now());
    const remote = client ?? await cloudClient(ctx), evidence = { ...ctx.raw };
    // Only these two read operations are exposed to the fixed verifier.
    const reader = Object.fromEntries([['DescribeCommands', 'describe-commands.json'], ['DescribeInvocationTasks', 'describe-invocation-tasks.json']].map(([action, name]) =>
      [action, async input => { const value = await remote[action](input); evidence[name] = bytes(value); return json(evidence[name]); }]));
    try {
      await ctx.tat.verifyTatInvocation({ client: reader, request: ctx.encoded, config: ctx.config, binding: ctx.binding, invocationId: spec.invocation_id,
        parseRequest: ctx.request.parseReleaseRequest, receiptValidator: ctx.request.validateReleaseReceipt });
    } catch { throw new VerificationError('TAT_READBACK_FAILED'); }
    const tasks = json(evidence['describe-invocation-tasks.json']);
    evidence['release-receipt.json'] = Buffer.from(tasks.InvocationTaskSet[0].TaskResult.Output, 'base64');
    const verifiedNow = now(), receipt = await verifyEvidence(ctx, evidence, new Date(verifiedNow).toISOString(), verifiedNow);
    // Revalidate the complete source selection before publishing any evidence.
    const fresh = await context(specPath); check(fresh.inputHash === ctx.inputHash, 'INPUT_CHANGED');
    check(!await exists(spec.output_dir), 'OUTPUT_CHANGED');
    staging = join(dirname(spec.output_dir), '.' + parse(spec.output_dir).base + '.' + randomUUID() + '.pending');
    await mkdir(staging, { mode: 0o700 });
    for (const [name, raw] of Object.entries({ ...evidence, 'receipt.json': bytes(receipt) })) await writeNew(join(staging, name), raw);
    await syncDirectory(staging);
    // Reserve the final directory exclusively, then publish complete files with
    // no-replace links. The receipt is last; interrupted output stays incomplete
    // and cannot be overwritten or trigger another remote query on a repeat.
    try { await mkdir(spec.output_dir, { mode: 0o700 }); } catch (error) {
      if (error.code === 'EEXIST') throw new VerificationError('OUTPUT_CHANGED');
      throw error;
    }
    for (const name of [...FILES, 'receipt.json']) {
      await link(join(staging, name), join(spec.output_dir, name));
      await unlink(join(staging, name));
    }
    await syncDirectory(spec.output_dir); await syncDirectory(dirname(spec.output_dir));
    return { ...(await existing(ctx, now())), reused: false };
  } finally {
    if (staging) await rm(staging, { recursive: true, force: true });
    if (lock) { await lock.close(); await unlink(lockPath); }
  }
}

async function main(args = process.argv.slice(2)) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]; check(['--spec', '--apply'].includes(arg) && !Object.hasOwn(options, arg), 'ARGUMENTS_INVALID');
    if (arg === '--apply') options[arg] = true;
    else { check(typeof args[i + 1] === 'string' && !args[i + 1].startsWith('--'), 'ARGUMENTS_INVALID'); options[arg] = args[++i]; }
  }
  check(typeof options['--spec'] === 'string', 'ARGUMENTS_INVALID');
  const result = await verifyTestDeployment({ specPath: options['--spec'], apply: !!options['--apply'] });
  const source = result.receipt ?? result, safe = {};
  for (const key of ['project', 'environment', 'application_commit', 'build_id', 'candidate_tag', 'invocation_id', 'verified_at',
    'verification_scope', 'current_runtime_verified', 'current_tag_status', 'current_annotations_status']) if (Object.hasOwn(source, key)) safe[key] = source[key];
  process.stdout.write(JSON.stringify({ status: result.status, reused: result.reused, ...safe }) + '\n');
}
if (process.argv[1] && await realpath(process.argv[1]).catch(() => null) === fileURLToPath(import.meta.url)) main().catch(error => {
  process.stderr.write(JSON.stringify({ status: 'stopped', code: error instanceof VerificationError ? error.code : 'TEST_VERIFICATION_FAILED' }) + '\n');
  process.exitCode = 1;
});
