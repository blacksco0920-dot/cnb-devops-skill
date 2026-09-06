#!/usr/bin/env node
// Administrator setup only. Never invokes, modifies, or deletes a command.
// Official API 2020-10-28: https://cloud.tencent.com/document/api/1340/52684
// DescribeCommands: https://cloud.tencent.com/document/api/1340/52681
// Install the bundle's pinned dependencies with npm ci --ignore-scripts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';

const SDK = 'tencentcloud-sdk-nodejs-tat', SDK_VERSION = '4.1.241';
const fail = code => { throw new Error(code); };
const hash = value => createHash('sha256').update(value).digest('hex');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function keys(value, expected) {
  if (!object(value) || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail('TAT_SPEC_INVALID');
}
function requireMatch(value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) fail('TAT_SPEC_INVALID');
}
export function validateSpec(spec) {
  const hasArtifacts = object(spec) && Object.hasOwn(spec, 'expected_artifacts');
  keys(spec, ['schema_version', 'project', 'environment', 'version', 'target', 'expectedCommand',
    ...(hasArtifacts ? ['expected_artifacts'] : [])]);
  if (spec.schema_version !== 1 || !['test', 'staging', 'production'].includes(spec.environment)) fail('TAT_SPEC_INVALID');
  requireMatch(spec.project, /^[a-z][a-z0-9-]{0,62}$/);
  requireMatch(spec.version, /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-zA-Z0-9.-]+)?$/);
  keys(spec.target, ['region', 'instance_id']);
  requireMatch(spec.target.region, /^[a-z]{2,8}-[a-z][a-z0-9-]{1,29}$/);
  requireMatch(spec.target.instance_id, /^(?:lhins|ins|mi)-[a-z0-9]{4,32}$/);
  const c = spec.expectedCommand;
  keys(c, ['CommandName', 'Description', 'CommandType', 'Content', 'Username', 'WorkingDirectory',
    'Timeout', 'EnableParameter', 'DefaultParameters', 'DefaultParameterConfs']);
  requireMatch(c.CommandName, /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/);
  if (Buffer.byteLength(c.CommandName) > 60 || !c.CommandName.endsWith(`-v${spec.version}`)) fail('TAT_SPEC_INVALID');
  if (typeof c.Description !== 'string' || [...c.Description].length > 120 || /[\x00-\x1f\x7f]/.test(c.Description)) fail('TAT_SPEC_INVALID');
  if (c.CommandType !== 'SHELL' || typeof c.Content !== 'string' || !c.Content.trim() ||
      /\0|\r/.test(c.Content) || Buffer.from(c.Content).toString('utf8') !== c.Content ||
      Buffer.byteLength(Buffer.from(c.Content).toString('base64')) > 65536) fail('TAT_SPEC_INVALID');
  requireMatch(c.Username, /^[a-z_][a-z0-9_-]{0,31}$/);
  requireMatch(c.WorkingDirectory, /^\/(?:[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*)?$/);
  if (c.WorkingDirectory.split('/').some(part => part === '.' || part === '..') ||
      !Number.isInteger(c.Timeout) || c.Timeout < 1 || c.Timeout > 86400 ||
      typeof c.EnableParameter !== 'boolean') fail('TAT_SPEC_INVALID');
  keys(c.DefaultParameters, c.EnableParameter ? ['release_request_b64url'] : []);
  if (c.EnableParameter && c.DefaultParameters.release_request_b64url !== 'INVALID') fail('TAT_SPEC_INVALID');
  const expectedConfs = c.EnableParameter ? [{ ParameterName: 'release_request_b64url', ParameterValue: 'INVALID', ParameterDescription: '' }] : [];
  if (canonical(c.DefaultParameterConfs) !== canonical(expectedConfs)) fail('TAT_SPEC_INVALID');
  if (hasArtifacts) {
    keys(spec.expected_artifacts, ['program_sha256', 'compose_sha256', 'policy_sha256']);
    for (const value of Object.values(spec.expected_artifacts)) requireMatch(value, /^[a-f0-9]{64}$/);
    for (const [field, variable] of [['program_sha256', 'controller_sha256'], ['policy_sha256', 'policy_sha256']]) {
      const assignments = c.Content.split('\n').filter(line => line.startsWith(`${variable}=`));
      if (assignments.length !== 1 || assignments[0] !== `${variable}='${spec.expected_artifacts[field]}'`) fail('TAT_ARTIFACT_BINDING_MISMATCH');
    }
    // The generator hashes the policy's exact bytes, which contain compose_sha256.
    // This CLI has no policy/host input: these are expected identities, not attestation.
  }
  // Template substitution is not a shell-escaping or authorization guarantee.
  return spec;
}
function metadata(c) {
  return { CommandName: c.CommandName, Description: c.Description, CommandType: c.CommandType,
    ContentSha256: hash(c.Content), Username: c.Username, WorkingDirectory: c.WorkingDirectory,
    Timeout: c.Timeout, EnableParameter: c.EnableParameter, DefaultParameters: c.DefaultParameters,
    CreatedBy: 'USER', OutputCOSBucketUrl: '', OutputCOSKeyPrefix: '',
    DefaultParameterConfs: c.DefaultParameterConfs, Tags: [], Scenes: [] };
}
function verifyCommand(command, expected, id) {
  if (!object(command) || !/^cmd-[a-z0-9]{4,32}$/.test(command.CommandId) ||
      (id && command.CommandId !== id) || typeof command.Content !== 'string') fail('TAT_COMMAND_DRIFT');
  const bytes = Buffer.from(command.Content, 'base64');
  if (bytes.toString('base64') !== command.Content || !bytes.equals(Buffer.from(expected.Content))) fail('TAT_COMMAND_DRIFT');
  let defaults;
  try { defaults = command.DefaultParameters ? JSON.parse(command.DefaultParameters) : {}; }
  catch { fail('TAT_COMMAND_DRIFT'); }
  if (expected.EnableParameter && command.DefaultParameters !== canonical(expected.DefaultParameters)) fail('TAT_COMMAND_DRIFT');
  const actual = { ...command, ContentSha256: hash(bytes), DefaultParameters: defaults };
  const wanted = metadata(expected);
  for (const key of Object.keys(wanted)) {
    // TAT omits or returns null for unused optional collections/log destinations.
    const fallback = ['Tags', 'Scenes', 'DefaultParameterConfs'].includes(key) ? [] : '';
    const value = actual[key] ?? (['OutputCOSBucketUrl', 'OutputCOSKeyPrefix', 'Tags', 'Scenes', 'DefaultParameterConfs'].includes(key) ? fallback : undefined);
    if (canonical(value) !== canonical(wanted[key])) fail('TAT_COMMAND_DRIFT');
  }
  return command.CommandId;
}
function safeDirectory(input) {
  const absolute = path.resolve(input);
  for (let p = absolute;; p = path.dirname(p)) {
    const st = fs.lstatSync(p);
    const stickyAncestor = p !== absolute && st.uid === 0 && (st.mode & 0o1000) !== 0;
    if (!st.isDirectory() || st.isSymbolicLink() || ![0, process.getuid()].includes(st.uid) ||
        ((st.mode & 0o022) && !stickyAncestor)) fail('TAT_PATH_UNSAFE');
    if (p === path.dirname(p)) break;
  }
  return absolute;
}
function outputAvailable(output) {
  if (typeof output !== 'string' || !output) fail('TAT_OUTPUT_REQUIRED');
  const filename = path.resolve(output);
  safeDirectory(path.dirname(filename));
  try { fs.lstatSync(filename); fail('TAT_OUTPUT_EXISTS'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return filename;
}
function writeExclusive(filename, result) {
  const temp = `${filename}.${randomBytes(12).toString('hex')}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, `${canonical(result)}\n`);
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.linkSync(temp, filename); // Atomic publish, never replaces an existing path.
    fs.unlinkSync(temp);
    const dir = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } catch { fail('TAT_OUTPUT_WRITE_FAILED'); }
  finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') fail('TAT_OUTPUT_WRITE_FAILED'); }
  }
}
async function describe(client, request) {
  let response;
  try { response = await client.DescribeCommands({ ...request, Limit: 100, Offset: 0 }); }
  catch { fail('TAT_QUERY_FAILED'); }
  if (!object(response) || !Number.isInteger(response.TotalCount) || response.TotalCount < 0 ||
      !Array.isArray(response.CommandSet) || response.TotalCount !== response.CommandSet.length ||
      response.TotalCount > 1) fail('TAT_QUERY_AMBIGUOUS');
  return response.CommandSet;
}
export async function configureTat({ spec, apply = false, client, output }) {
  validateSpec(spec);
  if (typeof apply !== 'boolean') fail('TAT_APPLY_INVALID');
  const filename = output ? outputAvailable(output) : undefined;
  if (apply && !filename) fail('TAT_OUTPUT_REQUIRED');
  const c = spec.expectedCommand, meta = metadata(c);
  const result = { schema: 'cnb-tat-binding/v1', project: spec.project, environment: spec.environment,
    version: spec.version, region: spec.target.region, instance_id: spec.target.instance_id,
    command_name: c.CommandName, command_sha256: meta.ContentSha256,
    command_metadata_sha256: hash(`${canonical(meta)}\n`), metadata: meta,
    username: c.Username, working_directory: c.WorkingDirectory, timeout: c.Timeout,
    configuration_only: true, target_verified: false, deployment_ready: false,
    artifacts_status: spec.expected_artifacts ? 'expected_not_host_verified' : 'not_supplied',
    ...(spec.expected_artifacts || {}), status: 'planned' };
  if (apply) {
    if (!client || typeof client.DescribeCommands !== 'function') fail('TAT_CLIENT_REQUIRED');
    const filter = { Filters: [{ Name: 'command-name', Values: [c.CommandName] }] };
    const existing = await describe(client, filter);
    let id;
    if (existing.length) id = verifyCommand(existing[0], c);
    else {
      const request = { ...c, Content: Buffer.from(c.Content).toString('base64') };
      // CreateCommand 不允许同时发送两种参数表示；显式保留唯一参数的空描述。
      delete request.DefaultParameters;
      if (!c.EnableParameter) delete request.DefaultParameterConfs;
      // A timeout may follow successful server-side creation. Never retry a write here.
      let created;
      try { created = await client.CreateCommand(request); } catch { fail('TAT_CREATE_UNCERTAIN'); }
      if (!object(created) || !/^cmd-[a-z0-9]{4,32}$/.test(created.CommandId)) fail('TAT_CREATE_UNCERTAIN');
      id = created.CommandId;
      const readback = await describe(client, { CommandIds: [id] });
      if (readback.length !== 1) fail('TAT_READBACK_INCOMPLETE');
      verifyCommand(readback[0], c, id);
      const byName = await describe(client, filter);
      if (byName.length !== 1) fail('TAT_READBACK_INCOMPLETE');
      verifyCommand(byName[0], c, id);
    }
    Object.assign(result, { status: 'verified', command_id: id });
  }
  if (filename) writeExclusive(filename, result);
  return result;
}
function readJson(filename, secret = false) {
  safeDirectory(path.dirname(path.resolve(filename)));
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || ![0, process.getuid()].includes(st.uid) ||
        (st.mode & 0o022) || (secret && (st.mode & 0o777) !== 0o600) || st.size > 1024 * 1024) fail('TAT_INPUT_UNSAFE');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}
function credentials(filename) {
  const value = filename ? readJson(filename, true) : {
    secretId: process.env.TENCENTCLOUD_SECRET_ID, secretKey: process.env.TENCENTCLOUD_SECRET_KEY,
    ...(process.env.TENCENTCLOUD_TOKEN ? { token: process.env.TENCENTCLOUD_TOKEN } : {}),
  };
  if (!object(value) || Object.keys(value).some(key => !['secretId', 'secretKey', 'token'].includes(key)) ||
      ['secretId', 'secretKey'].some(key => typeof value[key] !== 'string' || !value[key] || /\s/.test(value[key])) ||
      (value.token !== undefined && (typeof value.token !== 'string' || !value.token || /\s/.test(value.token)))) fail('TAT_CREDENTIALS_INVALID');
  return value;
}
function clientFactory(sdkRoot) {
  const root = safeDirectory(sdkRoot);
  const manifest = readJson(path.join(root, 'package.json'));
  const lock = readJson(path.join(root, 'package-lock.json'));
  if (manifest.dependencies?.[SDK] !== SDK_VERSION || lock.packages?.[`node_modules/${SDK}`]?.version !== SDK_VERSION) fail('TAT_SDK_VERSION_MISMATCH');
  const require = createRequire(path.join(root, 'package.json'));
  const actual = require(`${SDK}/package.json`);
  if (actual.version !== SDK_VERSION || !require.resolve(`${SDK}/package.json`).startsWith(`${root}/node_modules/`)) fail('TAT_SDK_VERSION_MISMATCH');
  const Client = require(SDK).tat.v20201028.Client;
  return (credential, region) => new Client({ credential, region, profile: {
    signMethod: 'TC3-HMAC-SHA256', httpProfile: { endpoint: 'tat.tencentcloudapi.com',
      protocol: 'https://', reqMethod: 'POST', reqTimeout: 30 },
  } });
}
export async function main(args = process.argv.slice(2)) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (!['--spec', '--output', '--apply', '--credentials', '--sdk-root'].includes(key) || Object.hasOwn(options, key)) fail('TAT_ARGUMENTS_INVALID');
    if (key === '--apply') options[key] = true;
    else {
      if (!args[i + 1] || args[i + 1].startsWith('--')) fail('TAT_ARGUMENTS_INVALID');
      options[key] = args[++i];
    }
  }
  if (!options['--spec']) fail('TAT_ARGUMENTS_INVALID');
  const spec = validateSpec(readJson(options['--spec']));
  const output = options['--output'];
  if (output) outputAvailable(output);
  let client;
  if (options['--apply']) {
    if (!output) fail('TAT_OUTPUT_REQUIRED');
    if (process.env.NODE_DEBUG || process.env.NODE_DEBUG_NATIVE || process.env.NODE_OPTIONS) fail('TAT_DEBUG_ENV_REFUSED');
    const makeClient = clientFactory(options['--sdk-root'] || fileURLToPath(new URL('../assets/cnb-tcr-tat/dependencies', import.meta.url)));
    client = makeClient(credentials(options['--credentials']), spec.target.region); // Credentials read last.
  }
  return configureTat({ spec, output, client, apply: options['--apply'] === true });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(result => process.stdout.write(`${canonical(result)}\n`)).catch(error => {
    process.stderr.write(`${/^TAT_[A-Z_]+$/.test(error.message) ? error.message : 'TAT_CONFIGURATION_FAILED'}\n`);
    process.exitCode = 1;
  });
}
