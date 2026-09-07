#!/usr/bin/env node
// Administrator-only CAM identity/policy setup. Never creates, rotates, or deletes access keys.
// CAM API 2019-01-16; STS GetCallerIdentity API 2018-08-13.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';

const COMMON = 'tencentcloud-sdk-nodejs-common', COMMON_VERSION = '4.1.220';
const fail = code => { throw new Error(code); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : object(value)
  ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const sha = value => createHash('sha256').update(value).digest('hex');
function keys(value, allowed) {
  if (!object(value) || Object.keys(value).sort().join(',') !== [...allowed].sort().join(',')) fail('CAM_SPEC_INVALID');
}
function match(value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) fail('CAM_SPEC_INVALID');
}
export function validateCamSpec(spec) {
  keys(spec, ['schema_version', 'project', 'environment', 'account_id', 'user_name', 'policy_name', 'target']);
  if (spec.schema_version !== 1 || !['test', 'staging', 'production'].includes(spec.environment)) fail('CAM_SPEC_INVALID');
  match(spec.project, /^[a-z][a-z0-9-]{0,62}$/);
  match(spec.account_id, /^[1-9][0-9]{4,15}$/);
  if (!Number.isSafeInteger(Number(spec.account_id))) fail('CAM_SPEC_INVALID');
  for (const name of [spec.user_name, spec.policy_name]) {
    match(name, /^[a-z][a-z0-9-]{0,63}$/);
    if (!name.startsWith(`${spec.project}-${spec.environment}-`)) fail('CAM_SPEC_INVALID');
  }
  keys(spec.target, ['region', 'instance_id', 'command_ids']);
  match(spec.target.region, /^[a-z]{2,8}-[a-z][a-z0-9-]{1,29}$/);
  match(spec.target.instance_id, /^(?:lhins|ins)-[a-z0-9]{4,32}$/);
  if (!Array.isArray(spec.target.command_ids) || spec.target.command_ids.length < 1 || spec.target.command_ids.length > 2 ||
      new Set(spec.target.command_ids).size !== spec.target.command_ids.length) fail('CAM_SPEC_INVALID');
  for (const command of spec.target.command_ids) match(command, /^cmd-[a-z0-9]{4,32}$/);
  return spec;
}
function policyFor(spec) {
  const { region, instance_id, command_ids } = spec.target;
  const commands = [...command_ids].sort().map(id => `qcs::tat:${region}:uin/${spec.account_id}:command/${id}`);
  const service = instance_id.startsWith('lhins-') ? 'lighthouse' : 'cvm';
  const instance = `qcs::${service}:${region}:uin/${spec.account_id}:instance/${instance_id}`;
  return { version: '2.0', statement: [
    { effect: 'allow', action: ['tat:InvokeCommand', 'tat:DescribeInvocationTasks'], resource: [...commands, instance] },
    { effect: 'allow', action: ['tat:DescribeCommands'], resource: commands },
  ] };
}
async function call(client, action, request, write = false) {
  try { return await client.request(action, request); }
  catch (error) {
    if (action === 'GetUser' && error.code === 'ResourceNotFound.UserNotExist') return null;
    fail(write ? 'CAM_WRITE_UNCERTAIN' : 'CAM_QUERY_FAILED');
  }
}
function collection(result, countKey, listKey) {
  if (!object(result) || !Number.isInteger(result[countKey]) || result[countKey] < 0 || result[countKey] > 200 ||
      !Array.isArray(result[listKey]) || result[countKey] !== result[listKey].length) fail('CAM_QUERY_INCOMPLETE');
  return result[listKey];
}
function resourceId(value) {
  const id = typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(id) || id <= 0) fail('CAM_RESOURCE_CONFLICT');
  return id;
}
async function verifyPolicy(client, id, spec, document, marker) {
  const policy = await call(client, 'GetPolicy', { PolicyId: id });
  let actual;
  try { actual = parseStrictJson(policy.PolicyDocument, { maxBytes: 65536 }); }
  catch { fail('CAM_RESOURCE_CONFLICT'); }
  if (policy.PolicyName !== spec.policy_name || policy.Description !== marker || policy.Type !== 1 ||
      policy.IsServiceLinkedRolePolicy !== 0 || canonical(actual) !== canonical(document)) fail('CAM_RESOURCE_CONFLICT');
}
async function verifyUser(client, user, spec, policyId, marker) {
  const uin = resourceId(user?.Uin);
  if (user.Name !== spec.user_name || user.ConsoleLogin !== 0 || user.Remark !== marker || String(uin) === spec.account_id) fail('CAM_RESOURCE_CONFLICT');
  const groups = collection(await call(client, 'ListGroupsForUser', { SubUin: uin, Rp: 200, Page: 1 }), 'TotalNum', 'GroupInfo');
  if (groups.length) fail('CAM_RESOURCE_CONFLICT');
  const attached = collection(await call(client, 'ListAttachedUserAllPolicies', { TargetUin: uin, Rp: 200, Page: 1, AttachType: 0 }), 'TotalNum', 'PolicyList');
  if (attached.length > 1 || attached.some(policy => !policyId || resourceId(policy.PolicyId) !== policyId ||
      policy.PolicyName !== spec.policy_name || (policy.Groups != null && (!Array.isArray(policy.Groups) || policy.Groups.length)))) fail('CAM_RESOURCE_CONFLICT');
  const keys = await call(client, 'ListAccessKeys', { TargetUin: uin });
  if (!object(keys) || !Array.isArray(keys.AccessKeys)) fail('CAM_QUERY_INCOMPLETE');
  if (keys.AccessKeys.length) fail('CAM_CREDENTIAL_RECOVERY_REQUIRED');
  return attached.length === 1;
}
export async function configureCam({ spec, apply = false, client, identityClient }) {
  validateCamSpec(spec);
  if (typeof apply !== 'boolean') fail('CAM_ARGUMENTS_INVALID');
  const policy = policyFor(spec), marker = `cnb-devops:${spec.project}:${spec.environment}:${sha(canonical(policy))}`;
  const result = { schema: 'cnb-cam-identity/v1', project: spec.project, environment: spec.environment,
    account_id: spec.account_id, user_name: spec.user_name, policy_name: spec.policy_name,
    policy_sha256: sha(canonical(policy)), policy, credential_status: 'not_created', deployment_ready: false, status: 'planned' };
  if (!apply) return result;
  if (typeof client?.request !== 'function' || typeof identityClient?.request !== 'function') fail('CAM_CLIENT_REQUIRED');
  const identity = await call(identityClient, 'GetCallerIdentity', {});
  if (identity?.AccountId !== spec.account_id) fail('CAM_ACCOUNT_MISMATCH');
  const policies = collection(await call(client, 'ListPolicies', { Scope: 'Local', Keyword: spec.policy_name, Rp: 200, Page: 1 }), 'TotalNum', 'List');
  const matching = policies.filter(p => p?.PolicyName === spec.policy_name);
  if (matching.length > 1) fail('CAM_RESOURCE_CONFLICT');
  let policyId = matching.length ? resourceId(matching[0].PolicyId) : null;
  if (policyId) await verifyPolicy(client, policyId, spec, policy, marker);
  let user = await call(client, 'GetUser', { Name: spec.user_name });
  let attached = user ? await verifyUser(client, user, spec, policyId, marker) : false;
  if (!policyId) {
    const created = await call(client, 'CreatePolicy', { PolicyName: spec.policy_name, Description: marker, PolicyDocument: canonical(policy) }, true);
    policyId = resourceId(created?.PolicyId);
    await verifyPolicy(client, policyId, spec, policy, marker);
  }
  if (!user) {
    const created = await call(client, 'AddUser', { Name: spec.user_name, Remark: marker, ConsoleLogin: 0, UseApi: 0 }, true);
    const expectedUin = resourceId(created?.Uin);
    user = await call(client, 'GetUser', { Name: spec.user_name });
    if (user?.Uin !== expectedUin) fail('CAM_RESOURCE_CONFLICT');
    attached = await verifyUser(client, user, spec, policyId, marker);
  }
  if (!attached) await call(client, 'AttachUserPolicy', { PolicyId: policyId, AttachUin: user.Uin }, true);
  await verifyPolicy(client, policyId, spec, policy, marker);
  const verifiedUin = user.Uin;
  user = await call(client, 'GetUser', { Name: spec.user_name });
  if (user?.Uin !== verifiedUin) fail('CAM_RESOURCE_CONFLICT');
  if (!await verifyUser(client, user, spec, policyId, marker)) fail('CAM_ATTACHMENT_NOT_VERIFIED');
  return { ...result, status: 'verified', user_uin: user.Uin, policy_id: policyId };
}
function safeDirectory(input) {
  const absolute = path.resolve(input);
  for (let p = absolute;; p = path.dirname(p)) {
    const st = fs.lstatSync(p), sticky = p !== absolute && st.uid === 0 && (st.mode & 0o1000);
    if (!st.isDirectory() || st.isSymbolicLink() || ![0, process.getuid()].includes(st.uid) || ((st.mode & 0o022) && !sticky)) fail('CAM_PATH_UNSAFE');
    if (p === path.dirname(p)) return absolute;
  }
}
function readJson(file, secret = false) {
  safeDirectory(path.dirname(path.resolve(file)));
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || ![0, process.getuid()].includes(st.uid) || (st.mode & 0o022) ||
        (secret && (st.mode & 0o777) !== 0o600) || st.size > 65536) fail('CAM_INPUT_UNSAFE');
    return parseStrictJson(fs.readFileSync(fd, 'utf8'), { maxBytes: 65536 });
  } finally { fs.closeSync(fd); }
}
function loadSdk(sdkRoot) {
  const root = safeDirectory(sdkRoot), lock = readJson(path.join(root, 'package-lock.json'));
  const require = createRequire(path.join(root, 'package.json'));
  if (lock.packages?.[`node_modules/${COMMON}`]?.version !== COMMON_VERSION ||
      require(`${COMMON}/package.json`).version !== COMMON_VERSION ||
      !require.resolve(`${COMMON}/package.json`).startsWith(`${root}/node_modules/`)) fail('CAM_SDK_VERSION_MISMATCH');
  return require(COMMON).AbstractClient;
}
export async function main(args = process.argv.slice(2)) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (!['--spec', '--apply', '--credentials', '--sdk-root'].includes(flag) || Object.hasOwn(options, flag)) fail('CAM_ARGUMENTS_INVALID');
    if (flag === '--apply') options[flag] = true;
    else {
      if (!args[i + 1] || args[i + 1].startsWith('--')) fail('CAM_ARGUMENTS_INVALID');
      options[flag] = args[++i];
    }
  }
  if (!options['--spec']) fail('CAM_ARGUMENTS_INVALID');
  const spec = validateCamSpec(readJson(options['--spec']));
  if (!options['--apply']) return configureCam({ spec });
  if (process.env.NODE_DEBUG || process.env.NODE_DEBUG_NATIVE || process.env.NODE_OPTIONS) fail('CAM_DEBUG_ENV_REFUSED');
  const AbstractClient = loadSdk(options['--sdk-root'] || fileURLToPath(new URL('../assets/cnb-tcr-tat/dependencies', import.meta.url)));
  const credential = options['--credentials'] ? readJson(options['--credentials'], true) : {
    secretId: process.env.TENCENTCLOUD_SECRET_ID, secretKey: process.env.TENCENTCLOUD_SECRET_KEY,
    ...(process.env.TENCENTCLOUD_TOKEN ? { token: process.env.TENCENTCLOUD_TOKEN } : {}),
  };
  if (!object(credential) || Object.keys(credential).some(k => !['secretId', 'secretKey', 'token'].includes(k)) ||
      ['secretId', 'secretKey'].some(k => typeof credential[k] !== 'string' || !credential[k] || /\s/.test(credential[k])) ||
      (credential.token !== undefined && (typeof credential.token !== 'string' || !credential.token || /\s/.test(credential.token)))) fail('CAM_CREDENTIALS_INVALID');
  const make = (service, version) => new AbstractClient(`${service}.tencentcloudapi.com`, version, {
    credential, region: spec.target.region, profile: { signMethod: 'TC3-HMAC-SHA256', httpProfile: {
      endpoint: `${service}.tencentcloudapi.com`, protocol: 'https://', reqMethod: 'POST', reqTimeout: 30,
    } },
  });
  return configureCam({ spec, apply: true, client: make('cam', '2019-01-16'), identityClient: make('sts', '2018-08-13') });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(result => process.stdout.write(`${canonical(result)}\n`)).catch(error => {
    process.stderr.write(`${/^CAM_[A-Z_]+$/.test(error.message) ? error.message : 'CAM_CONFIGURATION_FAILED'}\n`);
    process.exitCode = 1;
  });
}
