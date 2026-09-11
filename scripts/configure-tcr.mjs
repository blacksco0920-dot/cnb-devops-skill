#!/usr/bin/env node
// TCR Personal administrator setup. API 2019-09-24; CAM 2019-01-16; STS 2018-08-13.
// No API/password reset, key deletion, registry login, Docker, or image operations.
import path from 'node:path';
import { lstatSync, realpathSync } from 'node:fs';
import { randomInt } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';
import { fail, object, canonical, sha, safeDirectory, readJson, writeJson, openState } from './tcr-local-state.mjs';
const ROLES = ['build-push', 'host-pull'];
const COMMON = 'tencentcloud-sdk-nodejs-common', COMMON_VERSION = '4.1.220';
function keys(value, expected) {
  if (!object(value) || Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail('TCR_SPEC_INVALID');
}
function match(value, pattern) { if (typeof value !== 'string' || !pattern.test(value)) fail('TCR_SPEC_INVALID'); }
function identifier(value) { if (!Number.isSafeInteger(value) || value <= 0) fail('TCR_RESOURCE_CONFLICT'); return value; }
function id(value) { return identifier(typeof value === 'string' && /^[1-9]\d*$/.test(value) ? Number(value) : value); }
function textField(value) { match(value, /^[^\x00-\x1f\x7f]{1,255}$/u); }
function iso(value) {
  match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/);
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString().replace('.000Z', 'Z') !== value.replace('.000Z', 'Z')) fail('TCR_SPEC_INVALID');
  return Date.parse(value);
}
function creation(value) { match(value, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/); return iso(value.replace(' ', 'T') + 'Z') - 8 * 3600000; }
export function validateTcrSpec(spec) {
  keys(spec, ['schema_version', 'project', 'environment', 'account_id', 'edition', 'region', 'registry', 'namespace', 'repositories', 'lease', 'identities', ...(Object.hasOwn(spec || {}, 'existing') ? ['existing'] : [])]);
  if (spec.schema_version !== 1 || !['test', 'staging', 'production'].includes(spec.environment) || spec.edition !== 'Personal' ||
      spec.region !== 'ap-guangzhou' || spec.registry !== 'ccr.ccs.tencentyun.com') fail('TCR_SPEC_INVALID');
  match(spec.project, /^[a-z][a-z0-9-]{0,39}$/); match(spec.account_id, /^[1-9][0-9]{4,15}$/); id(spec.account_id);
  match(spec.namespace, /^[a-z][a-z0-9-]{1,29}$/);
  if (!Array.isArray(spec.repositories) || spec.repositories.length < 1 || spec.repositories.length > 20 ||
      new Set(spec.repositories.map(repo => repo?.name)).size !== spec.repositories.length) fail('TCR_SPEC_INVALID');
  for (const repo of spec.repositories) {
    keys(repo, ['name', 'description']); match(repo.name, /^[a-z][a-z0-9-]{1,29}\/[a-z][a-z0-9-]{0,59}$/);
    if (!repo.name.startsWith(`${spec.namespace}/`)) fail('TCR_SPEC_INVALID'); textField(repo.description);
  }
  keys(spec.lease, ['expires_at']); iso(spec.lease.expires_at);
  keys(spec.identities, ROLES);
  const names = [];
  for (const role of ROLES) {
    keys(spec.identities[role], ['user_name', 'policy_name', 'initialization_policy_name']);
    for (const name of Object.values(spec.identities[role])) {
      match(name, /^[a-z][a-z0-9-]{0,99}$/);
      if (!name.startsWith(`${spec.project}-${spec.environment}-`)) fail('TCR_SPEC_INVALID'); names.push(name);
    }
    if (spec.identities[role].user_name.length > 64) fail('TCR_SPEC_INVALID');
  }
  if (new Set(names).size !== names.length) fail('TCR_SPEC_INVALID');
  if (Object.hasOwn(spec, 'existing')) {
    keys(spec.existing, ['namespace_creation_time', 'repositories', 'identities']); creation(spec.existing.namespace_creation_time);
    if (!Array.isArray(spec.existing.repositories) || spec.existing.repositories.length !== spec.repositories.length) fail('TCR_SPEC_INVALID');
    spec.existing.repositories.forEach((repo, index) => {
      keys(repo, ['name', 'creation_time']); if (repo.name !== spec.repositories[index].name) fail('TCR_SPEC_INVALID'); creation(repo.creation_time);
    });
    keys(spec.existing.identities, ROLES);
    const uins = [], policies = [], files = [];
    for (const role of ROLES) {
      const e = spec.existing.identities[role];
      keys(e, ['user_uin', 'user_uid', 'user_remark', 'policy_id', 'policy_description', 'policy_add_time', 'policy_update_time',
        'key_create_time', 'key_description', 'api_credentials_file', 'registry_credentials_file']);
      for (const key of ['user_uin', 'user_uid', 'policy_id']) identifier(e[key]);
      if (String(e.user_uin) === spec.account_id) fail('TCR_SPEC_INVALID');
      for (const key of ['user_remark', 'policy_description', 'key_description']) textField(e[key]);
      for (const key of ['policy_add_time', 'policy_update_time', 'key_create_time']) creation(e[key]);
      for (const key of ['api_credentials_file', 'registry_credentials_file']) {
        if (typeof e[key] !== 'string' || !path.isAbsolute(e[key]) || path.normalize(e[key]) !== e[key]) fail('TCR_SPEC_INVALID'); files.push(e[key]);
      }
      uins.push(e.user_uin); policies.push(e.policy_id);
    }
    if (new Set(uins).size !== 2 || new Set(policies).size !== 2 || new Set(files).size !== 4) fail('TCR_SPEC_INVALID');
  }
  return spec;
}
function policyFor(spec, role, initialization = false) {
  return { version: '2.0', statement: [{ effect: 'allow', action: initialization ? ['tcr:CreateUserPersonal'] :
    role === 'build-push' ? ['tcr:PullRepositoryPersonal', 'tcr:PushRepositoryPersonal'] : ['tcr:PullRepositoryPersonal'],
    resource: initialization ? ['*'] : spec.repositories.map(repo => `qcs::tcr:::repo/${repo.name}`),
    condition: { date_less_than: { 'qcs:current_time': spec.lease.expires_at } } }] };
}
function full(response, count, list, max = 200) {
  if (!object(response) || !Number.isInteger(response[count]) || response[count] < 0 || response[count] > max ||
      !Array.isArray(response[list]) || response[list].length !== response[count]) fail('TCR_QUERY_INCOMPLETE');
  return response[list];
}
async function query(client, action, request) {
  try { return await client.request(action, request); }
  catch (error) {
    if (action === 'GetUser' && error.code === 'ResourceNotFound.UserNotExist') return null;
    if (['ResourceNotFound.ErrUserNotExist', 'ResourceNotFound.UserNotExist'].includes(error.code) && action === 'DescribeUserQuotaPersonal') fail('TCR_ACCOUNT_INITIALIZATION_REQUIRED');
    fail('TCR_QUERY_FAILED');
  }
}
function credential(value) {
  if (!object(value) || Object.keys(value).some(key => !['secretId', 'secretKey', 'token'].includes(key)) ||
      ['secretId', 'secretKey', ...(value.token !== undefined ? ['token'] : [])].some(key => typeof value[key] !== 'string' || !value[key] ||
        value[key].length > 16384 || /[\s\x00]/.test(value[key]))) fail('TCR_CREDENTIALS_INVALID');
  return value;
}
function registryCredential(value, spec, role, uin) {
  keys(value, ['registry', 'username', 'password', 'role', 'policy_expires_at']);
  if (value.registry !== spec.registry || value.username !== String(uin) || value.role !== role || value.policy_expires_at !== spec.lease.expires_at ||
      typeof value.password !== 'string' || !/^[A-Za-z0-9]{16}$/.test(value.password)) fail('TCR_CREDENTIALS_INVALID');
  return value;
}
function equal(actual, expected) { if (canonical(actual) !== canonical(expected)) fail('TCR_RESOURCE_CONFLICT'); }

export async function configureTcr({ spec, apply = false, verifyExisting = false, camClient, tcrClient, identityClient,
  makeChildClients, stateDir, now = () => new Date(), credentialsExpiresAt }) {
  validateTcrSpec(spec);
  if (typeof apply !== 'boolean' || typeof verifyExisting !== 'boolean' || (apply && verifyExisting) ||
      (apply && spec.existing) || (verifyExisting && !spec.existing)) fail('TCR_ARGUMENTS_INVALID');
  const digest = sha(canonical(spec));
  const plan = { schema: 'cnb-tcr-configuration/v1', status: 'planned', project: spec.project, environment: spec.environment,
    account_id: spec.account_id, edition: spec.edition, region: spec.region, registry: spec.registry, namespace: spec.namespace,
    repositories: spec.repositories.map(repo => repo.name), spec_sha256: digest, policy_expires_at: spec.lease.expires_at,
    resource_semantics: 'Personal repository QCS resources omit region and account; API calls and readbacks bind the declared account and region.',
    registry_login: 'not_checked', push_pull: 'not_checked', deployment_ready: false,
    identities: Object.fromEntries(ROLES.map(role => [role, { user_name: spec.identities[role].user_name,
      policy: policyFor(spec, role), registry_initialization: 'not_checked' }])) };
  if (!apply && !verifyExisting) return plan;
  const time = () => {
    const value = now(); if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail('TCR_ARGUMENTS_INVALID');
    if (Date.parse(spec.lease.expires_at) <= value.getTime()) fail('TCR_LEASE_EXPIRED');
    if (credentialsExpiresAt !== undefined && iso(credentialsExpiresAt) <= value.getTime()) fail('TCR_CREDENTIALS_EXPIRED');
    return value;
  };
  time();
  if ([camClient, tcrClient, identityClient].some(client => typeof client?.request !== 'function') || typeof makeChildClients !== 'function') fail('TCR_CLIENT_REQUIRED');
  const journal = apply ? openState(stateDir, digest) : null;
  const ops = journal?.state.operations || {};
  const stamp = `cnb-devops:${spec.project}:${spec.environment}:tcr`;
  const op = (name, action, target) => {
    const value = ops[name];
    if (value && (!object(value) || value.action !== action || value.target_sha256 !== sha(canonical(target)) ||
        !['pending', 'confirmed'].includes(value.status) || !Number.isFinite(Date.parse(value.started_at)))) fail('TCR_STATE_CONFLICT');
    return value;
  };
  const confirm = (name, metadata) => {
    const value = ops[name];
    if (value.status === 'confirmed') { equal(value.metadata, metadata); return; }
    value.status = 'confirmed'; value.metadata = metadata; journal.save();
  };
  const begin = (name, action, target) => {
    if (ops[name]) fail('TCR_WRITE_UNCERTAIN');
    time(); ops[name] = { action, target_sha256: sha(canonical(target)), started_at: time().toISOString(), status: 'pending' }; journal.save();
  };
  const mutate = async (name, client, action, request, code = 'TCR_WRITE_UNCERTAIN', target = request) => {
    begin(name, action, target);
    try { return await client.request(action, request); } catch { fail(code); }
  };
  const bind = (name, action, target, actual, expected) => {
    if (verifyExisting) { if (!actual) fail('TCR_RESOURCE_CONFLICT'); equal(actual, expected); return; }
    const operation = op(name, action, target);
    if (!actual) { if (operation) fail('TCR_WRITE_UNCERTAIN'); return; }
    if (!operation) fail('TCR_RESOURCE_CONFLICT');
    if (operation.status === 'confirmed') equal(actual, operation.metadata);
    else {
      if (operation.response_identity) {
        for (const [key, value] of Object.entries(operation.response_identity)) if (actual[key] !== value) fail('TCR_RESOURCE_CONFLICT');
      }
      const created = actual.creation_time || actual.add_time;
      if (created) {
        const start = Math.floor(Date.parse(operation.started_at) / 1000) * 1000, observed = creation(created);
        if (observed < start || observed > Math.min(time().getTime(), start + 300000)) fail('TCR_RESOURCE_CONFLICT');
      }
    }
  };
  const namespaceRequest = { Namespace: spec.namespace };
  const repoRequest = repo => ({ RepoName: repo.name, Public: 0, Description: repo.description });
  const names = role => spec.identities[role];
  const userRemark = role => spec.existing?.identities[role].user_remark || `${stamp}:${role}:${digest.slice(0, 16)}`;
  const userRequest = role => ({ Name: names(role).user_name, Remark: userRemark(role), ConsoleLogin: 0, UseApi: 0 });
  const policyRequest = (role, temporary) => ({ PolicyName: temporary ? names(role).initialization_policy_name : names(role).policy_name,
    Description: !temporary && spec.existing ? spec.existing.identities[role].policy_description : `${stamp}:${role}:${temporary ? 'initialize-once' : 'repositories'}:${digest.slice(0, 16)}`,
    PolicyDocument: canonical(policyFor(spec, role, temporary)) });
  async function namespaceRead() {
    const exists = (await query(tcrClient, 'ValidateNamespaceExistPersonal', namespaceRequest))?.Data;
    if (!object(exists) || typeof exists.IsExist !== 'boolean' || typeof exists.IsPreserved !== 'boolean') fail('TCR_QUERY_INCOMPLETE');
    if (exists.IsPreserved) fail('TCR_RESOURCE_CONFLICT');
    // Namespace is a fuzzy search in this API. A complete response may include
    // siblings; only the exact name participates in the ownership binding.
    const rows = full((await query(tcrClient, 'DescribeNamespacePersonal', { ...namespaceRequest, Limit: 100, Offset: 0 }))?.Data, 'NamespaceCount', 'NamespaceInfo', 100);
    for (const row of rows) {
      if (!object(row) || typeof row.Namespace !== 'string' || !/^[a-z][a-z0-9-]{1,29}$/.test(row.Namespace) ||
          !Number.isSafeInteger(row.RepoCount) || row.RepoCount < 0) fail('TCR_QUERY_INCOMPLETE');
      creation(row.CreationTime);
    }
    const owned = rows.filter(value => value.Namespace === spec.namespace);
    if (owned.length > 1 || exists.IsExist !== (owned.length === 1)) fail('TCR_RESOURCE_CONFLICT');
    const metadata = owned.length ? { namespace: spec.namespace, creation_time: owned[0].CreationTime } : null;
    if (metadata) creation(metadata.creation_time);
    bind('namespace', 'CreateNamespacePersonal', namespaceRequest, metadata, { namespace: spec.namespace, creation_time: spec.existing?.namespace_creation_time });
    return metadata;
  }
  async function repoRead(repo) {
    const exists = (await query(tcrClient, 'ValidateRepositoryExistPersonal', { RepoName: repo.name }))?.Data;
    if (!object(exists) || typeof exists.IsExist !== 'boolean') fail('TCR_QUERY_INCOMPLETE');
    let metadata = null;
    if (exists.IsExist) {
      const value = (await query(tcrClient, 'DescribeRepositoryPersonal', { RepoName: repo.name }))?.Data;
      if (!object(value) || value.RepoName !== repo.name || value.Server !== spec.registry || value.Public !== 0 ||
          value.Description !== repo.description || value.RepoType !== 'QCLOUD HUB' || value.IsQcloudOfficial !== false) fail('TCR_RESOURCE_CONFLICT');
      creation(value.CreationTime); metadata = { name: value.RepoName, creation_time: value.CreationTime, description: value.Description, public: 0 };
    }
    bind(`repo:${repo.name}`, 'CreateRepositoryPersonal', repoRequest(repo), metadata,
      { name: repo.name, creation_time: spec.existing?.repositories.find(item => item.name === repo.name)?.creation_time, description: repo.description, public: 0 });
    return metadata;
  }
  async function policyRead(role, temporary = false) {
    const request = policyRequest(role, temporary), operationName = `${role}:${temporary ? 'temporary-policy' : 'policy'}`;
    let policyId;
    if (verifyExisting) policyId = spec.existing.identities[role].policy_id;
    else {
      const matches = full(await query(camClient, 'ListPolicies', { Scope: 'Local', Keyword: request.PolicyName, Rp: 200, Page: 1 }), 'TotalNum', 'List').filter(p => p?.PolicyName === request.PolicyName);
      if (matches.length > 1) fail('TCR_RESOURCE_CONFLICT'); policyId = matches.length ? id(matches[0].PolicyId) : null;
    }
    let metadata = null;
    if (policyId) {
      const value = await query(camClient, 'GetPolicy', { PolicyId: policyId });
      if (!object(value) || value.PolicyName !== request.PolicyName || value.Description !== request.Description || value.Type !== 1 || value.IsServiceLinkedRolePolicy !== 0) fail('TCR_RESOURCE_CONFLICT');
      let actual; try { actual = parseStrictJson(value.PolicyDocument); } catch { fail('TCR_RESOURCE_CONFLICT'); }
      equal(actual, policyFor(spec, role, temporary)); creation(value.AddTime); creation(value.UpdateTime);
      metadata = { policy_id: policyId, add_time: value.AddTime, update_time: value.UpdateTime };
    }
    const existing = spec.existing?.identities[role];
    bind(operationName, 'CreatePolicy', request, metadata,
      { policy_id: existing?.policy_id, add_time: existing?.policy_add_time, update_time: existing?.policy_update_time });
    return metadata;
  }
  async function userRead(role) {
    const user = await query(camClient, 'GetUser', { Name: names(role).user_name });
    let metadata = null;
    if (user) {
      if (user.Name !== names(role).user_name || user.Remark !== userRemark(role) || user.ConsoleLogin !== 0 || String(user.Uin) === spec.account_id) fail('TCR_RESOURCE_CONFLICT');
      metadata = { user_uin: id(user.Uin), user_uid: id(user.Uid) };
    }
    const existing = spec.existing?.identities[role];
    bind(`${role}:user`, 'AddUser', userRequest(role), metadata, { user_uin: existing?.user_uin, user_uid: existing?.user_uid });
    return metadata;
  }
  const apiPath = role => verifyExisting ? spec.existing.identities[role].api_credentials_file : path.join(stateDir, `${role}.api-credentials.json`);
  const registryPath = role => verifyExisting ? spec.existing.identities[role].registry_credentials_file : path.join(stateDir, `${role}.registry-credentials.json`);
  function secretRead(role, user) {
    const api = readJson(apiPath(role), { optional: !verifyExisting }), registry = readJson(registryPath(role), { optional: !verifyExisting });
    const keyOp = ops[`${role}:key`], initOp = ops[`${role}:initialize`];
    if (api) {
      credential(api); if (api.token) fail('TCR_CREDENTIALS_INVALID');
      if (!verifyExisting && !keyOp) fail('TCR_CREDENTIAL_RECOVERY_REQUIRED');
      if (keyOp?.metadata && keyOp.metadata.credential_sha256 !== sha(canonical(api))) fail('TCR_CREDENTIAL_RECOVERY_REQUIRED');
    } else if (keyOp) fail('TCR_CREDENTIAL_RECOVERY_REQUIRED');
    if (registry) {
      if (!user) fail('TCR_CREDENTIALS_INVALID'); registryCredential(registry, spec, role, user.user_uin);
      if (initOp?.target_sha256 !== undefined && initOp.target_sha256 !== sha(canonical({ user_uin: user.user_uin, credential_sha256: sha(canonical(registry)) }))) fail('TCR_CREDENTIALS_INVALID');
    } else if (initOp) fail('TCR_INITIALIZATION_RECOVERY_REQUIRED');
    if (initOp?.status === 'pending') fail('TCR_INITIALIZATION_RECOVERY_REQUIRED');
    return { api, registry };
  }
  async function safety(role, user, policy, temporary, secrets, final = false) {
    if (!user) { if (secrets.api || secrets.registry) fail('TCR_CREDENTIALS_INVALID'); return []; }
    const uin = user.user_uin;
    if (full(await query(camClient, 'ListGroupsForUser', { SubUin: uin, Rp: 200, Page: 1 }), 'TotalNum', 'GroupInfo').length) fail('TCR_RESOURCE_CONFLICT');
    const attachments = full(await query(camClient, 'ListAttachedUserAllPolicies', { TargetUin: uin, Rp: 200, Page: 1, AttachType: 0 }), 'TotalNum', 'PolicyList');
    const allowed = [policy?.policy_id, ...(!final && !verifyExisting && ops[`${role}:detach`]?.status !== 'confirmed' ? [temporary?.policy_id] : [])].filter(Boolean);
    if (new Set(attachments.map(p => id(p.PolicyId))).size !== attachments.length || attachments.some(p => !allowed.includes(id(p.PolicyId)) ||
        (p.Groups != null && (!Array.isArray(p.Groups) || p.Groups.length)) ||
        p.PolicyName !== (id(p.PolicyId) === policy?.policy_id ? names(role).policy_name : names(role).initialization_policy_name))) fail('TCR_RESOURCE_CONFLICT');
    if ((verifyExisting || final) && (attachments.length !== 1 || id(attachments[0].PolicyId) !== policy?.policy_id)) fail('TCR_RESOURCE_CONFLICT');
    const inventory = await query(camClient, 'ListAccessKeys', { TargetUin: uin });
    if (!object(inventory) || !Array.isArray(inventory.AccessKeys)) fail('TCR_QUERY_INCOMPLETE');
    if (secrets.api) {
      const key = inventory.AccessKeys[0];
      if (inventory.AccessKeys.length !== 1 || key?.AccessKeyId !== secrets.api.secretId || key.Status !== 'Active') fail('TCR_RESOURCE_CONFLICT');
      creation(key.CreateTime);
      const expected = spec.existing?.identities[role];
      const description = expected?.key_description || `${stamp}:${role}:initialization-only`;
      if (key.Description !== description || (expected && key.CreateTime !== expected.key_create_time)) fail('TCR_RESOURCE_CONFLICT');
      const operation = op(`${role}:key`, 'CreateAccessKey', { TargetUin: uin, Description: description });
      if (!verifyExisting && operation?.metadata && operation.metadata.create_time !== key.CreateTime) fail('TCR_RESOURCE_CONFLICT');
    } else if (inventory.AccessKeys.length) fail('TCR_CREDENTIAL_RECOVERY_REQUIRED');
    return attachments.map(p => id(p.PolicyId));
  }
  async function childIdentity(api, user) {
    let children; try { children = await makeChildClients(api); } catch { fail('TCR_CLIENT_REQUIRED'); }
    if (typeof children?.identityClient?.request !== 'function' || typeof children?.tcrClient?.request !== 'function') fail('TCR_CLIENT_REQUIRED');
    const caller = await query(children.identityClient, 'GetCallerIdentity', {});
    if (caller?.AccountId !== spec.account_id || String(caller.UserId) !== String(user.user_uin)) fail('TCR_ACCOUNT_MISMATCH');
    return children;
  }
  try {
    const caller = await query(identityClient, 'GetCallerIdentity', {});
    if (caller?.AccountId !== spec.account_id) fail('TCR_ACCOUNT_MISMATCH');
    if (apply) {
      const quota = (await query(tcrClient, 'DescribeUserQuotaPersonal', {}))?.Data?.LimitInfo;
      if (!Array.isArray(quota) || !['namespace', 'repo'].every(type => quota.some(row => row.Type === type && row.Username === spec.account_id && Number.isSafeInteger(row.Value) && row.Value > 0))) fail('TCR_ACCOUNT_INITIALIZATION_REQUIRED');
    }
    // Complete discovery, local secret checks, and effective permissions for BOTH roles before any cloud mutation.
    let namespace = await namespaceRead(); const repos = {};
    for (const repo of spec.repositories) repos[repo.name] = await repoRead(repo);
    const roles = {};
    for (const role of ROLES) {
      const user = await userRead(role), policy = await policyRead(role), temporary = verifyExisting ? null : await policyRead(role, true);
      const secrets = secretRead(role, user); const attachments = await safety(role, user, policy, temporary, secrets);
      if (secrets.api) await childIdentity(secrets.api, user);
      roles[role] = { user, policy, temporary, secrets, attachments };
    }
    if (apply) {
      if (!namespace) { await mutate('namespace', tcrClient, 'CreateNamespacePersonal', namespaceRequest); namespace = await namespaceRead(); }
      if (!namespace) fail('TCR_WRITE_UNCERTAIN'); confirm('namespace', namespace);
      for (const repo of spec.repositories) {
        if (!repos[repo.name]) { await mutate(`repo:${repo.name}`, tcrClient, 'CreateRepositoryPersonal', repoRequest(repo)); repos[repo.name] = await repoRead(repo); }
        if (!repos[repo.name]) fail('TCR_WRITE_UNCERTAIN'); confirm(`repo:${repo.name}`, repos[repo.name]);
      }
      for (const role of ROLES) {
        const item = roles[role];
        if (!item.user) {
          const response = await mutate(`${role}:user`, camClient, 'AddUser', userRequest(role));
          ops[`${role}:user`].response_identity = { user_uin: id(response?.Uin) }; journal.save(); item.user = await userRead(role);
        }
        if (!item.user) fail('TCR_WRITE_UNCERTAIN'); confirm(`${role}:user`, item.user);
        for (const temporary of [false, true]) {
          const field = temporary ? 'temporary' : 'policy', operationName = `${role}:${temporary ? 'temporary-policy' : 'policy'}`;
          if (!item[field]) {
            const response = await mutate(operationName, camClient, 'CreatePolicy', policyRequest(role, temporary));
            ops[operationName].response_identity = { policy_id: id(response?.PolicyId) }; journal.save(); item[field] = await policyRead(role, temporary);
          }
          if (!item[field]) fail('TCR_WRITE_UNCERTAIN'); confirm(operationName, item[field]);
        }
        item.attachments = await safety(role, await userRead(role), item.policy, item.temporary, item.secrets);
        for (const temporary of [false, true]) {
          if (temporary && ops[`${role}:detach`]) continue;
          const policyId = item[temporary ? 'temporary' : 'policy'].policy_id, operationName = `${role}:attach-${temporary ? 'temporary' : 'final'}`;
          const request = { PolicyId: policyId, AttachUin: item.user.user_uin }, recorded = op(operationName, 'AttachUserPolicy', request);
          if (!item.attachments.includes(policyId)) {
            if (recorded) fail('TCR_WRITE_UNCERTAIN');
            await mutate(operationName, camClient, 'AttachUserPolicy', request);
            item.attachments = await safety(role, await userRead(role), item.policy, item.temporary, item.secrets);
            if (!item.attachments.includes(policyId)) fail('TCR_WRITE_UNCERTAIN');
          } else if (!recorded) fail('TCR_RESOURCE_CONFLICT');
          confirm(operationName, { policy_id: policyId, user_uin: item.user.user_uin });
        }
        if (!item.secrets.api) {
          const request = { TargetUin: item.user.user_uin, Description: `${stamp}:${role}:initialization-only` };
          const response = await mutate(`${role}:key`, camClient, 'CreateAccessKey', request, 'TCR_CREDENTIAL_RECOVERY_REQUIRED');
          const key = response?.AccessKey;
          if (!object(key)) fail('TCR_CREDENTIAL_RECOVERY_REQUIRED');
          // This is the only response containing SecretAccessKey. Persist the
          // usable secret before inspecting optional metadata; inventory and STS
          // readbacks below establish its status, creation metadata and identity.
          const api = credential({ secretId: key.AccessKeyId, secretKey: key.SecretAccessKey });
          writeJson(apiPath(role), api); item.secrets.api = api;
        }
        await safety(role, await userRead(role), item.policy, item.temporary, item.secrets);
        const inventory = (await query(camClient, 'ListAccessKeys', { TargetUin: item.user.user_uin })).AccessKeys;
        confirm(`${role}:key`, { credential_sha256: sha(canonical(item.secrets.api)), create_time: inventory[0].CreateTime });
        const children = await childIdentity(item.secrets.api, item.user);
        if (!item.secrets.registry) {
          const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
          const password = Array.from({ length: 16 }, () => alphabet[randomInt(alphabet.length)]).join('');
          item.secrets.registry = { registry: spec.registry, username: String(item.user.user_uin), password, role, policy_expires_at: spec.lease.expires_at };
          writeJson(registryPath(role), item.secrets.registry);
        }
        const initTarget = { user_uin: item.user.user_uin, credential_sha256: sha(canonical(item.secrets.registry)) };
        const initialized = op(`${role}:initialize`, 'CreateUserPersonal', initTarget);
        if (!initialized) {
          const response = await mutate(`${role}:initialize`, children.tcrClient, 'CreateUserPersonal', { Password: item.secrets.registry.password }, 'TCR_INITIALIZATION_RECOVERY_REQUIRED', initTarget);
          if (typeof response?.RequestId !== 'string' || !/^[A-Za-z0-9-]{1,128}$/.test(response.RequestId)) fail('TCR_INITIALIZATION_RECOVERY_REQUIRED');
          confirm(`${role}:initialize`, { request_id: response.RequestId });
        } else if (initialized.status !== 'confirmed') fail('TCR_INITIALIZATION_RECOVERY_REQUIRED');
        const detachRequest = { PolicyId: item.temporary.policy_id, DetachUin: item.user.user_uin };
        const detached = op(`${role}:detach`, 'DetachUserPolicy', detachRequest);
        item.attachments = await safety(role, await userRead(role), item.policy, item.temporary, item.secrets);
        if (item.attachments.includes(item.temporary.policy_id)) {
          if (detached) fail('TCR_WRITE_UNCERTAIN');
          await mutate(`${role}:detach`, camClient, 'DetachUserPolicy', detachRequest);
        } else if (!detached) fail('TCR_RESOURCE_CONFLICT');
        await safety(role, await userRead(role), item.policy, item.temporary, item.secrets, true);
        confirm(`${role}:detach`, { policy_id: item.temporary.policy_id, user_uin: item.user.user_uin });
      }
    }
    // Final readback rechecks all identities, metadata and grants after the entire operation.
    await namespaceRead(); for (const repo of spec.repositories) await repoRead(repo);
    const identities = {};
    for (const role of ROLES) {
      const item = roles[role], user = await userRead(role), policy = await policyRead(role);
      equal(user, item.user); equal(policy, item.policy);
      const secrets = secretRead(role, user);
      await safety(role, user, policy, item.temporary, secrets, true); await childIdentity(secrets.api, user);
      identities[role] = { ...plan.identities[role], user_uin: user.user_uin, policy_id: policy.policy_id,
        registry_initialization: apply ? 'api_response_confirmed' : 'not_checked', temporary_policy_attached: false,
        api_credentials_file: apiPath(role), registry_credentials_file: registryPath(role) };
    }
    time(); return { ...plan, status: apply ? 'verified' : 'existing_verified', namespace_creation_time: namespace.creation_time,
      repository_metadata: spec.repositories.map(repo => ({ name: repo.name, creation_time: repos[repo.name].creation_time })), identities };
  } finally { journal?.close(); }
}
function loadSdk(root) {
  for (const file of [root, path.join(root, 'package.json'), path.join(root, 'package-lock.json'), path.join(root, 'node_modules', COMMON, 'package.json')]) {
    try { lstatSync(file); } catch (error) { if (error.code === 'ENOENT') fail('TCR_SDK_UNAVAILABLE'); throw error; }
  }
  safeDirectory(root); const lock = readJson(path.join(root, 'package-lock.json'), { secret: false });
  const require = createRequire(path.join(root, 'package.json'));
  if (lock.packages?.[`node_modules/${COMMON}`]?.version !== COMMON_VERSION || require(`${COMMON}/package.json`).version !== COMMON_VERSION ||
      !require.resolve(`${COMMON}/package.json`).startsWith(`${root}/node_modules/`)) fail('TCR_SDK_VERSION_MISMATCH');
  return require(COMMON).AbstractClient;
}
export async function main(args = process.argv.slice(2)) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!['--spec', '--apply', '--verify-existing', '--state-dir', '--credentials', '--credentials-expires-at', '--sdk-root'].includes(flag) || Object.hasOwn(options, flag)) fail('TCR_ARGUMENTS_INVALID');
    if (['--apply', '--verify-existing'].includes(flag)) options[flag] = true;
    else { if (!args[index + 1] || args[index + 1].startsWith('--')) fail('TCR_ARGUMENTS_INVALID'); options[flag] = args[++index]; }
  }
  if (!options['--spec']) fail('TCR_ARGUMENTS_INVALID');
  const spec = validateTcrSpec(readJson(options['--spec'], { secret: false }));
  if (!options['--apply'] && !options['--verify-existing']) return configureTcr({ spec });
  if (process.env.NODE_DEBUG || process.env.NODE_DEBUG_NATIVE || process.env.NODE_OPTIONS) fail('TCR_DEBUG_ENV_REFUSED');
  if (!options['--credentials'] || (options['--apply'] && !options['--state-dir'])) fail('TCR_ARGUMENTS_INVALID');
  const admin = credential(readJson(options['--credentials']));
  if (admin.token && !options['--credentials-expires-at']) fail('TCR_CREDENTIAL_EXPIRY_REQUIRED');
  if (options['--credentials-expires-at'] && iso(options['--credentials-expires-at']) <= Date.now()) fail('TCR_CREDENTIALS_EXPIRED');
  const AbstractClient = loadSdk(options['--sdk-root'] || fileURLToPath(new URL('../assets/cnb-tcr-tat/dependencies', import.meta.url)));
  const make = (service, version, auth, region) => new AbstractClient(`${service}.tencentcloudapi.com`, version, {
    credential: auth, ...(region ? { region } : {}), profile: { signMethod: 'TC3-HMAC-SHA256', httpProfile: {
      endpoint: `${service}.tencentcloudapi.com`, protocol: 'https://', reqMethod: 'POST', reqTimeout: 30,
    } },
  });
  return configureTcr({ spec, apply: !!options['--apply'], verifyExisting: !!options['--verify-existing'], stateDir: options['--state-dir'],
    credentialsExpiresAt: options['--credentials-expires-at'], camClient: make('cam', '2019-01-16', admin),
    identityClient: make('sts', '2018-08-13', admin, spec.region), tcrClient: make('tcr', '2019-09-24', admin, spec.region),
    makeChildClients: auth => ({ identityClient: make('sts', '2018-08-13', auth, spec.region), tcrClient: make('tcr', '2019-09-24', auth) }) });
}
if (process.argv[1] && (() => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })()) {
  main().then(result => process.stdout.write(`${canonical(result)}\n`)).catch(error => {
    process.stderr.write(`${/^TCR_[A-Z_]+$/.test(error.message) ? error.message : 'TCR_CONFIGURATION_FAILED'}\n`); process.exitCode = 1;
  });
}
