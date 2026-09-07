// Adapted from the source-pinned TAT caller; see dependencies/SOURCES.md.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import process from 'node:process';

import { parseReleaseRequest, renderReleaseRequest, validateReleaseReceipt } from './release-request.mjs';

// Task states from the pinned TAT API 2020-10-28 InvocationTask model.
const PENDING_STATUSES = new Set(['PENDING', 'DELIVERING', 'DELIVER_DELAYED', 'RUNNING']);
const TERMINAL_FAILURES = new Set([
  'DELIVER_FAILED',
  'START_FAILED',
  'CANCELLING',
  'FAILED',
  'TIMEOUT',
  'TASK_TIMEOUT',
  'CANCELLED',
  'TERMINATED',
]);
const SECRET_ID_PATTERN = /^AKID[A-Za-z0-9]+$/u;
const INVOCATION_ID_PATTERN = /^inv-[A-Za-z0-9-]{8,64}$/u;
const COMMAND_ID_PATTERN = /^cmd-[A-Za-z0-9-]{8,64}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const UTC_SECOND_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export const TAT_HTTP_REQUEST_TIMEOUT_SECONDS = 15;


function fail(message, invocationId) {
  const error = new Error(message);
  if (typeof invocationId === 'string' && INVOCATION_ID_PATTERN.test(invocationId)) {
    Object.defineProperty(error, 'invocationId', { value: invocationId, enumerable: true });
  }
  throw error;
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0 || /[\r\n\0]/u.test(value)) {
    fail(`required TAT configuration is invalid: ${name}`);
  }
  return value;
}

function requireInvocationId(response) {
  const value = response?.InvocationId;
  if (typeof value !== 'string' || !INVOCATION_ID_PATTERN.test(value)) {
    fail('TAT InvokeCommand did not return one valid invocation ID');
  }
  return value;
}

function exactInvocationTask(response, { invocationId, commandId, instanceId }) {
  const tasks = response?.InvocationTaskSet;
  const task = Array.isArray(tasks) && tasks.length === 1 ? tasks[0] : undefined;
  if (
    response?.TotalCount !== 1 ||
    task?.InvocationId !== invocationId ||
    task.CommandId !== commandId ||
    task.InstanceId !== instanceId
  ) {
    fail('TAT task query did not return the exact invocation task', invocationId);
  }
  return task;
}

export function validateBinding(binding, config) {
  if (binding?.schema !== 'cnb-tat-binding/v1' || binding.project !== config.project || binding.environment !== config.environment || !['test','production'].includes(binding.environment)) fail('TAT protected binding mismatch');
  for (const [field,pattern] of Object.entries({region:/^[a-z]+-[a-z]+[0-9]*$/u,instance_id:/^(?:lhins|ins)-[A-Za-z0-9-]{8,64}$/u,command_id:COMMAND_ID_PATTERN,command_sha256:/^[0-9a-f]{64}$/u,program_sha256:/^[0-9a-f]{64}$/u,compose_sha256:/^[0-9a-f]{64}$/u,policy_sha256:/^[0-9a-f]{64}$/u,username:/^[a-z_][a-z0-9_-]{0,31}$/u,working_directory:/^\/[A-Za-z0-9_./-]+$/u})) {
    if(typeof binding[field] !== 'string' || !pattern.test(binding[field])) fail(`invalid protected binding ${field}`);
  }
  for(const [field,configField] of [['program_sha256',config.environment==='production'?'production_entry_sha256':'controller_program_sha256'],['compose_sha256','controller_compose_sha256'],['policy_sha256','policy_sha256']]) if(binding[field]!==config[configField]) fail('protected binding does not match the generated controller, Compose or policy');
  if(binding.command_id==='cmd-PENDING0' || binding.working_directory.split('/').includes('..') || !Number.isInteger(binding.timeout) || binding.timeout<1 || binding.timeout>3600) fail('invalid protected command policy');
  return binding;
}
function validateSavedCommand(response, binding) {
  const commands = response?.CommandSet;
  const command = Array.isArray(commands) && commands.length === 1 ? commands[0] : undefined;
  const encoded=command?.Content;
  let content;
  if(typeof encoded !== 'string') fail('saved TAT command content is invalid');
  content=Buffer.from(encoded,'base64');
  if(content.length === 0 || content.length>48*1024 || content.includes(0) || content.toString('base64')!==encoded || createHash('sha256').update(content).digest('hex')!==binding.command_sha256) fail('saved TAT command content hash mismatch');
  if (
    response?.TotalCount !== 1 ||
    command.CommandId !== binding.command_id ||
    command.CommandType !== 'SHELL' ||
    command.WorkingDirectory !== binding.working_directory ||
    command.Timeout !== binding.timeout ||
    command.EnableParameter !== true ||
    command.DefaultParameters !== JSON.stringify({ release_request_b64url: 'INVALID' }) ||
    command.CreatedBy !== 'USER' ||
    command.Username !== binding.username ||
    (command.OutputCOSBucketUrl ?? '') !== '' ||
    (command.OutputCOSKeyPrefix ?? '') !== ''
  ) fail('saved TAT command configuration is invalid');
  const text=content.toString('utf8');
  if(!Buffer.from(text,'utf8').equals(content) || text.split('{{release_request_b64url}}').length!==2 || /\{\{|\}\}/u.test(text.replace('{{release_request_b64url}}',''))) fail('saved TAT command parameter contract is invalid');
  return text;
}
function readReleaseReceipt(task, invocationId, binding, request, config, expectedScript, receiptValidator=validateReleaseReceipt) {
  if(task.TaskStatus!=='SUCCESS' || task.TaskResult?.ExitCode!==0 || task.TaskResult?.Dropped!==0) fail('TAT task receipt does not match invocation',invocationId);
  const document=task.CommandDocument;
  if(document?.Content!==Buffer.from(expectedScript,'utf8').toString('base64') || document.CommandType!=='SHELL' || document.Username!==binding.username || document.WorkingDirectory!==binding.working_directory || document.Timeout!==binding.timeout || (document.OutputCOSBucketUrl??'')!=='' || (document.OutputCOSKeyPrefix??'')!=='') fail('executed TAT command does not match the protected command and parameters',invocationId);
  const encoded=task.TaskResult.Output;
  if(typeof encoded!=='string' || encoded.length>128*1024) fail('TAT receipt output is invalid',invocationId);
  const raw=Buffer.from(encoded,'base64');
  if(raw.toString('base64')!==encoded) fail('TAT receipt encoding is invalid',invocationId);
  let receipt;
  try {receipt=JSON.parse(raw.toString('utf8'));} catch {fail('TAT receipt is invalid JSON',invocationId);}
  if(raw.toString('utf8')!==JSON.stringify(receipt)+'\n') fail('TAT receipt is not exact JSON',invocationId);
  try {return receiptValidator(receipt,request,config,binding);} catch {fail('TAT release receipt mismatches the bound request',invocationId);}
}

function reportProgress(onProgress, invocationId, status) {
  try {
    onProgress({ invocationId, status });
  } catch {
    // Logging must never abandon an invocation that is already running remotely.
  }
}

export function renderTatEvidenceOutputs({ invocationId, completedAt }) {
  const parsed = typeof completedAt === 'string' ? Date.parse(completedAt) : Number.NaN;
  if (
    typeof invocationId !== 'string' ||
    !INVOCATION_ID_PATTERN.test(invocationId) ||
    typeof completedAt !== 'string' ||
    !UTC_SECOND_PATTERN.test(completedAt) ||
    !Number.isFinite(parsed) ||
    new Date(parsed).toISOString().replace('.000Z', 'Z') !== completedAt
  ) {
    fail('TAT completion evidence is invalid');
  }
  return (
    `##[set-output invocation_id=${invocationId}]\n` +
    `##[set-output completed_at=${completedAt}]\n`
  );
}

export async function runTatCommand({
  client,
  request,
  config,
  binding,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now = Date.now,
  deadlineMs = 61 * 60 * 1000,
  pollIntervalMs = 5_000,
  onProgress = () => {},
  parseRequest,
  receiptValidator,
}) {
  if (
    !client ||
    typeof client.DescribeCommands !== 'function' ||
    typeof client.InvokeCommand !== 'function' ||
    typeof client.DescribeInvocationTasks !== 'function' ||
    typeof onProgress !== 'function' || typeof parseRequest !== 'function' || typeof receiptValidator !== 'function'
  ) {
    fail('TAT client is invalid');
  }
  validateBinding(binding,config);
  const {command_id:commandId,instance_id:instanceId}=binding;
  if(typeof request!=='string'||!BASE64URL_PATTERN.test(request)||request.length>48*1024) fail('invalid TAT request size');
  const model=parseRequest(request,config);
  const checkedRequest=request;
  if(!Number.isFinite(deadlineMs)||deadlineMs<=0||deadlineMs>61*60*1000||!Number.isFinite(pollIntervalMs)||pollIntervalMs<=0) fail('invalid TAT polling bounds');
  const parameters = JSON.stringify({ release_request_b64url: checkedRequest });
  const commandResponse = await client.DescribeCommands({
    CommandIds: [commandId],
    Limit: 1,
    Offset: 0,
  });
  const commandTemplate=validateSavedCommand(commandResponse, binding);
  const expectedScript=commandTemplate.replace('{{release_request_b64url}}',checkedRequest);
  if(Buffer.byteLength(expectedScript,'utf8')>64*1024) fail('executed TAT command is too large');
  const response = await client.InvokeCommand({
    CommandId: commandId,
    InstanceIds: [instanceId],
    Parameters: parameters,
  });
  const invocationId = requireInvocationId(response);
  reportProgress(onProgress, invocationId, 'SUBMITTED');
  const deadline = now() + deadlineMs;
  let readFailures = 0;
  while (now() < deadline) {
    let readResponse;
    try {
      readResponse = await client.DescribeInvocationTasks({Filters:[{Name:'invocation-id',Values:[invocationId]}],HideOutput:false,Limit:1,Offset:0});
      readFailures = 0;
    } catch {
      readFailures += 1;
      if (readFailures >= 3) {
        fail('TAT invocation status query failed', invocationId);
      }
      await sleep(pollIntervalMs);
      continue;
    }
    const task = exactInvocationTask(readResponse, {
      invocationId,
      commandId,
      instanceId,
    });
    const status = task.TaskStatus;
    reportProgress(onProgress, invocationId, status);
    if (status === 'SUCCESS') {
      const completedAt = new Date(Math.floor(now() / 1000) * 1000)
        .toISOString()
        .replace('.000Z', 'Z');
      const receipt=readReleaseReceipt(task,invocationId,binding,model,config,expectedScript,receiptValidator);
      return { invocationId, completedAt, receipt };
    }
    if (!PENDING_STATUSES.has(status)) {
      if (!TERMINAL_FAILURES.has(status)) {
        fail('TAT invocation returned an unknown terminal status', invocationId);
      }
      fail(`TAT invocation did not succeed: ${status}`, invocationId);
    }
    await sleep(pollIntervalMs);
  }
  fail('TAT invocation polling deadline exceeded', invocationId);
}

export function runTatRelease(options) {
  return runTatCommand({...options,parseRequest:parseReleaseRequest,receiptValidator:validateReleaseReceipt});
}

/** Independent administrator readback. This function has no Invoke path. */
export async function verifyTatInvocation({client,request,config,binding,invocationId,parseRequest,receiptValidator}) {
  validateBinding(binding,config);
  if(!INVOCATION_ID_PATTERN.test(invocationId)||typeof request!=='string'||!BASE64URL_PATTERN.test(request)||request.length>48*1024||typeof parseRequest!=='function'||typeof receiptValidator!=='function') fail('invalid TAT verification inputs');
  const model=parseRequest(request,config);
  const template=validateSavedCommand(await client.DescribeCommands({CommandIds:[binding.command_id],Limit:1,Offset:0}),binding);
  const script=template.replace('{{release_request_b64url}}',request);
  if(Buffer.byteLength(script,'utf8')>64*1024) fail('executed TAT command is too large');
  const task=exactInvocationTask(await client.DescribeInvocationTasks({Filters:[{Name:'invocation-id',Values:[invocationId]}],HideOutput:false,Limit:1,Offset:0}),{invocationId,commandId:binding.command_id,instanceId:binding.instance_id});
  return {invocationId,receipt:readReleaseReceipt(task,invocationId,binding,model,config,script,receiptValidator)};
}

export function createTatClientFromEnvironment(region) {
  const secretId=requiredEnvironment('TENCENTCLOUD_SECRET_ID'),secretKey=requiredEnvironment('TENCENTCLOUD_SECRET_KEY');
  if(!SECRET_ID_PATTERN.test(secretId)) fail('TAT credentials are invalid');
  delete process.env.TENCENTCLOUD_SECRET_ID;delete process.env.TENCENTCLOUD_SECRET_KEY;
  const require=createRequire(new URL('../dependencies/package.json',import.meta.url));
  const expected=require('../dependencies/package.json').dependencies['tencentcloud-sdk-nodejs-tat'];
  if(require('tencentcloud-sdk-nodejs-tat/package.json').version!==expected) fail('Tencent SDK version does not match bundle lock');
  const Client=resolveTatClient(require('tencentcloud-sdk-nodejs-tat'));
  return new Client(createTatClientOptions({secretId,secretKey,region}));
}

export function createTatClientOptions({ secretId, secretKey, region }) {
  return {
    credential: { secretId, secretKey },
    region,
    profile: {
      httpProfile: {
        endpoint: 'tat.tencentcloudapi.com',
        reqTimeout: TAT_HTTP_REQUEST_TIMEOUT_SECONDS,
      },
    },
  };
}

function resolveTatClient(sdk) {
  const Client = sdk?.tat?.v20201028?.Client ?? sdk?.default?.tat?.v20201028?.Client;
  if (typeof Client !== 'function') {
    fail('Tencent TAT SDK client is unavailable');
  }
  return Client;
}

async function main() {
  const args={};
  for(const argument of process.argv.slice(2)) {
    const match=/^--(config|binding|images|receipt)=(.+)$/u.exec(argument);
    if(!match||Object.hasOwn(args,match[1])||/[\r\n\0]/u.test(match[2])) fail('invalid TAT caller argument');
    args[match[1]]=match[2];
  }
  if(Object.keys(args).length!==4) fail('TAT caller requires --config/--binding/--images/--receipt');
  const config=JSON.parse(await readFile(args.config,'utf8'));
  const binding=JSON.parse(await readFile(args.binding,'utf8'));
  validateBinding(binding,config);
  const secretId=requiredEnvironment('TENCENTCLOUD_SECRET_ID');
  const secretKey=requiredEnvironment('TENCENTCLOUD_SECRET_KEY');
  if(!SECRET_ID_PATTERN.test(secretId)) fail('TAT credentials are invalid');
  const gitSha=requiredEnvironment('CNB_COMMIT');
  const request=renderReleaseRequest({schema:'cnb-release-request/v1',project:config.project,environment:config.environment,controller:config.controller_id,git_sha:gitSha,controller_commit:gitSha,build_id:requiredEnvironment('CNB_BUILD_ID'),images:JSON.parse(await readFile(args.images,'utf8'))},config);
  const require=createRequire(new URL('../dependencies/package.json',import.meta.url));
  const expected=require('../dependencies/package.json').dependencies['tencentcloud-sdk-nodejs-tat'];
  if(require('tencentcloud-sdk-nodejs-tat/package.json').version!==expected) fail('Tencent SDK version does not match bundle lock');
  const Client=resolveTatClient(require('tencentcloud-sdk-nodejs-tat'));
  const client=new Client(createTatClientOptions({secretId,secretKey,region:binding.region}));
  const result=await runTatRelease({client,request,config,binding,onProgress:({invocationId,status})=>process.stdout.write(`tat_invocation_id=${invocationId}\ntat_invocation_status=${status}\n`)});
  const raw=JSON.stringify(result.receipt)+'\n';
  await writeFile(args.receipt,raw,{mode:0o600,flag:'wx'});
  process.stdout.write(renderTatEvidenceOutputs(result));
  process.stdout.write(`##[set-output receipt_sha256=${createHash('sha256').update(raw).digest('hex')}]\n`);
}
function isMain() {
  try {return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);} catch {return false;}
}
if (isMain()) {
  main().catch((error) => {
    if (typeof error?.invocationId === 'string' && INVOCATION_ID_PATTERN.test(error.invocationId)) process.stdout.write(`tat_invocation_id=${error.invocationId}\n`);
    process.stderr.write('TAT release failed; inspect the bound invocation and protected configuration\n');
    process.exitCode = 1;
  });
}
