#!/usr/bin/env node
// Build evidence contains no credentials. A root permit is still required by TAT.
import {readFile,writeFile} from 'node:fs/promises';
import {realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {validateReleaseRequest,validateReleaseReceipt} from './release-request.mjs';
import {parseStrictJson} from './strict-json.mjs';
import {runTatCommand,validateBinding,createTatClientFromEnvironment,renderTatEvidenceOutputs} from './run-tat-release.mjs';

const hash=raw=>createHash('sha256').update(raw).digest('hex');
const fail=()=>{throw Error('TEST_REPAIR_INPUT_INVALID');};
export function canonical(value) {
  if(Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object') return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
export function createBuildHandoff({configRaw,gitSha,buildId,images}) {
  const config=parseStrictJson(configRaw);
  if(config.environment!=='test') fail();
  const request=validateReleaseRequest({schema:'cnb-release-request/v1',project:config.project,environment:'test',
    controller:config.controller_id,git_sha:gitSha,controller_commit:gitSha,build_id:buildId,images},config);
  return Buffer.from(canonical({schema:'cnb-test-build-handoff/v1',request,ci_config_sha256:hash(configRaw)})).toString('base64url');
}
export function parseBuildHandoff(encoded,configRaw,currentCommit) {
  if(typeof encoded!=='string'||encoded.length>32*1024||!/^[A-Za-z0-9_-]+$/.test(encoded)) fail();
  const raw=Buffer.from(encoded,'base64url'),config=parseStrictJson(configRaw);
  const model=parseStrictJson(raw.toString('utf8'));
  if(config.environment!=='test'||raw.toString('base64url')!==encoded||canonical(model)!==raw.toString('utf8')||
    Object.keys(model).sort().join(',')!=='ci_config_sha256,request,schema'||model.schema!=='cnb-test-build-handoff/v1'||
    model.ci_config_sha256!==hash(configRaw)) fail();
  validateReleaseRequest(model.request,config);
  if(model.request.git_sha!==currentCommit) fail();
  return model;
}
export function renderRepairRequest(request,config) {
  validateReleaseRequest(request,config);
  if(config.environment!=='test') fail();
  const encoded=Buffer.from(canonical({...request,schema:'cnb-test-repair-request/v1'})).toString('base64url');
  if(encoded.length>16*1024) fail();
  return encoded;
}
export function parseRepairRequest(encoded,config) {
  if(config.environment!=='test'||typeof encoded!=='string'||encoded.length>16*1024||!/^[A-Za-z0-9_-]+$/.test(encoded)) fail();
  const raw=Buffer.from(encoded,'base64url'),wire=parseStrictJson(raw.toString('utf8'));
  if(raw.toString('base64url')!==encoded||canonical(wire)!==raw.toString('utf8')||wire.schema!=='cnb-test-repair-request/v1') fail();
  return validateReleaseRequest({...wire,schema:'cnb-release-request/v1'},config);
}
async function main() {
  const args={};
  for(const arg of process.argv.slice(2)) {
    const m=/^--(action|config|images|binding|receipt)=(.+)$/.exec(arg);
    if(!m||Object.hasOwn(args,m[1])||/[\r\n\0]/.test(m[2])) fail();
    args[m[1]]=m[2];
  }
  const configRaw=await readFile(args.config,'utf8');
  if(args.action==='record') {
    if(Object.keys(args).sort().join(',')!=='action,config,images') fail();
    const handoff=createBuildHandoff({configRaw,gitSha:process.env.CNB_COMMIT,buildId:process.env.CNB_BUILD_ID,
      images:parseStrictJson(await readFile(args.images,'utf8'))});
    process.stdout.write('CNB_TEST_BUILD_HANDOFF='+handoff+'\n');
    return;
  }
  if(!['prepare','deploy'].includes(args.action)) fail();
  const handoff=parseBuildHandoff(process.env.CNB_TEST_REPAIR_BUILD,configRaw,process.env.CNB_COMMIT);
  if(!/^cnb-[a-z0-9][a-z0-9-]{2,127}$/.test(process.env.CNB_BUILD_ID||'')||
     process.env.CNB_BUILD_ID===handoff.request.build_id) fail();
  if(args.action==='prepare') {
    if(Object.keys(args).sort().join(',')!=='action,config') fail();
    await writeFile('.cnb-release/repair-execution.json',canonical({schema:'cnb-test-repair-execution/v1',
      source_build_id:handoff.request.build_id,execution_build_id:process.env.CNB_BUILD_ID,
      request_sha256:hash(canonical(handoff.request)+'\n')})+'\n',{flag:'wx',mode:0o600});
    process.stdout.write(`##[set-output source_build_id=${handoff.request.build_id}]\n`);
    return;
  }
  if(Object.keys(args).sort().join(',')!=='action,binding,config,receipt') fail();
  const config=parseStrictJson(configRaw),binding=parseStrictJson(await readFile(args.binding,'utf8'));
  validateBinding(binding,config);
  const result=await runTatCommand({client:createTatClientFromEnvironment(binding.region),
    request:renderRepairRequest(handoff.request,config),config,binding,
    parseRequest:parseRepairRequest,receiptValidator:validateReleaseReceipt,
    onProgress:({invocationId,status})=>process.stdout.write(`tat_invocation_id=${invocationId}\ntat_invocation_status=${status}\n`)});
  const raw=JSON.stringify(result.receipt)+'\n';
  await writeFile(args.receipt,raw,{mode:0o600,flag:'wx'});
  process.stdout.write(renderTatEvidenceOutputs(result));
  process.stdout.write(`##[set-output receipt_sha256=${hash(raw)}]\n`);
}
let isMain=false;
try {isMain=process.argv[1]&&realpathSync(process.argv[1])===fileURLToPath(import.meta.url);} catch {}
if(isMain) main().catch(()=>{process.stderr.write('TEST_REPAIR_FAILED\n');process.exitCode=1;});
