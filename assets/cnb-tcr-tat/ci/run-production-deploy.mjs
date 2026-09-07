import { createPublicKey } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runTatCommand, verifyTatInvocation, createTatClientFromEnvironment, renderTatEvidenceOutputs } from './run-tat-release.mjs';
import { validateReleaseReceipt } from './release-request.mjs';
import { parseStrictJson } from './strict-json.mjs';
import { canonicalBytes, parseCanonical, exact, requireValue, sha256, decodeBase64url, createProductionRequest,
         validateProductionContext, validateReadiness, validateApprovedSelection } from './production-contract.mjs';

const RESULT_KEYS=['schema','status','project','environment','approval_id','approval_sha256','candidate_tag','candidate_manifest_sha256','candidate_bytes_sha256','prepared_sha256','production_entry_sha256','production_authority_sha256','release_record_sha256','release'];
export function productionOperation({action,candidateRaw,candidateConfig,config,binding,readiness=null,approval=null,publicKey=null,now=Date.now()}) {
  const candidate=validateProductionContext(candidateRaw,candidateConfig,config);
  requireValue(['readiness','apply'].includes(action),'production action invalid');
  const approved=action==='apply'?validateApprovedSelection(approval,publicKey,candidate,candidateRaw,readiness,config,now):null;
  const request=createProductionRequest(action,candidateRaw,approval);
  const parseRequest=encoded=>{
    requireValue(encoded===request,'production request changed');
    const model=exact(parseCanonical(decodeBase64url(encoded)),['schema','action','candidate_b64url','approval']);
    requireValue(model.schema==='cnb-production-request/v1'&&model.action===action,'production request scope');return model;
  };
  const receiptValidator=receipt=>{
    if(action==='readiness') return validateReadiness(receipt,candidate,candidateRaw,config);
    exact(receipt,RESULT_KEYS,'production result');
    requireValue(receipt.schema==='cnb-production-result/v1'&&receipt.status==='passed'&&receipt.project===config.project&&receipt.environment==='production','production result scope');
    const expected={approval_id:approved.approval_id,approval_sha256:sha256(canonicalBytes(approval)),candidate_tag:candidate.candidate_tag,
      candidate_manifest_sha256:candidate.manifest_sha256,candidate_bytes_sha256:sha256(candidateRaw),prepared_sha256:approved.prepared_sha256,
      production_entry_sha256:config.production_entry_sha256,production_authority_sha256:config.production_authority_sha256};
    requireValue(Object.entries(expected).every(([key,value])=>receipt[key]===value)&&/^[0-9a-f]{64}$/.test(receipt.release_record_sha256),'production result binding');
    const release={schema:'cnb-release-request/v1',project:config.project,environment:'production',controller:config.controller_id,
      git_sha:candidate.application_commit,controller_commit:candidate.controller_commit,build_id:candidate.build_id,images:candidate.services};
    // The TAT binding pins the outer entry. The inner receipt independently pins
    // the shared transaction program through the generated production config.
    validateReleaseReceipt(receipt.release,release,config,{...binding,program_sha256:config.controller_program_sha256});
    return receipt;
  };
  return {candidate,request,parseRequest,receiptValidator};
}
export async function runProductionTat(options) {
  const operation=productionOperation(options);
  return runTatCommand({...options,...operation});
}
export async function verifyProductionReadiness(options) {
  const operation=productionOperation({...options,action:'readiness',approval:null});
  return verifyTatInvocation({...options,...operation});
}
export function argumentsMap(argv,allowed) {
  const args={};
  for(const argument of argv) {
    const match=/^--([a-z-]+)=(.+)$/.exec(argument);
    requireValue(match&&allowed.includes(match[1])&&!Object.hasOwn(args,match[1])&&!/[\r\n\0]/.test(match[2]),'production CLI arguments');
    args[match[1]]=match[2];
  }
  return args;
}
export async function readJson(path) {
  const bytes=await readFile(path);requireValue(bytes.length>0&&bytes.length<=128*1024,'production JSON file size');
  // Generated config/binding may be pretty printed; duplicate keys still fail.
  const value=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{maxBytes:128*1024});
  canonicalBytes(value); // Reject unsupported numeric and Unicode values too.
  return value;
}
export async function readPublicKey(path,expectedHash) {
  const raw=await readFile(path);requireValue(raw.length<=4096&&sha256(raw)===expectedHash,'production approval key hash');
  const key=createPublicKey(raw);requireValue(key.asymmetricKeyType==='ed25519'&&Buffer.from(key.export({format:'pem',type:'spki'})).equals(raw),'production approval key encoding');return key;
}
async function main() {
  const [action,...argv]=process.argv.slice(2), args=argumentsMap(argv,['config','candidate-config','binding','manifest','receipt','readiness','approval']);
  for(const key of ['config','candidate-config','binding','manifest','receipt']) requireValue(args[key],'production CLI required argument');
  requireValue(['readiness','apply'].includes(action)&&(action==='readiness'?Object.keys(args).length===5:Object.keys(args).length===7),'production CLI action arguments');
  const config=await readJson(args.config),candidateConfig=await readJson(args['candidate-config']),binding=await readJson(args.binding),candidateRaw=await readFile(args.manifest);
  const publicKey=await readPublicKey(join(dirname(args.config),'approval-ed25519.pub'),config.approval_public_key_sha256);
  const readiness=action==='apply'?parseCanonical(await readFile(args.readiness)):null;
  const approval=action==='apply'?parseCanonical(await readFile(args.approval)):null;
  const inputs={action,config,candidateConfig,binding,candidateRaw,publicKey,readiness,approval};
  productionOperation(inputs); // Reject bad public inputs before loading credentials.
  const client=createTatClientFromEnvironment(binding.region);
  const result=await runProductionTat({...inputs,client,onProgress:({invocationId,status})=>process.stdout.write(`tat_invocation_id=${invocationId}\ntat_invocation_status=${status}\n`)});
  const raw=canonicalBytes(result.receipt);await writeFile(args.receipt,raw,{mode:0o600,flag:'wx'});
  process.stdout.write(renderTatEvidenceOutputs(result));
  const outputs=action==='readiness'?{production_readiness_b64url:raw.toString('base64url'),production_prepared_sha256:result.receipt.prepared_sha256,
    production_readiness_invocation_id:result.invocationId,production_readiness_status:'passed'}:
    {production_deploy_status:'passed',production_receipt_sha256:sha256(raw)};
  for(const [key,value] of Object.entries(outputs)) process.stdout.write(`##[set-output ${key}=${value}]\n`);
}
try {
  if(process.argv[1]&&realpathSync(process.argv[1])===fileURLToPath(import.meta.url)) main().catch(error=>{
    if(typeof error.invocationId==='string'&&/^inv-[A-Za-z0-9-]{8,64}$/.test(error.invocationId)) process.stdout.write(`tat_invocation_id=${error.invocationId}\n`);
    process.stderr.write('Production verification failed; retain the exact invocation and local evidence\n');process.exitCode=1;
  });
} catch { /* Imported modules have no command-line effects. */ }
