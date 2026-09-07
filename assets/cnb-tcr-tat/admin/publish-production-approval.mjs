// Publish an already authorized public envelope; this program never loads a signing key.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { argumentsMap, readJson, readPublicKey } from '../ci/run-production-deploy.mjs';
import { canonicalBytes, parseCanonical, requireValue, sha256, validateProductionContext, validateApprovedSelection } from '../ci/production-contract.mjs';
import { parseStrictJson } from '../ci/strict-json.mjs';

export function expectedApprovalAnnotations({config,candidateConfig,candidateRaw,readiness,approval,publicKey,invocationId,now=Date.now()}) {
  const candidate=validateProductionContext(candidateRaw,candidateConfig,config);
  const approved=validateApprovedSelection(approval,publicKey,candidate,candidateRaw,readiness,config,now);
  requireValue(typeof invocationId==='string'&&/^inv-[A-Za-z0-9-]{8,64}$/.test(invocationId),'readiness invocation required');
  requireValue(typeof candidateConfig.cnb_repository==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*){1,7}$/.test(candidateConfig.cnb_repository),'CNB repository invalid');
  const raw=canonicalBytes(approval);
  return {url:`https://api.cnb.cool/${candidateConfig.cnb_repository}/-/git/tag-annotations/${encodeURIComponent(candidate.candidate_tag)}`,
    candidate_tag:candidate.candidate_tag,approval_id:approved.approval_id,
    prerequisites:{candidate_format:candidate.schema,candidate_manifest_sha256:candidate.manifest_sha256,candidate_commit:candidate.application_commit,
      test_build_status:candidate.evidence.build.status,test_runtime_status:candidate.evidence.runtime.status,test_public_status:candidate.evidence.public.status,candidate_status:'ready',
      production_readiness_b64url:canonicalBytes(readiness).toString('base64url'),production_prepared_sha256:readiness.prepared_sha256,
      production_readiness_invocation_id:invocationId,production_readiness_status:'passed'},
    payload:{production_approval_b64url:raw.toString('base64url'),production_approval_sha256:sha256(raw)}};
}

async function responseJson(response) {
  const chunks=[];let size=0;
  requireValue(response.body,'CNB annotation response missing');
  for await(const chunk of response.body) {
    size+=chunk.length;requireValue(size<=256*1024,'CNB annotation response too large');chunks.push(Buffer.from(chunk));
  }
  return parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),{maxBytes:256*1024});
}

/** Preview is local only. Apply updates three approval fields, with status last. */
export async function publishProductionApproval(inputs) {
  const {apply=false,token,fetchImpl=globalThis.fetch}=inputs;
  const now=typeof inputs.now==='function'?inputs.now:Date.now;
  const plan=expectedApprovalAnnotations({...inputs,now:now()});
  const result={schema:'cnb-production-approval-publication/v1',status:'preview',candidate_tag:plan.candidate_tag,
    approval_id:plan.approval_id,approval_sha256:plan.payload.production_approval_sha256,endpoint:plan.url};
  if(!apply)return result;
  requireValue(typeof token==='string'&&token.length>0&&token.length<=16384&&!/[\r\n\0]/.test(token),'project-scoped CNB token required');
  requireValue(typeof fetchImpl==='function','CNB HTTP client required');
  async function request(method,annotations) {
    const response=await fetchImpl(plan.url,{method,redirect:'error',signal:AbortSignal.timeout(15000),
      headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.cnb.api+json',...(method==='PUT'?{'Content-Type':'application/json'}:{})},
      ...(method==='PUT'?{body:JSON.stringify({annotations:Object.entries(annotations).map(([key,value])=>({key,value}))})}:{})});
    requireValue(response.ok,`CNB annotation ${method} failed (HTTP ${response.status})`);
    if(method==='PUT'){await response.body?.cancel();return;}
    const model=await responseJson(response);requireValue(Array.isArray(model)&&model.length<=1024,'CNB annotation response shape');
    const map=Object.create(null);
    for(const item of model) {
      requireValue(item&&typeof item==='object'&&!Array.isArray(item)&&typeof item.key==='string'&&typeof item.value==='string'&&!Object.hasOwn(map,item.key),'CNB annotation duplicate or invalid entry');
      map[item.key]=item.value;
    }
    return map;
  }
  function checked(map,expected={}) {
    expectedApprovalAnnotations({...inputs,now:now()}); // Time may expire between network calls.
    for(const [key,value] of Object.entries({...plan.prerequisites,...expected}))requireValue(map[key]===value,`CNB annotation mismatch: ${key}`);
    return map;
  }
  let state=checked(await request('GET'));
  if(state.production_approval_status==='signed'&&Object.entries(plan.payload).every(([key,value])=>state[key]===value))return {...result,status:'signed',writes:0};
  await request('PUT',{production_approval_status:'pending'});
  state=checked(await request('GET'),{production_approval_status:'pending'});
  await request('PUT',plan.payload);
  state=checked(await request('GET'),{...plan.payload,production_approval_status:'pending'});
  await request('PUT',{production_approval_status:'signed'});
  checked(await request('GET'),{...plan.payload,production_approval_status:'signed'});
  return {...result,status:'signed',writes:3};
}

async function main() {
  const argv=process.argv.slice(2),apply=argv.at(-1)==='--apply';
  const args=argumentsMap(apply?argv.slice(0,-1):argv,['config','candidate-config','manifest','readiness','approval','readiness-invocation-id']);
  requireValue(Object.keys(args).length===6,'publisher requires config, candidate-config, manifest, readiness, approval and readiness-invocation-id');
  const config=await readJson(args.config),candidateConfig=await readJson(args['candidate-config']),candidateRaw=await readFile(args.manifest);
  const readiness=parseCanonical(await readFile(args.readiness)),approval=parseCanonical(await readFile(args.approval));
  const publicKey=await readPublicKey(join(dirname(args.config),'approval-ed25519.pub'),config.approval_public_key_sha256);
  const inputs={config,candidateConfig,candidateRaw,readiness,approval,publicKey,invocationId:args['readiness-invocation-id'],apply};
  expectedApprovalAnnotations(inputs); // Reject invalid inputs before credential access.
  if(apply){inputs.token=process.env.CNB_TOKEN;delete process.env.CNB_TOKEN;}
  process.stdout.write(JSON.stringify(await publishProductionApproval(inputs))+'\n');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  main().catch(()=>{process.stderr.write('Production approval publication stopped; retain the selected candidate and exact annotation readback\n');process.exitCode=1;});
}
