// Local administrator only. Freeze this program, imported modules, generated
// target config/binding and chosen candidate before reading a real private key.
import { constants } from 'node:fs';
import { lstat, open, realpath, writeFile, readFile } from 'node:fs/promises';
import { dirname, resolve, join, parse } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { canonicalBytes, requireValue, sha256, signApproval, validateProductionContext, utc } from '../ci/production-contract.mjs';
import { argumentsMap, readJson, readPublicKey, verifyProductionReadiness } from '../ci/run-production-deploy.mjs';
import { createTatClientFromEnvironment } from '../ci/run-tat-release.mjs';

async function secureDirectory(value) {
  const directory=resolve(value);requireValue(await realpath(directory)===directory,'signer directory symlink');
  for(let current=directory;;current=dirname(current)) {
    const info=await lstat(current),sticky=current!==directory&&info.uid===0&&(info.mode&0o1000)!==0;
    requireValue(info.isDirectory()&&!info.isSymbolicLink()&&[0,process.getuid()].includes(info.uid)&&((info.mode&0o022)===0||sticky),'signer directory unsafe');
    if(current===parse(current).root) break;
  }
  return directory;
}
async function privateKeyBytes(value) {
  const path=resolve(value);await secureDirectory(dirname(path));
  const handle=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    const before=await handle.stat();requireValue(before.isFile()&&before.nlink===1&&before.uid===process.getuid()&&(before.mode&0o7777)===0o600&&before.size>0&&before.size<=16384,'signer private key metadata');
    const bytes=await handle.readFile(),after=await handle.stat(),named=await lstat(path);
    requireValue(bytes.length===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs&&after.ctimeMs===before.ctimeMs&&named.ino===before.ino&&named.dev===before.dev&&!named.isSymbolicLink(),'signer private key changed');return bytes;
  } finally {await handle.close();}
}
/** `authorized` comes from the operator's granted scope, never an annotation. */
export async function approveProduction({client,config,candidateConfig,binding,candidateRaw,publicKey,invocationId,privateKeyPath,output,authorized=false,now=Date.now}) {
  requireValue(authorized===true&&process.env.CNB!=='true'&&typeof process.getuid==='function','local production authorization required');
  const candidate=validateProductionContext(candidateRaw,candidateConfig,config);
  const verified=await verifyProductionReadiness({client,config,candidateConfig,binding,candidateRaw,invocationId,publicKey});
  const readiness=verified.receipt,issued=Math.floor(now()/1000)*1000;
  requireValue(issued<utc(readiness.prepared_expires_at),'readiness expired before signing');
  const payload={schema:'cnb-production-approval/v1',project:config.project,environment:'production',authorize:'production-apply',approval_id:randomBytes(16).toString('hex'),
    candidate_tag:candidate.candidate_tag,candidate_manifest_sha256:candidate.manifest_sha256,candidate_bytes_sha256:sha256(candidateRaw),
    application_commit:candidate.application_commit,build_id:candidate.build_id,authority_sha256:config.production_authority_sha256,
    prepared_sha256:readiness.prepared_sha256,previous_release_sha256:readiness.previous_release_sha256,
    issued_at:new Date(issued).toISOString().replace('.000Z','Z'),expires_at:new Date(Math.min(issued+3600000,utc(readiness.prepared_expires_at))).toISOString().replace('.000Z','Z')};
  await secureDirectory(dirname(resolve(output)));
  let bytes;
  try {
    bytes=await privateKeyBytes(privateKeyPath);
    const key=createPrivateKey(bytes),derived=Buffer.from(createPublicKey(key).export({format:'pem',type:'spki'}));
    requireValue(key.asymmetricKeyType==='ed25519'&&derived.equals(Buffer.from(publicKey.export({format:'pem',type:'spki'})))&&sha256(derived)===config.approval_public_key_sha256,'signer key differs from installed approval key');
    const envelope=signApproval(payload,key),raw=canonicalBytes(envelope);
    await writeFile(output,raw,{mode:0o600,flag:'wx'});
    requireValue((await readFile(output)).equals(raw),'approval output readback');
    return {approval_id:payload.approval_id,approval_sha256:sha256(raw),production_approval_b64url:raw.toString('base64url'),readiness_invocation_id:invocationId};
  } finally {bytes?.fill(0);}
}
async function main() {
  const argv=process.argv.slice(2);requireValue(argv.at(-1)==='--authorize-production-apply','explicit production authorization flag required');
  const args=argumentsMap(argv.slice(0,-1),['config','candidate-config','binding','manifest','readiness-invocation-id','private-key','public-key','output']);
  for(const key of ['config','candidate-config','binding','manifest','readiness-invocation-id','private-key','output']) requireValue(args[key],'signer required argument');
  requireValue(process.env.CNB!=='true','signing key never belongs in CI');
  const config=await readJson(args.config),candidateConfig=await readJson(args['candidate-config']),binding=await readJson(args.binding),candidateRaw=await readFile(args.manifest);
  const publicKey=await readPublicKey(args['public-key']??join(dirname(args.config),'approval-ed25519.pub'),config.approval_public_key_sha256);
  validateProductionContext(candidateRaw,candidateConfig,config);
  const client=createTatClientFromEnvironment(binding.region);
  const result=await approveProduction({client,config,candidateConfig,binding,candidateRaw,publicKey,invocationId:args['readiness-invocation-id'],privateKeyPath:args['private-key'],output:args.output,authorized:true});
  process.stdout.write(JSON.stringify(result)+'\n');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  main().catch(()=>{process.stderr.write('Production approval stopped; no unverified readiness or CI approval annotation authorizes signing\n');process.exitCode=1;});
}
