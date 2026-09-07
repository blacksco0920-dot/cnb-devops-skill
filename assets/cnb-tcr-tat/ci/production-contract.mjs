// Bounded Ed25519 framing adapted from the FinAgent local production signer.
import { createHash, sign, verify } from 'node:crypto';
import { validateConfig } from './release-request.mjs';

export const APPROVAL_DOMAIN = Buffer.from('cnb-production-approval-v1\0');
export const MAX_ENVELOPE = 48 * 1024;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const requireValue = (value, message) => {if (!value) throw new Error(message);};
export function exact(value, keys, name='production object') {
  requireValue(value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===keys.length && keys.every(key=>Object.hasOwn(value,key)), `${name} fields mismatch`);
  return value;
}
export function canonicalBytes(value) {
  const seen=new Set();let count=0;
  function render(item,depth=0) {
    requireValue(depth<=64 && ++count<=100000,'production JSON limit');
    if(item===null || typeof item==='boolean') return JSON.stringify(item);
    if(typeof item==='number') {requireValue(Number.isSafeInteger(item),'production JSON integer required');return JSON.stringify(item);}
    if(typeof item==='string') {
      for(const c of item) requireValue(c.codePointAt(0)<0xd800 || c.codePointAt(0)>0xdfff,'invalid Unicode');
      return JSON.stringify(item);
    }
    requireValue(item && typeof item==='object' && !seen.has(item),'production JSON value');seen.add(item);
    const descriptors=Object.getOwnPropertyDescriptors(item), keys=Reflect.ownKeys(descriptors);
    requireValue(keys.every(key=>typeof key==='string' && Object.hasOwn(descriptors[key],'value')),'production JSON data required');
    let result;
    if(Array.isArray(item)) {
      requireValue(keys.length===item.length+1 && Array.from({length:item.length},(_,i)=>Object.hasOwn(item,i)).every(Boolean),'production JSON array');
      result='['+item.map(v=>render(v,depth+1)).join(',')+']';
    } else {
      requireValue([Object.prototype,null].includes(Object.getPrototypeOf(item)) && keys.every(key=>/^[\x20-\x7e]*$/.test(key)),'production JSON keys');
      result='{'+keys.sort().map(key=>JSON.stringify(key)+':'+render(descriptors[key].value,depth+1)).join(',')+'}';
    }
    seen.delete(item);return result;
  }
  return Buffer.from(render(value)+'\n','utf8');
}
export function parseCanonical(raw,limit=64*1024) {
  requireValue(Buffer.isBuffer(raw)&&raw.length>0&&raw.length<=limit,'production JSON size');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw), value=JSON.parse(text);
  requireValue(canonicalBytes(value).equals(raw),'production JSON not canonical');return value;
}
export function decodeBase64url(text,limit=MAX_ENVELOPE) {
  requireValue(typeof text==='string'&&/^[A-Za-z0-9_-]+$/.test(text)&&text.length<=limit,'production base64url size');
  const raw=Buffer.from(text,'base64url');requireValue(raw.toString('base64url')===text,'production base64url canonical');return raw;
}
const H64=/^[0-9a-f]{64}$/,H40=/^[0-9a-f]{40}$/;
const matches=(v,re)=>typeof v==='string'&&re.test(v);
export function utc(value) {
  requireValue(matches(value,/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString().replace('.000Z','Z')===value,'production UTC invalid');return Date.parse(value);
}
export const APPROVAL_KEYS=['schema','project','environment','authorize','approval_id','candidate_tag','candidate_manifest_sha256','candidate_bytes_sha256','application_commit','build_id','authority_sha256','prepared_sha256','previous_release_sha256','issued_at','expires_at'];
export function approvalPayload(payload) {
  exact(payload,APPROVAL_KEYS,'approval');
  requireValue(payload.schema==='cnb-production-approval/v1'&&payload.environment==='production'&&payload.authorize==='production-apply'&&matches(payload.project,/^[a-z][a-z0-9-]{0,62}$/),'approval scope');
  requireValue(matches(payload.approval_id,/^[0-9a-f]{32}$/)&&matches(payload.application_commit,H40)&&matches(payload.build_id,/^cnb-[a-z0-9][a-z0-9-]{2,127}$/)&&matches(payload.candidate_tag,/^[a-z][a-z0-9-]{0,191}$/),'approval identity');
  for(const key of ['candidate_manifest_sha256','candidate_bytes_sha256','authority_sha256','prepared_sha256','previous_release_sha256']) requireValue(matches(payload[key],H64),'approval hash');
  requireValue(utc(payload.expires_at)>utc(payload.issued_at)&&utc(payload.expires_at)-utc(payload.issued_at)<=3600000,'approval lifetime');return payload;
}
export function signApproval(payload,privateKey) {
  approvalPayload(payload);requireValue(privateKey.asymmetricKeyType==='ed25519','approval key type');
  const raw=canonicalBytes(payload),signature=sign(null,Buffer.concat([APPROVAL_DOMAIN,raw]),privateKey);
  requireValue(signature.length===64,'approval signature size');
  return {schema:'cnb-production-approval-envelope/v1',payload_b64url:raw.toString('base64url'),signature_b64url:signature.toString('base64url')};
}
export function verifyApproval(envelope,publicKey) {
  exact(envelope,['schema','payload_b64url','signature_b64url'],'approval envelope');
  requireValue(envelope.schema==='cnb-production-approval-envelope/v1'&&publicKey.asymmetricKeyType==='ed25519','approval envelope scope');
  const raw=decodeBase64url(envelope.payload_b64url,8192),signature=decodeBase64url(envelope.signature_b64url,86);
  requireValue(signature.length===64&&verify(null,Buffer.concat([APPROVAL_DOMAIN,raw]),publicKey,signature),'approval signature rejected');
  return approvalPayload(parseCanonical(raw,8192));
}
export const CANDIDATE_KEYS=['project','environment','controller','policy_sha256','release_receipt_sha256','application_commit','build_id','build_url','candidate_tag','controller_commit','controller_compose_sha256','controller_program_sha256','created_at','evidence','manifest_sha256','schema','services'];
export function parseCandidate(raw,config) {
  const candidate=exact(parseCanonical(raw,24*1024),CANDIDATE_KEYS,'candidate');
  requireValue(candidate.schema==='cnb-candidate/v1'&&candidate.project===config.project&&candidate.environment==='test'&&candidate.controller===config.controller_id,'candidate scope');
  requireValue(matches(candidate.application_commit,H40)&&candidate.controller_commit===candidate.application_commit&&matches(candidate.build_id,/^cnb-[a-z0-9][a-z0-9-]{2,127}$/),'candidate commit/build');
  requireValue(candidate.candidate_tag===config.candidate_prefix+candidate.build_id&&candidate.build_url===`https://cnb.cool/${config.cnb_repository}/-/build/logs/${candidate.build_id}`,'candidate tag/build URL');
  utc(candidate.created_at);
  for(const key of ['controller_program_sha256','controller_compose_sha256','policy_sha256']) requireValue(matches(candidate[key],H64)&&candidate[key]===config[key],'candidate controller hashes');
  requireValue(matches(candidate.release_receipt_sha256,H64)&&matches(candidate.manifest_sha256,H64),'candidate evidence hashes');
  exact(candidate.services,Object.keys(config.services),'candidate services');
  for(const [role,spec] of Object.entries(config.services)) requireValue(typeof candidate.services[role]==='string'&&candidate.services[role].startsWith(spec.image_repository+'@sha256:')&&H64.test(candidate.services[role].slice(spec.image_repository.length+8)),'candidate immutable image');
  exact(candidate.evidence,['build','runtime','public'],'candidate evidence');
  const probes=[...new Set(config.probes.map(p=>p.url))].sort();
  for(const [plane,keys] of Object.entries({build:['status','verified_at','reference'],runtime:['status','verified_at','reference','container_count'],public:['status','verified_at','reference','probe_count','probes']})) {
    const value=exact(candidate.evidence[plane],keys,plane);requireValue(value.status==='passed','candidate evidence not passed');utc(value.verified_at);
    requireValue(typeof value.reference==='string'&&(/^(https:\/\/[^\s]+|tat:inv-[A-Za-z0-9-]{8,64})$/).test(value.reference),'candidate evidence reference');
  }
  requireValue(candidate.evidence.build.reference===candidate.build_url&&candidate.evidence.runtime.container_count===Object.keys(config.services).length&&candidate.evidence.public.probe_count===probes.length&&canonicalBytes(candidate.evidence.public.probes).equals(canonicalBytes(probes)),'candidate evidence coverage');
  const unsigned={...candidate};delete unsigned.manifest_sha256;
  requireValue(candidate.manifest_sha256===sha256(canonicalBytes(unsigned).subarray(0,-1)),'candidate content hash');return candidate;
}
export const READY_KEYS=['schema','status','project','environment','controller','application_commit','build_id','images','candidate_tag','candidate_manifest_sha256','candidate_bytes_sha256','production_entry_sha256','production_authority_sha256','controller_program_sha256','policy_sha256','controller_compose_sha256','prepared_sha256','prepared_created_at','prepared_expires_at','previous_release_sha256','host_fingerprint_sha256'];
export function validateReadiness(receipt,candidate,raw,config,now=Date.now()) {
  exact(receipt,READY_KEYS,'readiness');
  requireValue(receipt.schema==='cnb-production-readiness/v1'&&receipt.status==='ready'&&receipt.project===config.project&&receipt.environment==='production'&&receipt.controller===config.controller_id,'readiness scope');
  for(const field of ['application_commit','build_id','candidate_tag']) requireValue(receipt[field]===candidate[field],'readiness candidate identity');
  requireValue(receipt.candidate_manifest_sha256===candidate.manifest_sha256&&receipt.candidate_bytes_sha256===sha256(raw)&&canonicalBytes(receipt.images).equals(canonicalBytes(candidate.services)),'readiness candidate bytes/images');
  for(const field of ['production_entry_sha256','production_authority_sha256','controller_program_sha256','policy_sha256','controller_compose_sha256']) requireValue(matches(receipt[field],H64)&&receipt[field]===config[field],'readiness target hash');
  for(const field of ['prepared_sha256','previous_release_sha256','host_fingerprint_sha256']) requireValue(matches(receipt[field],H64),'readiness state hash');
  requireValue(utc(receipt.prepared_created_at)<=now&&now<utc(receipt.prepared_expires_at)&&utc(receipt.prepared_expires_at)-utc(receipt.prepared_created_at)===86400000,'readiness expired');return receipt;
}
export function createProductionRequest(action,candidateRaw,approval=null) {
  requireValue(['readiness','apply'].includes(action)&&(action==='readiness'?approval===null:approval!==null),'production action');
  const request={schema:'cnb-production-request/v1',action,candidate_b64url:candidateRaw.toString('base64url'),approval};
  const encoded=canonicalBytes(request).toString('base64url');requireValue(encoded.length<=MAX_ENVELOPE,'production request too large');return encoded;
}

export function validateProductionContext(candidateRaw,candidateConfig,config) {
  validateConfig(config);validateConfig(candidateConfig);
  requireValue(candidateConfig.environment==='test','tested candidate config scope');
  requireValue(config.schema==='cnb-devops-ci/v1'&&config.environment==='production'&&config.project===candidateConfig.project,'production config scope');
  for(const key of ['production_entry_sha256','production_authority_sha256','approval_public_key_sha256','controller_program_sha256','controller_compose_sha256','policy_sha256']) requireValue(matches(config[key],H64),'production config hash');
  exact(config.services,Object.keys(candidateConfig.services),'production service roles');
  for(const name of Object.keys(config.services)) requireValue(config.services[name].image_repository===candidateConfig.services[name].image_repository,'production repository differs from tested candidate');
  return parseCandidate(candidateRaw,candidateConfig);
}
export function validateApprovedSelection(envelope,publicKey,candidate,candidateRaw,readiness,config,now=Date.now()) {
  const payload=verifyApproval(envelope,publicKey);validateReadiness(readiness,candidate,candidateRaw,config,now);
  for(const key of ['project','candidate_tag','application_commit','build_id','candidate_manifest_sha256','candidate_bytes_sha256','prepared_sha256','previous_release_sha256']) requireValue(payload[key]===readiness[key],'approval/readiness binding mismatch');
  requireValue(payload.authority_sha256===config.production_authority_sha256&&utc(readiness.prepared_created_at)<=utc(payload.issued_at)&&utc(payload.issued_at)<=now&&now<utc(payload.expires_at)&&utc(payload.expires_at)<=utc(readiness.prepared_expires_at),'approval expired or target changed');return payload;
}
