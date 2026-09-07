import { generateKeyPairSync } from 'node:crypto';
import { canonicalBytes, sha256, signApproval, createProductionRequest } from '../assets/cnb-tcr-tat/ci/production-contract.mjs';

export function productionFixture(names=['web']) {
  const instant=Math.floor(Date.now()/1000)*1000,stamp=value=>new Date(value).toISOString().replace('.000Z','Z');
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const publicPem=Buffer.from(publicKey.export({type:'spki',format:'pem'}));
  const services=Object.fromEntries(names.map(name=>[name,{image_repository:`registry.example/team/sample-${name}`,image_env:`RELEASE_${name.toUpperCase()}_IMAGE`}]));
  const candidateConfig={schema:'cnb-devops-ci/v1',project:'sample',environment:'test',controller_id:'sample-test-controller-v1',candidate_prefix:'sample-candidate-',cnb_repository:'example/sample',services,
    probes:names.map(name=>({url:`https://${name}.test.example/health`})),controller_program_sha256:'a'.repeat(64),controller_compose_sha256:'b'.repeat(64),policy_sha256:'c'.repeat(64)};
  const config={...candidateConfig,environment:'production',controller_id:'sample-production-controller-v1',probes:names.map(name=>({url:`https://${name}.example/health`})),
    controller_program_sha256:'d'.repeat(64),controller_compose_sha256:'e'.repeat(64),policy_sha256:'f'.repeat(64),production_entry_sha256:'1'.repeat(64),production_authority_sha256:'2'.repeat(64),approval_public_key_sha256:sha256(publicPem)};
  const images=Object.fromEntries(names.map((name,i)=>[name,services[name].image_repository+'@sha256:'+String(i+3).repeat(64)]));
  const candidate={schema:'cnb-candidate/v1',project:'sample',environment:'test',controller:candidateConfig.controller_id,application_commit:'a'.repeat(40),controller_commit:'a'.repeat(40),build_id:'cnb-example-123',
    build_url:'https://cnb.cool/example/sample/-/build/logs/cnb-example-123',candidate_tag:'sample-candidate-cnb-example-123',created_at:stamp(instant-120000),services:images,
    controller_program_sha256:candidateConfig.controller_program_sha256,controller_compose_sha256:candidateConfig.controller_compose_sha256,policy_sha256:candidateConfig.policy_sha256,release_receipt_sha256:'6'.repeat(64),
    evidence:{build:{status:'passed',verified_at:stamp(instant-120000),reference:'https://cnb.cool/example/sample/-/build/logs/cnb-example-123'},
      runtime:{status:'passed',verified_at:stamp(instant-120000),reference:'tat:inv-DEMO1234',container_count:names.length},
      public:{status:'passed',verified_at:stamp(instant-120000),reference:'tat:inv-DEMO1234',probe_count:names.length,probes:candidateConfig.probes.map(p=>p.url).sort()}}};
  candidate.manifest_sha256=sha256(canonicalBytes(candidate).subarray(0,-1));
  const candidateRaw=canonicalBytes(candidate);
  const readiness={schema:'cnb-production-readiness/v1',status:'ready',project:'sample',environment:'production',controller:config.controller_id,
    application_commit:candidate.application_commit,build_id:candidate.build_id,images,candidate_tag:candidate.candidate_tag,candidate_manifest_sha256:candidate.manifest_sha256,candidate_bytes_sha256:sha256(candidateRaw),
    production_entry_sha256:config.production_entry_sha256,production_authority_sha256:config.production_authority_sha256,controller_program_sha256:config.controller_program_sha256,policy_sha256:config.policy_sha256,controller_compose_sha256:config.controller_compose_sha256,
    prepared_sha256:'7'.repeat(64),previous_release_sha256:'8'.repeat(64),host_fingerprint_sha256:'9'.repeat(64),prepared_created_at:stamp(instant-60000),prepared_expires_at:stamp(instant-60000+86400000)};
  const payload={schema:'cnb-production-approval/v1',project:'sample',environment:'production',authorize:'production-apply',approval_id:'a'.repeat(32),candidate_tag:candidate.candidate_tag,
    candidate_manifest_sha256:candidate.manifest_sha256,candidate_bytes_sha256:sha256(candidateRaw),application_commit:candidate.application_commit,build_id:candidate.build_id,authority_sha256:config.production_authority_sha256,
    prepared_sha256:readiness.prepared_sha256,previous_release_sha256:readiness.previous_release_sha256,issued_at:stamp(instant),expires_at:stamp(instant+3600000)};
  const approval=signApproval(payload,privateKey);
  const template='#!/bin/sh\n# production {{release_request_b64url}}\n';
  const binding={schema:'cnb-tat-binding/v1',project:'sample',environment:'production',region:'ap-guangzhou',instance_id:'lhins-DEMO1234',command_id:'cmd-DEMO1234',command_sha256:sha256(template),program_sha256:config.production_entry_sha256,compose_sha256:config.controller_compose_sha256,policy_sha256:config.policy_sha256,username:'release',working_directory:'/home/release',timeout:3600};
  const release={schema:'cnb-deploy-result/v1',status:'passed',project:'sample',environment:'production',controller:config.controller_id,git_sha:candidate.application_commit,controller_commit:candidate.controller_commit,build_id:candidate.build_id,images,
    controller_program_sha256:config.controller_program_sha256,controller_compose_sha256:config.controller_compose_sha256,policy_sha256:config.policy_sha256,database_backup_sha256:'b'.repeat(64),container_count:names.length,probe_count:names.length,probes:config.probes.map(p=>p.url).sort()};
  const result={schema:'cnb-production-result/v1',status:'passed',project:'sample',environment:'production',approval_id:payload.approval_id,approval_sha256:sha256(canonicalBytes(approval)),candidate_tag:candidate.candidate_tag,candidate_manifest_sha256:candidate.manifest_sha256,candidate_bytes_sha256:sha256(candidateRaw),prepared_sha256:readiness.prepared_sha256,production_entry_sha256:config.production_entry_sha256,production_authority_sha256:config.production_authority_sha256,release_record_sha256:'c'.repeat(64),release};
  function clientFor(action='readiness') {
    const encoded=createProductionRequest(action,candidateRaw,action==='apply'?approval:null);
    const metadata={CommandId:binding.command_id,CommandType:'SHELL',Username:binding.username,WorkingDirectory:binding.working_directory,Timeout:binding.timeout};
    const task={InvocationId:'inv-DEMO1234',CommandId:binding.command_id,InstanceId:binding.instance_id,TaskStatus:'SUCCESS',CommandDocument:{...metadata,Content:Buffer.from(template.replace('{{release_request_b64url}}',encoded)).toString('base64')},TaskResult:{ExitCode:0,Dropped:0,Output:canonicalBytes(action==='apply'?result:readiness).toString('base64')}};
    let invoked=0,described=0;
    const client={DescribeCommands:async()=>{described++;return {TotalCount:1,CommandSet:[{...metadata,CreatedBy:'USER',EnableParameter:true,DefaultParameters:'{"release_request_b64url":"INVALID"}',Content:Buffer.from(template).toString('base64')}]};},InvokeCommand:async()=>{invoked++;return {InvocationId:task.InvocationId};},DescribeInvocationTasks:async()=>({TotalCount:1,InvocationTaskSet:[task]})};
    return {client,task,invoked:()=>invoked,described:()=>described};
  }
  return {candidate,candidateRaw,candidateConfig,config,binding,readiness,payload,approval,publicKey,privateKey,publicPem,result,instant,clientFor};
}
