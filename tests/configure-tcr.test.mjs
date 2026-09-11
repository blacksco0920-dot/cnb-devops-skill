import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const module = await import('../scripts/configure-tcr.mjs').catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {};
  throw error;
});
const NOW = '2026-09-11T10:00:00.000Z', TIME = '2026-09-11 18:00:00';
const roles = ['build-push', 'host-pull'];
const spec = () => ({schema_version:1,project:'sample',environment:'test',account_id:'90001',edition:'Personal',
  region:'ap-guangzhou',registry:'ccr.ccs.tencentyun.com',namespace:'sample-test',
  repositories:[{name:'sample-test/api',description:'cnb-devops:sample:test:api'}],lease:{expires_at:'2026-09-18T10:00:00Z'},
  identities:Object.fromEntries(roles.map(role=>[role,{user_name:`sample-test-${role}`,policy_name:`sample-test-${role}-repositories`,
    initialization_policy_name:`sample-test-${role}-initialize-once`}]))});
function directory(t) {
  const dir=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'configure-tcr-'));fs.chmodSync(dir,0o700);
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir;
}
function fake(input, stateDir) {
  const state={namespace:null,repos:{},users:{},policies:{},attachments:{},keys:{},groups:{},writes:[],reads:[],nextId:101,initialized:{}};
  const f={state,stateDir,now:()=>new Date(NOW)};
  const read=(action,request)=>state.reads.push([action,structuredClone(request)]);
  f.identityClient={async request(action,request){read(action,request);assert.equal(action,'GetCallerIdentity');return {AccountId:input.account_id,UserId:input.account_id,Type:'Root'};}};
  f.tcrClient={async request(action,request){
    read(action,request);
    if(action==='DescribeUserQuotaPersonal')return {Data:{LimitInfo:[{Username:input.account_id,Type:'namespace',Value:10},{Username:input.account_id,Type:'repo',Value:500}]}};
    if(action==='ValidateNamespaceExistPersonal')return {Data:{IsExist:!!state.namespace,IsPreserved:false}};
    if(action==='DescribeNamespacePersonal')return {Data:{NamespaceCount:state.namespace?1:0,NamespaceInfo:state.namespace?[state.namespace]:[]}};
    if(action==='ValidateRepositoryExistPersonal')return {Data:{IsExist:!!state.repos[request.RepoName]}};
    if(action==='DescribeRepositoryPersonal')return {Data:state.repos[request.RepoName]};
    state.writes.push(action);
    if(action==='CreateNamespacePersonal'){state.namespace={Namespace:request.Namespace,CreationTime:TIME,RepoCount:0};return {RequestId:'created-namespace'};}
    if(action==='CreateRepositoryPersonal'){
      assert.equal(request.Public,0);state.repos[request.RepoName]={RepoName:request.RepoName,Public:request.Public,Description:request.Description,
        Server:input.registry,CreationTime:TIME,RepoType:'QCLOUD HUB',IsQcloudOfficial:false};return {RequestId:'created-repo'};
    }
    throw Error('unexpected private API error');
  }};
  f.camClient={async request(action,request){
    read(action,request);
    if(action==='GetUser') {if(state.users[request.Name])return state.users[request.Name];throw Object.assign(Error('private'),{code:'ResourceNotFound.UserNotExist'});}
    if(action==='ListPolicies'){const items=Object.entries(state.policies).filter(([,p])=>p.PolicyName.includes(request.Keyword)).map(([id,p])=>({PolicyId:Number(id),PolicyName:p.PolicyName}));return {TotalNum:items.length,List:items};}
    if(action==='GetPolicy')return state.policies[request.PolicyId];
    if(action==='ListGroupsForUser'){const items=state.groups[request.SubUin]||[];return {TotalNum:items.length,GroupInfo:items};}
    if(action==='ListAttachedUserAllPolicies'){assert.equal(request.AttachType,0);const items=(state.attachments[request.TargetUin]||[]).map(id=>({PolicyId:String(id),PolicyName:state.policies[id]?.PolicyName,Groups:[]}));return {TotalNum:items.length,PolicyList:items};}
    if(action==='ListAccessKeys')return {AccessKeys:state.keys[request.TargetUin]||[]};
    state.writes.push(action);
    if(action==='AddUser'){assert.equal(request.ConsoleLogin,0);assert.equal(request.UseApi,0);const id=state.nextId++;return state.users[request.Name]={Name:request.Name,Uin:90000+id,Uid:id,Remark:request.Remark,ConsoleLogin:0};}
    if(action==='CreatePolicy'){const id=state.nextId++;state.policies[id]={PolicyName:request.PolicyName,Description:request.Description,PolicyDocument:request.PolicyDocument,Type:1,IsServiceLinkedRolePolicy:0,AddTime:TIME,UpdateTime:TIME};return {PolicyId:id,RequestId:'policy-created'};}
    if(action==='AttachUserPolicy'){(state.attachments[request.AttachUin]||=[]).push(request.PolicyId);return {RequestId:'attached'};}
    if(action==='DetachUserPolicy'){state.attachments[request.DetachUin]=state.attachments[request.DetachUin].filter(id=>id!==request.PolicyId);return {RequestId:'detached'};}
    if(action==='CreateAccessKey'){
      assert.ok(Object.values(state.users).some(u=>u.Uin===request.TargetUin));assert.notEqual(String(request.TargetUin),input.account_id);
      const key={AccessKeyId:`key-${request.TargetUin}`,Status:'Active',CreateTime:TIME,Description:request.Description};
      state.keys[request.TargetUin]=[key];return {AccessKey:{...key,SecretAccessKey:`private-key-${request.TargetUin}`},RequestId:'key-created'};
    }
    throw Error('unexpected private API error');
  }};
  f.makeChildClients=credential=>{
    const user=Object.values(state.users).find(u=>credential.secretId===`key-${u.Uin}`);
    assert.ok(user);assert.equal(credential.secretKey,`private-key-${user.Uin}`);
    return {identityClient:{async request(action){assert.equal(action,'GetCallerIdentity');return {AccountId:input.account_id,UserId:String(user.Uin),Type:'SubAccount'};}},
      tcrClient:{async request(action,request){assert.equal(action,'CreateUserPersonal');assert.deepEqual(Object.keys(request),['Password']);
        const role=roles.find(r=>input.identities[r].user_name===user.Name);
        const saved=JSON.parse(fs.readFileSync(path.join(stateDir,`${role}.registry-credentials.json`),'utf8'));
        assert.equal(saved.password,request.Password);assert.match(request.Password,/^[A-Za-z0-9]{16}$/);
        assert.equal(fs.statSync(path.join(stateDir,`${role}.registry-credentials.json`)).mode&0o777,0o600);
        assert.ok(!JSON.stringify(JSON.parse(fs.readFileSync(path.join(stateDir,'state.json'),'utf8'))).includes(request.Password));
        state.writes.push(action);state.initialized[user.Uin]=true;return {RequestId:'initialized'};
      }}};
  };
  return f;
}
async function create(t){const input=spec(),f=fake(input,directory(t));const result=await module.configureTcr({spec:input,apply:true,...f});return {input,f,result};}
function imported(input,f,result){
  const value=structuredClone(input);
  value.existing={namespace_creation_time:TIME,repositories:[{name:'sample-test/api',creation_time:TIME}],identities:{}};
  for(const role of roles){const identity=result.identities[role],u=f.state.users[input.identities[role].user_name],p=f.state.policies[identity.policy_id],key=f.state.keys[u.Uin][0];
    value.existing.identities[role]={user_uin:u.Uin,user_uid:u.Uid,user_remark:u.Remark,policy_id:identity.policy_id,policy_description:p.Description,
      policy_add_time:p.AddTime,policy_update_time:p.UpdateTime,key_create_time:key.CreateTime,key_description:key.Description,
      api_credentials_file:path.join(f.stateDir,`${role}.api-credentials.json`),registry_credentials_file:path.join(f.stateDir,`${role}.registry-credentials.json`)};
  }return value;
}
test('offline preview fixes the two role grants and does not access clients or state paths',async()=>{
  assert.equal(typeof module.configureTcr,'function');
  const result=await module.configureTcr({spec:spec(),stateDir:'/does-not-exist',camClient:{request(){throw Error('network');}},now:()=>new Date(NOW)});
  assert.equal(result.status,'planned');assert.equal(result.registry_login,'not_checked');assert.equal(result.push_pull,'not_checked');
  assert.deepEqual(result.identities['host-pull'].policy.statement[0],{effect:'allow',action:['tcr:PullRepositoryPersonal'],resource:['qcs::tcr:::repo/sample-test/api'],condition:{date_less_than:{'qcs:current_time':'2026-09-18T10:00:00Z'}}});
  assert.deepEqual(result.identities['build-push'].policy.statement[0].action,['tcr:PullRepositoryPersonal','tcr:PushRepositoryPersonal']);
});
test('create persists private credentials before registry initialization and exact readbacks make second apply read-only',async t=>{
  const {input,f,result}=await create(t);assert.equal(result.status,'verified');assert.equal(result.identities['build-push'].registry_initialization,'api_response_confirmed');
  assert.deepEqual(Object.values(f.state.attachments).map(x=>x.length),[1,1]);
  assert.deepEqual(f.state.writes.filter(x=>x==='CreateAccessKey'),['CreateAccessKey','CreateAccessKey']);
  for(const role of roles){const secret=fs.readFileSync(path.join(f.stateDir,`${role}.api-credentials.json`),'utf8');assert.ok(secret.includes('private-key-'));assert.ok(!JSON.stringify(result).includes('private-key-'));}
  const before=fs.readFileSync(path.join(f.stateDir,'state.json'));f.state.writes=[];
  assert.deepEqual(await module.configureTcr({spec:input,apply:true,...f}),result);assert.deepEqual(f.state.writes,[]);
  assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'state.json')),before);
});
test('wrong account, expired lease and a conflicting late role block all cloud writes',async t=>{
  for(const kind of ['account','lease','user','namespace']){const input=spec(),f=fake(input,directory(t));
    if(kind==='account')f.identityClient.request=async()=>({AccountId:'90099'});
    if(kind==='lease')input.lease.expires_at='2026-09-10T10:00:00Z';
    if(kind==='user')f.state.users[input.identities['host-pull'].user_name]={Name:input.identities['host-pull'].user_name,Uin:90888,Uid:888,ConsoleLogin:0,Remark:'unmanaged'};
    if(kind==='namespace')f.state.namespace={Namespace:input.namespace,CreationTime:TIME,RepoCount:0};
    await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:kind==='account'?'TCR_ACCOUNT_MISMATCH':kind==='lease'?'TCR_LEASE_EXPIRED':'TCR_RESOURCE_CONFLICT'});assert.deepEqual(f.state.writes,[]);
  }
});
test('lost key response cannot trigger another creation even when cloud readback finds zero or one keys',async t=>{
  for(const present of [true,false]){const input=spec(),f=fake(input,directory(t)),original=f.camClient.request;
    f.camClient.request=async(action,request)=>{if(action==='CreateAccessKey'){if(present)await original(action,request);else f.state.writes.push(action);throw Error('private-key-should-never-print');}return original(action,request);};
    await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_CREDENTIAL_RECOVERY_REQUIRED'});
    const writes=[...f.state.writes];f.camClient.request=original;
    await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_CREDENTIAL_RECOVERY_REQUIRED'});assert.deepEqual(f.state.writes,writes);
    assert.ok(!fs.readFileSync(path.join(f.stateDir,'state.json'),'utf8').includes('private-key-'));
  }
});
test('a lost ordinary write is resumed only by exact readback, never a second create',async t=>{
  const input=spec(),f=fake(input,directory(t)),original=f.tcrClient.request;let lost=false;
  f.tcrClient.request=async(action,request)=>{const response=await original(action,request);if(action==='CreateNamespacePersonal'&&!lost){lost=true;throw Error('private');}return response;};
  await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_WRITE_UNCERTAIN'});
  f.tcrClient.request=original;const result=await module.configureTcr({spec:input,apply:true,...f});assert.equal(result.status,'verified');
  assert.equal(f.state.writes.filter(x=>x==='CreateNamespacePersonal').length,1);
});
test('unknown ordinary write with absent or mismatched resource remains blocked',async t=>{
  for(const kind of ['absent','wrong-time']){const input=spec(),f=fake(input,directory(t)),original=f.tcrClient.request;
    f.tcrClient.request=async(action,request)=>{if(action==='CreateNamespacePersonal'){f.state.writes.push(action);throw Error('private');}return original(action,request);};
    await assert.rejects(module.configureTcr({spec:input,apply:true,...f}));
    if(kind==='wrong-time')f.state.namespace={Namespace:input.namespace,CreationTime:'2025-01-01 00:00:00',RepoCount:0};
    f.tcrClient.request=original;const writes=[...f.state.writes];await assert.rejects(module.configureTcr({spec:input,apply:true,...f}));assert.deepEqual(f.state.writes,writes);
  }
});
test('existing resources require explicit metadata and secrets then verify without local or cloud writes',async t=>{
  const {input,f,result}=await create(t),value=imported(input,f,result);f.state.writes=[];
  const before=Object.fromEntries(fs.readdirSync(f.stateDir).map(name=>[name,fs.readFileSync(path.join(f.stateDir,name)).toString('base64')]));
  const checked=await module.configureTcr({spec:value,verifyExisting:true,...f});assert.equal(checked.status,'existing_verified');
  assert.equal(checked.identities['host-pull'].registry_initialization,'not_checked');assert.deepEqual(f.state.writes,[]);
  assert.deepEqual(Object.fromEntries(fs.readdirSync(f.stateDir).map(name=>[name,fs.readFileSync(path.join(f.stateDir,name)).toString('base64')])),before);
  await assert.rejects(module.configureTcr({spec:value,apply:true,...f}),{message:'TCR_ARGUMENTS_INVALID'});
});
test('full revalidation rejects extra groups, grants, keys, inactive keys, metadata drift and replaced identities',async t=>{
  for(const kind of ['group','policy','key','inactive','uid','uin','creation','policy-time','public','secret-binding']){const {input,f,result}=await create(t),value=imported(input,f,result),u=f.state.users[input.identities['host-pull'].user_name];
    if(kind==='group')f.state.groups[u.Uin]=[{GroupId:777}];
    if(kind==='policy')f.state.attachments[u.Uin].push(777);
    if(kind==='key')f.state.keys[u.Uin].push({...f.state.keys[u.Uin][0],AccessKeyId:'another'});
    if(kind==='inactive')f.state.keys[u.Uin][0].Status='Inactive';
    if(kind==='uid')u.Uid++;
    if(kind==='uin')u.Uin++;
    if(kind==='creation')f.state.namespace.CreationTime='2025-01-01 00:00:00';
    if(kind==='policy-time')f.state.policies[result.identities['host-pull'].policy_id].UpdateTime='2025-01-01 00:00:00';
    if(kind==='public')f.state.repos['sample-test/api'].Public=1;
    if(kind==='secret-binding'){const file=value.existing.identities['host-pull'].registry_credentials_file,saved=JSON.parse(fs.readFileSync(file));saved.username=input.account_id;fs.writeFileSync(file,JSON.stringify(saved));}
    f.state.writes=[];await assert.rejects(module.configureTcr({spec:value,verifyExisting:true,...f}),undefined,kind);assert.deepEqual(f.state.writes,[],kind);
  }
});
test('lost initialization is never retried and does not discard the original private password',async t=>{
  const input=spec(),f=fake(input,directory(t)),original=f.makeChildClients;
  f.makeChildClients=credential=>{const clients=original(credential),initialize=clients.tcrClient.request;clients.tcrClient.request=async(...args)=>{await initialize(...args);throw Error('private-password');};return clients;};
  await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_INITIALIZATION_RECOVERY_REQUIRED'});
  const file=path.join(f.stateDir,'build-push.registry-credentials.json'),before=fs.readFileSync(file),writes=[...f.state.writes];
  f.makeChildClients=original;await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_INITIALIZATION_RECOVERY_REQUIRED'});
  assert.deepEqual(fs.readFileSync(file),before);assert.deepEqual(f.state.writes,writes);
});
test('state target cannot change and unsafe private inputs or locks block before cloud calls',async t=>{
  const {input,f}=await create(t);input.repositories[0].description='changed';f.state.reads=[];
  await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_STATE_CONFLICT'});assert.deepEqual(f.state.reads,[]);
  const fresh=spec();fs.mkdirSync(path.join(f.stateDir,'.lock'),{mode:0o700});
  await assert.rejects(module.configureTcr({spec:fresh,apply:true,...f}),{message:'TCR_STATE_LOCKED'});fs.rmdirSync(path.join(f.stateDir,'.lock'));
  fs.chmodSync(path.join(f.stateDir,'state.json'),0o644);
  await assert.rejects(module.configureTcr({spec:fresh,apply:true,...f}),{message:'TCR_INPUT_UNSAFE'});
});
test('CLI offline preview never needs credentials/SDK/state and rejects duplicate JSON and fixed scope expansion',t=>{
  const dir=directory(t),file=path.join(dir,'spec.json'),script=fileURLToPath(new URL('../scripts/configure-tcr.mjs',import.meta.url));
  fs.writeFileSync(file,JSON.stringify(spec()),{mode:0o600});
  const run=args=>spawnSync(process.execPath,[script,'--spec',file,...args],{encoding:'utf8',env:{PATH:process.env.PATH}});
  let result=run(['--credentials','/missing','--sdk-root','/missing','--state-dir','/missing']);assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).status,'planned');assert.deepEqual(fs.readdirSync(dir),['spec.json']);
  const linkedScript=path.join(dir,'installed-configure-tcr.mjs');fs.symlinkSync(script,linkedScript);
  const installed=spawnSync(process.execPath,[linkedScript,'--spec',file],{encoding:'utf8',env:{PATH:process.env.PATH}});
  assert.equal(installed.status,0,installed.stderr);assert.equal(installed.stdout,result.stdout);
  fs.writeFileSync(file,'{"schema_version":1,"schema_version":1}');result=run([]);assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr,'TCR_SPEC_INVALID\n');
  for(const edit of [s=>s.edition='Enterprise',s=>s.region='ap-shanghai',s=>s.registry='evil.example',s=>s.repositories[0].name='sample-test/*',s=>s.identities['host-pull'].actions=['*']]){const input=spec();edit(input);fs.writeFileSync(file,JSON.stringify(input));result=run([]);assert.equal(result.status,1);assert.equal(result.stderr,'TCR_SPEC_INVALID\n');}
});

test('CLI apply uses fixed endpoints, explicit child credentials without Region, and keeps SDK errors private',t=>{
  const dir=directory(t),stateDir=path.join(dir,'state');fs.mkdirSync(stateDir,{mode:0o700});
  const input=spec();input.lease.expires_at='2099-01-01T00:00:00Z';
  const file=path.join(dir,'spec.json'),admin=path.join(dir,'admin.json'),script=fileURLToPath(new URL('../scripts/configure-tcr.mjs',import.meta.url));
  fs.writeFileSync(file,JSON.stringify(input),{mode:0o600});fs.writeFileSync(admin,JSON.stringify({secretId:'test-admin',secretKey:'administrator-private',token:'private-token'}),{mode:0o600});
  const root=path.join(dir,'sdk'),common=path.join(root,'node_modules/tencentcloud-sdk-nodejs-common');fs.mkdirSync(common,{recursive:true,mode:0o700});
  fs.writeFileSync(path.join(root,'package.json'),'{}');fs.writeFileSync(path.join(root,'package-lock.json'),JSON.stringify({packages:{'node_modules/tencentcloud-sdk-nodejs-common':{version:'4.1.220'}}}));
  fs.writeFileSync(path.join(common,'package.json'),JSON.stringify({main:'index.js',version:'4.1.220'}));
  fs.writeFileSync(path.join(common,'index.js'),`
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const roles=['build-push','host-pull'],NOW=new Date().toISOString(),cloudTime=()=>new Date(Date.now()+8*3600000).toISOString().replace('T',' ').slice(0,19);
const f=(${fake.toString().replace(/\bTIME\b/g,'cloudTime()')})(${JSON.stringify(input)},${JSON.stringify(stateDir)});
module.exports={AbstractClient:class {
 constructor(endpoint,version,config){
  assert.ok(['cam.tencentcloudapi.com','sts.tencentcloudapi.com','tcr.tencentcloudapi.com'].includes(endpoint));
  assert.equal(config.profile.httpProfile.endpoint,endpoint);assert.equal(config.profile.httpProfile.protocol,'https://');
  assert.equal(config.profile.httpProfile.reqMethod,'POST');assert.equal(config.profile.signMethod,'TC3-HMAC-SHA256');
  assert.equal(version,endpoint.startsWith('cam.')?'2019-01-16':endpoint.startsWith('sts.')?'2018-08-13':'2019-09-24');
  if(config.credential.secretId==='test-admin'){
    assert.deepEqual(config.credential,{secretId:'test-admin',secretKey:'administrator-private',token:'private-token'});
    if(endpoint.startsWith('tcr.')||endpoint.startsWith('sts.'))assert.equal(config.region,'ap-guangzhou');else assert.equal(config.region,undefined);
    this.client=endpoint.startsWith('cam.')?f.camClient:endpoint.startsWith('sts.')?f.identityClient:f.tcrClient;
  }else{
    assert.equal(config.region,endpoint.startsWith('sts.')?'ap-guangzhou':undefined);const children=f.makeChildClients(config.credential);
    this.client=endpoint.startsWith('sts.')?children.identityClient:children.tcrClient;
  }
 }
 request(action,request){return this.client.request(action,request);}
}};`);
  const run=extra=>spawnSync(process.execPath,[script,'--spec',file,'--apply','--credentials',admin,'--state-dir',stateDir,'--sdk-root',root,...extra],{encoding:'utf8',env:{PATH:process.env.PATH}});
  let result=run([]);assert.equal(result.status,1);assert.equal(result.stderr,'TCR_CREDENTIAL_EXPIRY_REQUIRED\n');
  result=run(['--credentials-expires-at','2020-01-01T00:00:00Z']);assert.equal(result.status,1);assert.equal(result.stderr,'TCR_CREDENTIALS_EXPIRED\n');
  result=run(['--credentials-expires-at','2099-01-01T00:00:00Z']);assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');assert.equal(JSON.parse(result.stdout).status,'verified');
  for(const secret of ['administrator-private','private-token','private-key-'])assert.equal(result.stdout.includes(secret),false);
  const other=directory(t);fs.writeFileSync(path.join(common,'index.js'),`module.exports={AbstractClient:class{async request(){throw new Error('administrator-private private-token raw diagnostic');}}};`);
  const rejected=spawnSync(process.execPath,[script,'--spec',file,'--apply','--credentials',admin,'--credentials-expires-at','2099-01-01T00:00:00Z','--state-dir',other,'--sdk-root',root],{encoding:'utf8',env:{PATH:process.env.PATH}});
  assert.equal(rejected.status,1);assert.equal(rejected.stdout,'');assert.equal(rejected.stderr,'TCR_QUERY_FAILED\n');
});

test('private files reject symlinks, hardlinks, broad modes and unsafe ancestor directories',async t=>{
  for(const kind of ['symlink','hardlink','mode','directory']){
    const {input,f,result}=await create(t),value=imported(input,f,result),file=value.existing.identities['host-pull'].api_credentials_file;
    if(kind==='symlink'){fs.renameSync(file,file+'.original');fs.symlinkSync(file+'.original',file);}
    if(kind==='hardlink')fs.linkSync(file,file+'.alias');
    if(kind==='mode')fs.chmodSync(file,0o644);
    if(kind==='directory')fs.chmodSync(f.stateDir,0o777);
    f.state.writes=[];await assert.rejects(module.configureTcr({spec:value,verifyExisting:true,...f}));assert.deepEqual(f.state.writes,[]);
  }
});

test('lost policy, user, attachment and detach responses resume only their exact readback',async t=>{
  for(const actionToLose of ['AddUser','CreatePolicy','AttachUserPolicy','DetachUserPolicy']){
    const input=spec(),f=fake(input,directory(t)),original=f.camClient.request;let lost=false;
    f.camClient.request=async(action,request)=>{const response=await original(action,request);if(action===actionToLose&&!lost){lost=true;throw Error('private');}return response;};
    await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:'TCR_WRITE_UNCERTAIN'});
    f.camClient.request=original;const result=await module.configureTcr({spec:input,apply:true,...f});assert.equal(result.status,'verified',actionToLose);
    assert.equal(f.state.writes.filter(action=>action===actionToLose).length,{AddUser:2,CreatePolicy:4,AttachUserPolicy:4,DetachUserPolicy:2}[actionToLose],actionToLose);
  }
});

test('incomplete collection, changed policy document, and uninitialized owner block configuration',async t=>{
  for(const kind of ['collection','owner','document']){
    const input=spec(),f=fake(input,directory(t));
    if(kind==='collection'){const original=f.camClient.request;f.camClient.request=async(action,request)=>action==='ListPolicies'?{TotalNum:201,List:[]}:original(action,request);}
    if(kind==='owner'){const original=f.tcrClient.request;f.tcrClient.request=async(action,request)=>{if(action==='DescribeUserQuotaPersonal')throw Object.assign(Error('private'),{code:'ResourceNotFound.ErrUserNotExist'});return original(action,request);};}
    if(kind==='document'){
      await module.configureTcr({spec:input,apply:true,...f});
      const policy=Object.values(f.state.policies).find(p=>p.PolicyName===input.identities['host-pull'].policy_name);
      const value=JSON.parse(policy.PolicyDocument);value.statement[0].action.push('tcr:PushRepositoryPersonal');policy.PolicyDocument=JSON.stringify(value);
    }
    f.state.writes=[];await assert.rejects(module.configureTcr({spec:input,apply:true,...f}),{message:kind==='collection'?'TCR_QUERY_INCOMPLETE':kind==='owner'?'TCR_ACCOUNT_INITIALIZATION_REQUIRED':'TCR_RESOURCE_CONFLICT'});assert.deepEqual(f.state.writes,[]);
  }
});

test('an explicit existing property cannot be null or bypass read-only mode validation',async()=>{
  const input=spec();input.existing=null;
  await assert.rejects(module.configureTcr({spec:input}),{message:'TCR_SPEC_INVALID'});
});

test('one-time key material survives nullable or invalid ancillary response metadata',async t=>{
  for(const field of ['Description','CreateTime','Status']){
    const input=spec(),f=fake(input,directory(t)),original=f.camClient.request;
    f.camClient.request=async(action,request)=>{const response=await original(action,request);if(action==='CreateAccessKey')response.AccessKey[field]=null;return response;};
    const result=await module.configureTcr({spec:input,apply:true,...f});assert.equal(result.status,'verified');
    for(const role of roles){const saved=JSON.parse(fs.readFileSync(path.join(f.stateDir,`${role}.api-credentials.json`)));assert.match(saved.secretId,/^key-/);assert.match(saved.secretKey,/^private-key-/);}
    assert.equal(f.state.writes.filter(action=>action==='CreateAccessKey').length,2);
  }
});

test('missing online SDK returns a safe installation diagnostic without state or cloud changes',t=>{
  const dir=directory(t),file=path.join(dir,'spec.json'),admin=path.join(dir,'admin.json'),script=fileURLToPath(new URL('../scripts/configure-tcr.mjs',import.meta.url)),input=spec();
  input.lease.expires_at='2099-01-01T00:00:00Z';fs.writeFileSync(file,JSON.stringify(input),{mode:0o600});fs.writeFileSync(admin,JSON.stringify({secretId:'id',secretKey:'SYNTHETIC_PRIVATE'}),{mode:0o600});
  const result=spawnSync(process.execPath,[script,'--spec',file,'--apply','--credentials',admin,'--state-dir',dir,'--sdk-root',path.join(dir,'missing-sdk')],{encoding:'utf8',env:{PATH:process.env.PATH}});
  assert.equal(result.status,1);assert.equal(result.stdout,'');assert.equal(result.stderr,'TCR_SDK_UNAVAILABLE\n');assert.deepEqual(fs.readdirSync(dir).sort(),['admin.json','spec.json']);
});

test('fuzzy namespace search siblings are validated and filtered before exact namespace binding',async t=>{
  const input=spec(),f=fake(input,directory(t)),original=f.tcrClient.request;
  f.tcrClient.request=async(action,request)=>{const response=await original(action,request);if(action==='DescribeNamespacePersonal'){
    response.Data.NamespaceInfo.push({Namespace:'sample-test-other',CreationTime:TIME,RepoCount:0});response.Data.NamespaceCount++;
  }return response;};
  const result=await module.configureTcr({spec:input,apply:true,...f});assert.equal(result.status,'verified');
  const value=imported(input,f,result);f.state.writes=[];
  assert.equal((await module.configureTcr({spec:value,verifyExisting:true,...f})).status,'existing_verified');assert.deepEqual(f.state.writes,[]);
  f.tcrClient.request=async(action,request)=>{const response=await original(action,request);if(action==='DescribeNamespacePersonal'){
    response.Data.NamespaceInfo.push({Namespace:7,CreationTime:TIME,RepoCount:0});response.Data.NamespaceCount++;
  }return response;};
  await assert.rejects(module.configureTcr({spec:value,verifyExisting:true,...f}));
});
