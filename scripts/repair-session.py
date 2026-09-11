#!/usr/bin/env python3
"""Collect a verified CNB build or grant its fixed test repair. Preview is default.

Official CNB CLI authentication is reused. Raw build responses stay in private
evidence; stdout contains only the selected identity and evidence path.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType

ROOT=Path(__file__).resolve().parents[1]
setup=ModuleType('repair_setup')
setup.__file__=str(ROOT/'scripts/setup-host.py')
exec(compile(Path(setup.__file__).read_bytes(),setup.__file__,'exec'),setup.__dict__)

def require(value,code):
    if not value:raise ValueError(code)

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def selected_pipeline(bundle,build_id,status):
    data=status.get('data',{})
    require(data.get('status') in ('success','error'),'REPAIR_BUILD_NOT_FINISHED')
    pipelines=data.get('pipelinesStatus')
    require(type(pipelines) is dict and len(pipelines)==1,'REPAIR_PIPELINE_AMBIGUOUS')
    pipeline=next(iter(pipelines.values()))
    require(pipeline.get('id')==build_id+'-001' and pipeline.get('name') in
            ('cnb-devops-'+bundle['policy']['project']+'-test','cnb-devops-'+bundle['policy']['project']+'-prepare-repair')
            and pipeline.get('status') in ('success','error'),'REPAIR_PIPELINE_MISMATCH')
    return pipeline

def validate_build_evidence(bundle,git_sha,build_id,test_branch,repository,builds,status,stages):
    rows=builds.get('data',{}).get('data',[])
    matches=[row for row in rows if row.get('sn')==build_id]
    require(len(matches)==1,'REPAIR_BUILD_AMBIGUOUS')
    source=matches[0]
    require(all(source.get(k)==v for k,v in {'sha':git_sha,'slug':repository,'sourceSlug':repository,
            'sourceRef':test_branch,'targetRef':test_branch}.items()) and source.get('event') in
            ('push','api_trigger_prepare_repair'),'REPAIR_BUILD_SOURCE_MISMATCH')
    pipeline=selected_pipeline(bundle,build_id,status)
    expected=['validate release identity','install pinned deployment dependencies','verify project',
              'configure TCR push credentials',*['build and push '+role for role in sorted(bundle['host'].SERVICES)],
              'record digests and remove push credentials']
    entries=pipeline.get('stages')
    require(type(entries) is list,'REPAIR_STAGE_INVALID')
    by_name={}
    for name in expected:
        matches=[s for s in entries if s.get('name')==name]
        require(len(matches)==1 and matches[0].get('status')=='success','REPAIR_BUILD_STAGE_NOT_PASSED')
        by_name[name]=matches[0]
    def lines(name):
        summary=by_name[name];stage=stages.get(summary['id'])
        require(type(stage) is dict and all(stage.get(k)==summary.get(k) for k in ('id','name','status'))
                and stage.get('status')=='success' and not stage.get('error') and stage.get('endTime',0)>stage.get('startTime',0)
                and type(stage.get('content')) is list and all(type(s) is str for s in stage['content']),'REPAIR_STAGE_INVALID')
        return '\n'.join(stage['content']).splitlines()
    verify=[line for line in lines('verify project') if line.startswith('CNB_PROJECT_VERIFIED=')]
    require(verify==['CNB_PROJECT_VERIFIED='+git_sha],'REPAIR_VERIFICATION_INCOMPLETE')
    captured=[line.split('=',1)[1] for line in lines('record digests and remove push credentials') if line.startswith('CNB_TEST_BUILD_HANDOFF=')]
    require(len(captured)==1 and re.fullmatch('[A-Za-z0-9_-]{1,32768}',captured[0]),'REPAIR_HANDOFF_INVALID')
    encoded=captured[0];raw=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
    model=setup.strict_json(raw)
    require(base64.urlsafe_b64encode(raw).decode().rstrip('=')==encoded and canonical(model).rstrip(b'\n')==raw
            and type(model) is dict and set(model)=={'schema','request','ci_config_sha256'}
            and model['schema']=='cnb-test-build-handoff/v1' and model['ci_config_sha256']==sha(bundle['files']['ci-config.json']),
            'REPAIR_HANDOFF_INVALID')
    bundle['host'].validate_release_request_model(model['request'])
    request=model['request']
    require(request['git_sha']==git_sha and request['controller_commit']==git_sha and request['build_id']==build_id
            and request['environment']=='test','REPAIR_REQUEST_MISMATCH')
    return {'schema':'cnb-test-repair-build-evidence/v1','status':'verified','repository':repository,
            'git_sha':git_sha,'source_build_id':build_id,'pipeline_id':pipeline['id'],
            'request':request,'request_sha256':sha(canonical(request)),'handoff':encoded,
            'ci_config_sha256':model['ci_config_sha256'],'verification_passed':True}

def load_bundle(directory,lock_sha):
    raw=setup.read_safe(directory/'artifact-lock.json')
    require(re.fullmatch('[a-f0-9]{64}',lock_sha) and sha(raw)==lock_sha,'REPAIR_BUNDLE_LOCK_MISMATCH')
    lock=setup.strict_json(raw);code=setup.read_safe(directory/'host/install-project.py')
    require(sha(code)==lock['files'].get('host/install-project.py'),'REPAIR_INSTALLER_PIN_MISMATCH')
    installer=ModuleType('repair_installer');installer.__file__=str(directory/'host/install-project.py')
    exec(compile(code,installer.__file__,'exec'),installer.__dict__)
    bundle=installer.verify_bundle(directory,lock_sha)
    require(bundle['policy']['environment']=='test','REPAIR_TEST_ONLY')
    return bundle

def write_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def cli_json(cli,arguments):
    result=subprocess.run([str(cli),*arguments,'--verbose'],capture_output=True,timeout=60)
    require(result.returncode==0 and len(result.stdout)<=32*1024*1024,'REPAIR_CNB_QUERY_FAILED')
    model=setup.strict_json(result.stdout)
    require(type(model) is dict and model.get('status')==200,'REPAIR_CNB_RESPONSE_INVALID')
    return model

def verify_source_files(bundle,source_files):
    """Bind executable source, not just log labels, to the reviewed generator."""
    import yaml
    for name,raw in bundle['files'].items():
        require(source_files.get('deploy/vendor/cnb-devops/'+name)==raw,'REPAIR_SOURCE_ARTIFACT_MISMATCH')
    manifest=setup.strict_json(bundle['files']['bundle.json'])
    renderer_raw=setup.read_safe(ROOT/'assets/cnb-tcr-tat/templates/render.py')
    require(sha(renderer_raw)==manifest['files'].get('templates/render.py'),'REPAIR_RENDERER_PIN_MISMATCH')
    renderer=ModuleType('repair_renderer')
    exec(compile(renderer_raw,'verified-render.py','exec'),renderer.__dict__)
    # The generator's loader also rejects ambiguous duplicate YAML keys.
    generator=ModuleType('repair_generator');generator.__file__=str(ROOT/'scripts/prepare-project.py')
    exec(compile(setup.read_safe(generator.__file__),generator.__file__,'exec'),generator.__dict__)
    config=yaml.load(source_files['deploy/project.yml'],Loader=generator.UniqueLoader)
    ci=setup.strict_json(bundle['files']['ci-config.json'])
    policy,expected_ci,_=renderer.model(config,ci['controller_program_sha256'])
    require(renderer.json_bytes(expected_ci)==bundle['files']['ci-config.json']
            and renderer.json_bytes(policy)==bundle['files']['host-policy.json'],'REPAIR_SOURCE_CONFIG_MISMATCH')
    expected=renderer.pipeline(config);actual=yaml.load(source_files['.cnb.yml'],Loader=generator.UniqueLoader)
    for event in ('push','api_trigger_prepare_repair','api_trigger_repair_test'):
        require(actual.get(config['test_branch'],{}).get(event)==expected[config['test_branch']][event],
                'REPAIR_SOURCE_PIPELINE_MISMATCH')
    return {'pipeline_verified':True,'test_branch':config['test_branch'],
            'files':{name:sha(raw) for name,raw in source_files.items()}}

def collect(args):
    bundle=load_bundle(args.bundle_dir,args.lock_sha256)
    require(bundle['host'].GIT_SHA.fullmatch(args.git_sha) and bundle['host'].BUILD_ID.fullmatch(args.build_id)
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_./-]{0,127}',args.test_branch),'REPAIR_IDENTITY_INVALID')
    config=setup.strict_json(bundle['files']['ci-config.json']);repo=config['cnb_repository']
    require(re.fullmatch('[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+',repo),'REPAIR_REPOSITORY_INVALID')
    source_files={}
    for name in [*['deploy/vendor/cnb-devops/'+name for name in bundle['files']],'.cnb.yml','deploy/project.yml']:
        source=subprocess.run(['git','-C',str(args.project_dir),'show',args.git_sha+':'+name],capture_output=True)
        require(source.returncode==0,'REPAIR_SOURCE_FILE_MISSING');source_files[name]=source.stdout
    source_evidence=verify_source_files(bundle,source_files)
    require(source_evidence['test_branch']==args.test_branch,'REPAIR_BRANCH_MISMATCH')
    preview={'status':'preview','action':'collect_verified_test_build','repository':repo,'git_sha':args.git_sha,'build_id':args.build_id}
    if not args.apply:return preview
    output=args.evidence_dir.absolute();setup.validate_output_path(output)
    require(not os.path.lexists(output),'REPAIR_NEW_EVIDENCE_DIRECTORY_REQUIRED')
    output.mkdir(mode=0o700)
    setup.validate_output_path(output/'request.json')
    def query(name,arguments):
        value=cli_json(args.cnb_cli,arguments);write_new(output/name,canonical(value));return value
    builds=query('builds.json',['build','get-build-logs','--repo',repo,'--sha',args.git_sha,'--page-size','50'])
    status=query('status.json',['build','get-build-status','--repo',repo,'--sn',args.build_id])
    pipeline=selected_pipeline(bundle,args.build_id,status);stages={}
    for name in ['verify project','record digests and remove push credentials']:
        matching=[s for s in pipeline['stages'] if s.get('name')==name]
        require(len(matching)==1,'REPAIR_STAGE_AMBIGUOUS');stage_id=matching[0]['id']
        require(type(stage_id) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',stage_id),'REPAIR_STAGE_ID_INVALID')
        stages[stage_id]=query(stage_id+'.json',['build','get-build-stage','--repo',repo,'--sn',args.build_id,
                             '--pipelineId',pipeline['id'],'--stageId',stage_id])['data']
    result=validate_build_evidence(bundle,args.git_sha,args.build_id,args.test_branch,repo,builds,status,stages)
    write_new(output/'source-files.json',canonical(source_evidence))
    write_new(output/'request.json',canonical(result['request']))
    write_new(output/'build-evidence.json',canonical(result))
    write_new(output/'handoff.txt',(result['handoff']+'\n').encode())
    return {'status':'verified','repository':repo,'git_sha':args.git_sha,'build_id':args.build_id,'evidence_dir':str(output)}

def main(argv=None):
    os.umask(0o077)
    argv=sys.argv[1:] if argv is None else argv
    if argv and argv[0]=='grant':
        grant=ModuleType('repair_grant_entry');grant.__file__=str(ROOT/'scripts/grant-test-repair.py')
        exec(compile(setup.read_safe(grant.__file__),grant.__file__,'exec'),grant.__dict__)
        return grant.main(argv[1:])
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('grant',help='Verify collected build and isolated recovery, then prepare a scoped root permit')
    sub=commands.add_parser('collect')
    for name in ['bundle-dir','project-dir','cnb-cli','evidence-dir']:sub.add_argument('--'+name,type=Path,required=True)
    for name in ['lock-sha256','git-sha','build-id','test-branch']:sub.add_argument('--'+name,required=True)
    sub.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv)
    try:print(json.dumps(collect(args),ensure_ascii=False,sort_keys=True))
    except Exception as error:
        code=str(error)
        print(code if re.fullmatch('REPAIR_[A-Z_]+',code) else 'REPAIR_SESSION_FAILED',file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':sys.exit(main())
