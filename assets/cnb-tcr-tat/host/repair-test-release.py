#!/usr/bin/env python3
"""Root-issued, single-request repair of a test release that failed at public probes.

Administrator grant preview verifies evidence and may cache exact digest images
and create/remove stopped inspection containers; it never writes a permit.
The ordinary release protocol is unchanged. This module never runs migrations and
never removes a failed parent or manufactures an accepted release.
"""
import argparse
import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import tarfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import ModuleType, SimpleNamespace

HASH = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[a-z][a-z0-9-]{0,47}')
PERMIT_SCHEMA = 'cnb-test-repair-permit/v1'
MAX_INSPECTION = 32 * 1024 ** 2

class RepairError(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise RepairError(reason)

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'repair_duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'repair_json_invalid'))

def timestamp(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value), 'repair_time_invalid')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def safe_path(value):
    require(type(value) is str and 0 < len(value) <= 256 and not value.startswith('/')
            and all(re.fullmatch(r'[A-Za-z0-9_.-]+', part) and part not in ('.', '..') for part in value.split('/')),
            'repair_migration_path_invalid')
    return value

def validate_spec(core, spec):
    require(type(spec) is dict and set(spec) == {'schema','service','schema_path','migrations_path','lock_path'}
            and spec['schema'] == 'cnb-prisma-repair-inspection/v1' and core.POLICY['migration'] is not None
            and spec['service'] == core.POLICY['migration']['service'], 'repair_migration_spec_invalid')
    for key in ('schema_path','migrations_path','lock_path'):
        safe_path(spec[key])
    require(spec['schema_path'].endswith('/schema.prisma')
            and spec['lock_path'] == spec['migrations_path'] + '/migration_lock.toml'
            and not spec['schema_path'].startswith(spec['migrations_path'] + '/'), 'repair_prisma_layout_required')
    return spec

def validate_permit(core, permit, request, *, now=None):
    digests = {'controller_sha256','policy_sha256','compose_sha256','recovery_policy_sha256',
               'failed_transaction_sha256','failed_snapshot_manifest_sha256','accepted_release_sha256',
               'source_state_sha256','migration_evidence_sha256','archive_sha256','manifest_sha256',
               'restore_receipt_sha256','request_sha256'}
    require(type(permit) is dict and set(permit) == digests | {'schema','permit_id','project','environment','controller',
            'issued_at','expires_at','failed_snapshot','migration_spec'} and permit['schema'] == PERMIT_SCHEMA,
            'repair_permit_invalid')
    require(core.POLICY['environment'] == permit['environment'] == request['environment'] == 'test'
            and permit['project'] == core.POLICY['project'] and permit['controller'] == core.CONTROLLER_ID,
            'repair_scope_mismatch')
    require(type(permit['permit_id']) is str and re.fullmatch(r'[0-9a-f]{32}', permit['permit_id'])
            and all(type(permit[key]) is str and HASH.fullmatch(permit[key]) for key in digests)
            and type(permit['failed_snapshot']) is str and core.SNAPSHOT_NAME.fullmatch(permit['failed_snapshot']),
            'repair_permit_invalid')
    core.validate_release_request_model(request)
    require(sha(canonical(request)) == permit['request_sha256'], 'repair_request_mismatch')
    issued, expires = timestamp(permit['issued_at']), timestamp(permit['expires_at'])
    now = now or datetime.now(timezone.utc)
    require(issued <= now < expires and 0 < (expires-issued).total_seconds() <= 3600, 'repair_permit_expired')
    validate_spec(core, permit['migration_spec'])
    return permit

def read_image_archive(raw, basename, *, directory):
    """Read bounded docker cp tar bytes without writing any image-controlled path."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_INSPECTION, 'repair_image_archive_invalid')
    files, seen, total, directories = {}, set(), 0, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        for item in tar:
            name = item.name.rstrip('/') if item.isdir() else item.name
            safe_path(name)
            require(name not in seen and len(seen) < 4096 and (item.isdir() or item.isfile()), 'repair_image_archive_invalid')
            seen.add(name)
            require(name == basename or directory and name.startswith(basename + '/'), 'repair_image_archive_path')
            if item.isdir():
                require(directory, 'repair_image_archive_invalid')
                directories.add(name)
                continue
            require(0 <= item.size <= MAX_INSPECTION and total + item.size <= MAX_INSPECTION, 'repair_image_archive_too_large')
            total += item.size
            key = name[len(basename)+1:] if directory else name
            require(key and (directory or name == basename), 'repair_image_archive_invalid')
            content = tar.extractfile(item).read()
            require(len(content) == item.size, 'repair_image_archive_truncated')
            files[key] = content
    require(files and (directory or set(files) == {basename}), 'repair_image_archive_empty')
    # Empty or unexpected directories are part of the inspected file set and cannot disappear silently.
    require(all(d == basename or any((basename+'/'+f).startswith(d+'/') for f in files) for d in directories),
            'repair_empty_migration_directory')
    return files

def validate_prisma_files(files):
    require(type(files) is dict and 'migration_lock.toml' in files and len(files) >= 2,
            'repair_prisma_files_invalid')
    lock = tomllib.loads(files['migration_lock.toml'].decode('utf-8', 'strict'))
    require(lock == {'provider':'postgresql'}, 'repair_postgres_prisma_required')
    require(all(name == 'migration_lock.toml' or re.fullmatch(r'[0-9]{14}_[A-Za-z0-9_-]+/migration\.sql', name)
                for name in files), 'repair_unknown_migration_file')

def validate_prisma_history(files, rows):
    validate_prisma_files(files)
    expected = {name.split('/')[0]: sha(content) for name,content in files.items() if name.endswith('/migration.sql')}
    require(type(rows) is list and len(rows) == len(expected), 'repair_prisma_history_mismatch')
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'migration_name','checksum','finished','rolled_back','applied_steps_count'},
                'repair_prisma_history_invalid')
        name = row['migration_name']
        require(type(name) is str and name not in seen and name in expected and row['checksum'] == expected[name]
                and row['finished'] is True and row['rolled_back'] is False
                and type(row['applied_steps_count']) is int and row['applied_steps_count'] > 0,
                'repair_prisma_history_mismatch')
        seen.add(name)
    require(seen == set(expected), 'repair_prisma_history_mismatch')

def inspect_prisma_image(docker, image, spec):
    require(type(image) is str and re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image), 'repair_digest_image_required')
    cid = docker.run(['create','--pull=never','--network=none','--entrypoint=/bin/false', image], maximum=1024).decode().strip()
    require(HASH.fullmatch(cid), 'repair_inspection_container_invalid')
    try:
        captured = {}
        for key, directory in (('schema_path',False),('migrations_path',True),('lock_path',False)):
            path = safe_path(spec[key])
            raw = docker.run(['cp',cid + ':/' + path,'-'], maximum=MAX_INSPECTION)
            captured[key] = read_image_archive(raw, PurePosixPath(path).name, directory=directory)
        schema = captured['schema_path']['schema.prisma']
        require(re.search(rb'\bprovider\s*=\s*"postgresql"', schema) is not None, 'repair_postgres_prisma_required')
        files = captured['migrations_path']
        require(files.get('migration_lock.toml') == captured['lock_path']['migration_lock.toml'], 'repair_prisma_lock_mismatch')
        validate_prisma_files(files)
        return {'schema_sha256':sha(schema), 'files':{name:sha(raw) for name,raw in sorted(files.items())}, '_contents':files}
    finally:
        # This exact stopped, newly created inspection container is the sole removable resource.
        docker.run(['rm','-v',cid], maximum=1024)

def load_recovery(core):
    return core._load_installed_module('recover-project.py')

def source_state(core, recovery, account, failed_sha):
    require(core.POLICY['environment'] == 'test' and not os.path.lexists(core.RECOVERY_TRANSACTION_PATH), 'repair_source_blocked')
    raw, parent = recovery.source_record(core, account, failed_sha)
    recovery_raw = recovery.root_read(Path(core.POLICY['install_dir'])/'recovery-policy.json', 0o444)
    policy = recovery.validate_recovery_policy(strict_json(recovery_raw), core.POLICY, core.POLICY_SHA256)
    docker = recovery.Docker(core._docker_prefix(), core.BASE_ENV)
    containers = [docker.inspect(core.CONTAINERS[role]) for role in core.SERVICES]
    recovery.validate_failed_runtime(core, docker, parent, containers)
    for role, item in zip(core.SERVICES, containers):
        require(not core.POLICY['services'][role]['healthcheck'] or item['health'] == 'healthy',
                'repair_source_healthcheck_missing')
        actual = strict_json(docker.run(['inspect','--type','container','--format','{{json .Mounts}}',item['id']]))
        observed = sorted((m['Type'],m['Source'],m['Destination']) for m in actual if m['Type'] != 'tmpfs')
        declared = sorted(('bind',m['source'],m['target']) for m in core.POLICY['services'][role]['mounts'])
        require(observed == declared, 'repair_mounts_changed')
    database = core.POLICY['database']
    db = docker.inspect(database['container'])
    require(db['running'] is True and db['health'] in (None,'healthy') and recovery.IMAGE.fullmatch(db['image']),
            'repair_database_unhealthy')
    pg = recovery.Postgres(docker,db['id'],database['admin_user'],database['name'])
    mounts = {name: {'classification':classification, **(recovery.tree_fingerprint(core.APP_DIR/name)
                      if classification == 'backup' else {})} for name,classification in sorted(policy['mounts'].items())}
    result = {'parent_transaction_sha256':sha(raw), 'accepted_release_sha256':parent['previous_release_sha256'],
              'env_sha256':sha(recovery.read_file(core.ENV_PATH)), 'compose_sha256':sha(recovery.read_file(core.COMPOSE_PATH)),
              'recovery_policy_sha256':sha(recovery_raw), 'containers':containers, 'source_docker_id_sha256':docker.identity(),
              'postgres':{'id':db['id'],'image':db['image'],'version_num':pg.version(),'database':database['name']},
              'database':pg.fingerprint(), 'mounts':mounts}
    require(recovery.source_record(core, account, failed_sha)[0] == raw, 'repair_source_changed')
    return result

def migration_evidence(core, recovery, state, parent, request, spec):
    validate_spec(core,spec)
    docker = recovery.Docker(core._docker_prefix(), core.BASE_ENV)
    role = spec['service']
    old = inspect_prisma_image(docker, parent['images'][role], spec)
    new = inspect_prisma_image(docker, request['images'][role], spec)
    require(old == new, 'repair_migration_content_changed')
    db = core.POLICY['database']
    pg = recovery.Postgres(docker,state['postgres']['id'],db['admin_user'],db['name'])
    query = b'''SELECT COALESCE(json_agg(json_build_object('migration_name',migration_name,'checksum',checksum,'finished',finished_at IS NOT NULL,'rolled_back',rolled_back_at IS NOT NULL,'applied_steps_count',applied_steps_count) ORDER BY migration_name,id),'[]') FROM public._prisma_migrations;'''
    rows = strict_json(pg.sql(query))
    validate_prisma_history(old.pop('_contents'), rows)
    return {'spec':spec, 'migration':core.POLICY['migration'], 'image_contents':old, 'database_history':rows}

def history_path(core, failed_sha):
    require(type(failed_sha) is str and HASH.fullmatch(failed_sha), 'repair_parent_pin_invalid')
    return core.APP_DIR/'.repair-history'/failed_sha

def require_unused(core, parent_sha):
    path = history_path(core,parent_sha)
    require(not os.path.lexists(path), 'repair_parent_already_consumed')
    if os.path.lexists(path.parent):
        env = core.ENV_PATH.stat()
        core._require_private_directory(path.parent,env.st_uid,env.st_gid)

def authorize_locked(core, request, account):
    """Called under the normal release flock, before any candidate or snapshot write."""
    try:
        recovery = load_recovery(core)
        permit_path = Path(core.POLICY['install_dir'])/'test-repair/permit.json'
        permit_raw = recovery.root_read(permit_path,0o444)
        permit = validate_permit(core,strict_json(permit_raw),request)
        require(permit_raw == canonical(permit), 'repair_permit_not_canonical')
        audit_raw = recovery.root_read(permit_path.parent/'permits'/(permit['permit_id']+'.json'),0o444)
        require(audit_raw == permit_raw, 'repair_permit_audit_mismatch')
        require_unused(core,permit['failed_transaction_sha256'])
        require((permit['controller_sha256'],permit['policy_sha256'],permit['compose_sha256']) ==
                (core.controller_program_sha256(),core.POLICY_SHA256,core.CONTROLLER_COMPOSE_SHA256), 'repair_installed_pin_mismatch')
        parent_raw,parent = recovery.source_record(core,account,permit['failed_transaction_sha256'])
        require((parent['snapshot'],parent['snapshot_manifest_sha256'],parent['previous_release_sha256']) ==
                (permit['failed_snapshot'],permit['failed_snapshot_manifest_sha256'],permit['accepted_release_sha256']),
                'repair_parent_binding_mismatch')
        state = source_state(core,recovery,account,permit['failed_transaction_sha256'])
        require(state['recovery_policy_sha256'] == permit['recovery_policy_sha256']
                and sha(canonical(state)) == permit['source_state_sha256'], 'repair_source_drift')
        evidence = migration_evidence(core,recovery,state,parent,request,permit['migration_spec'])
        require(sha(canonical(evidence)) == permit['migration_evidence_sha256'], 'repair_migration_evidence_changed')
        require(source_state(core,recovery,account,permit['failed_transaction_sha256']) == state, 'repair_source_drift')
        validate_permit(core,permit,request)
        return {'parent':parent,'parent_raw':parent_raw,'permit':permit,'permit_raw':permit_raw,
                'request':request,'state':state,'account':account}
    except core.DeploymentError:
        raise
    except Exception as exc:
        raise core.DeploymentError(str(exc) if isinstance(exc,RepairError) else 'repair_authorization_failed') from exc

def revalidate_source_locked(core, context):
    recovery = load_recovery(core)
    state = source_state(core,recovery,context['account'],context['permit']['failed_transaction_sha256'])
    require(sha(canonical(state)) == context['permit']['source_state_sha256'], 'repair_source_drift')


def begin_locked(core, context, fresh_snapshot, uid, gid):
    parent, permit = context['parent'], context['permit']
    require_unused(core,permit['failed_transaction_sha256'])
    require(core._load_private_record(core.TRANSACTION_PATH,kind='transaction',uid=uid,gid=gid,required=True)[0]
            == context['parent_raw'], 'repair_parent_changed')
    require(sha(core._load_private_record(core.RELEASE_PATH,kind='release',uid=uid,gid=gid,required=True)[0])
            == permit['accepted_release_sha256'], 'repair_accepted_release_changed')
    validate_permit(core,permit,context['request'])
    revalidate_source_locked(core,context)
    history = history_path(core,permit['failed_transaction_sha256'])
    if not history.parent.exists(): core._safe_mkdir(history.parent,0o700,uid,gid)
    core._safe_mkdir(history,0o700,uid,gid)
    request = context['request']
    child = {'schema':'cnb-test-release-transaction/v3','status':'active','phase':'prepared',
             'controller':core.CONTROLLER_ID,'controller_program_sha256':core.controller_program_sha256(),
             'controller_compose_sha256':core.CONTROLLER_COMPOSE_SHA256,'git_sha':request['git_sha'],
             'build_id':request['build_id'],'images':request['images'],'source_images':parent['images'],
             'accepted_release_sha256':permit['accepted_release_sha256'],
             'parent_transaction_sha256':permit['failed_transaction_sha256'],'permit_sha256':sha(context['permit_raw']),
             'source_state_sha256':permit['source_state_sha256'],'snapshot':fresh_snapshot.name,
             'snapshot_manifest_sha256':fresh_snapshot.manifest_sha256,
             'updated_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
    core._validate_release_transaction_model(child)
    for name,raw in [('parent-transaction.json',context['parent_raw']),('permit.json',context['permit_raw']),
                     ('started.json',canonical({'schema':'cnb-test-repair-started/v1','transaction_sha256':sha(canonical(child)),
                                               'parent_transaction_sha256':permit['failed_transaction_sha256'],
                                               'permit_sha256':sha(context['permit_raw'])}))]:
        core._write_new(history/name,raw,0o600,uid,gid)
        require((history/name).read_bytes() == raw, 'repair_history_readback_failed')
    core._fsync_directory(history)
    core._fsync_directory(history.parent)
    core._atomic_write(core.TRANSACTION_PATH,canonical(child),0o600,uid,gid)
    return child

def complete_locked(core, transaction, release_record_sha256):
    history = history_path(core,transaction['parent_transaction_sha256'])
    env = core.ENV_PATH.stat()
    core._require_private_directory(history,env.st_uid,env.st_gid)
    raw,record = core._load_private_record(core.RELEASE_PATH,kind='release',uid=env.st_uid,gid=env.st_gid,required=True)
    require(sha(raw) == release_record_sha256 and record['status'] == 'passed'
            and all(record[key] == transaction[key] for key in ('git_sha','build_id','images','snapshot','snapshot_manifest_sha256')),
            'repair_completion_release_mismatch')
    core._write_new(history/'completed.json',canonical({'schema':'cnb-test-repair-completed/v1',
                    'parent_transaction_sha256':transaction['parent_transaction_sha256'],
                    'permit_sha256':transaction['permit_sha256'],'release_record_sha256':release_record_sha256}),
                    0o600,env.st_uid,env.st_gid)
    core._fsync_directory(history)

def validate_restore_receipt(receipt, manifest, args):
    expected = {'schema','status','external_restore_verified','archive_sha256','manifest_sha256','source_release_sha256',
                'source_docker_id_sha256','target_docker_id_sha256','postgres_image','postgres_version_num','schema_equal',
                'all_table_data_equal','sequences_equal','business_files_equal','file_ownership_remapped_to_local_user','scope',
                'target_volume','target_container_id','created_at','source_kind','source_baseline_sha256',
                'public_identity_verified','business_acceptance_verified'}
    require(type(receipt) is dict and set(receipt) == expected and receipt['schema'] == 'cnb-recovery-restore-receipt/v2'
            and receipt['status'] == 'verified', 'repair_restore_receipt_invalid')
    for key in ('external_restore_verified','schema_equal','all_table_data_equal','sequences_equal',
                'business_files_equal','file_ownership_remapped_to_local_user'):
        require(receipt[key] is True, 'repair_real_restore_required')
    require(receipt['public_identity_verified'] is False and receipt['business_acceptance_verified'] is False
            and receipt['source_kind'] == 'failed-test-release', 'repair_failed_source_evidence_required')
    require((receipt['archive_sha256'],receipt['manifest_sha256']) == (args.archive_sha256,args.manifest_sha256),
            'repair_restore_transfer_mismatch')
    for key in ('source_release_sha256','source_docker_id_sha256','source_baseline_sha256','scope'):
        require(receipt[key] == manifest[key], 'repair_restore_source_mismatch')
    require((receipt['postgres_image'],receipt['postgres_version_num']) ==
            (manifest['postgres']['image'],manifest['postgres']['version_num']), 'repair_restore_postgres_mismatch')
    require(type(receipt['target_docker_id_sha256']) is str and HASH.fullmatch(receipt['target_docker_id_sha256'])
            and receipt['target_docker_id_sha256'] != manifest['source_docker_id_sha256'], 'repair_external_daemon_required')
    require(type(receipt['target_container_id']) is str and HASH.fullmatch(receipt['target_container_id'])
            and type(receipt['target_volume']) is str and re.fullmatch(r'cnb-recovery-[0-9a-f]{24}',receipt['target_volume']),
            'repair_restore_target_invalid')
    timestamp(receipt['created_at'])


def validate_export_binding(core, recovery, state, parent, args, manifest):
    require(manifest['schema'] == 'cnb-recovery-export/v2' and manifest['source_kind'] == 'failed-test-release'
            and manifest['project'] == core.POLICY['project'] and manifest['environment'] == 'test'
            and manifest['source_release'] == parent and manifest['source_release_sha256'] == args.failed_transaction_sha256
            and manifest['source_baseline_sha256'] == parent['previous_release_sha256'], 'repair_export_source_mismatch')
    require(manifest['host_policy_sha256'] == core.POLICY_SHA256
            and manifest['recovery_policy_sha256'] == state['recovery_policy_sha256']
            and manifest['controller_sha256'] == core.controller_program_sha256(), 'repair_export_policy_mismatch')
    require(manifest['source_docker_id_sha256'] == state['source_docker_id_sha256']
            and manifest['postgres'] == {k:state['postgres'][k] for k in ('image','version_num','database')}
            and manifest['database'] == state['database'], 'repair_export_database_drift')
    mounts = {name:{key:value for key,value in item.items() if key != 'archive'} for name,item in manifest['mounts'].items()}
    require(mounts == state['mounts'], 'repair_export_mount_drift')
    # Only the fixed source export journal can prove these exact containers resumed.
    scope_args = SimpleNamespace(project=core.POLICY['project'],environment='test',export_id=manifest['export_id'],
                                 policy_sha256=core.POLICY_SHA256,controller_sha256=manifest['controller_sha256'],
                                 recovery_policy_sha256=state['recovery_policy_sha256'])
    export = recovery.export_directory(scope_args)
    journal_raw = recovery.root_read(export/'journal.json',0o600)
    journal = strict_json(journal_raw)
    expected = recovery.journal_identity(scope_args,args.failed_transaction_sha256,state['containers'],parent)
    require(journal == expected and journal_raw == canonical(journal), 'repair_export_journal_mismatch')
    resumed_raw = recovery.root_read(export/'source-resumed.json',0o600)
    resumed = {'schema':'cnb-recovery-source-resume/v2','status':'resumed','journal_sha256':sha(journal_raw),
               **recovery.source_metadata(parent)}
    require(resumed_raw == canonical(resumed) and not os.path.lexists(core.RECOVERY_TRANSACTION_PATH),
            'repair_source_not_resumed')
    exported = strict_json(recovery.root_read(export/'export-receipt.json',0o600))
    require(exported == {'schema':'cnb-recovery-export-receipt/v2','status':'exported','archive_sha256':args.archive_sha256,
                         'manifest_sha256':args.manifest_sha256,'external_restore_verified':False,
                         **recovery.source_metadata(parent)}, 'repair_export_receipt_mismatch')


def bootstrap_core(args):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'repair_requires_linux_root')
    require(type(args.project) is str and NAME.fullmatch(args.project) and args.environment == 'test', 'repair_scope_mismatch')
    for value in (args.controller_sha256,args.policy_sha256,args.recovery_policy_sha256,args.failed_transaction_sha256,
                  args.archive_sha256,args.manifest_sha256,args.restore_receipt_sha256):
        require(type(value) is str and HASH.fullmatch(value), 'repair_pin_invalid')
    install = Path('/opt/cnb-devops')/args.project/'test/v1'
    # This bootstrap reads captured root-owned bytes before executing installed core.
    raw = root_input(install/'tat-deploy-test.py', mode=0o555)
    require(sha(raw) == args.controller_sha256, 'repair_controller_pin_mismatch')
    core = ModuleType('verified_repair_host')
    core.__file__ = str(install/'tat-deploy-test.py')
    exec(compile(raw,core.__file__,'exec'),core.__dict__)
    policy_raw = core._read_root_owned_bytes(install/'host-policy.json')
    require(sha(policy_raw) == args.policy_sha256, 'repair_policy_pin_mismatch')
    core.configure_policy(strict_json(policy_raw),policy_sha256=args.policy_sha256)
    require(core.POLICY['project'] == args.project and core.POLICY['environment'] == 'test'
            and core.POLICY['install_dir'] == str(install), 'repair_scope_mismatch')
    # Verify this helper, the recovery module, artifact lock and installation receipt.
    own = core._load_installed_module('repair-test-release.py')
    require(core._read_root_owned_bytes(Path(own.__file__),mode=0o555,maximum=256*1024)
            == root_input(Path(__file__),mode=0o555), 'repair_helper_not_installed')
    return core


def root_input(path, *, mode=0o600, maximum=2*1024**2, metadata_only=False):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.abspath(path), 'repair_root_path_invalid')
    descriptor = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require((info.st_uid,info.st_gid) == (0,0) and not info.st_mode & 0o022, 'repair_root_ancestor_invalid')
        handle = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=descriptor)
        with os.fdopen(handle,'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode)) == (0,0,mode)
                    and 0 < before.st_size <= maximum, 'repair_root_file_invalid')
            raw = b'' if metadata_only else stream.read(maximum+1)
            def identity(value):
                return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,
                        value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            require(identity(before) == identity(os.fstat(stream.fileno()))
                    == identity(os.stat(path.name,dir_fd=descriptor,follow_symlinks=False)), 'repair_root_file_changed')
            return raw
    finally:
        os.close(descriptor)


def grant_receipt(status, permit, permit_raw=None):
    return {'schema':'cnb-test-repair-grant/v1','status':status,'project':permit['project'],'environment':'test',
            **{key:permit[key] for key in ('request_sha256','failed_transaction_sha256','source_state_sha256',
                                           'migration_evidence_sha256','archive_sha256','manifest_sha256',
                                           'restore_receipt_sha256','expires_at')},
            'permit_sha256':sha(permit_raw) if permit_raw is not None else None,
            'permit_id':permit['permit_id'] if permit_raw is not None else None}


def prepare_inspection_images(docker, recovery, images):
    # Administrator preparation only. Runtime authorization never pulls images.
    for image in dict.fromkeys(images):
        require(type(image) is str and re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',image), 'repair_digest_image_required')
        try:
            docker.run(['image','inspect','--format','{{.Id}}',image],maximum=1024)
        except recovery.RecoveryError:
            docker.run(['pull',image],maximum=1024*1024,timeout=600)


def grant_locked(args, core, recovery, account):
    request_raw = root_input(Path(args.request))
    request = strict_json(request_raw)
    require(request_raw == canonical(request), 'repair_request_not_canonical')
    core.validate_release_request_model(request)  # Keep the original eight-field object for the permit hash.
    spec_raw = root_input(Path(args.migration_spec))
    spec = validate_spec(core,strict_json(spec_raw))
    require(spec_raw == canonical(spec), 'repair_migration_spec_not_canonical')
    require_unused(core,args.failed_transaction_sha256)
    parent_raw,parent = recovery.source_record(core,account,args.failed_transaction_sha256)
    state = source_state(core,recovery,account,args.failed_transaction_sha256)
    require(state['recovery_policy_sha256'] == args.recovery_policy_sha256, 'repair_recovery_policy_pin_mismatch')
    root_input(Path(args.archive),maximum=recovery.MAX_BYTES,metadata_only=True)
    receipt_raw = root_input(Path(args.restore_receipt))
    require(sha(receipt_raw) == args.restore_receipt_sha256, 'repair_restore_receipt_pin_mismatch')
    receipt = strict_json(receipt_raw)
    require(receipt_raw == canonical(receipt), 'repair_restore_receipt_not_canonical')
    with recovery.verified_archive(Path(args.archive),args.archive_sha256,args.manifest_sha256) as (_,manifest):
        validate_export_binding(core,recovery,state,parent,args,manifest)
        validate_restore_receipt(receipt,manifest,args)
    role = spec['service']
    prepare_inspection_images(recovery.Docker(core._docker_prefix(),core.BASE_ENV),recovery,
                              [parent['images'][role],request['images'][role]])
    evidence = migration_evidence(core,recovery,state,parent,request,spec)
    require(source_state(core,recovery,account,args.failed_transaction_sha256) == state, 'repair_source_drift')
    now = datetime.now(timezone.utc)
    permit = {'schema':PERMIT_SCHEMA,'permit_id':secrets.token_hex(16),'project':core.POLICY['project'],'environment':'test',
              'controller':core.CONTROLLER_ID,'issued_at':now.isoformat().replace('+00:00','Z'),'expires_at':args.expires_at,
              'controller_sha256':core.controller_program_sha256(),'policy_sha256':core.POLICY_SHA256,
              'compose_sha256':core.CONTROLLER_COMPOSE_SHA256,'recovery_policy_sha256':state['recovery_policy_sha256'],
              'failed_transaction_sha256':sha(parent_raw),'failed_snapshot':parent['snapshot'],
              'failed_snapshot_manifest_sha256':parent['snapshot_manifest_sha256'],
              'accepted_release_sha256':parent['previous_release_sha256'],'source_state_sha256':sha(canonical(state)),
              'migration_spec':spec,'migration_evidence_sha256':sha(canonical(evidence)),
              'archive_sha256':args.archive_sha256,'manifest_sha256':args.manifest_sha256,
              'restore_receipt_sha256':args.restore_receipt_sha256,'request_sha256':sha(request_raw)}
    validate_permit(core,permit,request,now=now)
    directory = Path(core.POLICY['install_dir'])/'test-repair'
    active = directory/'permit.json'
    if os.path.lexists(active):
        old_raw = recovery.root_read(active,0o444)
        old = strict_json(old_raw)
        require(old_raw == canonical(old) and old.get('schema') == PERMIT_SCHEMA, 'repair_existing_permit_invalid')
        require(recovery.root_read(directory/'permits'/(old['permit_id']+'.json'),0o444) == old_raw, 'repair_permit_audit_mismatch')
        if timestamp(old['expires_at']) > now:
            validate_permit(core,old,request,now=now)
            require(all(old.get(key) == value for key,value in permit.items() if key not in ('permit_id','issued_at')),
                    'repair_existing_permit_conflict')
            return grant_receipt('unchanged',old,old_raw)
    if not args.apply:
        return grant_receipt('preview',permit)
    recovery.root_directory(directory)
    recovery.root_directory(directory/'permits')
    permit_raw = canonical(permit)
    audit = directory/'permits'/(permit['permit_id']+'.json')
    recovery.write_new(audit,permit_raw,0o444)
    require(recovery.root_read(audit,0o444) == permit_raw, 'repair_permit_audit_mismatch')
    if os.path.lexists(active):
        core._atomic_write(active,permit_raw,0o444,0,0)
    else:
        core._write_new(active,permit_raw,0o444,0,0)
    require(recovery.root_read(active,0o444) == permit_raw, 'repair_permit_readback_failed')
    return grant_receipt('granted',permit,permit_raw)


def grant(args):
    core = bootstrap_core(args)
    recovery = load_recovery(core)
    with recovery.release_lock(core) as account:
        return grant_locked(args,core,recovery,account)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command',required=True).add_parser('grant')
    for name in ('project','environment','controller-sha256','policy-sha256','recovery-policy-sha256',
                 'failed-transaction-sha256','request','migration-spec','archive','archive-sha256','manifest-sha256',
                 'restore-receipt','restore-receipt-sha256','expires-at'):
        sub.add_argument('--'+name,required=True)
    sub.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = grant(args)
    except Exception as exc:
        result = {'schema':'cnb-test-repair-grant/v1','status':'stopped_review_required',
                  'reason':str(exc) if isinstance(exc,RepairError) else 'repair_grant_failed'}
        print(json.dumps(result,sort_keys=True))
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
