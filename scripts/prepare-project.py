#!/usr/bin/env python3
"""Validate, preview and explicitly apply a pinned, offline project bundle."""
import argparse
import base64
import copy
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit('Install generator dependencies: python3 -m pip install PyYAML==6.0.2 jsonschema==4.25.1')

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'assets/cnb-tcr-tat'
VENDOR = Path('deploy/vendor/cnb-devops')
LOCK = VENDOR / 'generation-lock.json'
JOURNAL = Path('deploy/.cnb-devops-prepare.json')


class PreparationError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise PreparationError('YAML keys must be unique strings')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def checked_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise PreparationError('path must remain inside the project')
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise PreparationError(f'symlink in managed path: {relative}')
    return current


def current_bytes(root, relative):
    file = checked_path(root, relative)
    if file.exists() and not file.is_file():
        raise PreparationError(f'expected regular file: {relative}')
    return file.read_bytes() if file.exists() else None


def atomic_write(root, relative, data):
    file = checked_path(root, relative)
    file.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + file.name + '.', dir=file.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, file)
        directory_fd = os.open(file.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def bundle_files():
    manifest = json.loads((BUNDLE / 'bundle.json').read_text())
    files = {}
    for relative, expected in manifest['files'].items():
        file = checked_path(BUNDLE, relative)
        content = file.read_bytes()
        if digest(content) != expected:
            raise PreparationError(f'bundle integrity mismatch: {relative}')
        files[relative] = content
    needed = {'host/tat-deploy-test.py', 'host/tat-command.sh.tmpl',
              'ci/run-tat-release.mjs', 'ci/candidate_manifest.py', 'dependencies/package-lock.json',
              'project.schema.json', 'templates/render.py'}
    if not needed <= files.keys():
        raise PreparationError('bundle is incomplete')
    return manifest, files


def validate_config(config, project_root, schema):
    errors = sorted(Draft202012Validator(schema).iter_errors(config), key=lambda e: str(e.json_path))
    if errors:
        # Do not include values: mistaken secret fields must never be echoed.
        raise PreparationError('invalid project configuration at ' + errors[0].json_path + ' (' + errors[0].validator + ')')
    if config['test_branch'] == config['production_branch']:
        raise PreparationError('test and production branches must differ')
    services = config['services']
    for role, service in services.items():
        for field, kind in [('dockerfile', 'file'), ('context', 'directory')]:
            path = checked_path(project_root, service[field])
            if not (path.is_file() if kind == 'file' else path.is_dir()):
                raise PreparationError(f'{role}.{field} must identify an existing {kind}')
        if not set(service.get('environment_refs', {}).values()) <= set(config['host']['required_env']):
            raise PreparationError(f'{role}: environment references must be declared in required_env')
    if len({s['image_repository'] for s in services.values()}) != len(services):
        raise PreparationError('each service requires a distinct image repository')
    host = config['host']
    if host['database']['url_env'] not in host['required_env']:
        raise PreparationError('database URL variable must be required')
    if host['migration'] and host['migration']['service'] not in services:
        raise PreparationError('migration must use a configured service')
    if {p['service'] for p in host['identity_probes']} != services.keys():
        raise PreparationError('identity probes must cover exactly the configured services')


def merged_pipeline(old_bytes, generated, previous):
    original = yaml.load(old_bytes, Loader=UniqueLoader) if old_bytes else {}
    if not isinstance(original, dict):
        raise PreparationError('.cnb.yml must be a mapping')
    merged = copy.deepcopy(original)
    # Only remove an exact previous owned fragment; unrelated branch/event/jobs survive.
    for branch, events in previous.items():
        for event, owned in events.items():
            actual = merged.get(branch, {}).get(event)
            if event == 'push':
                if not isinstance(actual, list):
                    raise PreparationError('owned CNB push job missing or modified')
                for job in owned:
                    matches = [item for item in actual if isinstance(item, dict) and item.get('name') == job['name']]
                    if matches != [job]:
                        raise PreparationError('owned CNB job drift: ' + job['name'])
                    actual.remove(matches[0])
            elif actual != owned:
                raise PreparationError('owned CNB event drift: ' + branch + '.' + event)
            else:
                del merged[branch][event]
    for branch, events in generated.items():
        if branch in merged and not isinstance(merged[branch], dict):
            raise PreparationError('CNB branch conflicts with generated pipeline')
        target = merged.setdefault(branch, {})
        for event, value in events.items():
            if event == 'push':
                jobs = target.setdefault(event, [])
                if not isinstance(jobs, list):
                    raise PreparationError('existing CNB push is not a job list')
                names = {item.get('name') for item in jobs if isinstance(item, dict)}
                if names & {item['name'] for item in value}:
                    raise PreparationError('CNB job already exists without ownership evidence')
                jobs.extend(value)
            elif event in target:
                raise PreparationError('CNB event already exists without ownership evidence')
            else:
                target[event] = value
    if merged == original:
        return old_bytes
    return yaml.safe_dump(merged, sort_keys=False, allow_unicode=True, width=120).encode()


def prepare(root, config_path):
    config = yaml.load(config_path.read_text(), Loader=UniqueLoader)
    manifest, files = bundle_files()
    validate_config(config, root, json.loads(files['project.schema.json']))
    spec = importlib.util.spec_from_file_location('cnb_bundle_render', BUNDLE / 'templates/render.py')
    render = importlib.util.module_from_spec(spec)
    exec(compile(files['templates/render.py'], str(BUNDLE / 'templates/render.py'), 'exec'), render.__dict__)
    host_spec = importlib.util.spec_from_file_location('cnb_host_policy', BUNDLE / 'host/tat-deploy-test.py')
    host_module = importlib.util.module_from_spec(host_spec)
    exec(compile(files['host/tat-deploy-test.py'], str(BUNDLE / 'host/tat-deploy-test.py'), 'exec'), host_module.__dict__)
    generated = environment_artifacts(config, manifest, files, render, host_module)
    outputs = {str(VENDOR / name): data for name, data in generated.items()}
    if config.get('production'):
        production = render.environment_config(config, 'production')
        generated_production = environment_artifacts(production, manifest, files, render, host_module)
        outputs.update({str(VENDOR / 'production' / name): data for name, data in generated_production.items()})
    new_pipeline = render.pipeline(config)
    lock_bytes = current_bytes(root, LOCK)
    previous = json.loads(lock_bytes) if lock_bytes else {}
    if previous and previous.get('project') != config['project']:
        raise PreparationError('project identity change requires a separate project directory')
    journal_bytes = current_bytes(root, JOURNAL)
    journal = json.loads(journal_bytes) if journal_bytes else None
    # An interrupted same-plan apply can contain either the old or new pipeline.
    cnb = current_bytes(root, '.cnb.yml')
    old_pipeline = previous.get('pipeline', {})
    if journal and cnb is not None and digest(cnb) == journal.get('new_hashes', {}).get('.cnb.yml'):
        old_pipeline = new_pipeline
    outputs['.cnb.yml'] = merged_pipeline(cnb, new_pipeline, old_pipeline)
    outputs['.cnb/tag_deploy.yml'] = render.yaml_bytes(render.tag_deploy(bool(config.get('production'))))
    outputs['deploy/project.yml'] = render.yaml_bytes(config)
    if config.get('github_sync', False):
        sync = files['templates/github-sync.yml.tmpl'].decode()
        for key in ('test_branch', 'production_branch', 'cnb_repository'):
            sync = sync.replace('@' + key.upper() + '@', config[key])
        outputs['.github/workflows/cnb-devops-sync.yml'] = sync.encode()
    ignore = current_bytes(root, '.gitignore') or b''
    rules = ['.cnb-release/', 'deploy/.cnb-devops-prepare.json', 'node_modules/']
    missing = [rule for rule in rules if rule not in ignore.decode().splitlines()]
    if missing:
        outputs['.gitignore'] = ignore + (b'\n' if ignore and not ignore.endswith(b'\n') else b'') + ('\n'.join(missing) + '\n').encode()
    for relative in ('docs/DEPLOYMENT.md', 'docs/PROJECT_STATUS.md'):
        if relative == 'docs/PROJECT_STATUS.md' and any(
                current_bytes(root, name) is not None for name in ('PROJECT_STATE.md', 'PROJECT_STATUS.md')):
            continue
        if current_bytes(root, relative) is None:
            text = ('# 部署记录\n\n当前配置：`deploy/project.yml`；固定工件：`deploy/vendor/cnb-devops/`。\n'
                    '\n本地文件已生成；账号、主机首装、测试发布、生产晋级与恢复均需各自验收。\n'
                    '\n下一步：按 Skill 的 `references/bootstrap.md` 核验主机和 Secret 配置；保留安装、TAT 绑定和发布证据的位置，不记录敏感值。\n') if relative.endswith('DEPLOYMENT.md') else (
                    '# 当前状态\n\n阶段：本地生成完成；云端尚未验证。\n\n应用提交：待记录；控制器提交：待记录。\n'
                    '\n首装 / 新增项目 / 测试 / 候选 / 生产 / 恢复 / 升级：均未验收。\n'
                    '\n下一动作：只读盘点已授权主机，核对项目差异和有效授权；不要重复已完成的账号操作。\n')
            outputs[relative] = text.encode()
    # Human-owned docs/config are not locked; generated core and the Tag UI are.
    managed = {relative: digest(data) for relative, data in outputs.items()
               if relative not in {'.cnb.yml', '.gitignore', 'deploy/project.yml'} and not relative.startswith('docs/')}
    new_lock = {'schema': 'cnb-devops-generation/v1', 'project': config['project'],
                'bundle_version': manifest['version'], 'files': managed, 'pipeline': new_pipeline}
    outputs[str(LOCK)] = json_bytes(new_lock)
    plan_hash = digest(json_bytes({key: digest(value) for key, value in sorted(outputs.items()) if not key.startswith('docs/') and key != '.gitignore'}))
    if journal and journal.get('plan_sha256') != plan_hash:
        raise PreparationError('interrupted apply belongs to another config/bundle; resume the original first')
    for relative, data in outputs.items():
        actual = current_bytes(root, relative)
        if relative in {'.cnb.yml', '.gitignore', 'deploy/project.yml', str(LOCK)} or relative.startswith('docs/'):
            continue
        accepted = {None, digest(data)}
        if relative in previous.get('files', {}):
            accepted.add(previous['files'][relative])
        if actual is not None and digest(actual) not in accepted:
            raise PreparationError('managed file drift: ' + relative)
    stale = set(previous.get('files', {})) - set(managed)
    if stale:
        raise PreparationError('upgrade removes owned files; explicit migration required: ' + ', '.join(sorted(stale)))
    return outputs, plan_hash


def environment_artifacts(config, manifest, files, render, host_module):
    """Produce one independently installable environment with its own artifact lock."""
    environment = config['environment']
    policy, ci_config, compose = render.model(config, digest(files['host/tat-deploy-test.py']))
    try:
        host_module.validate_host_policy(policy)
    except host_module.DeploymentError as error:
        raise PreparationError('project differences do not satisfy the host policy contract') from error
    outputs = {relative: data for relative, data in files.items()
               if relative.split('/')[0] in {'host', 'ci', 'admin', 'dependencies'}}
    outputs['bundle.json'] = json_bytes(manifest)
    outputs['host-policy.json'] = json_bytes(policy)
    outputs['docker-compose.yml'] = compose
    replacements = {'INSTALL_DIR': policy['install_dir'], 'RELEASE_USER': policy['release_user'],
                    'RELEASE_HOME': policy['release_home'],
                    'CONTROLLER_SHA256': digest(files['host/tat-deploy-test.py']),
                    'POLICY_SHA256': digest(json_bytes(policy)), 'COMPOSE_SHA256': digest(compose)}
    shim = files['host/tat-command.sh.tmpl'].decode()
    for key, value in replacements.items():
        shim = shim.replace('@' + key + '@', value)
    if re.search(r'@[A-Z_]+@', shim):
        raise PreparationError('unresolved TAT template field')
    if environment == 'production':
        pem = config['production']['approval_public_key'].encode('ascii')
        try:
            encoded = pem.decode().splitlines()[1]
            der = base64.b64decode(encoded, validate=True)
            if len(der) != 44 or not der.startswith(bytes.fromhex('302a300506032b6570032100')):
                raise ValueError('invalid Ed25519 SPKI')
        except (ValueError, IndexError) as exc:
            raise PreparationError('production approval key must be an Ed25519 public key') from exc
        authority = {'schema': 'cnb-production-authority/v1', 'project': config['project'],
                     'environment': 'production', 'controller_program_sha256': replacements['CONTROLLER_SHA256'],
                     'host_policy_sha256': replacements['POLICY_SHA256'],
                     'controller_compose_sha256': replacements['COMPOSE_SHA256'],
                     'approval_public_key_sha256': digest(pem)}
        outputs['approval-ed25519.pub'] = pem
        outputs['production-authority.json'] = json_bytes(authority)
        source = files.get('host/production-release.py')
        if source is None:
            raise PreparationError('production entry is missing from the bundle')
        wrapper_spec = importlib.util.spec_from_file_location('cnb_production_entry', BUNDLE / 'host/production-release.py')
        wrapper = importlib.util.module_from_spec(wrapper_spec)
        exec(compile(source, str(BUNDLE / 'host/production-release.py'), 'exec'), wrapper.__dict__)
        entry_sha, authority_sha = digest(source), digest(outputs['production-authority.json'])
        shim = wrapper.render_tat_template(policy, entry_sha, authority_sha).decode('ascii')
        replacements['CONTROLLER_SHA256'] = entry_sha
        ci_config.update({'production_entry_sha256': entry_sha, 'production_authority_sha256': authority_sha,
                          'approval_public_key_sha256': digest(pem), 'production_branch': config['production_branch']})
    outputs['ci-config.json'] = json_bytes(ci_config)
    if config.get('recovery'):
        recovery = config['recovery']
        mount_names = {Path(mount['source']).name for service in policy['services'].values() for mount in service['mounts']}
        if set(recovery['mounts']) != mount_names:
            raise PreparationError('recovery classifications must cover every persistent directory exactly')
        table_names = [(table['schema'], table['name']) for table in recovery['required_nonempty_tables']]
        if len(table_names) != len(set(table_names)):
            raise PreparationError('recovery evidence table names must be unique')
        outputs['recovery-policy.json'] = json_bytes({'schema': 'cnb-recovery-policy/v1',
            'project': config['project'], 'environment': environment, 'host_policy_sha256': replacements['POLICY_SHA256'],
            'mounts': recovery['mounts'], 'required_nonempty_tables': recovery['required_nonempty_tables']})
    outputs['tat-command.sh'] = shim.encode()
    command_spec = {'schema_version': 1, 'project': config['project'], 'environment': config['environment'],
                    'version': manifest['version'], 'target': {'region': None, 'instance_id': None},
                    'expected_artifacts': {'program_sha256': replacements['CONTROLLER_SHA256'],
                                           'compose_sha256': replacements['COMPOSE_SHA256'],
                                           'policy_sha256': replacements['POLICY_SHA256']},
                    'expectedCommand': {'CommandName': config['project'][:12] + '-' + digest(config['project'].encode())[:8] + '-' + environment + '-v' + manifest['version'],
                                        'Description': 'Pinned project ' + environment + ' release', 'CommandType': 'SHELL',
                                        'Content': shim, 'Username': policy['release_user'],
                                        'WorkingDirectory': policy['release_home'], 'Timeout': 3600,
                                        'EnableParameter': True, 'DefaultParameters': {'release_request_b64url': 'INVALID'},
                                        'DefaultParameterConfs': [{'ParameterName': 'release_request_b64url',
                                                                   'ParameterValue': 'INVALID', 'ParameterDescription': ''}]}}
    if environment == 'production':
        command_spec['production_authority_b64url'] = base64.urlsafe_b64encode(outputs['production-authority.json']).rstrip(b'=').decode('ascii')
    outputs['tat-spec.template.json'] = json_bytes(command_spec)
    artifacts = {name: digest(data) for name, data in outputs.items()}
    outputs['artifact-lock.json'] = json_bytes({'schema': 'cnb-devops-artifacts/v1',
                                                            'version': manifest['version'], 'files': artifacts})
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', help='write the reviewed local file plan; never contacts the cloud')
    parser.add_argument('--diff', action='store_true', help='show text differences, including project configuration')
    args = parser.parse_args()
    root = args.project_root.resolve(strict=True)
    outputs, plan_hash = prepare(root, args.config.resolve(strict=True))
    changed = {name: data for name, data in outputs.items() if current_bytes(root, name) != data}
    if not changed:
        if args.apply and current_bytes(root, JOURNAL) is not None:
            checked_path(root, JOURNAL).unlink()
        print('unchanged: generated bundle and owned pipeline are current')
        return
    for name, data in changed.items():
        old = current_bytes(root, name)
        print(('create ' if old is None else 'update ') + name)
        if args.diff:
            print(''.join(difflib.unified_diff((old or b'').decode().splitlines(True), data.decode().splitlines(True), fromfile=name, tofile=name)), end='')
    if not args.apply:
        print('preview only; rerun with --apply to write these local files')
        return
    atomic_write(root, JOURNAL, json_bytes({'plan_sha256': plan_hash, 'new_hashes': {name: digest(data) for name, data in outputs.items()}}))
    for name, data in changed.items():
        atomic_write(root, name, data)
    checked_path(root, JOURNAL).unlink()
    print('applied locally; cloud installation and deployment remain unverified')


if __name__ == '__main__':
    try:
        main()
    except (PreparationError, OSError, ValueError, yaml.YAMLError) as error:
        # Parser errors can quote secret input; never echo their full diagnostics.
        print(str(error) if isinstance(error, PreparationError) else 'preparation failed: invalid or unavailable input file', file=sys.stderr)
        sys.exit(1)
