"""Deterministic project material. Runtime algorithms live in ci/ and host/."""
import copy
import hashlib
import json
import shlex

import yaml

VENDOR = 'deploy/vendor/cnb-devops'
ANNOTATIONS_IMAGE = 'cnbcool/annotations:v1.0.0@sha256:bfd02b627f3b49082aa7dbbac1999560b4d66c7d85682084d0747eabecd75818'


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def yaml_bytes(value):
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=120).encode()


def environment_config(config, environment):
    """Select runtime differences; production retains the tested service/image set."""
    if environment not in {'test', 'production'}:
        raise ValueError('unsupported environment')
    selected = copy.deepcopy(config)
    if environment == 'test':
        return selected
    production = config.get('production')
    if not isinstance(production, dict):
        raise ValueError('production configuration is required')
    overrides = production.get('services', {})
    if set(overrides) - set(config['services']):
        raise ValueError('production cannot add services')
    for name, fields in overrides.items():
        if set(fields) - {'environment', 'environment_refs', 'loopback_port'}:
            raise ValueError('production cannot replace build or image identities')
        for field, value in fields.items():
            if field in {'environment', 'environment_refs'}:
                selected['services'][name].setdefault(field, {}).update(copy.deepcopy(value))
            else:
                selected['services'][name][field] = value
    selected['environment'] = environment
    selected['host'] = copy.deepcopy(production['host'])
    selected['secrets']['tat_import'] = production['tat_import']
    return selected


def model(config, controller_sha):
    project, environment = config['project'], config['environment']
    scope = f'{project}-{environment}'
    host = config['host']
    networks = host.get('networks', [scope])
    user = host.get('release_user', 'ubuntu')
    install = f'/opt/cnb-devops/{project}/{environment}/v1'
    services = {}
    compose_services = {}
    for role, spec in sorted(config['services'].items()):
        image_env = 'IMAGE_' + role.upper().replace('-', '_')
        service = {'image_repository': spec['image_repository'], 'image_env': image_env,
                   'container': f'{scope}-{role}', 'networks': networks,
                   'environment': spec.get('environment', {}),
                   'environment_refs': spec.get('environment_refs', {}),
                   'runtime_env': spec.get('runtime_env', False),
                   'healthcheck': bool(spec.get('healthcheck')),
                   'mounts': [{'type': 'bind', 'source': f'/opt/apps/{scope}/' + mount['source'],
                               'target': mount['target']} for mount in spec.get('mounts', [])]}
        services[role] = service
        composed = {'image': '${' + image_env + '}', 'container_name': service['container'],
                    'restart': 'unless-stopped', 'networks': networks}
        if 'resource_limits' in spec:
            limits = copy.deepcopy(spec['resource_limits'])
            service['resource_limits'] = limits
            composed.update(mem_limit=limits['memory_bytes'], cpus=limits['cpu_millis'] / 1000)
        if 'loopback_port' in spec:
            service['loopback_port'] = {'host_ip': '127.0.0.1', 'protocol': 'tcp',
                                        'published': spec['loopback_port'], 'target': spec['expose'][0]}
            composed['ports'] = [dict(service['loopback_port'], published=str(spec['loopback_port']))]
        if service['runtime_env']:
            composed['env_file'] = ['${CNB_RUNTIME_ENV_FILE:?required}']
        env = dict(service['environment'])
        env.update({key: '${' + ref + ':?required}' for key, ref in service['environment_refs'].items()})
        if env:
            composed['environment'] = env
        if spec.get('healthcheck'):
            composed['healthcheck'] = spec['healthcheck']
        if spec.get('expose'):
            composed['expose'] = [str(port) for port in spec['expose']]
        if service['mounts']:
            composed['volumes'] = service['mounts']
        compose_services[role] = composed
    compose = {'name': scope, 'services': compose_services,
               'networks': {name: {'external': True, 'name': name} for name in networks}}
    compose_bytes = yaml_bytes(compose)
    policy = {'schema': 'cnb-devops-host-policy/v1', 'project': project, 'environment': environment,
              'controller_id': scope + '-controller-v1', 'install_dir': install,
              'release_user': user, 'release_home': '/root' if user == 'root' else '/home/' + user,
              'app_dir': '/opt/apps/' + scope, 'docker_config': '/home/' + user + '/.docker/config.json',
              'recovery_root': '/opt/cnb-devops/' + project + '/recovery',
              'compose_sha256': hashlib.sha256(compose_bytes).hexdigest(),
              'services': services, 'networks': networks, 'required_env': host['required_env'],
              'database': host['database'], 'migration': host['migration'],
              'availability_probes': host['availability_probes'], 'identity_probes': host['identity_probes']}
    if host.get('proxy_container'):
        policy['proxy_container'] = host['proxy_container']
    if host.get('redis'):
        policy['redis'] = host['redis']
    if 'startup_timeout_seconds' in host:
        policy['startup_timeout_seconds'] = host['startup_timeout_seconds']
    if 'native_caddy_gateway' in host:
        policy['native_caddy_gateway'] = host['native_caddy_gateway']
    config_ci = {'schema': 'cnb-devops-ci/v1', 'project': project, 'environment': environment,
                 'controller_id': policy['controller_id'], 'candidate_prefix': project + '-candidate-',
                 'cnb_repository': config['cnb_repository'],
                 'services': {name: {key: value[key] for key in ('image_repository', 'image_env')}
                              for name, value in services.items()},
                 'probes': [{'url': url} for url in host['availability_probes']] + host['identity_probes'],
                 'controller_program_sha256': controller_sha,
                 'controller_compose_sha256': policy['compose_sha256'],
                 'policy_sha256': hashlib.sha256(json_bytes(policy)).hexdigest()}
    return policy, config_ci, compose_bytes


def pipeline(config):
    project = config['project']
    q = shlex.quote
    cfg = f'{VENDOR}/ci-config.json'
    manifest = '.cnb-release/candidate.json'
    config_arg = '--config ' + cfg
    gate = f'python3 {VENDOR}/ci/candidate_gate.py publication {config_arg} --manifest {manifest} --expected-tag "$RELEASE_CANDIDATE_TAG" --expected-commit "$CNB_COMMIT"'
    initialize = 'set -eu\ntest "$CNB_BRANCH" = ' + q(config['test_branch']) + '\ncase "$CNB_COMMIT" in *[!0-9a-f]*|\'\') exit 1;; esac\ntest "${#CNB_COMMIT}" -eq 40\ncase "$CNB_BUILD_ID" in cnb-[a-z0-9]*) ;; *) exit 1;; esac\numask 077\nmkdir -p .cnb-release'
    stages = [
        {'name': 'validate release identity', 'script': [initialize + '\nprintf \'##[set-output source_build_id=%s]\\n\' "$CNB_BUILD_ID"'],
         'exports': {'source_build_id': 'RELEASE_SOURCE_BUILD_ID'}},
        {'name': 'install pinned deployment dependencies', 'script': ['set -eu\nif ! command -v python3 >/dev/null || ! command -v git >/dev/null; then\n  apt-get update\n  apt-get install --yes --no-install-recommends ca-certificates git python3\nfi\nnpm ci --prefix ' + VENDOR + '/dependencies --ignore-scripts --prefer-offline --registry ' + q(config['ci']['npm_registry'])]},
        {'name': 'verify project', 'script': ['set -eu\n' + '\n'.join(config['ci']['verify']) + '\nprintf \'CNB_PROJECT_VERIFIED=%s\\n\' "$CNB_COMMIT"']},
        {'name': 'configure TCR push credentials', 'imports': config['secrets']['tcr_import'],
         'script': ['set -eu\n: "${TCR_USERNAME:?required}" "${TCR_PASSWORD:?required}"\numask 077\nmkdir -p "$HOME/.cnb-devops-docker"\nprintf \'%s\' "$TCR_PASSWORD" | DOCKER_CONFIG="$HOME/.cnb-devops-docker" docker login ccr.ccs.tencentyun.com --username "$TCR_USERNAME" --password-stdin']},
    ]
    for role, service in sorted(config['services'].items()):
        var = 'RELEASE_IMAGE_' + role.upper().replace('-', '_')
        script = 'set -eu\nrepository=' + q(service['image_repository']) + '\nimage="$repository:$CNB_BUILD_ID"\n'
        script += 'DOCKER_CONFIG="$HOME/.cnb-devops-docker" docker build --file ' + q(service['dockerfile']) + ' --tag "$image" --build-arg "GIT_SHA=$CNB_COMMIT" --build-arg "BUILD_ID=$CNB_BUILD_ID" ' + q(service['context']) + '\n'
        script += 'push_output="$(DOCKER_CONFIG="$HOME/.cnb-devops-docker" docker push "$image")"\nprintf \'%s\\n\' "$push_output"\ndigest="$(printf \'%s\\n\' "$push_output" | bash ' + VENDOR + '/ci/extract-docker-push-digest.sh)"\nprintf \'##[set-output image=%s@%s]\\n\' "$repository" "$digest"'
        stages.append({'name': 'build and push ' + role, 'script': [script], 'exports': {'image': var}})
    image_env = {role: 'RELEASE_IMAGE_' + role.upper().replace('-', '_') for role in sorted(config['services'])}
    script = "set -eu\npython3 - <<'PY'\nimport json, os\nfrom pathlib import Path\nkeys = " + repr(image_env) + "\nPath('.cnb-release/images.json').write_text(json.dumps({key: os.environ[value] for key, value in keys.items()}) + '\\n')\nPY\nrm -f -- \"$HOME/.cnb-devops-docker/config.json\""
    stages.append({'name': 'record digests and remove push credentials', 'script': [script + '\nnode ' + VENDOR + '/ci/test-repair.mjs --action=record --config=' + cfg + ' --images=.cnb-release/images.json']})
    build_stage_count = len(stages)
    stages.append({'name': 'deploy and verify test through TAT', 'imports': config['secrets']['tat_import'],
                   'script': ['set -eu\n: "${CNB_TAT_BINDING_JSON:?required}"\numask 077\nprintf \'%s\\n\' "$CNB_TAT_BINDING_JSON" > .cnb-release/tat-binding.json\nnode ' + VENDOR + '/ci/run-tat-release.mjs --config=' + cfg + ' --binding=.cnb-release/tat-binding.json --images=.cnb-release/images.json --receipt=.cnb-release/receipt.json'],
                   'exports': {'invocation_id': 'RELEASE_TEST_INVOCATION_ID', 'completed_at': 'RELEASE_TEST_COMPLETED_AT', 'receipt_sha256': 'RELEASE_TEST_RECEIPT_SHA256'}})
    stages.append({'name': 'assemble verified candidate', 'script': [f'python3 {VENDOR}/ci/candidate_manifest.py assemble --config {cfg} --receipt .cnb-release/receipt.json --receipt-sha256 "$RELEASE_TEST_RECEIPT_SHA256" --invocation-id "$RELEASE_TEST_INVOCATION_ID" --completed-at "$RELEASE_TEST_COMPLETED_AT" --build-id "$RELEASE_SOURCE_BUILD_ID" --commit "$CNB_COMMIT" --output {manifest}'],
                   'exports': {'candidate_tag': 'RELEASE_CANDIDATE_TAG', 'manifest_sha256': 'RELEASE_CANDIDATE_MANIFEST_SHA256', 'application_commit': 'RELEASE_CANDIDATE_COMMIT'}})
    stages.append({'name': 'publish immutable candidate Tag', 'script': [f'bash {VENDOR}/ci/publish-candidate-tag.sh --config={cfg} --manifest={manifest} --tag="$RELEASE_CANDIDATE_TAG" --commit="$CNB_COMMIT" --remote=https://cnb.cool/{config["cnb_repository"]}.git']})
    stages.append({'name': 'initialize annotation readback', 'script': ["umask 077\nprintf '{}\\n' > .cnb-release/before.json"]})
    def annotations(name, settings):
        return {'name': name, 'image': ANNOTATIONS_IMAGE,
                'settings': {'tag': '${RELEASE_CANDIDATE_TAG}', **settings}}
    stages += [annotations('read existing annotations', {'type': 'GET', 'toFile': '.cnb-release/before.json'}),
               {'name': 'verify existing annotation state', 'script': [gate + ' --annotations .cnb-release/before.json']},
               annotations('write non-ready evidence', {'type': 'ADD', 'data': 'candidate_format=cnb-candidate/v1\ncandidate_manifest_sha256=${RELEASE_CANDIDATE_MANIFEST_SHA256}\ncandidate_commit=${RELEASE_CANDIDATE_COMMIT}\ntest_build_status=passed\ntest_runtime_status=passed\ntest_public_status=passed'}),
               annotations('read non-ready evidence', {'type': 'GET', 'toFile': '.cnb-release/non-ready.json'}),
               {'name': 'verify non-ready evidence', 'script': [gate + ' --annotations .cnb-release/non-ready.json --require-non-ready-complete']},
               annotations('mark candidate ready last', {'type': 'ADD', 'data': 'candidate_status=ready'}),
               annotations('read ready evidence', {'type': 'GET', 'toFile': '.cnb-release/ready.json'}),
               {'name': 'verify ready evidence', 'script': [gate + ' --annotations .cnb-release/ready.json --require-ready-complete']}]
    job = {'name': f'cnb-devops-{project}-test', 'breakIfModify': True,
           'lock': {'key': f'{project}-test-release', 'expires': 14400, 'timeout': 14400, 'wait': True},
           'runner': {'tags': 'cnb:arch:amd64', 'cpus': 4}, 'docker': {'image': config['ci']['image']},
           'services': ['docker'], 'stages': stages}
    prepare_repair = copy.deepcopy(job)
    prepare_repair['name'] = f'cnb-devops-{project}-prepare-repair'
    prepare_repair['stages'] = copy.deepcopy(stages[:build_stage_count])
    repair = copy.deepcopy(job)
    repair['name'] = f'cnb-devops-{project}-repair-test'
    repair['stages'] = [
        {'name': 'validate repair source identity',
         'script': [initialize + f'\nnode {VENDOR}/ci/test-repair.mjs --action=prepare --config={cfg}'],
         'exports': {'source_build_id': 'RELEASE_SOURCE_BUILD_ID'}},
        copy.deepcopy(stages[1]),
        *copy.deepcopy(stages[build_stage_count:]),
    ]
    repair['stages'][2]['script'] = ['set -eu\n: "${CNB_TAT_BINDING_JSON:?required}"\numask 077\nprintf \'%s\\n\' "$CNB_TAT_BINDING_JSON" > .cnb-release/tat-binding.json\nnode ' + VENDOR + '/ci/test-repair.mjs --action=deploy --config=' + cfg + ' --binding=.cnb-release/tat-binding.json --receipt=.cnb-release/receipt.json']
    blocked = {'name': f'cnb-devops-{project}-production-blocked', 'docker': {'image': config['ci']['image']},
               'stages': [{'name': 'production adapter pending verification',
                           'script': ['echo "Production is not enabled in this bundle version; staging candidates remain available." >&2\nexit 1']}]}
    production_jobs = {'web_trigger_production_readiness': [copy.deepcopy(blocked)],
                       'tag_deploy.production': [blocked]}
    if config.get('production'):
        production_jobs = {'web_trigger_production_readiness': [production_job(config, 'readiness')],
                           'tag_deploy.production': [production_job(config, 'apply')]}
    return {config['test_branch']: {'push': [job], 'api_trigger_prepare_repair': [prepare_repair],
                                   'api_trigger_repair_test': [repair]}, project + '-candidate-*': production_jobs}


def production_job(config, phase):
    q = shlex.quote
    cfg = f'{VENDOR}/production/ci-config.json'
    test_cfg = f'{VENDOR}/ci-config.json'
    receipt = '.cnb-release/production-receipt.json'
    status = 'production_readiness_status' if phase == 'readiness' else 'production_deploy_status'
    def annotations(name, settings):
        return {'name': name, 'image': ANNOTATIONS_IMAGE,
                'settings': {'tag': '${CNB_BRANCH}', **settings}}
    gate = (f'python3 {VENDOR}/ci/candidate_gate.py production --config {test_cfg}'
            f' --tag "$CNB_BRANCH" --commit "$CNB_COMMIT" --branch {q(config["production_branch"])}'
            f' --annotations .cnb-release/input-annotations.json --output-dir .cnb-release --phase {phase}')
    run = (f'node {VENDOR}/ci/run-production-deploy.mjs {phase} --config={cfg}'
           f' --candidate-config={test_cfg} --binding=.cnb-release/tat-binding.json'
           f' --manifest=.cnb-release/candidate.json --receipt={receipt}')
    if phase == 'apply':
        run += ' --readiness=.cnb-release/readiness.json --approval=.cnb-release/approval.json'
    exports = ({'production_readiness_b64url': 'PRODUCTION_READINESS_B64URL',
                'production_prepared_sha256': 'PRODUCTION_PREPARED_SHA256',
                'production_readiness_invocation_id': 'PRODUCTION_READINESS_INVOCATION_ID'}
               if phase == 'readiness' else {'production_receipt_sha256': 'PRODUCTION_RECEIPT_SHA256'})
    data = '\n'.join(key + '=${' + value + '}' for key, value in exports.items())
    readback = (f'python3 {VENDOR}/ci/production_annotations.py --phase {phase} --receipt {receipt}'
                ' --annotations .cnb-release/production-annotations.json')
    if phase == 'readiness':
        readback += ' --invocation-id "$PRODUCTION_READINESS_INVOCATION_ID"'
    stages = [
        {'name': 'prepare production candidate verification', 'script': [
            'set -eu\numask 077\nmkdir -p .cnb-release\n'
            'if ! command -v python3 >/dev/null || ! command -v git >/dev/null; then\n'
            '  apt-get update\n  apt-get install --yes --no-install-recommends ca-certificates git python3\nfi\n'
            f'npm ci --prefix {VENDOR}/dependencies --ignore-scripts --prefer-offline --registry {q(config["ci"]["npm_registry"])}']},
        annotations('read candidate annotations', {'type': 'GET', 'toFile': '.cnb-release/input-annotations.json'}),
        {'name': 'verify immutable candidate and governed branch', 'script': ['set -eu\n' + gate]},
        annotations('mark production operation pending', {'type': 'ADD', 'data': status + '=pending'}),
        {'name': 'verify production through fixed TAT command', 'imports': config['production']['tat_import'],
         'script': ['set -eu\n: "${CNB_TAT_BINDING_JSON:?required}"\numask 077\n'
                    'printf \'%s\\n\' "$CNB_TAT_BINDING_JSON" > .cnb-release/tat-binding.json\n' + run],
         'exports': exports},
        annotations('write production receipt evidence', {'type': 'ADD', 'data': data}),
        annotations('read production receipt evidence', {'type': 'GET', 'toFile': '.cnb-release/production-annotations.json'}),
        {'name': 'verify production evidence before passed status', 'script': [readback]},
        annotations('mark production status passed last', {'type': 'ADD', 'data': status + '=passed'}),
        annotations('read final production annotations', {'type': 'GET', 'toFile': '.cnb-release/production-annotations.json'}),
        {'name': 'verify production annotation readback', 'script': [readback + ' --require-passed']},
    ]
    return {'name': f'cnb-devops-{config["project"]}-production-{phase}',
            'lock': {'key': f'{config["project"]}-production-release', 'expires': 14400, 'timeout': 14400, 'wait': True},
            'runner': {'tags': 'cnb:arch:amd64', 'cpus': 2},
            'docker': {'image': config['ci']['image']}, 'stages': stages}


def tag_deploy(production_enabled=False):
    return {'environments': [{'name': 'production',
        'description': ('将测试通过的同一批镜像发布到生产。先检查就绪，再由管理员确认候选。'
                        if production_enabled else '生产执行尚未接通，当前仅交付测试候选。'),
        'permissions': {'roles': ['owner']},
        'button': [{'name': '检查生产就绪', 'description': '检查选中候选的生产就绪状态。',
                    'event': 'web_trigger_production_readiness',
                    'permissions': {'roles': ['owner']}}],
        'deploy': [{'name': '发布已确认的候选' if production_enabled else '生产执行（尚未启用）'}],
        'require': [{'annotation': 'candidate_status', 'expect': {'eq': 'ready'}},
                    {'annotation': 'test_build_status', 'expect': {'eq': 'passed'}},
                    {'annotation': 'test_runtime_status', 'expect': {'eq': 'passed'}},
                    {'annotation': 'test_public_status', 'expect': {'eq': 'passed'}},
                    {'annotation': 'production_readiness_status', 'expect': {'eq': 'passed'}},
                    *([{'annotation': 'production_approval_status', 'expect': {'eq': 'signed'}}]
                      if production_enabled else []),
                    {'approver': {'roles': ['owner']}, 'title': '确认本候选的生产发布'}]}]}
