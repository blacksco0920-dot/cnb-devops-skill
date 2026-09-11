#!/usr/bin/env python3
"""Preview or explicitly upgrade one reviewed failed TEST installation over strict SSH."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType


class UpgradeError(ValueError):
    pass


def require(value, code):
    if not value:
        raise UpgradeError('UPGRADE_' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def setup_api():
    spec = importlib.util.spec_from_file_location('controller_upgrade_transport', Path(__file__).with_name('setup-host.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def verified_plan(setup, directory, lock_sha):
    raw_lock = setup.read_safe(directory / 'artifact-lock.json')
    require(type(lock_sha) is str and re.fullmatch('[a-f0-9]{64}', lock_sha) and sha(raw_lock) == lock_sha, 'LOCK_MISMATCH')
    lock = setup.strict_json(raw_lock)
    raw = setup.read_safe(directory / 'host/install-project.py')
    require(sha(raw) == lock['files'].get('host/install-project.py'), 'INSTALLER_MISMATCH')
    installer = ModuleType('controller_upgrade_installer')
    installer.__file__ = str(directory / 'host/install-project.py')
    exec(compile(raw, installer.__file__, 'exec'), installer.__dict__)
    plan = installer.verify_bundle(directory, lock_sha)
    for name, captured in plan['files'].items():
        require(setup.read_safe(directory / name) == captured, 'BUNDLE_CHANGED')
    return plan


def prepare(args):
    setup = setup_api()
    old = verified_plan(setup, args.old_bundle_dir, args.old_lock_sha256)
    new = verified_plan(setup, args.bundle_dir, args.lock_sha256)
    accepted = setup.read_safe(args.accepted_installation, {0o600})
    target_raw = setup.read_safe(args.target, {0o600})
    target = setup.strict_json(target_raw)
    require(type(target) is dict and set(target) == {'host', 'port', 'user', 'identity_file', 'known_hosts_file'}
            and type(target['host']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{0,252}', target['host'])
            and type(target['port']) is int and 1 <= target['port'] <= 65535
            and type(target['user']) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}', target['user']), 'TARGET_INVALID')
    for key, modes in (('identity_file', {0o400, 0o600}), ('known_hosts_file', {0o400, 0o600, 0o644})):
        require(type(target[key]) is str and Path(target[key]).is_absolute(), 'TARGET_INVALID')
        setup.read_safe(target[key], modes, 1024 * 1024)
    expected = {'old_lock_sha256': args.old_lock_sha256, 'lock_sha256': args.lock_sha256,
                'accepted_installation_sha256': sha(accepted), 'failed_transaction_sha256': args.failed_transaction_sha256,
                'target_sha256': sha(target_raw)}
    source = new['files']['host/upgrade-controller.py']
    driver = ModuleType('verified_controller_upgrade')
    driver.__file__ = str(args.bundle_dir / 'host/upgrade-controller.py')
    exec(compile(source, driver.__file__, 'exec'), driver.__dict__)
    driver.verify_pair(old, new, accepted, expected)
    evidence = Path(os.path.abspath(args.evidence_dir))
    require(Path(os.path.abspath(args.accepted_installation)) != evidence / 'accepted-installation.json', 'OLD_RECEIPT_OUTPUT_CONFLICT')
    if evidence.exists() or evidence.is_symlink():
        info = evidence.lstat()
        require(stat.S_ISDIR(info.st_mode) and not evidence.is_symlink() and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'EVIDENCE_UNSAFE')
        setup.validate_output_path(evidence / 'accepted-installation.json')
    else:
        setup.validate_output_path(evidence)
    files = {'accepted-installation.json': accepted}
    for prefix, plan in (('old', old), ('new', new)):
        files.update({prefix + '/' + name: raw for name, raw in plan['files'].items()})
        files[prefix + '/artifact-lock.json'] = plan['raw_lock']
    return setup, driver, old, new, expected, target, evidence, files


ROOT_GATE = r'''
import hashlib,io,json,re,sys,tarfile
try:
    raw=sys.stdin.buffer.read(128*1024*1024+1)
    if len(raw)>128*1024*1024: raise ValueError()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        item=archive.getmember('new/host/upgrade-controller.py')
        if not item.isfile() or item.size>1024*1024: raise ValueError()
        source=archive.extractfile(item).read()
    if hashlib.sha256(source).hexdigest()!=sys.argv[1]: raise ValueError()
    scope={'__name__':'verified_upgrade_driver','__file__':'/verified/upgrade-controller.py'}
    exec(compile(source,scope['__file__'],'exec'),scope)
    print(json.dumps(scope['upgrade_archive'](raw,json.loads(sys.argv[2])),sort_keys=True))
except Exception as error:
    code=str(error)
    print(json.dumps({'status':'stopped_review_required','code':code if re.fullmatch('UPGRADE_[A-Z0-9_]+',code) else 'UPGRADE_REMOTE_INCOMPLETE'}))
    sys.exit(1)
'''


def verify_readback(driver, response, old, new, expected):
    try:
        require(type(response) is dict and set(response) == {'receipt', 'readback'}, 'READBACK_INVALID')
        receipt, encoded = response['receipt'], response['readback']
        installation = canonical({'schema': 'cnb-test-installation/v1', 'lock_sha256': new['lock_sha256']})
        fixed = driver.fixed_files(new, installation)
        old_fixed = {name: sha(value) for name, (value, _mode) in driver.fixed_files(old, b'old receipt').items()}
        old_fixed['installation.json'] = expected['accepted_installation_sha256']
        require(type(encoded) is dict and set(encoded) == set(fixed) | {'empty-baseline.json'}, 'READBACK_FILES')
        raw = {name: base64.b64decode(value, validate=True) for name, value in encoded.items()}
        require(all(base64.b64encode(value).decode('ascii') == encoded[name] for name, value in raw.items()), 'READBACK_ENCODING')
        require(all(raw[name] == value for name, (value, _mode) in fixed.items()), 'READBACK_MISMATCH')
        require(type(receipt) is dict and receipt.get('schema') == 'cnb-controller-upgrade/v1' and receipt.get('status') == 'verified'
                and receipt.get('project') == new['policy']['project'] and receipt.get('environment') == 'test'
                and all(receipt.get(key) == value for key, value in expected.items())
                and receipt.get('fixed_sha256') == {name: sha(value) for name, (value, _mode) in fixed.items()}
                and receipt.get('old_fixed_sha256') == old_fixed and receipt.get('installation_sha256') == sha(installation)
                and receipt.get('application_changed') is False and receipt.get('release_executed') is False
                and receipt.get('failed_transaction_retained') is True
                and receipt['source']['empty_baseline_sha256'] == sha(raw['empty-baseline.json'])
                and receipt['source']['app']['transaction_sha256'] == expected['failed_transaction_sha256']
                and re.fullmatch('[a-f0-9]{64}', receipt['journal_sha256']), 'READBACK_RECEIPT')
        return raw['installation.json'], receipt
    except UpgradeError:
        raise
    except Exception as error:
        raise UpgradeError('UPGRADE_READBACK_INVALID') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('old-bundle-dir', 'bundle-dir', 'accepted-installation', 'target', 'evidence-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('old-lock-sha256', 'lock-sha256', 'failed-transaction-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    setup, driver, old, new, expected, target, evidence, files = prepare(args)
    result = {'schema': 'cnb-controller-upgrade/v1', 'status': 'preview', 'project': new['policy']['project'],
              'environment': 'test', **expected, 'release_executed': False}
    if args.apply:
        if not evidence.exists(): evidence.mkdir(mode=0o700)
        setup.save_installation(evidence / 'upgrade-inputs.json', canonical(result))
        remote = ['/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root', 'LANG=C.UTF-8',
                  '/usr/bin/python3', '-I', '-c', ROOT_GATE, sha(files['new/host/upgrade-controller.py']), json.dumps(expected, separators=(',', ':'))]
        if target['user'] != 'root': remote = ['/usr/bin/sudo', '-n', '--', *remote]
        try:
            completed = subprocess.run(setup.ssh_command(target, remote), input=setup.archive_bytes(files), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=1800, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise UpgradeError('UPGRADE_SSH_INCOMPLETE') from error
        require(len(completed.stdout) <= 16 * 1024 * 1024, 'READBACK_TOO_LARGE')
        response = setup.strict_json(completed.stdout)
        if completed.returncode:
            code = response.get('code') if type(response) is dict else None
            raise UpgradeError(code if type(code) is str and re.fullmatch('UPGRADE_[A-Z0-9_]+', code) else 'UPGRADE_REMOTE_INCOMPLETE')
        installation, receipt = verify_readback(driver, response, old, new, expected)
        setup.save_installation(evidence / 'accepted-installation.json', installation)
        setup.save_installation(evidence / 'upgrade-receipt.json', canonical(receipt))
        result.update(status='verified', installation_path=str(evidence / 'accepted-installation.json'),
                      installation_sha256=sha(installation), receipt_path=str(evidence / 'upgrade-receipt.json'),
                      receipt_sha256=sha(canonical(receipt)))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        code = str(error)
        print(json.dumps({'schema': 'cnb-controller-upgrade/v1', 'status': 'stopped_review_required',
                          'code': code if re.fullmatch('(?:UPGRADE|SETUP)_[A-Z0-9_]+', code) else 'UPGRADE_FAILED'}))
        raise SystemExit(1)
