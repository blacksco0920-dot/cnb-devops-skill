#!/usr/bin/env python3
"""Reuse the pinned official Tencent OAuth login; export only a temporary triple."""
import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

TCCLI_VERSION = '3.1.162.1'


def fail(code):
    raise ValueError(code)


def private_directory(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail('SESSION_DIRECTORY_NOT_PRIVATE')


def private_file(filename):
    private_directory(filename.parent)
    info = filename.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        fail('SESSION_FILE_NOT_PRIVATE')


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('SESSION_JSON_INVALID')
        result[key] = value
    return result


def read_session(filename, minimum):
    private_file(filename)
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if info.st_size > 65536 or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            fail('SESSION_FILE_NOT_PRIVATE')
        value = json.load(handle, object_pairs_hook=unique_keys)
    if not isinstance(value, dict) or value.get('type') != 'oauth':
        fail('SESSION_OAUTH_REQUIRED')
    for key in ('secretId', 'secretKey', 'token'):
        item = value.get(key)
        if not isinstance(item, str) or not item or len(item) > 16384 or re.search(r'[\s\x00]', item):
            fail('SESSION_CREDENTIALS_INVALID')
    expires = value.get('expiresAt')
    if type(expires) is not int or expires - time.time() < minimum:
        fail('SESSION_EXPIRED_OR_TOO_SHORT')
    return {key: value[key] for key in ('secretId', 'secretKey', 'token')}, expires


def export_session(source, output, minimum):
    private_directory(output.parent)
    if output.exists() or output.is_symlink():
        fail('SESSION_OUTPUT_EXISTS')
    triple, expires = read_session(source, minimum)
    fd, temp = tempfile.mkstemp(prefix='.session-', dir=output.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(triple, handle, separators=(',', ':'))
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, output)
    finally:
        os.unlink(temp)
    return {'status': 'exported', 'expires_at': datetime.fromtimestamp(expires, timezone.utc).isoformat(),
            'scope': 'local_bootstrap_session', 'deployment_ready': False}


def verified_request(original, session, method, url, **kwargs):
    if urlsplit(url).scheme != 'https':
        fail('SESSION_HTTPS_REQUIRED')
    # This pinned upstream release passes verify=False. Restore verification in
    # this process, without editing the installed CLI or implementing OAuth.
    kwargs['verify'] = True
    kwargs['timeout'] = 30
    kwargs['allow_redirects'] = False
    return original(session, method, url, **kwargs)


@contextmanager
def verified_transport(requests):
    original = requests.sessions.Session.request
    requests.sessions.Session.request = lambda *args, **kwargs: verified_request(original, *args, **kwargs)
    try:
        yield
    finally:
        requests.sessions.Session.request = original


class LoginOutput(io.TextIOBase):
    """Show the official authorization URL, never upstream HTTP errors/bodies."""
    def __init__(self, destination):
        self.destination = destination
        self.pending = ''

    def write(self, value):
        self.pending += value
        while '\n' in self.pending:
            line, self.pending = self.pending.split('\n', 1)
            if line.startswith('https://cloud.tencent.com/open/authorize?') and not re.search(r'[\s\x00]', line):
                self.destination.write(line + '\n')
                self.destination.flush()
        if len(self.pending) > 65536:
            self.pending = ''
        return len(value)

    def flush(self):
        self.destination.flush()


def official_session(profile, login, minimum=900):
    if importlib.metadata.version('tccli') != TCCLI_VERSION:
        fail('SESSION_TCCLI_VERSION_MISMATCH')
    import requests
    from tccli import oauth
    directory = Path.home() / '.tccli'
    directory.mkdir(mode=0o700, exist_ok=True)
    private_directory(directory)
    source = directory / (profile + '.credential')
    if source.exists() or source.is_symlink():
        private_file(source)
    mask = os.umask(0o077)
    try:
        with verified_transport(requests):
            if login:
                from tccli.plugins.auth import browser_flow, login as auth
                original_bind = browser_flow.ThreadingHTTPServer.server_bind
                original_traceback = browser_flow.traceback.format_exc

                def local_bind(server):
                    server.server_address = ('127.0.0.1', server.server_address[1])
                    return original_bind(server)

                browser_flow.ThreadingHTTPServer.server_bind = local_bind
                browser_flow.traceback.format_exc = lambda *args, **kwargs: 'SESSION_LOGIN_CALLBACK_FAILED'
                def timeout():
                    try:
                        browser_flow.HTTPHandler.result_queue.put_nowait(TimeoutError('SESSION_LOGIN_TIMEOUT'))
                    except Exception:
                        pass
                timer = threading.Timer(600, timeout)
                timer.daemon = True
                timer.start()
                sys.stdout.write('请在腾讯云官方页面完成登录授权。\n')
                sys.stdout.flush()
                try:
                    with redirect_stdout(LoginOutput(sys.stdout)), redirect_stderr(io.StringIO()):
                        auth.login_command_entrypoint({}, {'profile': profile, 'language': 'zh-CN'})
                finally:
                    timer.cancel()
                    browser_flow.ThreadingHTTPServer.server_bind = original_bind
                    browser_flow.traceback.format_exc = original_traceback
            else:
                # Upstream refresh diagnostics may contain HTTP response bodies.
                original_margin = oauth._CRED_REFRESH_SAFE_DUR
                oauth._CRED_REFRESH_SAFE_DUR = max(original_margin, minimum + 60)
                try:
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        oauth.maybe_refresh_credential(profile)
                finally:
                    oauth._CRED_REFRESH_SAFE_DUR = original_margin
    finally:
        os.umask(mask)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile')
    parser.add_argument('--credential-file', type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--login', action='store_true', help='Open the official login page; uses local browser callback')
    action.add_argument('--refresh', action='store_true', help='Let the official CLI refresh its existing OAuth session')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--min-validity-seconds', type=int, default=900)
    args = parser.parse_args()
    if bool(args.profile) == bool(args.credential_file) or not 300 <= args.min_validity_seconds <= 86400:
        fail('SESSION_ARGUMENTS_INVALID')
    if args.profile and (not re.fullmatch(r'[a-z][a-z0-9-]{2,63}', args.profile) or args.profile == 'default'):
        fail('SESSION_PROFILE_INVALID')
    if (args.login or args.refresh) and not args.profile:
        fail('SESSION_PROFILE_REQUIRED')
    if args.output:
        private_directory(args.output.parent)
        if args.output.exists() or args.output.is_symlink():
            fail('SESSION_OUTPUT_EXISTS')
    elif not args.login:
        fail('SESSION_OUTPUT_REQUIRED')
    if args.login or args.refresh:
        source = official_session(args.profile, args.login, args.min_validity_seconds)
    else:
        source = args.credential_file or Path.home() / '.tccli' / (args.profile + '.credential')
    if args.output:
        result = export_session(source, args.output, args.min_validity_seconds)
    else:
        _, expires = read_session(source, args.min_validity_seconds)
        result = {'status': 'logged_in', 'expires_at': datetime.fromtimestamp(expires, timezone.utc).isoformat()}
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        code = str(error)
        sys.stderr.write((code if re.fullmatch(r'SESSION_[A-Z_]+', code) else 'SESSION_OPERATION_FAILED') + '\n')
        sys.exit(1)
