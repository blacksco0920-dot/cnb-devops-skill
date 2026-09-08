#!/usr/bin/env python3
"""Import one PAT through a non-echoing local TTY; never authenticate to CNB."""
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import warnings


TOKEN = re.compile(r'[A-Za-z0-9._~+/-]+=*', re.ASCII)


class TokenInputError(Exception):
    pass


def fail(code):
    raise TokenInputError(code)


def check_directory(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail('CNB_TOKEN_DIRECTORY_NOT_PRIVATE')


def open_directory(directory):
    descriptor = None
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        check_directory(descriptor)
        return descriptor
    except (OSError, TokenInputError):
        if descriptor is not None:
            os.close(descriptor)
        fail('CNB_TOKEN_DIRECTORY_NOT_PRIVATE')


def ensure_absent(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    fail('CNB_TOKEN_OUTPUT_EXISTS')


def publish_token(directory, name, token):
    check_directory(directory)
    temporary = '.cnb-token-' + secrets.token_hex(16) + '.tmp'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write((token + '\n').encode('ascii'))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # A hard-link publish is atomic and cannot replace any existing entry.
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except FileExistsError:
            fail('CNB_TOKEN_OUTPUT_EXISTS')
    finally:
        os.unlink(temporary, dir_fd=directory)
    os.fsync(directory)


def main(argv=None, *, read_token=getpass.getpass):
    directory = None
    try:
        arguments = sys.argv[1:] if argv is None else argv
        if len(arguments) != 2 or arguments[0] != '--output':
            fail('CNB_TOKEN_ARGUMENTS_INVALID')
        output = Path(arguments[1])
        if not output.is_absolute() or '..' in output.parts or '\0' in str(output):
            fail('CNB_TOKEN_ARGUMENTS_INVALID')
        directory = open_directory(output.parent)
        ensure_absent(directory, output.name)
        if not sys.stdin.isatty():
            fail('CNB_TOKEN_TTY_REQUIRED')
        # getpass must stop before its fallback reads echoed input.
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            token = read_token('Token: ')
        if not isinstance(token, str) or not 1 <= len(token) <= 8192 or TOKEN.fullmatch(token) is None:
            fail('CNB_TOKEN_FORMAT_INVALID')
        publish_token(directory, output.name, token)
        print(json.dumps({'status': 'saved', 'scope': 'local_bootstrap', 'configuration_only': True}))
        return 0
    except getpass.GetPassWarning:
        code = 'CNB_TOKEN_NOECHO_REQUIRED'
    except (EOFError, KeyboardInterrupt):
        code = 'CNB_TOKEN_INPUT_CANCELLED'
    except TokenInputError as error:
        code = str(error)
    except Exception:
        code = 'CNB_TOKEN_SAVE_FAILED'
    finally:
        if directory is not None:
            os.close(directory)
    print(json.dumps({'status': 'failed', 'code': code}), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
