#!/usr/bin/env python3
"""Maintainer integrity check; --refresh records reviewed bundle file changes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

BUNDLE = Path(__file__).resolve().parents[1] / 'assets/cnb-tcr-tat'


def inventory():
    result = {}
    for file in sorted(BUNDLE.rglob('*')):
        relative = file.relative_to(BUNDLE)
        if any(part in {'node_modules', '__pycache__'} for part in relative.parts):
            continue
        if file.is_symlink():
            raise ValueError('bundle must not contain symbolic links')
        if not file.is_file() or any(part in {'node_modules', '__pycache__'} for part in relative.parts):
            continue
        if relative.as_posix() == 'bundle.json' or file.suffix == '.pyc':
            continue
        result[relative.as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    path = BUNDLE / 'bundle.json'
    bundle = json.loads(path.read_text())
    files = inventory()
    if args.refresh:
        bundle['files'] = files
        path.write_text(json.dumps(bundle, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
        print('recorded reviewed bundle hashes')
    elif files != bundle['files']:
        sys.exit('bundle content differs from its manifest; inspect changes before --refresh')
    else:
        print('bundle hashes verified')


if __name__ == '__main__':
    main()
