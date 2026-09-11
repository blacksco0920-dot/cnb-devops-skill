#!/usr/bin/env python3
"""Verify an installed Skill snapshot without Git or the private development repo.

Checksums detect accidental changes; they are not a publisher signature. Obtain
the release from the documented repository and pin its tag. --smoke additionally
requires the documented generator dependencies and performs no cloud operations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

IGNORED = {'.git', 'node_modules', '__pycache__', '.DS_Store'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inside(root, name):
    path = Path(name)
    if not name or path.is_absolute() or '..' in path.parts or path.as_posix() != name:
        raise ValueError('invalid package path')
    result = root / path
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError('symlink in package: ' + name)
    return result


def prose(text):
    lines, fence = [], None
    for line in text.splitlines():
        marker = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return '\n'.join(lines)


def anchors(text):
    body, found = prose(text), set()
    for heading in re.findall(r'(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$', body):
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        value, suffix = slug, 0
        while value in found:
            suffix += 1
            value = f'{slug}-{suffix}'
        found.add(value)
    for _, value in re.findall(r'<a\b[^>]*\b(?:id|name)\s*=\s*([\'\"])(.*?)\1', body, re.I):
        found.add(value)
    return found


def verify(root):
    manifest = json.loads((root / 'skill-release.json').read_text())
    if manifest.get('schema') != 'cnb-devops-skill-release/v1' or not re.fullmatch(
            r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', manifest.get('version', '')):
        raise ValueError('invalid release manifest')
    files = manifest['files']
    required = {'SKILL.md', 'README.md', 'README.en.md', 'LICENSE',
                'assets/cnb-tcr-tat/bundle.json',
                'assets/cnb-tcr-tat/dependencies/SOURCES.md',
                'assets/cnb-tcr-tat/dependencies/THIRD_PARTY.md',
                'assets/cnb-tcr-tat/dependencies/package-lock.json'}
    if not isinstance(files, dict) or not required <= files.keys():
        raise ValueError('incomplete release manifest')
    actual = set()
    for parent, directories, names in os.walk(root, followlinks=False):
        directories[:] = [d for d in directories if d not in IGNORED]
        for name in directories + names:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError('symlink in package')
        actual.update((Path(parent) / n).relative_to(root).as_posix()
                      for n in names if n not in IGNORED and not n.endswith('.pyc'))
    if actual != set(files) | {'skill-release.json'}:
        raise ValueError('package file inventory differs from release manifest')
    for name, expected in files.items():
        path = inside(root, name)
        if sha(path.read_bytes()) != expected['sha256']:
            raise ValueError('package hash mismatch: ' + name)
        mode = '100755' if path.stat().st_mode & 0o111 else '100644'
        if mode != expected['mode']:
            raise ValueError('package mode mismatch: ' + name)
        if path.suffix == '.md':
            for target in re.findall(r'\[[^]]+\]\(([^)]+)\)', prose(path.read_text())):
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc:
                    continue
                resolved = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
                if not resolved.is_relative_to(root) or not resolved.exists():
                    raise ValueError(f'broken local link in {name}: {target}')
                if parsed.fragment and (not resolved.is_file() or unquote(parsed.fragment)
                                        not in anchors(resolved.read_text())):
                    raise ValueError(f'missing anchor in {name}: {target}')
    bundle_root = root / 'assets/cnb-tcr-tat'
    bundle = json.loads((bundle_root / 'bundle.json').read_text())
    if bundle['version'] != manifest['bundle_version']:
        raise ValueError('bundle version differs from release manifest')
    bundle_members = {'assets/cnb-tcr-tat/' + name for name in bundle['files']}
    if bundle_members != {n for n in files if n.startswith('assets/cnb-tcr-tat/')
                          and n != 'assets/cnb-tcr-tat/bundle.json'}:
        raise ValueError('bundle file inventory differs from bundle manifest')
    for name, expected in bundle['files'].items():
        if sha(inside(bundle_root, name).read_bytes()) != expected:
            raise ValueError('bundle hash mismatch: ' + name)
    return manifest


def smoke(root):
    try:
        import yaml
    except ImportError as error:
        raise ValueError('--smoke requires PyYAML==6.0.2 and jsonschema==4.25.1') from error
    with tempfile.TemporaryDirectory(prefix='skill-install-check-') as temporary:
        for example in ('project.example.yml', 'project.full.example.yml'):
            project = Path(temporary) / example.removesuffix('.yml')
            project.mkdir()
            values = yaml.safe_load((root / 'assets/cnb-tcr-tat' / example).read_text())
            if values.get('production'):
                # Full examples intentionally contain no reusable signing key.
                # Generate a temporary pair and retain only its public half.
                key = subprocess.run([
                    'node', '-e', "const {publicKey}=require('node:crypto').generateKeyPairSync('ed25519');"
                    "process.stdout.write(publicKey.export({type:'spki',format:'pem'}));"],
                    capture_output=True, text=True)
                if key.returncode:
                    raise ValueError('--smoke requires Node.js 22 for a temporary example public key')
                values['production']['approval_public_key'] = key.stdout
            config = project / 'project.yml'
            config.write_text(yaml.safe_dump(values))
            for service in values['services'].values():
                (project / service['context']).mkdir(parents=True, exist_ok=True)
                dockerfile = project / service['dockerfile']
                dockerfile.parent.mkdir(parents=True, exist_ok=True)
                dockerfile.write_text('FROM scratch\n')
            command = [sys.executable, str(root / 'scripts/prepare-project.py'),
                       '--project-root', str(project), '--config', str(config), '--apply']
            def generate():
                result = subprocess.run(command, cwd=project, capture_output=True, text=True)
                if result.returncode:
                    raise ValueError('example generation failed: ' + example + '\n' + result.stderr)
                return {p.relative_to(project).as_posix(): sha(p.read_bytes())
                        for p in project.rglob('*') if p.is_file()}
            first = generate()
            if 'deploy/vendor/cnb-devops/generation-lock.json' not in first or first != generate():
                raise ValueError('example generation is incomplete or not repeatable: ' + example)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        manifest = verify(root)
        if args.smoke:
            smoke(root)
        print(json.dumps({'version': manifest['version'], 'files': len(manifest['files']),
                          'integrity': 'passed', 'example_generation': 'passed' if args.smoke else 'not-run'}))
    except (ValueError, OSError, KeyError, TypeError) as error:
        sys.exit(str(error))


if __name__ == '__main__':
    main()
