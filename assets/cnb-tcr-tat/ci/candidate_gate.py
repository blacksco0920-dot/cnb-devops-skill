#!/usr/bin/env python3
"""Ready-last publication gate, extracted from source-pinned candidate_gate.py.

Production inputs are checked here; signed host authorization is a separate gate.
"""
import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import candidate_manifest


class CandidateGateError(ValueError):
    pass


def candidate_annotation_values(candidate):
    return {
        "candidate_format":candidate["schema"],
        "candidate_manifest_sha256":candidate["manifest_sha256"],
        "candidate_commit":candidate["application_commit"],
        "test_build_status":candidate["evidence"]["build"]["status"],
        "test_runtime_status":candidate["evidence"]["runtime"]["status"],
        "test_public_status":candidate["evidence"]["public"]["status"],
        "candidate_status":"ready",
    }


def validate_publication_annotations(annotations, candidate, *, require_non_ready_complete=False, require_ready_complete=False):
    if type(annotations) is not dict:
        raise CandidateGateError("candidate annotations must be a map")
    expected=candidate_annotation_values(candidate)
    actual_keys=set(annotations)
    if actual_keys-set(expected):
        raise CandidateGateError("unknown publication annotation keys")
    for key,value in annotations.items():
        if type(value) is not str or value!=expected[key]:
            raise CandidateGateError(f"publication annotation {key} does not match candidate")
    # Only prefixes of the deterministic non-ready sequence may resume.
    ordered=list(expected)
    allowed=[set(ordered[:count]) for count in range(len(ordered)+1)]
    if actual_keys not in allowed:
        raise CandidateGateError("publication annotations are incomplete or out of order")
    if require_non_ready_complete and actual_keys not in (set(ordered[:-1]),set(ordered)):
        raise CandidateGateError("non-ready publication annotations are not complete and exact")
    if require_ready_complete and actual_keys!=set(ordered):
        raise CandidateGateError("ready publication annotations are not complete and exact")
    return "ready" if actual_keys==set(ordered) else "pending"


def verify_production_candidate(config, tag, commit, branch, annotations, root, *, fetch=True):
    candidate_manifest.validate_config(config)
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_/-]*', branch)
            or not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(re.escape(config['candidate_prefix']) + r'cnb-[a-z0-9][a-z0-9-]{2,127}', tag)):
        raise CandidateGateError('invalid production reference')

    def git(*args, env=None):
        result = subprocess.run(['git', '-c', 'credential.helper=', *args], cwd=root, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if result.returncode:
            raise CandidateGateError('candidate or governed branch Git verification failed')
        return result.stdout

    git('check-ref-format', 'refs/heads/' + branch)
    tag_ref = 'refs/tags/' + tag
    branch_ref = 'refs/cnb-devops/production-branch' if fetch else 'refs/heads/' + branch
    if fetch:
        if not os.environ.get('CNB_TOKEN'):
            raise CandidateGateError('CNB_TOKEN is required for production reference verification')
        with tempfile.TemporaryDirectory(prefix='cnb-production-git-') as directory:
            askpass = Path(directory) / 'askpass.py'
            askpass.write_text('#!/usr/bin/env python3\nimport os,sys\nprint(os.environ.get("CNB_TOKEN_USER_NAME","cnb") if "Username" in sys.argv[1] else os.environ["CNB_TOKEN"])\n')
            askpass.chmod(0o700)
            env = {**os.environ, 'GIT_ASKPASS': str(askpass), 'GIT_TERMINAL_PROMPT': '0'}
            options = ['--no-tags']
            if git('rev-parse', '--is-shallow-repository').strip() == b'true':
                options.append('--unshallow')
            git('fetch', *options, 'https://cnb.cool/' + config['cnb_repository'] + '.git',
                '+refs/heads/' + branch + ':' + branch_ref, tag_ref + ':' + tag_ref, env=env)
    if git('cat-file', '-t', tag_ref).strip() != b'tag':
        raise CandidateGateError('production candidate must be an annotated Tag')
    if not 1 <= int(git('cat-file', '-s', tag_ref)) <= 64 * 1024:
        raise CandidateGateError('production candidate Tag exceeds the size limit')
    if git('rev-parse', tag_ref + '^{}').decode().strip() != commit:
        raise CandidateGateError('candidate peeled commit does not match the requested release')
    git('merge-base', '--is-ancestor', commit, branch_ref)
    _, separator, raw = git('cat-file', 'tag', tag_ref).partition(b'\n\n')
    if not separator:
        raise CandidateGateError('candidate Tag is malformed')
    candidate = candidate_manifest.parse_manifest(raw, config, tag, commit)
    expected = candidate_annotation_values(candidate)
    if not isinstance(annotations, dict) or any(annotations.get(key) != value for key, value in expected.items()):
        raise CandidateGateError('candidate ready annotations do not match the immutable Tag')
    return raw


def write_transport(directory, name, raw):
    descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)


def decode_transport(value):
    if not isinstance(value, str) or len(value) > 64 * 1024 or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise CandidateGateError('production annotation transport is invalid')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != value:
        raise CandidateGateError('production annotation transport is noncanonical')
    return raw


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    subs=parser.add_subparsers(dest="command",required=True)
    publication=subs.add_parser("publication")
    for name in ("config","manifest","expected-tag","expected-commit","annotations"):
        publication.add_argument("--"+name,required=True)
    publication.add_argument("--require-non-ready-complete",action="store_true")
    publication.add_argument("--require-ready-complete",action="store_true")
    production=subs.add_parser("production")
    for name in ('config', 'tag', 'commit', 'branch', 'annotations', 'output-dir'):
        production.add_argument('--'+name, required=True)
    production.add_argument('--phase', choices=['readiness', 'apply'], required=True)
    args=parser.parse_args(argv)
    try:
        config=candidate_manifest.validate_config(candidate_manifest.load_json(args.config))
        if args.command == 'production':
            annotations = candidate_manifest.load_json(args.annotations)
            raw = verify_production_candidate(config, args.tag, args.commit, args.branch, annotations, Path.cwd())
            directory = Path(args.output_dir)
            if not directory.is_dir() or directory.is_symlink():
                raise CandidateGateError('production output directory is invalid')
            write_transport(directory, 'candidate.json', raw)
            if args.phase == 'apply':
                if annotations.get('production_readiness_status') != 'passed':
                    raise CandidateGateError('production readiness has not passed')
                # These files remain untrusted input until the production runner and host validate them.
                for key, name in [('production_readiness_b64url', 'readiness.json'),
                                  ('production_approval_b64url', 'approval.json')]:
                    write_transport(directory, name, decode_transport(annotations.get(key)))
            print('production_candidate_status=verified')
            return 0
        candidate=candidate_manifest.parse_manifest(Path(args.manifest).read_bytes(),config,args.expected_tag,args.expected_commit)
        state=validate_publication_annotations(candidate_manifest.load_json(args.annotations),candidate,require_non_ready_complete=args.require_non_ready_complete,require_ready_complete=args.require_ready_complete)
        print("candidate_publication_status="+state)
    except (OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired) as exc:
        print(f"candidate gate error: {exc}",file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
