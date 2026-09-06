#!/usr/bin/env python3
"""Ready-last publication gate, extracted from source-pinned candidate_gate.py.

Production execution is deliberately unavailable in this bundle version.
"""
import argparse
import sys
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


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    subs=parser.add_subparsers(dest="command",required=True)
    publication=subs.add_parser("publication")
    for name in ("config","manifest","expected-tag","expected-commit","annotations"):
        publication.add_argument("--"+name,required=True)
    publication.add_argument("--require-non-ready-complete",action="store_true")
    publication.add_argument("--require-ready-complete",action="store_true")
    subs.add_parser("production")
    args=parser.parse_args(argv)
    if args.command=="production":
        print("production blocked: this bundle has no accepted production execution adapter",file=sys.stderr)
        return 1
    try:
        config=candidate_manifest.validate_config(candidate_manifest.load_json(args.config))
        candidate=candidate_manifest.parse_manifest(Path(args.manifest).read_bytes(),config,args.expected_tag,args.expected_commit)
        state=validate_publication_annotations(candidate_manifest.load_json(args.annotations),candidate,require_non_ready_complete=args.require_non_ready_complete,require_ready_complete=args.require_ready_complete)
        print("candidate_publication_status="+state)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(f"candidate gate error: {exc}",file=sys.stderr)
        return 1
    return 0


if __name__=="__main__":
    raise SystemExit(main())
