#!/usr/bin/env python3
"""Compare CNB annotation readback with this run's verified production receipt."""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

import candidate_manifest


def verify(annotations, raw, phase, invocation_id=None, require_passed=False):
    receipt = json.loads(raw.decode('utf-8'), object_pairs_hook=candidate_manifest._unique_object,
                         parse_constant=candidate_manifest._reject_constant)
    if phase == 'readiness':
        if receipt.get('schema') != 'cnb-production-readiness/v1' or receipt.get('status') != 'ready':
            raise ValueError('successful readiness receipt required')
        if not re.fullmatch(r'inv-[A-Za-z0-9-]{8,64}', invocation_id or ''):
            raise ValueError('readiness invocation required')
        expected = {'production_readiness_b64url': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(),
                    'production_prepared_sha256': receipt['prepared_sha256'],
                    'production_readiness_invocation_id': invocation_id}
        status = 'production_readiness_status'
    else:
        if receipt.get('status') != 'passed' or receipt.get('environment') != 'production':
            raise ValueError('successful production receipt required')
        expected = {'production_receipt_sha256': hashlib.sha256(raw).hexdigest()}
        status = 'production_deploy_status'
    if not isinstance(annotations, dict) or any(annotations.get(key) != value for key, value in expected.items()):
        raise ValueError('production annotation readback differs from this run')
    if annotations.get(status) != ('passed' if require_passed else 'pending'):
        raise ValueError('production status must be published last')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=['readiness', 'apply'], required=True)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--annotations', required=True)
    parser.add_argument('--invocation-id')
    parser.add_argument('--require-passed', action='store_true')
    args = parser.parse_args()
    try:
        raw = Path(args.receipt).read_bytes()
        if not 1 <= len(raw) <= 48 * 1024:
            raise ValueError('production receipt size invalid')
        verify(candidate_manifest.load_json(args.annotations), raw, args.phase,
               args.invocation_id, args.require_passed)
        print('production_annotations=verified')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f'production annotation error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
