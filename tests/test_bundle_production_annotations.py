import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

CI = Path(__file__).parents[1] / 'assets/cnb-tcr-tat/ci'
sys.path.insert(0, str(CI))
spec = importlib.util.spec_from_file_location('production_annotations', CI / 'production_annotations.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.pop(0)


class ProductionAnnotationTests(unittest.TestCase):
    def test_readiness_requires_exact_receipt_and_status_last(self):
        raw = b'{"prepared_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"cnb-production-readiness/v1","status":"ready"}\n'
        annotations = {'production_readiness_b64url': base64.urlsafe_b64encode(raw).rstrip(b'=').decode(),
                       'production_prepared_sha256': 'a' * 64,
                       'production_readiness_invocation_id': 'inv-example123',
                       'production_readiness_status': 'pending', 'candidate_status': 'ready'}
        module.verify(annotations, raw, 'readiness', 'inv-example123')
        with self.assertRaises(ValueError):
            module.verify(annotations, raw, 'readiness', 'inv-example123', True)
        annotations['production_readiness_status'] = 'passed'
        module.verify(annotations, raw, 'readiness', 'inv-example123', True)
        for key in ('production_readiness_b64url', 'production_prepared_sha256', 'production_readiness_invocation_id'):
            with self.assertRaises(ValueError):
                module.verify({**annotations, key: 'other'}, raw, 'readiness', 'inv-example123', True)

    def test_apply_readback_rejects_other_run_and_duplicate_json(self):
        raw = b'{"environment":"production","status":"passed"}\n'
        annotations = {'production_receipt_sha256': hashlib.sha256(raw).hexdigest(), 'production_deploy_status': 'pending'}
        module.verify(annotations, raw, 'apply')
        with self.assertRaises(ValueError):
            module.verify(annotations, raw.replace(b'passed', b'failed'), 'apply')
        with self.assertRaises(ValueError):
            module.verify(annotations, b'{"status":"failed","status":"passed","environment":"production"}', 'apply')


if __name__ == '__main__':
    unittest.main()
