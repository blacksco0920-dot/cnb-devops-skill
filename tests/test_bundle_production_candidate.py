import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_bundle_ci_candidate import CI, fixture, load


class ProductionCandidateTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(CI))
        self.addCleanup(sys.path.pop, 0)
        self.gate = load('candidate_gate')
        self.manifest = load('candidate_manifest')

    def test_real_git_ancestry_and_exact_ready_candidate_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()

            git('init', '-q', '-b', 'main')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'base')
            initial = git('rev-parse', 'HEAD')
            git('checkout', '-q', '-b', 'test')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'candidate')
            commit = git('rev-parse', 'HEAD')
            config, receipt = fixture(('web',))
            receipt.update(git_sha=commit, controller_commit=commit)
            receipt_raw = json.dumps(receipt).encode()
            raw = self.manifest.assemble_candidate(receipt_raw, config,
                receipt_sha256=hashlib.sha256(receipt_raw).hexdigest(), invocation_id='inv-example123',
                completed_at='2026-09-07T00:00:00Z', build_id='cnb-build-123', commit=commit)
            candidate = self.manifest.parse_manifest(raw, config)
            tag = candidate['candidate_tag']
            (root / 'manifest.json').write_bytes(raw)
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'tag', '-a', tag,
                '-F', str(root / 'manifest.json'), '--cleanup=verbatim')
            annotations = self.gate.candidate_annotation_values(candidate)
            with self.assertRaisesRegex(ValueError, 'governed branch'):
                self.gate.verify_production_candidate(config, tag, commit, 'main', annotations, root, fetch=False)
            git('update-ref', 'refs/heads/main', commit, initial)
            # Provider annotations are transport metadata, not a second source of candidate identity.
            metadata = {**annotations, 'cnb-deploy-approve-1-1': '1', 'production_readiness_status': 'passed'}
            result = self.gate.verify_production_candidate(config, tag, commit, 'main', metadata, root, fetch=False)
            self.assertEqual(result, raw)
            for changes in [{'candidate_status': 'pending'}, {'candidate_commit': initial}]:
                with self.assertRaises(ValueError):
                    self.gate.verify_production_candidate(config, tag, commit, 'main', {**metadata, **changes}, root, fetch=False)


if __name__ == '__main__':
    unittest.main()
