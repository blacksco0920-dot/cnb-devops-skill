import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/tencent-session.py'


class TencentSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'session.credential'
        self.output = self.root / 'credentials.json'
        self.profile = dict(type='oauth', secretId='example-id', secretKey='example-key', token='example-token',
                            expiresAt=int(time.time()) + 3600, oauth={'refreshToken': 'must-stay-local'})
        self.save()

    def save(self):
        self.source.write_text(json.dumps(self.profile))
        self.source.chmod(0o600)

    def run_script(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), '--credential-file', str(self.source),
                               '--output', str(self.output), *extra], capture_output=True, text=True)

    def test_export_projects_only_temporary_triple_to_private_file(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text()), dict(secretId='example-id', secretKey='example-key', token='example-token'))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('example-key', result.stdout + result.stderr)
        self.assertNotIn('must-stay-local', result.stdout + result.stderr + self.output.read_text())
        self.assertEqual(json.loads(result.stdout)['status'], 'exported')

    def test_expiry_is_checked_before_output(self):
        self.profile['expiresAt'] = int(time.time()) + 30
        self.save()
        result = self.run_script('--min-validity-seconds', '900')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SESSION_EXPIRED_OR_TOO_SHORT', result.stderr)
        self.assertFalse(self.output.exists())

    def test_rejects_incomplete_or_non_oauth_credentials_without_output(self):
        for change in [{'token': ''}, {'type': 'static'}, {'expiresAt': True}]:
            with self.subTest(change=change):
                original = self.profile.copy()
                self.profile.update(change)
                self.save()
                self.assertNotEqual(self.run_script().returncode, 0)
                self.assertFalse(self.output.exists())
                self.profile = original

    def test_private_source_and_exclusive_destination(self):
        self.source.chmod(0o644)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.source.chmod(0o600)
        self.output.write_text('keep')
        self.output.chmod(0o600)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.output.read_text(), 'keep')

    def test_source_symlink_and_duplicate_json_keys_rejected(self):
        other = self.root / 'other'
        self.source.rename(other)
        self.source.symlink_to(other)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.source.unlink()
        self.source.write_text('{"type":"oauth","type":"oauth"}')
        self.source.chmod(0o600)
        self.assertNotEqual(self.run_script().returncode, 0)

    def test_login_transport_cannot_disable_certificate_verification(self):
        spec = importlib.util.spec_from_file_location('tencent_session', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        captured = {}
        def transport(*args, **kwargs):
            captured.update(kwargs)
            return 'response'
        self.assertEqual(module.verified_request(transport, None, 'POST', 'https://cli.cloud.tencent.com/example', verify=False), 'response')
        self.assertIs(captured['verify'], True)
        self.assertEqual(captured['timeout'], 30)
        self.assertIs(captured['allow_redirects'], False)
        with self.assertRaises(ValueError):
            module.verified_request(transport, None, 'POST', 'http://cli.cloud.tencent.com/example')


if __name__ == '__main__':
    unittest.main()
