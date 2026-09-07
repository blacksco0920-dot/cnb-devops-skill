"""Offline integration with the pinned upstream auth implementation.

Run with a Python environment containing tccli==3.1.162.1 and requests.
Only the actual loopback callback socket is opened. HTTPS is intercepted at
requests' adapter boundary, retaining Session redirects and transport options.
"""
import contextlib
import http.client
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
from queue import Queue
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

try:
    PINNED = importlib.metadata.version('tccli') == '3.1.162.1'
except importlib.metadata.PackageNotFoundError:
    PINNED = False
if PINNED:
    import requests
    from tccli import oauth
    from tccli.plugins.auth import browser_flow, login

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/tencent-session.py'
spec = importlib.util.spec_from_file_location('tencent_session_integration_subject', SCRIPT)
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


@unittest.skipUnless(PINNED, 'requires official tccli==3.1.162.1; no credentials or cloud access needed')
class TencentSessionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.home.chmod(0o700)
        self.environment = patch.dict(os.environ, {'HOME': str(self.home)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.calls = []
        self.servers = []
        self.callback_bodies = []
        self.callback_status = 307
        self.expiry = int(time.time()) + 3600
        self.old_queue = browser_flow.HTTPHandler.result_queue
        browser_flow.HTTPHandler.result_queue = Queue(1)
        self.addCleanup(setattr, browser_flow.HTTPHandler, 'result_queue', self.old_queue)
        self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def response(self, request, payload, status=200, headers=None):
        result = requests.Response()
        result.status_code = status
        result.url = request.url
        result.request = request
        result.headers.update({'Content-Type': 'application/json', **(headers or {})})
        result._content = json.dumps(payload).encode()
        return result

    def transport(self, adapter, request, **kwargs):
        self.calls.append((request, kwargs))
        self.assertEqual(urlsplit(request.url).netloc, 'cli.cloud.tencent.com')
        body = json.loads(request.body)
        self.assertEqual(body['Site'], 'cn')
        if request.url.endswith('/refresh_user_token'):
            self.assertEqual(body['RefreshToken'], 'synthetic-refresh-token')
            return self.response(request, {'AccessToken': 'synthetic-access-new', 'ExpiresAt': self.expiry})
        self.assertTrue(request.url.endswith('/get_temp_cred'))
        self.assertIn(body['AccessToken'], ['synthetic-access-token', 'synthetic-access-new'])
        return self.response(request, {'SecretId': 'synthetic-id', 'SecretKey': 'synthetic-key', 'Token': 'synthetic-token', 'ExpiresAt': self.expiry})

    @contextlib.contextmanager
    def capture_binding(self):
        original = browser_flow.ThreadingHTTPServer.server_bind
        def record(server):
            self.assertEqual(server.server_address[0], '127.0.0.1')
            self.servers.append(server)
            return original(server)
        with patch.object(browser_flow.ThreadingHTTPServer, 'server_bind', record):
            yield

    def browser(self, auth_url):
        parsed = urlsplit(auth_url)
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ('https', 'cloud.tencent.com', '/open/authorize'))
        query = parse_qs(parsed.query)
        self.assertEqual(query['scope'], ['login'])
        redirect = parse_qs(urlsplit(query['redirect_url'][0]).query)['redirect_url'][0]
        callback = urlsplit(redirect)
        self.assertEqual(callback.hostname, 'localhost')
        params = dict(open_id='synthetic-open-id', access_token='synthetic-access-token', refresh_token='synthetic-refresh-token', expires_at=self.expiry,
                      state=query['state'][0], redirect_url='https://cloud.tencent.com/', site='cn')
        connection = http.client.HTTPConnection('127.0.0.1', callback.port, timeout=3)
        try:
            connection.request('GET', '/?' + urlencode(params))
            result = connection.getresponse()
            self.callback_bodies.append(result.read().decode())
            self.assertEqual(result.status, self.callback_status)
        finally:
            connection.close()
        return True

    def seed(self, credential_remaining=600, access_remaining=30):
        directory = self.home / '.tccli'
        directory.mkdir(mode=0o700)
        path = directory / 'review-test.credential'
        path.write_text(json.dumps(dict(type='oauth', secretId='old-id', secretKey='old-key', token='old-token', expiresAt=int(time.time()) + credential_remaining,
            oauth=dict(openId='synthetic-open-id', accessToken='synthetic-access-token', refreshToken='synthetic-refresh-token', expiresAt=int(time.time()) + access_remaining, site='cn'))))
        path.chmod(0o600)
        return path

    def test_actual_login_callback_saves_private_oauth_and_export_omits_refresh_material(self):
        output = io.StringIO()
        with patch.object(requests.adapters.HTTPAdapter, 'send', autospec=True, side_effect=self.transport), \
                patch.object(login.webbrowser, 'open', side_effect=self.browser), self.capture_binding(), contextlib.redirect_stdout(output):
            source = subject.official_session('review-test', True)
        triple, _ = subject.read_session(source, 900)
        self.assertEqual(triple, dict(secretId='synthetic-id', secretKey='synthetic-key', token='synthetic-token'))
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.servers)
        self.assertEqual(self.servers[0].socket.getsockname()[0], '127.0.0.1')
        self.assertIn('https://cloud.tencent.com/open/authorize?', output.getvalue())
        for secret in ('synthetic-key', 'synthetic-access-token', 'synthetic-refresh-token'):
            self.assertNotIn(secret, output.getvalue() + ''.join(self.callback_bodies))
        self.assertTrue(all(kwargs['verify'] is True and kwargs['timeout'] == 30 for _, kwargs in self.calls))
        exported = self.home / 'export.json'
        subject.export_session(source, exported, 900)
        self.assertEqual(json.loads(exported.read_text()), triple)

    def test_refresh_handles_credential_between_upstream_300s_and_required_900s(self):
        path = self.seed()
        original_threshold = oauth._CRED_REFRESH_SAFE_DUR
        with patch.object(requests.adapters.HTTPAdapter, 'send', autospec=True, side_effect=self.transport):
            subject.official_session('review-test', False)
        triple, _ = subject.read_session(path, 900)
        self.assertEqual(triple['secretKey'], 'synthetic-key')
        self.assertEqual([urlsplit(req.url).path for req, _ in self.calls], ['/refresh_user_token', '/get_temp_cred'])
        self.assertEqual(oauth._CRED_REFRESH_SAFE_DUR, original_threshold)
        self.assertTrue(all(kwargs['verify'] is True for _, kwargs in self.calls))

    def test_reentry_reuses_valid_session_without_fetching_or_exposing_oauth_material(self):
        source = self.seed(credential_remaining=3600, access_remaining=3600)
        output = io.StringIO()
        with patch.object(requests.adapters.HTTPAdapter, 'send', side_effect=AssertionError('unexpected HTTP')), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(subject.official_session('review-test', False), source)
        self.assertEqual(output.getvalue(), '')

    def test_https_307_does_not_forward_oauth_secret_to_http(self):
        def redirect(adapter, request, **kwargs):
            self.calls.append((request, kwargs))
            if len(self.calls) == 1:
                return self.response(request, {}, 307, {'Location': 'http://untrusted.example/collect'})
            return self.response(request, {})
        with patch.object(requests.adapters.HTTPAdapter, 'send', autospec=True, side_effect=redirect), subject.verified_transport(requests):
            requests.post('https://cli.cloud.tencent.com/get_temp_cred', json={'AccessToken': 'synthetic-access-token'}, verify=False)
        self.assertEqual(len(self.calls), 1, 'HTTPS redirects must not forward a credential POST')
        self.assertTrue(self.calls[0][1]['verify'])

    def test_upstream_http_errors_do_not_escape_refresh_and_expired_session_stays_unexportable(self):
        source = self.seed(credential_remaining=-1)
        def error(adapter, request, **kwargs):
            return self.response(request, {'Error': {'Message': 'synthetic-refresh-token'}}, 403)
        output = io.StringIO()
        with patch.object(requests.adapters.HTTPAdapter, 'send', autospec=True, side_effect=error), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            subject.official_session('review-test', False)
        self.assertEqual(output.getvalue(), '')
        with self.assertRaisesRegex(ValueError, 'SESSION_EXPIRED_OR_TOO_SHORT'):
            subject.export_session(source, self.home / 'no-export.json', 900)
        self.assertFalse((self.home / 'no-export.json').exists())

    def test_actual_callback_error_redacts_browser_body_and_wait_is_bounded(self):
        self.callback_status = 400
        def error(adapter, request, **kwargs):
            return self.response(request, {'Error': {'Message': 'synthetic-refresh-token'}}, 403)
        output = io.StringIO()
        real_timer = subject.threading.Timer
        original_bind = browser_flow.ThreadingHTTPServer.server_bind
        original_traceback = browser_flow.traceback.format_exc
        with patch.object(requests.adapters.HTTPAdapter, 'send', autospec=True, side_effect=error), \
                patch.object(login.webbrowser, 'open', side_effect=self.browser), self.capture_binding(), \
                patch.object(subject.threading, 'Timer', side_effect=lambda delay, callback: real_timer(0.05, callback)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaisesRegex(TimeoutError, 'SESSION_LOGIN_TIMEOUT'):
                subject.official_session('review-test', True)
        self.assertIn('SESSION_LOGIN_CALLBACK_FAILED', self.callback_bodies[0])
        self.assertNotIn('synthetic-refresh-token', output.getvalue() + ''.join(self.callback_bodies))
        self.assertIs(browser_flow.ThreadingHTTPServer.server_bind, original_bind)
        self.assertIs(browser_flow.traceback.format_exc, original_traceback)
        self.assertFalse((self.home / '.tccli' / 'review-test.credential').exists())


if __name__ == '__main__':
    unittest.main()
