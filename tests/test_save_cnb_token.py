import contextlib
import errno
import getpass
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import warnings


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/save-cnb-token.py'
TOKEN = 'synthetic.PAT_~+/only-test-123=='


class SaveCnbTokenTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'save-cnb-token.py must implement the private TTY importer')
        spec = importlib.util.spec_from_file_location('save_cnb_token', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.output = self.root / 'bootstrap.token'

    def invoke(self, reader=lambda _: TOKEN, output=None, tty=True, args=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys.stdin, 'isatty', return_value=tty), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = self.module.main(args if args is not None else ['--output', str(output or self.output)], read_token=reader)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_private_failure(self, result, code, secret=TOKEN):
        status, stdout, stderr = result
        self.assertNotEqual(status, 0)
        self.assertEqual(stdout, '')
        self.assertEqual(json.loads(stderr), {'status': 'failed', 'code': code})
        self.assertNotIn(secret, stdout + stderr)
        self.assertNotIn('Traceback', stdout + stderr)

    def test_atomic_private_save_contains_only_raw_token_and_lf(self):
        original_link = os.link
        def publish(source, destination, **kwargs):
            self.assertFalse(self.output.exists())
            temporary = self.root / source
            self.assertEqual(temporary.read_bytes(), (TOKEN + '\n').encode('ascii'))
            self.assertEqual(temporary.stat().st_mode & 0o777, 0o600)
            return original_link(source, destination, **kwargs)
        with mock.patch.object(self.module.os, 'link', side_effect=publish):
            status, stdout, stderr = self.invoke()
        self.assertEqual(status, 0, stderr)
        self.assertEqual(json.loads(stdout), {'status': 'saved', 'scope': 'local_bootstrap', 'configuration_only': True})
        self.assertEqual(stderr, '')
        self.assertEqual(self.output.read_bytes(), (TOKEN + '\n').encode('ascii'))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_nlink, 1)
        self.assertEqual(list(self.root.iterdir()), [self.output])
        self.assertNotIn(TOKEN, stdout)

    def test_non_tty_never_uses_stdin_or_environment_token(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--output', str(self.output)],
                                input=TOKEN + '\n', capture_output=True, text=True,
                                env={**os.environ, 'CNB_TOKEN': TOKEN})
        self.assert_private_failure((result.returncode, result.stdout, result.stderr), 'CNB_TOKEN_TTY_REQUIRED')
        self.assertFalse(self.output.exists())

    def test_existing_file_symlink_or_hardlink_is_never_read_or_replaced(self):
        keeper = self.root / 'keep'
        keeper.write_text('preserve-existing')
        for kind in ['file', 'symlink', 'hardlink']:
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.output.write_text('preserve-existing')
                elif kind == 'symlink':
                    self.output.symlink_to(keeper)
                else:
                    os.link(keeper, self.output)
                reader = mock.Mock(side_effect=AssertionError('must reject before prompting'))
                self.assert_private_failure(self.invoke(reader), 'CNB_TOKEN_OUTPUT_EXISTS')
                self.assertEqual(self.output.read_text(), 'preserve-existing')
                reader.assert_not_called()
                self.output.unlink()

    def test_nonprivate_missing_or_symlink_parent_is_rejected_before_prompt(self):
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        public.chmod(0o755)  # Other in-process CLI tests may set a private umask.
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for parent in [public, alias, self.root / 'missing']:
            reader = mock.Mock(side_effect=AssertionError('must reject before prompting'))
            self.assert_private_failure(self.invoke(reader, parent / 'token'), 'CNB_TOKEN_DIRECTORY_NOT_PRIVATE')
            reader.assert_not_called()

    def test_bad_token_and_noninteractive_arguments_never_escape(self):
        for token in ['', 'has space', 'line\nbreak', 'line\rbreak', '{"token":"secret"}', '非ASCII', '=', 'abc=def', 'x' * 8193]:
            with self.subTest(kind=repr(token[:12])):
                self.assert_private_failure(self.invoke(lambda _, token=token: token), 'CNB_TOKEN_FORMAT_INVALID', token or 'empty-token')
                self.assertFalse(self.output.exists())
        for args in [['--output', str(self.output), '--token', TOKEN], ['--output', 'relative.token']]:
            self.assert_private_failure(self.invoke(args=args), 'CNB_TOKEN_ARGUMENTS_INVALID')

    def test_rfc6750_boundary_without_a_cnb_prefix_restriction(self):
        for token in ['a', 'x' * 8192, 'A.Z_z~+/9-===']:
            status, _, stderr = self.invoke(lambda _, token=token: token)
            self.assertEqual(status, 0, stderr)
            self.assertEqual(self.output.read_bytes(), (token + '\n').encode('ascii'))
            self.output.unlink()

    def test_getpass_echo_fallback_and_cancel_do_not_read_or_save(self):
        def fallback(_):
            warnings.warn('fallback must not print a secret', getpass.GetPassWarning)
            self.fail('getpass fallback must stop before echoed input')
        self.assert_private_failure(self.invoke(fallback), 'CNB_TOKEN_NOECHO_REQUIRED')
        for exception in [EOFError, KeyboardInterrupt]:
            self.assert_private_failure(self.invoke(mock.Mock(side_effect=exception)), 'CNB_TOKEN_INPUT_CANCELLED')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_publish_race_preserves_winner_and_cleans_temporary(self):
        original_link = os.link
        def race(*args, **kwargs):
            self.output.write_text('concurrent-winner')
            return original_link(*args, **kwargs)
        with mock.patch.object(self.module.os, 'link', side_effect=race):
            self.assert_private_failure(self.invoke(), 'CNB_TOKEN_OUTPUT_EXISTS')
        self.assertEqual(self.output.read_text(), 'concurrent-winner')
        self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_write_failure_cleans_temporary_without_leaking_exception(self):
        with mock.patch.object(self.module.os, 'fsync', side_effect=OSError(TOKEN)):
            self.assert_private_failure(self.invoke(), 'CNB_TOKEN_SAVE_FAILED')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_pty_getpass_never_echoes_input_and_restores_terminal(self):
        import termios
        pid, terminal = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, str(SCRIPT), '--output', str(self.output)])
        received = bytearray()
        finished = False
        try:
            deadline = time.monotonic() + 5
            while b'Token: ' not in received and time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.1)[0]:
                    received.extend(os.read(terminal, 4096))
            self.assertIn(b'Token: ', received)
            self.assertFalse(termios.tcgetattr(terminal)[3] & termios.ECHO)
            os.write(terminal, (TOKEN + '\n').encode('ascii'))
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(terminal, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    received.extend(chunk)
            child, status = os.waitpid(pid, os.WNOHANG)
            exit_deadline = time.monotonic() + 1
            while child == 0 and time.monotonic() < exit_deadline:
                time.sleep(0.01)
                child, status = os.waitpid(pid, os.WNOHANG)
            self.assertEqual(child, pid, 'TTY importer did not finish')
            finished = True
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, received.decode())
            self.assertNotIn(TOKEN.encode(), received)
            self.assertIn(b'"status": "saved"', received)
            self.assertTrue(termios.tcgetattr(terminal)[3] & termios.ECHO)
            self.assertEqual(self.output.read_bytes(), (TOKEN + '\n').encode('ascii'))
        finally:
            if not finished:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(terminal)


if __name__ == '__main__':
    unittest.main()
