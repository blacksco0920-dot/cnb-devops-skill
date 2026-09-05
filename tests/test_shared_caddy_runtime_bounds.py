"""Execution bounds and timeout evidence, with no Docker or public network calls."""
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_shared_caddy_helper_transactions as fixtures
from shared_caddy_test_support import install_fixture_bundle


class DockerCommands:
    """Docker boundary double with live attachment state and ordered commands."""

    def __init__(self, deployment_id, upstream="sample-app-staging-web"):
        self.deployment_id = deployment_id
        self.upstream = upstream
        self.attached = False
        self.calls = []
        self.timeout_at = None
        self.timeout_after_effect = False

    def __call__(self, arguments, **kwargs):
        argv = tuple(arguments)
        if argv[0] != "/usr/bin/docker":
            raise AssertionError("unexpected executable")
        self.calls.append((argv, kwargs))
        operation = argv[1:3]
        if argv[1] == "exec":
            operation = ("exec", argv[4])
        should_timeout = self.timeout_at == len(self.calls)
        if should_timeout and not self.timeout_after_effect:
            raise subprocess.TimeoutExpired(argv, 30)
        if operation == ("network", "inspect"):
            containers = {"upstream-id": {"Name": self.upstream}}
            if self.attached:
                containers["caddy-id"] = {"Name": "caddy"}
            output = json.dumps([{"Containers": containers}])
        elif argv[1] == "inspect":
            if argv[2] != self.upstream:
                raise AssertionError("unexpected upstream")
            output = json.dumps([{"Config": {"Labels": {
                "com.deploydesk.deployment-id": self.deployment_id,
            }}}])
        elif operation == ("network", "connect"):
            self.attached = True
            output = ""
        elif operation == ("network", "disconnect"):
            self.attached = False
            output = ""
        elif operation in (("exec", "validate"), ("exec", "reload")):
            output = ""
        else:
            raise AssertionError("unexpected Docker command: " + repr(argv))
        if should_timeout:
            raise subprocess.TimeoutExpired(argv, 30)
        return subprocess.CompletedProcess(argv, 0, stdout=output)


class RuntimeBoundsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SharedCaddyTransactionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.h = self.fixture.h
        self.layout = self.fixture.layout
        self.runtime = self.h.DockerRuntime({
            "caddy_container": "caddy", "container_config_root": "/etc/caddy",
        }, self.layout)
        self.fixture.runtime = self.runtime
        self.commands = DockerCommands(fixtures.DEPLOYMENT_ID)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(self.h.subprocess, "run", side_effect=self.commands).start()
        response = mock.MagicMock()
        response.__enter__.return_value.status = 204
        opener = mock.Mock()
        opener.open.return_value = response
        mock.patch.object(self.h.urllib.request, "build_opener", return_value=opener).start()

    def subject(self, phase_hook=None):
        return self.h.SharedCaddyHelper(
            self.layout, runtime=self.runtime,
            trust=self.h.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path, phase_hook=phase_hook,
        )

    def preflight(self):
        with self.layout.release_lock(fixtures.DEPLOYMENT_ID).open("r+") as descriptor:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.subject().preflight(fixtures.DEPLOYMENT_ID, self.fixture.bundle_id)

    def assert_locks_available(self):
        for path in (
            self.layout.project_lock(fixtures.DEPLOYMENT_ID),
            self.layout.shared_lock,
        ):
            with path.open("r+") as descriptor:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_retained(self, phase, pointer):
        self.assertTrue(self.layout.transaction_path.is_file())
        transaction = self.h.read_json(self.layout.transaction_path)
        self.assertEqual(phase, transaction["phase"])
        self.assertEqual(pointer, self.layout.current_generation().name)
        self.assertTrue((self.layout.intake_root / transaction["transaction_id"]).is_dir())
        self.assertTrue((self.layout.generations_root / transaction["new_generation"]).is_dir())
        self.assertTrue(self.layout.recovery_marker.is_file())
        self.assertEqual([], list(self.layout.receipts_root.iterdir()))
        self.assertFalse(self.layout.history_path.exists())
        self.assert_locks_available()
        calls = list(self.commands.calls)
        with self.assertRaises(self.h.RecoveryRequired):
            self.fixture.apply()
        self.assertEqual(calls, self.commands.calls, "blocked releases must not invoke Docker")
        return transaction

    def test_every_docker_command_path_receives_a_30_second_deadline(self):
        self.preflight()
        self.fixture.apply()
        self.runtime.verify_network("shared-edge", self.commands.upstream, fixtures.DEPLOYMENT_ID)
        self.runtime.detach_network("shared-edge")
        self.assertEqual(12, len(self.commands.calls))
        for argv, kwargs in self.commands.calls:
            with self.subTest(command=argv):
                self.assertEqual(30, kwargs.get("timeout"), "Docker execution must be bounded")
        self.assertFalse(self.commands.attached)

    def test_every_docker_command_path_translates_timeout_without_retry(self):
        operations = (
            ("validate", 1), ("reload", 1),
            ("ensure", 1), ("ensure", 2), ("ensure", 3), ("ensure", 4),
            ("verify", 1), ("verify", 2),
            ("detach", 1), ("detach", 2), ("detach", 3),
        )
        for operation, timeout_at in operations:
            with self.subTest(operation=operation, timeout_at=timeout_at):
                self.commands.calls.clear()
                self.commands.attached = operation in ("verify", "detach")
                self.commands.timeout_at = timeout_at
                error = None
                try:
                    if operation == "validate":
                        self.runtime.validate(self.layout.current_generation())
                    elif operation == "reload":
                        self.runtime.reload()
                    elif operation == "ensure":
                        self.runtime.ensure_network("shared-edge", self.commands.upstream, fixtures.DEPLOYMENT_ID, lambda network: None)
                    elif operation == "verify":
                        self.runtime.verify_network("shared-edge", self.commands.upstream, fixtures.DEPLOYMENT_ID)
                    else:
                        self.runtime.detach_network("shared-edge")
                except Exception as exc:
                    error = exc
                self.assertIsInstance(error, self.h.TransactionError)
                self.assertIsInstance(error.__cause__, subprocess.TimeoutExpired)
                self.assertEqual(timeout_at, len(self.commands.calls), "timeouts must not retry")
        self.assertEqual([], list(self.layout.infra_root.glob(".validate-*")))

    def test_pretransaction_validate_timeouts_clean_private_state_and_release_locks(self):
        old = self.layout.current_generation().name
        for operation in (self.preflight, self.fixture.apply):
            with self.subTest(operation=operation.__name__):
                self.commands.calls.clear()
                self.commands.timeout_at = 1
                error = None
                try:
                    operation()
                except Exception as exc:
                    error = exc
                self.assertIsInstance(error, self.h.TransactionError)
                self.assertFalse(self.layout.transaction_path.exists())
                self.assertFalse(self.layout.recovery_marker.exists())
                self.assertEqual(old, self.layout.current_generation().name)
                self.assertEqual([old], [p.name for p in self.layout.generations_root.iterdir()])
                self.assertEqual([], list(self.layout.intake_root.iterdir()))
                self.assertEqual([], list(self.layout.infra_root.glob(".preflight-*")))
                self.assertEqual([], list(self.layout.infra_root.glob(".validate-*")))
                self.assert_locks_available()

    def test_prepared_inspect_timeout_retains_transaction_without_rollback(self):
        old = self.layout.current_generation().name
        self.commands.timeout_at = 2
        error = None
        try:
            self.fixture.apply()
        except Exception as exc:
            error = exc
        self.assertIsInstance(error, self.h.RecoveryRequired)
        self.assert_retained("prepared", old)
        self.assertEqual(2, len(self.commands.calls))

    def test_uncertain_connect_timeout_keeps_attachment_intent_without_detach(self):
        old = self.layout.current_generation().name
        self.commands.timeout_at = 4
        self.commands.timeout_after_effect = True
        error = None
        try:
            self.fixture.apply()
        except Exception as exc:
            error = exc
        self.assertIsInstance(error, self.h.RecoveryRequired)
        transaction = self.assert_retained("prepared", old)
        self.assertEqual([{"network": "shared-edge", "pre_transaction_state": "absent"}], transaction["network_attachment_intents"])
        self.assertTrue(self.commands.attached)
        self.assertEqual(4, len(self.commands.calls))

    def test_post_connect_verification_timeout_retains_uncertain_transaction(self):
        old = self.layout.current_generation().name
        self.commands.timeout_at = 5
        error = None
        try:
            self.fixture.apply()
        except Exception as exc:
            error = exc
        self.assertIsInstance(error, self.h.RecoveryRequired)
        self.assert_retained("prepared", old)
        self.assertTrue(self.commands.attached)
        self.assertEqual(5, len(self.commands.calls))

    def test_uncertain_reload_timeout_keeps_new_pointer_and_never_rolls_back(self):
        self.commands.timeout_at = 6
        error = None
        try:
            self.fixture.apply()
        except Exception as exc:
            error = exc
        self.assertIsInstance(error, self.h.RecoveryRequired)
        transaction = self.h.read_json(self.layout.transaction_path)
        self.assert_retained("current-switched", transaction["new_generation"])
        self.assertEqual(6, len(self.commands.calls))
        self.assertTrue(self.commands.attached)

    def test_prepared_recovery_timeout_preserves_original_evidence_and_blocker(self):
        self.fixture.runtime = fixtures.Runtime()
        self.fixture.runtime.connect_new = True
        self.fixture.runtime.interrupt_after_connect = True
        with self.assertRaises(fixtures.Crash):
            self.fixture.apply()
        transaction = self.h.read_json(self.layout.transaction_path)
        self.fixture.runtime = self.runtime
        self.commands.attached = True
        self.commands.timeout_at = 2  # inspect succeeded; daemon-side disconnect is uncertain
        with self.assertRaises(self.h.RecoveryRequired):
            self.fixture.apply()
        self.assert_retained("prepared", transaction["old_generation"])
        self.assertEqual(transaction, self.h.read_json(self.layout.transaction_path))
        self.assertEqual(2, len(self.commands.calls))

    def test_switched_recovery_reload_timeout_preserves_original_evidence(self):
        def crash(phase, transaction):
            if phase == "current-switched":
                raise fixtures.Crash()
        with self.assertRaises(fixtures.Crash):
            self.fixture.apply(crash)
        transaction = self.h.read_json(self.layout.transaction_path)
        self.commands.calls.clear()
        self.commands.timeout_at = 4  # inspect, disconnect, verify, old-generation reload
        with self.assertRaises(self.h.RecoveryRequired):
            self.fixture.apply()
        self.assert_retained("current-switched", transaction["old_generation"])
        self.assertEqual(transaction, self.h.read_json(self.layout.transaction_path))
        self.assertEqual(4, len(self.commands.calls))

    def test_committed_recovery_timeout_preserves_evidence_without_receipt(self):
        def crash(phase, transaction):
            if phase == "committed":
                raise fixtures.Crash()
        with self.assertRaises(fixtures.Crash):
            self.fixture.apply(crash)
        transaction = self.h.read_json(self.layout.transaction_path)
        self.commands.calls.clear()
        self.commands.timeout_at = 1
        with self.assertRaises(self.h.RecoveryRequired):
            self.fixture.apply()
        self.assert_retained("committed", transaction["new_generation"])
        self.assertEqual(transaction, self.h.read_json(self.layout.transaction_path))
        self.assertEqual(1, len(self.commands.calls))

    def test_upstream_dns_boundaries_agree_across_declaration_ensure_and_verify(self):
        source = json.loads((fixtures.FIXTURE / "bundle/caddy/declaration.json").read_text())
        valid = ("a" * 63, "a" * 62 + ".b", ".".join(["a" * 63] * 3 + ["a" * 61]))
        invalid = ("a" * 64, ".".join(["a" * 63] * 3 + ["a" * 62]), "UPPER.test", "under_score", "tail.test.", "", None, 7)
        for upstream in valid + invalid:
            with self.subTest(upstream=upstream):
                declaration = json.loads(json.dumps(source))
                declaration["routes"][0]["upstream"] = upstream
                self.commands.calls.clear()
                self.commands.upstream = upstream
                self.commands.attached = True
                operations = (
                    ("declaration", lambda: self.h.validate_declaration(declaration)),
                    ("ensure", lambda: self.runtime.ensure_network("shared-edge", upstream, fixtures.DEPLOYMENT_ID, lambda network: None)),
                    ("verify", lambda: self.runtime.verify_network("shared-edge", upstream, fixtures.DEPLOYMENT_ID)),
                )
                for name, operation in operations:
                    with self.subTest(validator=name):
                        error = None
                        try:
                            operation()
                        except Exception as exc:
                            error = exc
                        if upstream in valid:
                            self.assertIsNone(error)
                        else:
                            self.assertIsInstance(error, self.h.ContractError)
                if upstream in invalid:
                    self.assertEqual([], self.commands.calls)

    def test_long_upstream_bundle_passes_preflight_and_applies_through_real_runtime(self):
        custom = Path(self.fixture.tempdir.name) / "custom-fixture"
        shutil.copytree(fixtures.FIXTURE, custom)
        declaration_path = custom / "bundle/caddy/declaration.json"
        declaration = json.loads(declaration_path.read_text())
        upstream = "api." + "a" * 59 + ".internal"
        declaration["routes"][0]["upstream"] = upstream
        declaration_path.write_text(json.dumps(declaration))
        (custom / "bundle/caddy/site.caddy").write_text(self.h.render_fragment(declaration))
        compose_path = custom / "bundle/runtime/compose.json"
        compose = json.loads(compose_path.read_text())
        compose["services"]["web"]["container_name"] = upstream
        compose["services"]["web"]["networks"]["shared-edge"]["aliases"] = [upstream]
        compose_path.write_text(json.dumps(compose))
        self.fixture.bundle_id = install_fixture_bundle(self.h, self.layout, custom, fixtures.DEPLOYMENT_ID)
        self.commands.upstream = upstream
        self.assertEqual("passed", self.preflight()["status"])
        error = None
        receipt = None
        try:
            receipt = self.fixture.apply()
        except Exception as exc:
            error = exc
        self.assertIsNone(error)
        self.assertEqual("committed", receipt["status"])
        self.assertTrue(self.commands.attached)


class LockBoundsTests(unittest.TestCase):
    def setUp(self):
        self.h = fixtures.load(fixtures.HELPER_PATH, "lock_bounds_helper")
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "fixed.lock"
        self.path.touch(mode=0o600)
        self.trust = self.h.TrustPolicy(owner_uid=os.getuid())

    def test_contended_lock_expires_at_30_monotonic_seconds_and_closes_descriptor(self):
        real_flock = fcntl.flock
        opened = []
        real_open = self.h._open_fixed_lock
        def observe_open(*args):
            descriptor = real_open(*args)
            opened.append(descriptor)
            return descriptor
        def nonblocking_only(descriptor, operation):
            if operation == fcntl.LOCK_EX:
                raise AssertionError("contended acquisition must never block in flock")
            return real_flock(descriptor, operation)
        with self.path.open("r+") as holder:
            real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (
                mock.patch.object(self.h.fcntl, "flock", side_effect=nonblocking_only),
                mock.patch.object(self.h, "_open_fixed_lock", side_effect=observe_open),
                mock.patch("time.monotonic", side_effect=[100, 100, 130]),
                mock.patch("time.sleep") as sleep,
            ):
                with self.assertRaises(self.h.TransactionError):
                    with self.h._locked(self.path, self.trust):
                        self.fail("contended lock entered its critical section")
                self.assertTrue(sleep.called)
            with self.assertRaises(OSError):
                os.fstat(opened[0])
        with self.h._locked(self.path, self.trust):
            pass

    def test_waiting_lock_can_acquire_after_contention_clears(self):
        real_flock = fcntl.flock
        with self.path.open("r+") as holder:
            real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def nonblocking_only(descriptor, operation):
                if operation == fcntl.LOCK_EX:
                    raise AssertionError("contended acquisition must never block in flock")
                return real_flock(descriptor, operation)
            with (
                mock.patch.object(self.h.fcntl, "flock", side_effect=nonblocking_only),
                mock.patch("time.sleep", side_effect=lambda seconds: real_flock(holder, fcntl.LOCK_UN)),
            ):
                with self.h._locked(self.path, self.trust) as descriptor:
                    self.assertEqual(os.stat(self.path).st_ino, os.fstat(descriptor).st_ino)

    def test_lock_released_after_deadline_does_not_enter_critical_section(self):
        real_flock = fcntl.flock
        with self.path.open("r+") as holder:
            real_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (
                mock.patch("time.monotonic", side_effect=[100, 100, 131]),
                mock.patch("time.sleep", side_effect=lambda seconds: real_flock(holder, fcntl.LOCK_UN)),
            ):
                with self.assertRaises(self.h.TransactionError):
                    with self.h._locked(self.path, self.trust):
                        self.fail("lock became available after the acquisition deadline")

    def test_noncontention_lock_errors_are_not_retried(self):
        with mock.patch.object(self.h.fcntl, "flock", side_effect=OSError(errno.EIO, "io error")) as flock:
            with self.assertRaises(OSError) as caught:
                with self.h._locked(self.path, self.trust):
                    self.fail("unexpected critical section")
        self.assertEqual(errno.EIO, caught.exception.errno)
        self.assertLessEqual(flock.call_count, 2)  # historical finally may attempt an unlock


class LocalProcessDeadlineTests(unittest.TestCase):
    def test_common_runner_terminates_a_real_local_child_when_deadline_expires(self):
        helper = fixtures.load(fixtures.HELPER_PATH, "local_deadline_helper")
        runtime = helper.DockerRuntime({"caddy_container": "caddy", "container_config_root": "/etc/caddy"}, mock.Mock())
        with tempfile.TemporaryDirectory() as directory:
            finished = Path(directory) / "finished"
            command = [sys.executable, "-c", "import pathlib,time; time.sleep(0.4); pathlib.Path(__import__('sys').argv[1]).touch()", str(finished)]
            error = None
            with mock.patch.object(helper, "DOCKER_TIMEOUT_SECONDS", 0.03, create=True):
                try:
                    runtime._run(command)
                except Exception as exc:
                    error = exc
            self.assertIsInstance(error, helper.TransactionError)
            self.assertFalse(finished.exists())


if __name__ == "__main__":
    unittest.main()
