import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import copy
import tempfile
import unittest
from unittest import mock

try:
    from shared_caddy_test_support import install_fixture_bundle
except ImportError:
    from tests.shared_caddy_test_support import install_fixture_bundle


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "deploydesk_caddy_apply.py"
INSTALLER_PATH = ROOT / "scripts" / "install_shared_caddy_helper.py"
FIXTURE = ROOT / "tests" / "fixtures" / "shared-caddy-v1"
DEPLOYMENT_ID = "sample-app--staging"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Crash(BaseException):
    pass


class Runtime:
    def __init__(self):
        self.reloads = 0
        self.validations = 0
        self.smokes = 0
        self.fail_reload = False
        self.fail_network = False
        self.connect_new = False
        self.fail_after_connect = False
        self.detached = []
        self.attached = set()
        self.interrupt_detach_once = False
        self.interrupt_after_connect = False
        self.connect_calls = 0

    def ensure_network(self, network, upstream, deployment_id, on_intent):
        if self.fail_network:
            raise RuntimeError("network verification failed")
        if self.connect_new:
            on_intent(network)
            self.connect_calls += 1
            self.attached.add(network)
            if self.interrupt_after_connect:
                raise Crash()
        if self.fail_after_connect:
            raise RuntimeError("post-connect verification failed")
        return self.connect_new

    def verify_network(self, network, upstream, deployment_id):
        if self.fail_network:
            raise RuntimeError("network verification failed")

    def detach_network(self, network):
        if network not in self.attached:
            return
        self.attached.remove(network)
        self.detached.append(network)
        if self.interrupt_detach_once:
            self.interrupt_detach_once = False
            raise Crash()

    def validate(self, generation):
        self.validations += 1

    def reload(self):
        self.reloads += 1
        if self.fail_reload:
            raise RuntimeError("reload failed")

    def smoke(self, hosts):
        self.smokes += 1


@unittest.skipUnless(HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "helper not implemented yet")
class SharedCaddyTransactionTests(unittest.TestCase):
    def setUp(self):
        self.h = load(HELPER_PATH, "transaction_helper")
        self.installer = load(INSTALLER_PATH, "transaction_installer")
        self.tempdir = tempfile.TemporaryDirectory()
        self.layout = self.h.Layout.for_test_root(Path(self.tempdir.name))
        self.installer.bootstrap_host(self.layout, owner_uid=os.getuid())
        self.installer.install_helper(
            self.layout, HELPER_PATH,
            expected_sha256=hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(), owner_uid=os.getuid()
        )
        self.installer.provision_deployments(
            self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid()
        )
        self.bundle_id = install_fixture_bundle(self.h, self.layout, FIXTURE, DEPLOYMENT_ID)
        self.runtime = Runtime()

    def tearDown(self):
        self.tempdir.cleanup()

    def apply(self, phase_hook=None):
        subject = self.h.SharedCaddyHelper(
            self.layout,
            runtime=self.runtime,
            trust=self.h.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path,
            phase_hook=phase_hook,
        )
        with self.layout.release_lock(DEPLOYMENT_ID).open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return subject.apply(DEPLOYMENT_ID, self.bundle_id)

    def history(self):
        path = self.layout.history_path
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    def test_noop_route_bytes_still_create_new_provenance_and_receipt(self):
        first = self.apply()
        second = self.apply()
        self.assertNotEqual(first["transaction_id"], second["transaction_id"])
        self.assertNotEqual(first["generation_id"], second["generation_id"])
        self.assertEqual(2, len(self.history()))
        self.assertEqual(2, self.runtime.reloads)
        self.assertEqual(2, self.runtime.smokes)

    def test_interrupted_current_switch_recovers_old_then_runs_new_transaction(self):
        old_generation = self.layout.current_generation().name

        def crash(phase, transaction):
            if phase == "current-switched":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        transaction = json.loads(self.layout.transaction_path.read_text())
        self.assertEqual("current-switched", transaction["phase"])
        self.assertNotEqual(old_generation, self.layout.current_generation().name)
        receipt = self.apply()
        self.assertEqual("committed", receipt["status"])
        self.assertFalse(self.layout.transaction_path.exists())
        self.assertFalse(self.layout.recovery_marker.exists())
        self.assertEqual(1, len(self.history()))
        self.assertGreaterEqual(self.runtime.reloads, 2)

    def test_prepared_reloaded_and_verified_interruptions_recover_deterministically(self):
        for phase in ("prepared", "reloaded", "verified"):
            with self.subTest(phase=phase):
                def crash(actual, transaction, expected=phase):
                    if actual == expected:
                        raise Crash()

                with self.assertRaises(Crash):
                    self.apply(crash)
                interrupted = json.loads(self.layout.transaction_path.read_text())
                self.assertEqual(phase, interrupted["phase"])
                receipt = self.apply()
                self.assertEqual("committed", receipt["status"])
                self.assertFalse((self.layout.intake_root / interrupted["transaction_id"]).exists())

    def test_committed_interruption_finishes_receipt_once_before_next_apply(self):
        def crash(phase, transaction):
            if phase == "committed":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        committed = json.loads(self.layout.transaction_path.read_text())
        self.apply()
        matching = [item for item in self.history() if item["transaction_id"] == committed["transaction_id"]]
        self.assertEqual(1, len(matching))
        self.assertTrue(self.layout.receipt_path(committed["transaction_id"]).is_file())

    def test_failed_reload_rolls_back_without_success_receipt(self):
        old_generation = self.layout.current_generation().name
        self.runtime.fail_reload = True
        self.runtime.connect_new = True
        with self.assertRaises(self.h.TransactionError):
            self.apply()
        self.assertEqual(old_generation, self.layout.current_generation().name)
        self.assertEqual([], self.history())
        self.assertEqual(["shared-edge"], self.runtime.detached)

    def test_successful_rollback_fsyncs_intake_parent_after_removal(self):
        original_smoke = self.runtime.smoke
        smoke_calls = [0]

        def fail_first_smoke(hosts):
            smoke_calls[0] += 1
            if smoke_calls[0] == 1:
                raise RuntimeError("injected smoke failure")
            return original_smoke(hosts)

        self.runtime.smoke = fail_first_smoke
        fsynced = []
        original_fsync = self.h._fsync_dir

        def record_fsync(path):
            fsynced.append(Path(path))
            return original_fsync(path)

        self.h._fsync_dir = record_fsync
        try:
            with self.assertRaises(self.h.TransactionError):
                self.apply()
        finally:
            self.h._fsync_dir = original_fsync
            self.runtime.smoke = original_smoke
        self.assertEqual(2, smoke_calls[0])
        self.assertGreaterEqual(fsynced.count(self.layout.intake_root), 2)
        self.assertFalse(self.layout.transaction_path.exists())

    def test_failed_network_check_discards_prepared_state_without_marker(self):
        old_generation = self.layout.current_generation().name
        self.runtime.fail_network = True
        with self.assertRaises(self.h.TransactionError):
            self.apply()
        self.assertEqual(old_generation, self.layout.current_generation().name)
        self.assertFalse(self.layout.transaction_path.exists())
        self.assertFalse(self.layout.recovery_marker.exists())
        self.assertEqual([], self.history())

    def test_post_connect_verification_failure_detaches_durably_recorded_attachment(self):
        self.runtime.connect_new = True
        self.runtime.fail_after_connect = True
        with self.assertRaises(self.h.TransactionError):
            self.apply()
        self.assertEqual(["shared-edge"], self.runtime.detached)
        self.assertFalse(self.layout.transaction_path.exists())

    def test_intent_write_failure_prevents_docker_connect(self):
        self.runtime.connect_new = True
        original = self.h._atomic_json

        def fail_intent(path, value, mode=0o600):
            if path == self.layout.transaction_path and value.get("network_attachment_intents"):
                raise OSError("injected intent persistence failure")
            return original(path, value, mode)

        self.h._atomic_json = fail_intent
        try:
            with self.assertRaises(self.h.TransactionError):
                self.apply()
        finally:
            self.h._atomic_json = original
        self.assertEqual(0, self.runtime.connect_calls)
        self.assertEqual(set(), self.runtime.attached)

    def test_crash_after_durable_intent_before_connect_needs_no_detach(self):
        self.runtime.connect_new = True

        def crash(phase, transaction):
            if phase == "prepared" and transaction["network_attachment_intents"]:
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        retained = json.loads(self.layout.transaction_path.read_text())
        self.assertEqual(
            [{"network": "shared-edge", "pre_transaction_state": "absent"}],
            retained["network_attachment_intents"],
        )
        self.assertEqual(0, self.runtime.connect_calls)
        self.runtime.connect_new = False
        self.apply()
        self.assertEqual([], self.runtime.detached)

    def test_crash_immediately_after_connect_is_recovered_from_durable_intent(self):
        self.runtime.connect_new = True
        self.runtime.interrupt_after_connect = True
        with self.assertRaises(Crash):
            self.apply()
        retained = json.loads(self.layout.transaction_path.read_text())
        self.assertEqual(
            [{"network": "shared-edge", "pre_transaction_state": "absent"}],
            retained["network_attachment_intents"],
        )
        self.assertEqual({"shared-edge"}, self.runtime.attached)
        self.runtime.connect_new = False
        self.runtime.interrupt_after_connect = False
        self.apply()
        self.assertEqual(["shared-edge"], self.runtime.detached)

    def test_docker_adapter_persists_intent_before_connect_and_post_connect_failure(self):
        runtime = self.h.DockerRuntime(
            {"caddy_container": "caddy", "container_config_root": "/etc/caddy"},
            self.layout,
        )
        responses = [
            mock.Mock(returncode=0, stdout=json.dumps([{"Containers": {"u": {"Name": "sample-upstream"}}}])),
            mock.Mock(returncode=0, stdout=json.dumps([{"Config": {"Labels": {"com.deploydesk.deployment-id": DEPLOYMENT_ID}}}])),
            mock.Mock(returncode=0, stdout=""),
            mock.Mock(returncode=1, stdout="inspect failed"),
        ]
        events = []

        def run_side_effect(arguments, **kwargs):
            events.append(("run", arguments))
            return responses.pop(0)

        with mock.patch.object(self.h.subprocess, "run", side_effect=run_side_effect):
            with self.assertRaises(self.h.TransactionError):
                runtime.ensure_network(
                    "shared-edge", "sample-upstream", DEPLOYMENT_ID,
                    lambda network: events.append(("intent", network)),
                )
        intent_index = events.index(("intent", "shared-edge"))
        connect_index = next(index for index, event in enumerate(events) if event[0] == "run" and "connect" in event[1])
        self.assertLess(intent_index, connect_index)

    def test_prepared_intent_interrupt_without_connect_does_not_detach(self):
        self.runtime.connect_new = True

        def crash(phase, transaction):
            if phase == "prepared" and transaction["network_attachment_intents"]:
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        retained = json.loads(self.layout.transaction_path.read_text())
        self.assertEqual(
            [{"network": "shared-edge", "pre_transaction_state": "absent"}],
            retained["network_attachment_intents"],
        )
        self.runtime.connect_new = False
        self.apply()
        self.assertEqual([], self.runtime.detached)

    def test_interrupted_prepared_recovery_resumes_idempotent_network_cleanup(self):
        self.runtime.connect_new = True
        self.runtime.interrupt_after_connect = True
        with self.assertRaises(Crash):
            self.apply()
        self.runtime.connect_new = False
        self.runtime.interrupt_after_connect = False
        self.runtime.interrupt_detach_once = True
        with self.assertRaises(Crash):
            self.apply()
        self.assertTrue(self.layout.transaction_path.exists())
        receipt = self.apply()
        self.assertEqual("committed", receipt["status"])
        self.assertEqual(["shared-edge"], self.runtime.detached)
        self.assertFalse(self.layout.recovery_marker.exists())

    def test_interrupted_switched_rollback_resumes_after_old_pointer_restored(self):
        self.runtime.connect_new = True

        def crash(phase, transaction):
            if phase == "current-switched":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        self.runtime.connect_new = False
        self.runtime.interrupt_detach_once = True
        with self.assertRaises(Crash):
            self.apply()
        retained = json.loads(self.layout.transaction_path.read_text())
        self.assertEqual(retained["old_generation"], self.layout.current_generation().name)
        receipt = self.apply()
        self.assertEqual("committed", receipt["status"])
        self.assertEqual(["shared-edge"], self.runtime.detached)

    def test_preexisting_attachment_is_never_detached_on_later_failure(self):
        self.runtime.connect_new = False
        self.runtime.fail_reload = True
        prepared = []
        with self.assertRaises(self.h.TransactionError):
            self.apply(lambda phase, transaction: prepared.append(dict(transaction)))
        self.assertEqual([], self.runtime.detached)
        self.assertTrue(all(not item["network_attachment_intents"] for item in prepared))

    def test_generation_tree_is_durable_before_prepared_transaction(self):
        events = []
        original = self.h._fsync_dir

        def recording_fsync(path):
            events.append(("fsync", Path(path)))
            return original(path)

        self.h._fsync_dir = recording_fsync
        try:
            def phase(phase_name, transaction):
                events.append(("phase", phase_name))

            self.apply(phase)
        finally:
            self.h._fsync_dir = original
        prepared_index = events.index(("phase", "prepared"))
        before = [value for kind, value in events[:prepared_index] if kind == "fsync"]
        generation = self.layout.generations_root / self.history()[0]["generation_id"]
        self.assertIn(self.layout.generations_root, before)
        self.assertIn(generation / "sites", before)
        self.assertIn(generation / "manifests", before)
        self.assertIn(generation, before)
        self.assertIn(self.layout.intake_root, before)
        committed_index = events.index(("phase", "committed"))
        after_committed = [
            value for kind, value in events[committed_index + 1:] if kind == "fsync"
        ]
        self.assertIn(self.layout.intake_root, after_committed)

    def test_prepared_recovery_fsyncs_intake_parent_after_removal(self):
        def crash(phase, transaction):
            if phase == "prepared":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        retained = json.loads(self.layout.transaction_path.read_text())
        subject = self.h.SharedCaddyHelper(
            self.layout,
            runtime=self.runtime,
            trust=self.h.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path,
        )
        contract, helper_hash = subject._attest_server()
        fsynced = []
        original_fsync = self.h._fsync_dir

        def record_fsync(path):
            fsynced.append(Path(path))
            return original_fsync(path)

        self.h._fsync_dir = record_fsync
        try:
            subject._recover_if_needed(contract, helper_hash)
        finally:
            self.h._fsync_dir = original_fsync
        self.assertIn(self.layout.intake_root, fsynced)
        self.assertFalse(
            (self.layout.intake_root / retained["transaction_id"]).exists()
        )

    def test_recovery_marker_blocks_all_normal_releases(self):
        self.layout.recovery_marker.write_text("manual recovery required\n")
        with self.assertRaises(self.h.RecoveryRequired):
            self.apply()

    def test_dangling_maintenance_marker_still_blocks_normal_releases(self):
        self.layout.maintenance_recovery_marker.symlink_to("missing-marker-target")
        with self.assertRaises(self.h.RecoveryRequired):
            self.apply()

    def test_normal_release_cannot_delete_an_owned_hostname(self):
        self.apply()
        changed_fixture = self.layout.root / "changed-fixture"
        shutil.copytree(FIXTURE, changed_fixture)
        declaration_path = changed_fixture / "bundle" / "caddy" / "declaration.json"
        declaration = json.loads(declaration_path.read_text())
        declaration["routes"] = declaration["routes"][:-1]
        declaration_path.write_text(json.dumps(declaration, sort_keys=True) + "\n")
        (changed_fixture / "bundle" / "caddy" / "site.caddy").write_text(
            self.h.render_fragment(declaration)
        )
        template_manifest_path = changed_fixture / "bundle" / "caddy" / "server-manifest.json"
        template_manifest = json.loads(template_manifest_path.read_text())
        template_manifest["hosts"] = [route["host"] for route in declaration["routes"]]
        template_manifest_path.write_text(json.dumps(template_manifest, sort_keys=True) + "\n")
        self.bundle_id = install_fixture_bundle(
            self.h, self.layout, changed_fixture, DEPLOYMENT_ID
        )
        with self.assertRaises(self.h.MaintenanceRequired):
            self.apply()

    def test_malformed_retained_transaction_sets_marker_without_path_action(self):
        outside = self.layout.root / "must-remain"
        outside.mkdir()
        malformed = {
            "schema_version": "shared-caddy-transaction/v1",
            "phase": "prepared",
            "old_generation": self.layout.current_generation().name,
            "new_generation": str(outside),
        }
        self.layout.transaction_path.write_text(json.dumps(malformed))
        with self.assertRaises(self.h.RecoveryRequired):
            self.apply()
        self.assertTrue(outside.is_dir())
        self.assertTrue(self.layout.recovery_marker.is_file())

    def test_every_transaction_evidence_field_fails_closed_when_mutated(self):
        def crash(phase, transaction):
            if phase == "prepared":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        original = json.loads(self.layout.transaction_path.read_text())
        mutations = {
            "schema_version": "wrong", "phase": "wrong",
            "contract_version": "wrong", "helper_version": "9.9.9",
            "helper_sha256": "x", "transaction_id": "tx-bad",
            "project_id": "Wrong_Project", "environment": "PROD",
            "deployment_id": "bad", "bundle_id": "x", "git_sha": "x",
            "source_repo": "git@example.invalid:owner/repo.git",
            "declaration_sha256": "x", "fragment_sha256": "x", "compose_sha256": "x",
            "helper_requirement_sha256": "x", "internal_provenance_sha256": "x",
            "old_generation": original["new_generation"],
            "new_generation": original["old_generation"],
            "hosts": ["APP.EXAMPLE.TEST"],
            "network_attachment_intents": [{"network": "shared-edge", "pre_transaction_state": "present"}],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field] = value
                if field == "new_generation":
                    changed["new_generation"] = changed["old_generation"]
                with self.assertRaises((self.h.ContractError, self.h.RecoveryRequired)):
                    self.h.validate_transaction(changed)

    def test_every_receipt_evidence_field_fails_closed_when_mutated(self):
        original = self.apply()
        mutations = {
            "schema_version": "wrong", "status": "wrong",
            "contract_version": "wrong", "helper_version": "9.9.9",
            "helper_sha256": "x", "transaction_id": "tx-bad",
            "project_id": "Wrong_Project", "environment": "PROD",
            "deployment_id": "bad", "bundle_id": "x", "git_sha": "x",
            "source_repo": "git@example.invalid:owner/repo.git",
            "declaration_sha256": "x", "fragment_sha256": "x", "compose_sha256": "x",
            "helper_requirement_sha256": "x", "internal_provenance_sha256": "x",
            "old_generation": original["generation_id"],
            "generation_id": original["old_generation"],
            "hosts": ["APP.EXAMPLE.TEST"],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field] = value
                if field == "generation_id":
                    changed["generation_id"] = changed["old_generation"]
                with self.assertRaises((self.h.ContractError, self.h.RecoveryRequired)):
                    self.h.validate_receipt(changed)

    def test_corrupt_persisted_history_is_not_trusted_on_later_commit(self):
        receipt = self.apply()
        corrupt = dict(receipt)
        corrupt["git_sha"] = "not-a-git-sha"
        self.layout.history_path.write_text(json.dumps(corrupt) + "\n")
        with self.assertRaises(self.h.RecoveryRequired):
            self.apply()
        self.assertTrue(self.layout.recovery_marker.exists())


if __name__ == "__main__":
    unittest.main()
