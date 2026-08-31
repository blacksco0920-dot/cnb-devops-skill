import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

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


class Runtime:
    def __init__(self):
        self.validated = []
        self.reloads = 0
        self.smokes = []
        self.networks = []

    def ensure_network(self, network, upstream, deployment_id, persist_intent):
        self.networks.append((network, upstream, deployment_id))
        return False

    def detach_network(self, network):
        return None

    def verify_network(self, network, upstream, deployment_id):
        return None

    def validate(self, generation):
        self.validated.append(generation)

    def reload(self):
        self.reloads += 1

    def smoke(self, hosts):
        self.smokes.append(tuple(hosts))


@unittest.skipUnless(HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "helper not implemented yet")
class SharedCaddySecurityTests(unittest.TestCase):
    def setUp(self):
        self.helper_module = load(HELPER_PATH, "security_helper")
        self.installer = load(INSTALLER_PATH, "security_installer")
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.layout = self.helper_module.Layout.for_test_root(self.root)
        self.installer.bootstrap_host(self.layout, owner_uid=os.getuid())
        self.installer.install_helper(
            self.layout, HELPER_PATH,
            expected_sha256=hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(), owner_uid=os.getuid()
        )
        self.installer.provision_deployments(
            self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid()
        )
        initial = self.layout.current_generation()
        os.chmod(initial, 0o700)
        os.chmod(initial / "manifests", 0o700)
        os.chmod(initial / "sites", 0o700)
        other_site = initial / "sites" / "other-app--production.caddy"
        other_site.write_text("other.example.test {\n    redir https://other.example.test{uri} 308\n}\n")
        other_manifest = json.loads((FIXTURE / "other-manifest.json").read_text())
        other_manifest["fragment_sha256"] = hashlib.sha256(other_site.read_bytes()).hexdigest()
        (initial / "manifests" / "other-app--production.json").write_text(
            json.dumps(other_manifest, sort_keys=True) + "\n"
        )
        os.chmod(initial / "manifests" / "other-app--production.json", 0o400)
        os.chmod(initial / "sites" / "other-app--production.caddy", 0o400)
        os.chmod(initial / "manifests", 0o500)
        os.chmod(initial / "sites", 0o500)
        os.chmod(initial, 0o500)
        self._install_bundle()
        self.runtime = Runtime()
        self.subject = self.helper_module.SharedCaddyHelper(
            self.layout,
            runtime=self.runtime,
            trust=self.helper_module.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _install_bundle(self):
        self.bundle_id = install_fixture_bundle(
            self.helper_module, self.layout, FIXTURE, DEPLOYMENT_ID
        )

    def _apply_with_release_lock(self):
        lock_path = self.layout.release_lock(DEPLOYMENT_ID)
        with lock_path.open("r+") as release_lock:
            fcntl.flock(release_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.subject.apply(DEPLOYMENT_ID, self.bundle_id)

    def test_normal_interface_rejects_paths_commands_and_extra_arguments(self):
        parser = self.helper_module.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--deployment-id", DEPLOYMENT_ID, "--bundle-id", self.bundle_id, "--path", "/tmp/x"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--deployment-id", "../../root", "--bundle-id", self.bundle_id])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--deployment-id", DEPLOYMENT_ID, "--bundle-id", "$(id)"])

    def test_release_lock_must_already_be_held_by_the_caller(self):
        with self.assertRaises(self.helper_module.SecurityError):
            self.subject.apply(DEPLOYMENT_ID, self.bundle_id)

    def test_lock_order_is_project_then_shared(self):
        self._apply_with_release_lock()
        self.assertEqual(["project", "shared"], self.subject.last_lock_order)

    def test_helper_drift_fails_attestation(self):
        self.layout.helper_path.write_text(self.layout.helper_path.read_text() + "\n# drift\n")
        with self.assertRaises(self.helper_module.AttestationError):
            self._apply_with_release_lock()

    def test_replaced_precreated_lock_inode_fails_attestation(self):
        self.layout.shared_lock.unlink()
        self.layout.shared_lock.write_text("")
        os.chmod(self.layout.shared_lock, 0o600)
        with self.assertRaises(self.helper_module.SecurityError):
            self._apply_with_release_lock()

    def test_reused_device_and_inode_with_changed_ctime_fails_attestation(self):
        manifest = json.loads(self.layout.lock_manifest_path.read_text())
        recorded = manifest["shared"]
        real_lstat = self.helper_module.os.lstat

        def same_inode_replacement(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if Path(path) == self.layout.shared_lock:
                values = list(info)
                values[1] = recorded["inode"]
                values[2] = recorded["device"]
                values[9] = info.st_ctime + 60
                return os.stat_result(values, {
                    "st_atime_ns": info.st_atime_ns,
                    "st_mtime_ns": info.st_mtime_ns,
                    "st_ctime_ns": info.st_ctime_ns + 60_000_000_000,
                })
            return info

        self.helper_module.os.lstat = same_inode_replacement
        try:
            with self.assertRaisesRegex(
                self.helper_module.SecurityError,
                "pre-created lock identity was replaced",
            ):
                self.subject._attest_lock_inodes(DEPLOYMENT_ID)
        finally:
            self.helper_module.os.lstat = real_lstat

    def test_normal_helper_rejects_non_integer_lock_identity_values(self):
        manifest = json.loads(self.layout.lock_manifest_path.read_text())
        manifest["shared"]["device"] = float(manifest["shared"]["device"])
        self.layout.lock_manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
        )

        with self.assertRaisesRegex(
            self.helper_module.SecurityError,
            "malformed lock inode identity",
        ):
            self.subject._attest_lock_inodes(DEPLOYMENT_ID)

    def test_normal_helper_rejects_malformed_unrelated_deployment_evidence(self):
        manifest = json.loads(self.layout.lock_manifest_path.read_text())
        manifest["deployments"]["other-app--production"] = {
            "project": {"device": 1, "inode": 2},
            "release": {"device": 3, "inode": 4, "ctime_ns": 5},
            "unexpected": {},
        }
        self.layout.lock_manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
        )

        with self.assertRaisesRegex(
            self.helper_module.SecurityError,
            "malformed deployment lock evidence",
        ):
            self.subject._attest_lock_inodes(DEPLOYMENT_ID)

    def _assert_fixed_lock_mode_drift_rejected(self, lock_path, drifted_mode):
        os.chmod(lock_path, drifted_mode)
        with self.assertRaisesRegex(
            self.helper_module.SecurityError,
            "pre-created lock metadata drift",
        ):
            self._apply_with_release_lock()

    def test_normal_helper_rejects_shared_lock_mode_drift(self):
        self._assert_fixed_lock_mode_drift_rejected(self.layout.shared_lock, 0o640)

    def test_normal_helper_rejects_project_lock_mode_drift(self):
        self._assert_fixed_lock_mode_drift_rejected(
            self.layout.project_lock(DEPLOYMENT_ID), 0o640,
        )

    def test_normal_helper_rejects_release_lock_mode_drift(self):
        self._assert_fixed_lock_mode_drift_rejected(
            self.layout.release_lock(DEPLOYMENT_ID), 0o600,
        )

    def test_trusted_chain_rejects_cross_device_controlled_component(self):
        real_lstat = self.helper_module.os.lstat
        changed = self.layout.infra_root / "managed"

        def different_device(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if not args and not kwargs and Path(path) == changed:
                values = list(info)
                values[2] = info.st_dev + 1
                return os.stat_result(values)
            return info

        self.helper_module.os.lstat = different_device
        try:
            with self.assertRaises(self.helper_module.SecurityError):
                self._apply_with_release_lock()
        finally:
            self.helper_module.os.lstat = real_lstat

    def test_normal_helper_treats_the_old_var_lock_alias_as_untrusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "var").mkdir()
            (root / "run" / "lock" / "deploydesk").mkdir(parents=True)
            (root / "var" / "lock").symlink_to(
                "../run/lock", target_is_directory=True,
            )

            with self.assertRaisesRegex(
                self.helper_module.SecurityError, "unexpected symlink",
            ):
                self.helper_module._verify_trusted_chain(
                    root / "var" / "lock" / "deploydesk",
                    root,
                    self.helper_module.TrustPolicy(owner_uid=os.getuid()),
                    "directory",
                )

    def test_maintenance_state_created_while_waiting_for_shared_lock_blocks_apply(self):
        before_generation = self.layout.current_generation().name
        original_locked = self.helper_module._locked
        injected = [False]

        @contextlib.contextmanager
        def inject_maintenance_state(path, trust):
            with original_locked(path, trust) as descriptor:
                if Path(path) == self.layout.shared_lock and not injected[0]:
                    self.layout.maintenance_transaction_path.write_text("injected\n")
                    os.chmod(self.layout.maintenance_transaction_path, 0o600)
                    injected[0] = True
                yield descriptor

        self.helper_module._locked = inject_maintenance_state
        try:
            with self.assertRaisesRegex(
                self.helper_module.RecoveryRequired,
                "helper maintenance state blocks normal releases",
            ):
                self._apply_with_release_lock()
        finally:
            self.helper_module._locked = original_locked
        self.assertTrue(injected[0])
        self.assertEqual(before_generation, self.layout.current_generation().name)
        self.assertFalse(self.layout.transaction_path.exists())
        self.assertFalse(self.layout.history_path.exists())
        self.assertEqual([], list(self.layout.intake_root.iterdir()))

    def _assert_lock_replacement_while_waiting_for_shared_is_rejected(self, lock_path, mode):
        original_locked = self.helper_module._locked
        injected = [False]

        @contextlib.contextmanager
        def replace_lock_after_shared_acquisition(path, trust):
            with original_locked(path, trust) as descriptor:
                if Path(path) == self.layout.shared_lock and not injected[0]:
                    retained = lock_path.with_name(lock_path.name + ".retained")
                    lock_path.rename(retained)
                    lock_path.write_bytes(b"")
                    os.chmod(lock_path, mode)
                    injected[0] = True
                yield descriptor

        self.helper_module._locked = replace_lock_after_shared_acquisition
        try:
            with self.assertRaisesRegex(
                self.helper_module.SecurityError,
                "pre-created lock identity was replaced",
            ):
                self._apply_with_release_lock()
        finally:
            self.helper_module._locked = original_locked
        self.assertTrue(injected[0])
        self.assertEqual([], list(self.layout.intake_root.iterdir()))
        self.assertFalse(self.layout.transaction_path.exists())

    def test_project_lock_replaced_while_waiting_for_shared_is_rejected(self):
        self._assert_lock_replacement_while_waiting_for_shared_is_rejected(
            self.layout.project_lock(DEPLOYMENT_ID), 0o600,
        )

    def test_release_lock_replaced_while_waiting_for_shared_is_rejected(self):
        self._assert_lock_replacement_while_waiting_for_shared_is_rejected(
            self.layout.release_lock(DEPLOYMENT_ID), 0o640,
        )

    def test_invalid_snapshot_evidence_leaves_no_intake_orphans(self):
        manifest_path = (
            self.layout.bundle_root / DEPLOYMENT_ID / self.bundle_id / "server-manifest.json"
        )
        manifest = json.loads(manifest_path.read_text())
        manifest["unexpected"] = True
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        before_generation = self.layout.current_generation().name
        for _ in range(2):
            with self.assertRaises(self.helper_module.ContractError):
                self._apply_with_release_lock()
            self.assertEqual([], list(self.layout.intake_root.iterdir()))
            self.assertEqual(before_generation, self.layout.current_generation().name)
            self.assertFalse(self.layout.transaction_path.exists())
            self.assertFalse(self.layout.history_path.exists())

    def test_prepared_validation_failure_leaves_no_intake_or_generation_orphans(self):
        before_generation = self.layout.current_generation().name
        before_generations = {path.name for path in self.layout.generations_root.iterdir()}

        def fail_validation(generation):
            raise RuntimeError("injected pre-transaction validation failure")

        self.runtime.validate = fail_validation
        with self.assertRaisesRegex(RuntimeError, "injected pre-transaction validation failure"):
            self._apply_with_release_lock()
        self.assertEqual([], list(self.layout.intake_root.iterdir()))
        self.assertEqual(
            before_generations,
            {path.name for path in self.layout.generations_root.iterdir()},
        )
        self.assertEqual(before_generation, self.layout.current_generation().name)
        self.assertFalse(self.layout.transaction_path.exists())
        self.assertFalse(self.layout.history_path.exists())

    def test_existing_recovery_marker_never_leaks_new_intake(self):
        self.layout.recovery_marker.write_text("administrator review required\n")
        os.chmod(self.layout.recovery_marker, 0o600)
        for _ in range(2):
            with self.assertRaisesRegex(
                self.helper_module.RecoveryRequired,
                "caddy-recovery-required blocks normal releases",
            ):
                self._apply_with_release_lock()
            self.assertEqual([], list(self.layout.intake_root.iterdir()))

    def test_shared_lock_revalidation_failure_leaves_no_intake(self):
        original_locked = self.helper_module._locked
        injected = [False]

        @contextlib.contextmanager
        def drift_helper_after_shared_lock(path, trust):
            with original_locked(path, trust) as descriptor:
                if Path(path) == self.layout.shared_lock and not injected[0]:
                    self.layout.helper_path.write_text(
                        self.layout.helper_path.read_text() + "\n# injected drift\n"
                    )
                    injected[0] = True
                yield descriptor

        self.helper_module._locked = drift_helper_after_shared_lock
        try:
            with self.assertRaises(self.helper_module.AttestationError):
                self._apply_with_release_lock()
        finally:
            self.helper_module._locked = original_locked
        self.assertTrue(injected[0])
        self.assertEqual([], list(self.layout.intake_root.iterdir()))
        self.assertFalse(self.layout.transaction_path.exists())

    def test_bundle_symlink_and_hardlink_inputs_fail_closed(self):
        archive = self.layout.bundle_root / DEPLOYMENT_ID / self.bundle_id / "deploy-bundle.tar.gz"
        original = archive.read_bytes()
        archive.unlink()
        outside = self.root / "outside.archive"
        outside.write_bytes(original)
        archive.symlink_to(outside)
        with self.assertRaises(self.helper_module.SecurityError):
            self._apply_with_release_lock()
        archive.unlink()
        os.link(outside, archive)
        with self.assertRaises(self.helper_module.SecurityError):
            self._apply_with_release_lock()

    def test_bundle_parent_symlink_fails_beneath_walk(self):
        project_anchor = self.layout.bundle_root / DEPLOYMENT_ID
        moved = self.layout.root / "moved-project-bundles"
        project_anchor.rename(moved)
        project_anchor.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(self.helper_module.SecurityError):
            self._apply_with_release_lock()

    def test_raw_archive_hash_must_equal_bundle_id(self):
        archive = self.layout.bundle_root / DEPLOYMENT_ID / self.bundle_id / "deploy-bundle.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"tamper")
        with self.assertRaises(self.helper_module.SecurityError):
            self._apply_with_release_lock()

    def test_inline_root_config_blocks_normal_release(self):
        root_config = self.layout.infra_root / "Caddyfile"
        root_config.write_text(root_config.read_text() + "unowned.example.test { respond 200 }\n")
        with self.assertRaises(self.helper_module.MaintenanceRequired):
            self._apply_with_release_lock()

    def test_cross_project_hostname_conflict_is_rejected(self):
        manifest_path = self.layout.current_generation() / "manifests" / "other-app--production.json"
        os.chmod(manifest_path, 0o600)
        manifest = json.loads(manifest_path.read_text())
        manifest["hosts"] = ["app.example.test"]
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        os.chmod(manifest_path, 0o400)
        with self.assertRaises(self.helper_module.OwnershipError):
            self._apply_with_release_lock()

    def test_legacy_opaque_owner_cannot_be_modified_or_claimed(self):
        manifest_path = self.layout.current_generation() / "manifests" / f"{DEPLOYMENT_ID}.json"
        opaque = json.loads((FIXTURE / "legacy-opaque-manifest.json").read_text())
        os.chmod(manifest_path.parent, 0o700)
        os.chmod(self.layout.current_generation() / "sites", 0o700)
        manifest_path.write_text(json.dumps(opaque, sort_keys=True) + "\n")
        (self.layout.current_generation() / "sites" / f"{DEPLOYMENT_ID}.caddy").write_text("opaque bytes\n")
        os.chmod(manifest_path, 0o400)
        os.chmod(self.layout.current_generation() / "sites" / f"{DEPLOYMENT_ID}.caddy", 0o400)
        os.chmod(manifest_path.parent, 0o500)
        os.chmod(self.layout.current_generation() / "sites", 0o500)
        with self.assertRaises(self.helper_module.MaintenanceRequired):
            self._apply_with_release_lock()

    def test_normal_bundle_cannot_mint_baseline_provenance(self):
        manifest_path = self.layout.bundle_root / DEPLOYMENT_ID / self.bundle_id / "server-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source"] = {"kind": "baseline_import"}
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        with self.assertRaises(self.helper_module.MaintenanceRequired):
            self._apply_with_release_lock()


if __name__ == "__main__":
    unittest.main()
