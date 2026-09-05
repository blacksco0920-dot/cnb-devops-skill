import importlib.util
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
import json


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "deploydesk_caddy_apply.py"
INSTALLER_PATH = ROOT / "scripts" / "install_shared_caddy_helper.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "installer not implemented yet")
class SharedCaddyInstallerTests(unittest.TestCase):
    def setUp(self):
        self.helper = load(HELPER_PATH, "installer_helper")
        self.installer = load(INSTALLER_PATH, "installer_subject")
        self.tempdir = tempfile.TemporaryDirectory()
        self.layout = self.helper.Layout.for_test_root(Path(self.tempdir.name))

    def tearDown(self):
        self.tempdir.cleanup()

    def bootstrap(self, **kwargs):
        return self.installer.bootstrap_host(self.layout, owner_uid=os.getuid(), **kwargs)

    def install(self):
        return self.installer.install_helper(
            self.layout, HELPER_PATH,
            expected_sha256=hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(),
            owner_uid=os.getuid(),
        )

    def test_host_and_test_layout_use_the_persistent_deploydesk_lock_root(self):
        expected_host_root = Path("/var/lib/deploydesk/locks")
        self.assertEqual(expected_host_root, self.helper.Layout.for_host().lock_root)
        self.assertEqual(expected_host_root, self.installer.Layout.for_host().lock_root)
        self.assertEqual(
            self.layout.root / "var" / "lib" / "deploydesk" / "locks",
            self.layout.lock_root,
        )

    def test_bootstrap_ignores_volatile_group_writable_ubuntu_var_lock_alias(self):
        (self.layout.root / "var").mkdir()
        (self.layout.root / "run" / "lock").mkdir(parents=True)
        os.chmod(self.layout.root / "run" / "lock", 0o775)
        (self.layout.root / "var" / "lock").symlink_to(
            "../run/lock", target_is_directory=True,
        )

        self.bootstrap()

        self.assertTrue(self.layout.shared_lock.is_file())
        self.assertTrue(
            (self.layout.root / "var" / "lib" / "deploydesk" / "locks" / "shared-caddy.lock").is_file()
        )
        self.assertFalse(
            (self.layout.root / "run" / "lock" / "deploydesk" / "shared-caddy.lock").exists()
        )

    def test_installer_walker_treats_the_old_var_lock_alias_as_untrusted(self):
        root = self.layout.root
        (root / "var").mkdir()
        (root / "run" / "lock").mkdir(parents=True)
        (root / "var" / "lock").symlink_to(
            "../run/lock", target_is_directory=True,
        )

        with self.installer.TrustedInstallerWalker(root, os.getuid()) as walker:
            with self.assertRaisesRegex(
                self.installer.InstallError,
                "unexpected symlink or non-directory",
            ):
                walker.ensure_dir(root / "var" / "lock")

    def test_install_creates_fixed_layout_attestation_and_immutable_locks(self):
        self.bootstrap()
        self.install()
        self.installer.provision_deployments(
            self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid()
        )
        self.assertTrue(self.layout.helper_path.is_file())
        self.assertTrue(self.layout.shared_lock.is_file())
        self.assertTrue(self.layout.project_lock("sample-app--staging").is_file())
        self.assertTrue(self.layout.release_lock("sample-app--staging").is_file())
        contract = self.helper.read_json(self.layout.contract_path)
        self.assertEqual(self.helper.sha256_file(self.layout.helper_path), contract["helper_sha256"])
        self.assertEqual("shared-caddy-contract/v1", contract["contract_version"])

    def test_installer_refuses_wrong_source_hash_and_symlink_destination(self):
        self.bootstrap()
        with self.assertRaises(self.installer.InstallError):
            self.installer.install_helper(
                self.layout, HELPER_PATH, expected_sha256="0" * 64,
                owner_uid=os.getuid()
            )
        self.layout.helper_path.parent.mkdir(parents=True, exist_ok=True)
        outside = self.layout.root / "outside"
        outside.write_text("untouched")
        self.layout.helper_path.symlink_to(outside)
        with self.assertRaises(self.installer.InstallError):
            self.installer.install_helper(
                self.layout, HELPER_PATH,
                expected_sha256=hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(),
                owner_uid=os.getuid()
            )
        self.assertEqual("untouched", outside.read_text())

    def test_installer_refuses_symlinked_parent_before_writing_outside_root(self):
        outside = Path(self.tempdir.name) / "outside-root"
        outside.mkdir()
        (self.layout.root / "opt").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.installer.InstallError):
            self.installer.bootstrap_host(
                self.layout, owner_uid=os.getuid()
            )
        self.assertFalse((outside / "infra" / "caddy" / "contract.json").exists())

    def test_runtime_mount_change_requires_separate_baseline_maintenance(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        with self.assertRaises(self.installer.InstallError):
            self.installer.install(
                self.layout, HELPER_PATH, expected_sha256=approved_hash,
                owner_uid=os.getuid(),
                caddy_container="new-proxy", container_config_root="/srv/new-config",
            )
        contract = self.helper.read_json(self.layout.contract_path)
        self.assertEqual("/etc/caddy", contract["container_config_root"])

    def test_container_identity_change_alone_requires_separate_maintenance(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        with self.assertRaises(self.installer.InstallError):
            self.installer.install(
                self.layout, HELPER_PATH, approved_hash, owner_uid=os.getuid(),
                caddy_container="new-proxy", container_config_root="/etc/caddy",
            )

    def test_upgrade_rejects_replaced_shared_lock_inode(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        self.layout.shared_lock.unlink()
        self.layout.shared_lock.write_text("")
        os.chmod(self.layout.shared_lock, 0o600)
        with self.assertRaises(self.installer.InstallError):
            self.installer.install(self.layout, HELPER_PATH, approved_hash, owner_uid=os.getuid())

    def test_provision_rejects_replaced_project_or_release_lock_inode(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        for lock_kind in ("project", "release"):
            with self.subTest(lock_kind=lock_kind):
                with tempfile.TemporaryDirectory() as temporary:
                    layout = self.helper.Layout.for_test_root(Path(temporary))
                    self.installer.bootstrap_host(layout, owner_uid=os.getuid())
                    self.installer.install_helper(layout, HELPER_PATH, approved_hash, owner_uid=os.getuid())
                    self.installer.provision_deployments(
                        layout, ["sample-app--staging"], owner_uid=os.getuid(),
                        release_uid=os.getuid(), release_gid=os.getgid(),
                    )
                    lock = (layout.project_lock if lock_kind == "project" else layout.release_lock)("sample-app--staging")
                    lock.unlink()
                    lock.write_text("")
                    os.chmod(lock, 0o600 if lock_kind == "project" else 0o640)
                    with self.assertRaises(self.installer.InstallError):
                        self.installer.provision_deployments(
                            layout, ["sample-app--staging"], owner_uid=os.getuid(),
                            release_uid=os.getuid(), release_gid=os.getgid(),
                        )

    def test_provision_rejects_lock_owner_link_and_exact_mode_drift(self):
        cases = (
            ("shared-mode", "shared", 0o640),
            ("project-link", "project", None),
            ("release-mode", "release", 0o600),
            ("release-owner", "release", None),
        )
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        for label, lock_kind, changed_mode in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                layout = self.helper.Layout.for_test_root(Path(temporary))
                self.installer.bootstrap_host(layout, owner_uid=os.getuid())
                self.installer.install_helper(
                    layout, HELPER_PATH, approved_hash, owner_uid=os.getuid(),
                )
                self.installer.provision_deployments(
                    layout, ["sample-app--staging"], owner_uid=os.getuid(),
                    release_uid=os.getuid(), release_gid=os.getgid(),
                )
                lock = {
                    "shared": layout.shared_lock,
                    "project": layout.project_lock("sample-app--staging"),
                    "release": layout.release_lock("sample-app--staging"),
                }[lock_kind]
                if changed_mode is not None:
                    os.chmod(lock, changed_mode)
                elif label == "project-link":
                    os.link(lock, lock.with_name(lock.name + ".unexpected-link"))
                else:
                    original_stat = self.installer.os.stat
                    target_identity = (os.lstat(lock).st_dev, os.lstat(lock).st_ino)

                    def wrong_owner(path, *args, **kwargs):
                        info = original_stat(path, *args, **kwargs)
                        if (info.st_dev, info.st_ino) == target_identity:
                            values = list(info)
                            values[4] = info.st_uid + 1
                            return os.stat_result(values)
                        return info

                    self.installer.os.stat = wrong_owner
                try:
                    with self.assertRaisesRegex(
                        self.installer.InstallError, "recorded lock metadata drift",
                    ):
                        self.installer.provision_deployments(
                            layout, ["sample-app--staging"], owner_uid=os.getuid(),
                            release_uid=os.getuid(), release_gid=os.getgid(),
                        )
                finally:
                    if label == "release-owner":
                        self.installer.os.stat = original_stat

    def test_provision_adds_inode_evidence_for_genuinely_new_deployment(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        self.installer.provision_deployments(
            self.layout, ["first--staging"], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        before = json.loads(self.layout.lock_manifest_path.read_text())
        self.installer.provision_deployments(
            self.layout, ["second--staging"], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        after = json.loads(self.layout.lock_manifest_path.read_text())
        self.assertEqual(before["shared"], after["shared"])
        self.assertEqual(before["deployments"]["first--staging"], after["deployments"]["first--staging"])
        self.assertIn("second--staging", after["deployments"])

    def test_lock_ctime_identity_survives_open_flock_upgrade_and_reprovision(self):
        approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        self.installer.provision_deployments(
            self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        before = json.loads(self.layout.lock_manifest_path.read_text())
        expected_identities = (
            (self.layout.shared_lock, before["shared"]),
            (
                self.layout.project_lock("sample-app--staging"),
                before["deployments"]["sample-app--staging"]["project"],
            ),
            (
                self.layout.release_lock("sample-app--staging"),
                before["deployments"]["sample-app--staging"]["release"],
            ),
        )
        for path, expected in expected_identities:
            self.assertEqual({"device", "inode", "ctime_ns"}, set(expected))
            with path.open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                opened = os.fstat(lock.fileno())
                self.assertEqual(
                    expected,
                    {
                        "device": opened.st_dev,
                        "inode": opened.st_ino,
                        "ctime_ns": opened.st_ctime_ns,
                    },
                )
                fcntl.flock(lock, fcntl.LOCK_UN)
        self.installer.install(
            self.layout, HELPER_PATH, approved_hash, owner_uid=os.getuid(),
        )
        self.installer.provision_deployments(
            self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        after = json.loads(self.layout.lock_manifest_path.read_text())
        self.assertEqual(before, after)

    def test_concurrent_provision_merges_manifest_under_shared_lock(self):
        self.bootstrap()
        self.install()
        original_open_shared_lock = self.installer._open_shared_lock
        both_loaded_manifest = threading.Barrier(2)
        errors = []

        def synchronized_open(walker, layout, manifest):
            descriptor = original_open_shared_lock(walker, layout, manifest)
            both_loaded_manifest.wait(timeout=5)
            return descriptor

        def provision(deployment_id):
            try:
                self.installer.provision_deployments(
                    self.layout, [deployment_id], owner_uid=os.getuid(),
                    release_uid=os.getuid(), release_gid=os.getgid(),
                )
            except BaseException as exc:
                errors.append(exc)

        self.installer._open_shared_lock = synchronized_open
        threads = [
            threading.Thread(target=provision, args=("first--staging",)),
            threading.Thread(target=provision, args=("second--staging",)),
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
        finally:
            self.installer._open_shared_lock = original_open_shared_lock
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        manifest = json.loads(self.layout.lock_manifest_path.read_text())
        self.assertEqual(
            {"first--staging", "second--staging"},
            set(manifest["deployments"]),
        )

    def test_normal_helper_and_maintenance_installer_have_separate_parsers(self):
        helper_parser = self.helper.build_parser()
        installer_parser = self.installer.build_parser()
        self.assertEqual(
            {"preflight", "deployment_id", "bundle_id"},
            {action.dest for action in helper_parser._actions if action.dest != "help"},
        )
        self.assertIn("maintenance_action", {action.dest for action in installer_parser._actions})

    def test_baseline_maintenance_has_no_application_helper_or_sudo_authority(self):
        installer_parser = self.installer.build_parser()
        self.assertIn("baseline_bundle_id", {action.dest for action in installer_parser._actions})
        self.assertNotIn(
            "baseline_bundle_id",
            {action.dest for action in self.helper.build_parser()._actions},
        )
        rendered = self.installer.render_deployment_sudoers(
            "sample-app--test", "ubuntu", "SAMPLE_APP",
        )
        self.assertEqual(2, rendered.count("Cmnd_Alias"))
        self.assertNotIn("baseline", rendered.lower())
        self.assertNotIn("install-shared-caddy-helper", rendered)

    def test_sudoers_rendering_grants_only_one_deployments_preflight_and_apply(self):
        self.assertEqual(
            (
                "Cmnd_Alias SAMPLE_APP_CADDY_PREFLIGHT = "
                "/usr/local/sbin/deploydesk-caddy-apply ^--preflight "
                "--deployment-id sample-app--test --bundle-id [0-9a-f]{64}$\n"
                "Cmnd_Alias SAMPLE_APP_CADDY_APPLY = "
                "/usr/local/sbin/deploydesk-caddy-apply ^--deployment-id "
                "sample-app--test --bundle-id [0-9a-f]{64}$\n"
                "ubuntu ALL=(root) NOPASSWD: SAMPLE_APP_CADDY_PREFLIGHT, SAMPLE_APP_CADDY_APPLY\n"
            ),
            self.installer.render_deployment_sudoers(
                "sample-app--test", "ubuntu", "SAMPLE_APP",
            ),
        )

    def test_sudoers_rendering_rejects_untrusted_identity_or_alias(self):
        for deployment_id, release_identity, alias in (
            ("sample-app--test --bundle-id x", "ubuntu", "SAMPLE_APP"),
            ("sample-app--test", "ubuntu ALL=(root)", "SAMPLE_APP"),
            ("sample-app--test", "ubuntu", "SAMPLE_APP, ALL"),
        ):
            with self.subTest(
                deployment_id=deployment_id,
                release_identity=release_identity,
                alias=alias,
            ):
                with self.assertRaises(self.installer.InstallError):
                    self.installer.render_deployment_sudoers(
                        deployment_id, release_identity, alias,
                    )

    def test_install_records_approved_runtime_mount_instead_of_hardcoding_target(self):
        self.bootstrap(
            caddy_container="host-shared-proxy",
            container_config_root="/srv/proxy-config",
        )
        contract = self.install()
        self.assertEqual("host-shared-proxy", contract["caddy_container"])
        self.assertEqual("/srv/proxy-config", contract["container_config_root"])
        self.assertIn("/srv/proxy-config/managed/current", (self.layout.infra_root / "Caddyfile").read_text())


if __name__ == "__main__":
    unittest.main()
