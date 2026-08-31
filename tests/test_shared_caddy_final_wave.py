import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
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


class Crash(BaseException):
    pass


def changed_stat(
    info, *, device=None, inode=None, mode=None, nlink=None, uid=None, gid=None,
):
    values = list(info)
    if mode is not None:
        values[0] = mode
    if inode is not None:
        values[1] = inode
    if device is not None:
        values[2] = device
    if nlink is not None:
        values[3] = nlink
    if uid is not None:
        values[4] = uid
    if gid is not None:
        values[5] = gid
    return os.stat_result(values)


class Runtime:
    def __init__(self):
        self.runtime_ok = True
        self.reloads = 0
        self.smokes = 0
        self.validations = 0
        self.network_checks = []

    def ensure_network(self, network, upstream, deployment_id, persist_intent):
        return False

    def verify_network(self, network, upstream, deployment_id):
        self.network_checks.append((network, upstream, deployment_id))
        if not self.runtime_ok:
            raise RuntimeError("injected live runtime mismatch")

    def detach_network(self, network):
        return None

    def validate(self, generation):
        self.validations += 1

    def reload(self):
        self.reloads += 1

    def smoke(self, hosts):
        self.smokes += 1


@unittest.skipUnless(HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "package not implemented")
class FinalWaveInstallerTests(unittest.TestCase):
    def setUp(self):
        self.h = load(HELPER_PATH, "final_installer_helper")
        self.i = load(INSTALLER_PATH, "final_installer_subject")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = self.h.Layout.for_test_root(self.root)
        self.approved_hash = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def bootstrap(self, **kwargs):
        return self.i.bootstrap_host(
            self.layout,
            owner_uid=os.getuid(),
            caddy_container="shared-caddy",
            container_config_root="/etc/caddy",
            **kwargs,
        )

    def install(self, **kwargs):
        return self.i.install_helper(
            self.layout,
            HELPER_PATH,
            self.approved_hash,
            owner_uid=os.getuid(),
            **kwargs,
        )

    def test_installer_does_not_execute_candidate_helper_before_hash_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            isolated_installer = isolated / INSTALLER_PATH.name
            isolated_helper = isolated / HELPER_PATH.name
            marker = isolated / "candidate-executed"
            shutil.copy2(INSTALLER_PATH, isolated_installer)
            isolated_helper.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
            )
            result = subprocess.run(
                [
                    sys.executable, str(isolated_installer),
                    "--maintenance-action", "install-helper",
                    "--expected-helper-sha256", "0" * 64,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())

    def test_install_function_does_not_execute_unapproved_candidate_helper(self):
        self.bootstrap()
        candidate = self.root / "unapproved-helper.py"
        marker = self.root / "candidate-function-executed"
        candidate.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
        )
        with self.assertRaises(self.i.InstallError):
            self.i.install_helper(
                self.layout, candidate, "0" * 64, owner_uid=os.getuid(),
            )
        self.assertFalse(marker.exists())
        self.assertFalse(self.layout.helper_path.exists())
        self.assertFalse(self.layout.contract_path.exists())

    def test_installer_requires_nofollow_directory_and_dirfd_primitives_before_mutation(self):
        self.assertEqual(
            ("open", "stat", "mkdir", "rename", "symlink", "unlink", "readlink", "rmdir"),
            tuple(operation.__name__ for operation in self.i._REQUIRED_DIR_FD_OPERATIONS),
        )
        self.assertEqual(
            ("listdir",),
            tuple(operation.__name__ for operation in self.i._REQUIRED_FD_PATH_OPERATIONS),
        )
        self.assertEqual(
            ("stat",),
            tuple(operation.__name__ for operation in self.i._REQUIRED_NOFOLLOW_OPERATIONS),
        )
        primitive_cases = (
            "O_NOFOLLOW", "O_DIRECTORY", "supports_dir_fd",
            "supports_follow_symlinks", "supports_fd",
        )
        for primitive in primitive_cases:
            with self.subTest(primitive=primitive), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                original = getattr(self.i.os, primitive)
                setattr(
                    self.i.os, primitive,
                    set() if primitive.startswith("supports_") else 0,
                )
                try:
                    with self.assertRaises(self.i.InstallError):
                        self.i.bootstrap_host(
                            layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                            container_config_root="/etc/caddy",
                        )
                finally:
                    setattr(self.i.os, primitive, original)
                self.assertFalse(layout.infra_root.exists())
                self.assertFalse(layout.state_root.exists())

        original = self.i.os.O_NOFOLLOW
        self.i.os.O_NOFOLLOW = 0
        try:
            with self.assertRaises(self.i.InstallError):
                self.i._read_approved_helper(HELPER_PATH, self.approved_hash)
        finally:
            self.i.os.O_NOFOLLOW = original

    def test_installer_embedded_contract_matches_helper_contract_surface(self):
        self.assertEqual(self.h.CONTRACT_VERSION, self.i.CONTRACT_VERSION)
        self.assertEqual(self.h.HELPER_VERSION, self.i.HELPER_VERSION)
        for name in (
            "DEPLOYMENT_RE", "SHA256_RE", "SAFE_RUNTIME_NAME_RE", "CONFIG_ROOT_RE",
        ):
            self.assertEqual(getattr(self.h, name).pattern, getattr(self.i, name).pattern)

        helper_layout = self.h.Layout.for_host()
        installer_layout = self.i.Layout.for_host()
        for name in (
            "root", "infra_root", "state_root", "lock_root", "bundle_root",
            "helper_path", "managed_root", "generations_root", "current_link",
            "contract_path", "transaction_path", "history_path", "recovery_marker",
            "bootstrap_attestation_path", "maintenance_transaction_path",
            "maintenance_recovery_marker", "maintenance_root", "intake_root",
            "receipts_root", "shared_lock", "lock_manifest_path",
        ):
            self.assertEqual(getattr(helper_layout, name), getattr(installer_layout, name))

        valid_contract = {
            "contract_version": self.h.CONTRACT_VERSION,
            "helper_version": self.h.HELPER_VERSION,
            "helper_sha256": "a" * 64,
            "caddy_container": "shared-caddy",
            "container_config_root": "/etc/caddy",
        }
        valid_attestation = {
            "schema_version": "shared-caddy-host-bootstrap/v1",
            "contract_version": self.h.CONTRACT_VERSION,
            "caddy_container": "shared-caddy",
            "container_config_root": "/etc/caddy",
            "initial_generation": "gen-" + "b" * 32,
            "initial_current_target": "generations/gen-" + "b" * 32,
            "root_config_sha256": "c" * 64,
            "server_options_sha256": "d" * 64,
            "shared_lock_device": 1,
            "shared_lock_inode": 2,
        }
        cases = (
            ("validate_deployment_id", "sample-app--staging"),
            ("validate_deployment_id", "Sample-App--staging"),
            ("validate_bundle_id", "e" * 64),
            ("validate_bundle_id", "E" * 64),
            ("validate_server_contract", valid_contract),
            ("validate_server_contract", {**valid_contract, "unknown": True}),
            ("validate_bootstrap_attestation", valid_attestation),
            (
                "validate_bootstrap_attestation",
                {**valid_attestation, "initial_current_target": "generations/gen-" + "f" * 32},
            ),
        )
        for name, value in cases:
            with self.subTest(name=name, value=value):
                outcomes = []
                for module in (self.h, self.i):
                    try:
                        getattr(module, name)(copy.deepcopy(value))
                    except module.ContractError:
                        outcomes.append(False)
                    else:
                        outcomes.append(True)
                self.assertEqual(outcomes[0], outcomes[1])

    def test_bootstrap_and_helper_install_are_separate_authorities(self):
        evidence = self.bootstrap()
        self.assertEqual("shared-caddy-host-bootstrap/v1", evidence["schema_version"])
        self.assertTrue(self.layout.current_link.is_symlink())
        self.assertFalse(self.layout.helper_path.exists())
        self.assertFalse(self.layout.contract_path.exists())
        before_current = os.readlink(self.layout.current_link)
        before_root = (self.layout.infra_root / "Caddyfile").read_bytes()
        contract = self.install()
        self.assertEqual(self.approved_hash, contract["helper_sha256"])
        self.assertEqual(before_current, os.readlink(self.layout.current_link))
        self.assertEqual(before_root, (self.layout.infra_root / "Caddyfile").read_bytes())

    def test_install_helper_refuses_unbootstrapped_host_without_mutation(self):
        with self.assertRaises(self.i.InstallError):
            self.install()
        self.assertFalse(self.layout.helper_path.exists())
        self.assertFalse(self.layout.contract_path.exists())
        self.assertFalse(self.layout.current_link.exists())

    def test_install_helper_rejects_app_recovery_or_maintenance_state_before_mutation(self):
        blockers = (
            self.layout.transaction_path,
            self.layout.recovery_marker,
            self.layout.maintenance_transaction_path,
            self.layout.maintenance_recovery_marker,
        )
        for blocker in blockers:
            with self.subTest(blocker=blocker.name), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )
                blocker_path = getattr(layout, {
                    "transaction.json": "transaction_path",
                    "caddy-recovery-required": "recovery_marker",
                    "maintenance-transaction.json": "maintenance_transaction_path",
                    "maintenance-recovery-required": "maintenance_recovery_marker",
                }[blocker.name])
                blocker_path.write_text("blocked\n")
                with self.assertRaises(self.i.InstallError):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid()
                    )
                self.assertFalse(layout.helper_path.exists())
                self.assertFalse(layout.contract_path.exists())

    def test_bootstrap_fsyncs_generation_tree_pointer_root_and_evidence_in_order(self):
        events = []
        original = self.i._fsync_descriptor

        def record(descriptor, evidence_path):
            events.append(str(evidence_path))
            return original(descriptor, evidence_path)

        self.i._fsync_descriptor = record
        try:
            self.bootstrap()
        finally:
            self.i._fsync_descriptor = original
        joined = "\n".join(events)
        for suffix in (
            "/managed/generations/gen-00000000000000000000000000000000/sites",
            "/managed/generations/gen-00000000000000000000000000000000/manifests",
            "/managed/generations/gen-00000000000000000000000000000000",
            "/managed/generations",
            "/managed",
            "/caddy/Caddyfile",
            "/caddy/bootstrap-attestation.json",
        ):
            self.assertIn(suffix, joined)

    def test_controller_parent_replacement_during_open_blocks_handoff_mutation(self):
        parent = self.root / "controllers"
        parent.mkdir()
        old_parent = self.root / "old-controllers"
        target = parent / "sample-app--staging"
        original_open = self.i.os.open
        replaced = [False]

        def replace_parent_after_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            if path == parent.name and kwargs.get("dir_fd") is not None and not replaced[0]:
                parent.rename(old_parent)
                parent.mkdir()
                replaced[0] = True
            return descriptor

        self.i.os.open = replace_parent_after_open
        try:
            with self.i.TrustedInstallerWalker(self.root, os.getuid()) as walker:
                with self.assertRaisesRegex(
                    self.i.InstallError, "retained maintenance ancestor was replaced",
                ):
                    walker.handoff_directory(
                        target, os.getuid(), os.getgid(), 0o700,
                    )
        finally:
            self.i.os.open = original_open
        self.assertTrue(replaced[0])
        self.assertFalse(target.exists())
        self.assertFalse((old_parent / target.name).exists())

    def test_group_writable_ancestor_is_rejected_before_bootstrap_write(self):
        (self.root / "opt").mkdir(mode=0o775)
        os.chmod(self.root / "opt", 0o775)
        with self.assertRaises(self.i.InstallError):
            self.bootstrap()
        self.assertFalse((self.root / "opt" / "infra").exists())

    def test_cross_device_component_is_rejected(self):
        original_open = self.i.os.open
        original_close = self.i.os.close
        original_fstat = self.i.os.fstat
        original_stat = self.i.os.stat
        cross_device_fds = set()
        cross_device = original_stat(self.root).st_dev + 29

        def record_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            parent_fd = kwargs.get("dir_fd")
            if (path == "infra" and parent_fd is not None) or parent_fd in cross_device_fds:
                cross_device_fds.add(descriptor)
            return descriptor

        def changed_device(descriptor):
            info = original_fstat(descriptor)
            if descriptor in cross_device_fds:
                return changed_stat(info, device=cross_device)
            return info

        def changed_entry(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            parent_fd = kwargs.get("dir_fd")
            if (path == "infra" and parent_fd is not None) or parent_fd in cross_device_fds:
                return changed_stat(info, device=cross_device)
            return info

        def record_close(descriptor):
            cross_device_fds.discard(descriptor)
            return original_close(descriptor)

        self.i.os.open = record_open
        self.i.os.close = record_close
        self.i.os.fstat = changed_device
        self.i.os.stat = changed_entry
        try:
            with self.assertRaisesRegex(
                self.i.InstallError,
                r"maintenance path crosses a device boundary: .*/opt/infra$",
            ):
                self.bootstrap()
        finally:
            self.i.os.open = original_open
            self.i.os.close = original_close
            self.i.os.fstat = original_fstat
            self.i.os.stat = original_stat

    def test_rejected_root_and_component_opens_close_their_descriptors(self):
        def assert_closed(descriptor, original_fstat, original_close):
            try:
                original_fstat(descriptor)
            except OSError:
                return
            original_close(descriptor)
            self.fail("rejected directory descriptor remained open")

        original_open = self.i.os.open
        original_fstat = self.i.os.fstat
        original_close = self.i.os.close
        opened = []

        def record_open(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            opened.append((str(path), descriptor))
            return descriptor

        original_check = self.i.TrustedInstallerWalker._check_directory

        def reject_root(walker, info, display):
            if Path(display) == self.root:
                raise self.i.InstallError("injected root rejection")
            return original_check(walker, info, display)

        self.i.os.open = record_open
        self.i.TrustedInstallerWalker._check_directory = reject_root
        try:
            with self.assertRaisesRegex(self.i.InstallError, "injected root rejection"):
                self.i.TrustedInstallerWalker(self.root, os.getuid())
        finally:
            self.i.TrustedInstallerWalker._check_directory = original_check
            self.i.os.open = original_open
        root_descriptor = opened[-1][1]
        assert_closed(root_descriptor, original_fstat, original_close)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rejected_path = root / "opt"
            rejected_path.mkdir()
            opened = []
            self.i.os.open = record_open
            walker = self.i.TrustedInstallerWalker(root, os.getuid())
            original_instance_check = walker._check_directory

            def reject_component(info, display):
                if Path(display) == rejected_path:
                    raise self.i.InstallError("injected component rejection")
                return original_instance_check(info, display)

            walker._check_directory = reject_component
            try:
                with self.assertRaisesRegex(
                    self.i.InstallError, "injected component rejection",
                ):
                    walker.ensure_dir(rejected_path)
                rejected_descriptors = [
                    descriptor for name, descriptor in opened if name == "opt"
                ]
                self.assertEqual(1, len(rejected_descriptors))
                assert_closed(
                    rejected_descriptors[0], original_fstat, original_close,
                )
            finally:
                walker.close()
                self.i.os.open = original_open

    def test_root_provision_hands_off_controller_without_invalidating_walker(self):
        self.bootstrap()
        self.install()
        original_geteuid = self.i.os.geteuid
        original_fchown = self.i.os.fchown
        original_chown = self.i.os.chown
        original_fstat = self.i.os.fstat
        original_stat = self.i.os.stat
        release_uid = os.getuid() + 1000
        release_gid = os.getgid() + 1000
        simulated_owners = {}
        deployment_ids = (DEPLOYMENT_ID, "sample-api--staging")
        controller_handoffs = []
        release_lock_handoffs = []

        def controlled_path_chown(path, uid, gid, *args, **kwargs):
            raise AssertionError("provisioning handoffs must use opened descriptors")

        def record_fchown(descriptor, uid, gid):
            info = original_fstat(descriptor)
            simulated_owners[(info.st_dev, info.st_ino)] = (uid, gid)
            target = (info.st_dev, info.st_ino, uid, gid)
            if stat.S_ISDIR(info.st_mode):
                controller_handoffs.append(target)
            else:
                release_lock_handoffs.append(target)

        def owned_fstat(descriptor):
            info = original_fstat(descriptor)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        def owned_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        self.i.os.geteuid = lambda: 0
        self.i.os.fchown = record_fchown
        self.i.os.chown = controlled_path_chown
        self.i.os.fstat = owned_fstat
        self.i.os.stat = owned_stat
        try:
            for _ in range(2):
                self.i.provision_deployments(
                    self.layout, deployment_ids, owner_uid=os.getuid(),
                    release_uid=release_uid, release_gid=release_gid,
                )
        finally:
            self.i.os.geteuid = original_geteuid
            self.i.os.fchown = original_fchown
            self.i.os.chown = original_chown
            self.i.os.fstat = original_fstat
            self.i.os.stat = original_stat
        manifest = json.loads(self.layout.lock_manifest_path.read_text())
        self.assertEqual(set(deployment_ids), set(manifest["deployments"]))
        self.assertEqual(2, len(controller_handoffs))
        self.assertEqual(2, len(release_lock_handoffs))

    def test_root_provision_retries_root_owned_controller_after_handoff_failure(self):
        self.bootstrap()
        self.install()
        original_geteuid = self.i.os.geteuid
        original_fchown = self.i.os.fchown
        original_chown = self.i.os.chown
        original_fstat = self.i.os.fstat
        original_stat = self.i.os.stat
        release_uid = os.getuid() + 1000
        release_gid = os.getgid() + 1000
        simulated_owners = {}
        failures = [True]

        def path_chown(path, uid, gid, *args, **kwargs):
            raise AssertionError("provisioning handoffs must use opened descriptors")

        def descriptor_chown(descriptor, uid, gid):
            info = original_fstat(descriptor)
            if stat.S_ISDIR(info.st_mode) and failures:
                failures.pop()
                raise OSError("injected controller handoff failure")
            simulated_owners[(info.st_dev, info.st_ino)] = (uid, gid)

        def owned_fstat(descriptor):
            info = original_fstat(descriptor)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        def owned_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        self.i.os.geteuid = lambda: 0
        self.i.os.fchown = descriptor_chown
        self.i.os.chown = path_chown
        self.i.os.fstat = owned_fstat
        self.i.os.stat = owned_stat
        try:
            with self.assertRaisesRegex(self.i.InstallError, "controller directory handoff failed"):
                self.i.provision_deployments(
                    self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
                    release_uid=release_uid, release_gid=release_gid,
                )
            manifest = json.loads(self.layout.lock_manifest_path.read_text())
            self.assertIn(DEPLOYMENT_ID, manifest["deployments"])
            self.i.provision_deployments(
                self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
                release_uid=release_uid, release_gid=release_gid,
            )
        finally:
            self.i.os.geteuid = original_geteuid
            self.i.os.fchown = original_fchown
            self.i.os.chown = original_chown
            self.i.os.fstat = original_fstat
            self.i.os.stat = original_stat

    def test_root_provision_rejects_ineffective_controller_handoff(self):
        self.bootstrap()
        self.install()
        original_geteuid = self.i.os.geteuid
        original_fchown = self.i.os.fchown
        original_chown = self.i.os.chown
        original_fstat = self.i.os.fstat
        original_stat = self.i.os.stat
        simulated_owners = {}

        def no_path_handoff(path, uid, gid, *args, **kwargs):
            raise AssertionError("provisioning handoffs must use opened descriptors")

        def selective_fchown(descriptor, uid, gid):
            info = original_fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                simulated_owners[(info.st_dev, info.st_ino)] = (uid, gid)

        def owned_fstat(descriptor):
            info = original_fstat(descriptor)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        def owned_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            owner = simulated_owners.get((info.st_dev, info.st_ino))
            return changed_stat(info, uid=owner[0], gid=owner[1]) if owner is not None else info

        self.i.os.geteuid = lambda: 0
        self.i.os.fchown = selective_fchown
        self.i.os.chown = no_path_handoff
        self.i.os.fstat = owned_fstat
        self.i.os.stat = owned_stat
        try:
            with self.assertRaisesRegex(self.i.InstallError, "controller directory handoff"):
                self.i.provision_deployments(
                    self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
                    release_uid=os.getuid() + 1000, release_gid=os.getgid() + 1000,
                )
        finally:
            self.i.os.geteuid = original_geteuid
            self.i.os.fchown = original_fchown
            self.i.os.chown = original_chown
            self.i.os.fstat = original_fstat
            self.i.os.stat = original_stat

    def test_root_provision_rejects_ineffective_release_lock_handoff(self):
        self.bootstrap()
        self.install()
        original_geteuid = self.i.os.geteuid
        original_fchown = self.i.os.fchown
        original_chown = self.i.os.chown
        self.i.os.geteuid = lambda: 0
        self.i.os.fchown = lambda descriptor, uid, gid: None
        self.i.os.chown = lambda path, uid, gid, *args, **kwargs: None
        try:
            with self.assertRaisesRegex(self.i.InstallError, "release lock handoff"):
                self.i.provision_deployments(
                    self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
                    release_uid=os.getuid(), release_gid=os.getgid() + 1000,
                )
        finally:
            self.i.os.geteuid = original_geteuid
            self.i.os.fchown = original_fchown
            self.i.os.chown = original_chown

    def test_release_lock_handoff_rejects_mode_and_entry_identity_drift(self):
        for variant in ("mode", "entry-inode"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lock_root = root / "locks"
                lock_root.mkdir()
                target = lock_root / "sample.release.lock"
                target.write_bytes(b"")
                os.chmod(target, 0o600)
                original_fchmod = self.i.os.fchmod
                original_stat = self.i.os.stat
                target_lstats = [0]

                def ineffective_mode(descriptor, mode):
                    return original_fchmod(descriptor, 0o600)

                def replaced_entry(path, *args, **kwargs):
                    info = original_stat(path, *args, **kwargs)
                    if (
                        str(path) == target.name
                        and kwargs.get("dir_fd") is not None
                        and kwargs.get("follow_symlinks") is False
                    ):
                        target_lstats[0] += 1
                        if target_lstats[0] > 1:
                            return changed_stat(info, inode=info.st_ino + 1)
                    return info

                if variant == "mode":
                    self.i.os.fchmod = ineffective_mode
                else:
                    self.i.os.stat = replaced_entry
                try:
                    with self.i.TrustedInstallerWalker(root, os.getuid()) as walker:
                        walker.ensure_dir(lock_root)
                        with self.assertRaisesRegex(
                            self.i.InstallError,
                            "release lock handoff postcondition failed",
                        ):
                            walker.handoff_regular_file(
                                target, os.getuid(), os.getgid(), 0o640,
                            )
                finally:
                    self.i.os.fchmod = original_fchmod
                    self.i.os.stat = original_stat

    def test_release_lock_handoff_open_uses_nofollow(self):
        nofollow = getattr(self.i.os, "O_NOFOLLOW", 0)
        if not nofollow:
            self.skipTest("platform has no O_NOFOLLOW")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_root = root / "locks"
            lock_root.mkdir()
            target = lock_root / "sample.release.lock"
            target.write_bytes(b"")
            os.chmod(target, 0o640)
            original_open = self.i.os.open
            target_flags = []

            def record_open(path, flags, *args, **kwargs):
                if str(path) == target.name and kwargs.get("dir_fd") is not None:
                    target_flags.append(flags)
                return original_open(path, flags, *args, **kwargs)

            self.i.os.open = record_open
            try:
                with self.i.TrustedInstallerWalker(root, os.getuid()) as walker:
                    walker.ensure_dir(lock_root)
                    walker.handoff_regular_file(
                        target, os.getuid(), os.getgid(), 0o640,
                    )
            finally:
                self.i.os.open = original_open
            self.assertEqual(1, len(target_flags))
            self.assertTrue(target_flags[0] & nofollow)

    def test_controller_handoff_rejects_wrong_gid_mode_and_replaced_entry(self):
        variants = ("gid", "mode", "inode", "device")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                parent = root / "controllers"
                parent.mkdir()
                target = parent / "sample-app--staging"
                target_uid = os.getuid() + 1000
                target_gid = os.getgid() + 1000
                original_fchown = self.i.os.fchown
                original_fchmod = self.i.os.fchmod
                original_fstat = self.i.os.fstat
                original_stat = self.i.os.stat
                original_open = self.i.os.open
                simulated_owners = {}
                replaced_identity = [None]
                controller_descriptors = []

                def record_open(path, flags, *args, **kwargs):
                    descriptor = original_open(path, flags, *args, **kwargs)
                    if str(path) == target.name and kwargs.get("dir_fd") is not None:
                        controller_descriptors.append(descriptor)
                    return descriptor

                def simulated_fchown(descriptor, uid, gid):
                    info = original_fstat(descriptor)
                    recorded_gid = gid + 1 if variant == "gid" else gid
                    simulated_owners[(info.st_dev, info.st_ino)] = (uid, recorded_gid)
                    if stat.S_ISDIR(info.st_mode) and variant == "mode":
                        original_fchmod(descriptor, 0o750)
                    if stat.S_ISDIR(info.st_mode) and variant in ("inode", "device"):
                        replaced_identity[0] = (info.st_dev, info.st_ino)

                def simulated_fstat(descriptor):
                    info = original_fstat(descriptor)
                    owner = simulated_owners.get((info.st_dev, info.st_ino))
                    return (
                        changed_stat(info, uid=owner[0], gid=owner[1])
                        if owner is not None else info
                    )

                def simulated_stat(path, *args, **kwargs):
                    info = original_stat(path, *args, **kwargs)
                    owner = simulated_owners.get((info.st_dev, info.st_ino))
                    if owner is not None:
                        info = changed_stat(info, uid=owner[0], gid=owner[1])
                    if (
                        replaced_identity[0] is not None
                        and str(path) == target.name
                        and kwargs.get("dir_fd") is not None
                    ):
                        if variant == "inode":
                            return changed_stat(info, inode=info.st_ino + 1)
                        if variant == "device":
                            return changed_stat(info, device=info.st_dev + 1)
                    return info

                self.i.os.fchown = simulated_fchown
                self.i.os.fstat = simulated_fstat
                self.i.os.stat = simulated_stat
                self.i.os.open = record_open
                try:
                    with self.i.TrustedInstallerWalker(root, os.getuid()) as walker:
                        walker.ensure_dir(parent)
                        with self.assertRaisesRegex(
                            self.i.InstallError,
                            "controller directory handoff postcondition failed",
                        ):
                            walker.handoff_directory(
                                target, target_uid, target_gid, 0o700,
                            )
                finally:
                    self.i.os.fchown = original_fchown
                    self.i.os.fchmod = original_fchmod
                    self.i.os.fstat = original_fstat
                    self.i.os.stat = original_stat
                    self.i.os.open = original_open
                self.assertEqual(1, len(controller_descriptors))
                try:
                    original_fstat(controller_descriptors[0])
                except OSError:
                    pass
                else:
                    original_close = self.i.os.close
                    original_close(controller_descriptors[0])
                    self.fail("rejected controller handoff leaked its descriptor")

    def test_manifest_is_durable_and_current_before_controller_handoff(self):
        self.bootstrap()
        self.install()
        events = []
        durability_descriptors = []
        old_manifest_identity = (
            self.layout.lock_manifest_path.stat().st_dev,
            self.layout.lock_manifest_path.stat().st_ino,
        )
        manifest_parent_identity = (
            self.layout.lock_manifest_path.parent.stat().st_dev,
            self.layout.lock_manifest_path.parent.stat().st_ino,
        )
        original_fsync = self.i._fsync_descriptor
        original_handoff = self.i.TrustedInstallerWalker.handoff_directory
        original_rename = self.i.os.rename
        original_validate = self.i._assert_recorded_locks

        def record_fsync(descriptor, evidence_path):
            evidence_path = Path(evidence_path)
            if evidence_path == self.layout.lock_manifest_path:
                events.append("manifest-fsync")
                descriptor_info = os.fstat(descriptor)
                current_info = os.lstat(self.layout.lock_manifest_path)
                durability_descriptors.append((
                    "file", descriptor_info.st_mode,
                    (descriptor_info.st_dev, descriptor_info.st_ino),
                    (current_info.st_dev, current_info.st_ino),
                ))
            elif evidence_path == self.layout.lock_manifest_path.parent:
                events.append("manifest-parent-fsync")
                descriptor_info = os.fstat(descriptor)
                durability_descriptors.append((
                    "parent", descriptor_info.st_mode,
                    (descriptor_info.st_dev, descriptor_info.st_ino), None,
                ))
            return original_fsync(descriptor, evidence_path)

        def record_rename(source, target, *args, **kwargs):
            if str(target) == self.layout.lock_manifest_path.name:
                events.append("manifest-rename")
            return original_rename(source, target, *args, **kwargs)

        def record_validation(walker, layout, manifest, release_gid=None):
            result = original_validate(
                walker, layout, manifest, release_gid=release_gid,
            )
            if DEPLOYMENT_ID in manifest["deployments"]:
                events.append("manifest-validated")
            return result

        def record_handoff(walker, path, target_uid, target_gid, mode=0o700):
            manifest = json.loads(self.layout.lock_manifest_path.read_text())
            events.append(("handoff", set(manifest["deployments"])))
            return original_handoff(walker, path, target_uid, target_gid, mode)

        self.i._fsync_descriptor = record_fsync
        self.i.TrustedInstallerWalker.handoff_directory = record_handoff
        self.i.os.rename = record_rename
        self.i._assert_recorded_locks = record_validation
        try:
            self.i.provision_deployments(
                self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
                release_uid=os.getuid(), release_gid=os.getgid(),
            )
        finally:
            self.i._fsync_descriptor = original_fsync
            self.i.TrustedInstallerWalker.handoff_directory = original_handoff
            self.i.os.rename = original_rename
            self.i._assert_recorded_locks = original_validate

        handoff_index = next(
            index for index, event in enumerate(events)
            if isinstance(event, tuple) and event[0] == "handoff"
        )
        rename_index = events.index("manifest-rename")
        temp_fsync_index = max(
            index for index, event in enumerate(events[:rename_index])
            if event == "manifest-fsync"
        )
        parent_fsync_index = next(
            index for index in range(rename_index + 1, len(events))
            if events[index] == "manifest-parent-fsync"
        )
        final_fsync_index = next(
            index for index in range(parent_fsync_index + 1, len(events))
            if events[index] == "manifest-fsync"
        )
        validation_index = events.index("manifest-validated")
        self.assertLess(
            temp_fsync_index,
            rename_index,
        )
        self.assertLess(rename_index, parent_fsync_index)
        self.assertLess(parent_fsync_index, final_fsync_index)
        self.assertLess(final_fsync_index, validation_index)
        self.assertLess(validation_index, handoff_index)
        self.assertIn(DEPLOYMENT_ID, events[handoff_index][1])
        file_barriers = [item for item in durability_descriptors if item[0] == "file"]
        parent_barriers = [item for item in durability_descriptors if item[0] == "parent"]
        self.assertEqual(2, len(file_barriers))
        self.assertTrue(all(stat.S_ISREG(item[1]) for item in file_barriers))
        self.assertNotEqual(old_manifest_identity, file_barriers[0][2])
        self.assertEqual(old_manifest_identity, file_barriers[0][3])
        self.assertEqual(file_barriers[0][2], file_barriers[1][2])
        self.assertEqual(file_barriers[1][2], file_barriers[1][3])
        self.assertEqual(1, len(parent_barriers))
        self.assertTrue(stat.S_ISDIR(parent_barriers[0][1]))
        self.assertEqual(manifest_parent_identity, parent_barriers[0][2])

    def test_replaced_retained_ancestor_is_rejected_before_install_write(self):
        self.bootstrap()
        original_infra = self.layout.infra_root

        def replace_after_lock(phase, transaction):
            if phase == "locked":
                moved = original_infra.with_name("caddy-moved")
                original_infra.rename(moved)
                original_infra.mkdir()

        with self.assertRaises(self.i.InstallError):
            self.install(phase_hook=replace_after_lock)
        self.assertFalse(self.layout.helper_path.exists())
        self.assertFalse(self.layout.contract_path.exists())

    def test_every_helper_contract_maintenance_phase_is_recoverable(self):
        phases = ("staged", "helper-installed", "contract-installed", "committed")
        for crash_phase in phases:
            with self.subTest(phase=crash_phase), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )

                def crash(phase, transaction):
                    if phase == crash_phase:
                        raise Crash()

                with self.assertRaises(Crash):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash,
                        owner_uid=os.getuid(), phase_hook=crash,
                    )
                self.assertTrue(layout.maintenance_transaction_path.exists())
                self.i.recover_helper_maintenance(layout, owner_uid=os.getuid())
                self.assertFalse(layout.maintenance_transaction_path.exists())
                self.assertFalse(layout.maintenance_recovery_marker.exists())
                if crash_phase == "staged":
                    self.assertFalse(layout.helper_path.exists())
                    self.assertFalse(layout.contract_path.exists())
                else:
                    contract = self.h.read_json(layout.contract_path)
                    self.assertEqual(self.h.sha256_file(layout.helper_path), contract["helper_sha256"])

    def test_cross_helper_version_change_is_a_separate_schema_migration(self):
        old_version = self.i.HELPER_VERSION
        new_version = "1.0.1"
        old_assignment = f'HELPER_VERSION = "{old_version}"'
        candidate_source = HELPER_PATH.read_text()
        self.assertEqual(1, candidate_source.count(old_assignment))
        candidate_source = candidate_source.replace(
            old_assignment, f'HELPER_VERSION = "{new_version}"', 1,
        )

        candidate = self.root / "deploydesk-caddy-apply-new.py"
        candidate.write_text(candidate_source)
        candidate_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
        self.bootstrap()
        self.install()
        before_helper = self.layout.helper_path.read_bytes()
        before_contract = self.layout.contract_path.read_bytes()

        self.i.HELPER_VERSION = new_version
        try:
            with self.assertRaises(self.i.InstallError):
                self.i.install_helper(
                    self.layout, candidate, candidate_hash, owner_uid=os.getuid(),
                )
        finally:
            self.i.HELPER_VERSION = old_version

        self.assertEqual(before_helper, self.layout.helper_path.read_bytes())
        self.assertEqual(before_contract, self.layout.contract_path.read_bytes())
        self.assertFalse(self.layout.maintenance_transaction_path.exists())
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())

    def test_upgrade_rejects_noncanonical_live_pair_modes_before_staging(self):
        for target, drift_mode in (("helper", 0o700), ("contract", 0o600)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )
                self.i.install_helper(
                    layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
                )
                drift_path = layout.helper_path if target == "helper" else layout.contract_path
                drift_path.chmod(drift_mode)

                with self.assertRaises(self.i.InstallError):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
                    )
                self.assertFalse(layout.maintenance_transaction_path.exists())
                self.assertFalse(layout.maintenance_recovery_marker.exists())
                self.assertEqual(drift_mode, stat.S_IMODE(drift_path.stat().st_mode))

    def test_malformed_maintenance_hash_sets_recovery_marker(self):
        self.bootstrap()

        def crash_after_staging(phase, transaction):
            if phase == "staged":
                raise Crash()

        with self.assertRaises(Crash):
            self.i.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_after_staging,
            )
        transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
        transaction["new_helper_sha256"] = "not-a-sha256"
        self.layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

        with self.assertRaises(self.i.InstallError):
            self.i.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())

    def test_partial_old_maintenance_pair_sets_recovery_marker(self):
        self.bootstrap()

        def crash_after_staging(phase, transaction):
            if phase == "staged":
                raise Crash()

        with self.assertRaises(Crash):
            self.i.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_after_staging,
            )
        transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
        self.assertIsNone(transaction["old_helper_sha256"])
        self.assertIsNone(transaction["old_contract_sha256"])
        transaction["old_contract_sha256"] = "f" * 64
        self.layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

        with self.assertRaises(self.i.InstallError):
            self.i.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())
        self.assertFalse(self.layout.helper_path.exists())
        self.assertFalse(self.layout.contract_path.exists())

    def test_maintenance_recovery_binds_runtime_identity_to_bootstrap_and_staged_contract(self):
        cases = ("transaction-container", "transaction-config-root", "staged-contract")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )

                def crash_after_staging(phase, transaction):
                    if phase == "staged":
                        raise Crash()

                with self.assertRaises(Crash):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash,
                        owner_uid=os.getuid(), phase_hook=crash_after_staging,
                    )
                transaction = json.loads(layout.maintenance_transaction_path.read_text())
                if case == "transaction-container":
                    transaction["caddy_container"] = "other-caddy"
                elif case == "transaction-config-root":
                    transaction["container_config_root"] = "/other/caddy"
                else:
                    stage = layout.maintenance_root / transaction["transaction_id"]
                    contract_path = stage / "new-contract.json"
                    contract = json.loads(contract_path.read_text())
                    contract["caddy_container"] = "other-caddy"
                    contract_data = (
                        json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"
                    ).encode()
                    contract_path.write_bytes(contract_data)
                    transaction["new_contract_sha256"] = hashlib.sha256(contract_data).hexdigest()
                layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

                with self.assertRaises(self.i.InstallError):
                    self.i.recover_helper_maintenance(layout, owner_uid=os.getuid())
                self.assertTrue(layout.maintenance_recovery_marker.is_file())
                self.assertTrue(layout.maintenance_transaction_path.is_file())

    def test_maintenance_recovery_rejects_staged_contract_helper_attestation_drift(self):
        self.bootstrap()

        def crash_after_staging(phase, transaction):
            if phase == "staged":
                raise Crash()

        with self.assertRaises(Crash):
            self.i.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_after_staging,
            )
        transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
        stage = self.layout.maintenance_root / transaction["transaction_id"]
        contract_path = stage / "new-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["helper_sha256"] = "f" * 64
        contract_data = (
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        contract_path.write_bytes(contract_data)
        transaction["new_contract_sha256"] = hashlib.sha256(contract_data).hexdigest()
        self.layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

        with self.assertRaises(self.i.InstallError):
            self.i.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())

    def test_maintenance_recovery_validates_unused_staged_old_contract(self):
        self.bootstrap()
        self.install()

        def crash_after_contract(phase, transaction):
            if phase == "contract-installed":
                raise Crash()

        with self.assertRaises(Crash):
            self.i.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_after_contract,
            )
        transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
        stage = self.layout.maintenance_root / transaction["transaction_id"]
        contract_path = stage / "old-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["caddy_container"] = "other-caddy"
        contract_data = (
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        contract_path.write_bytes(contract_data)
        transaction["old_contract_sha256"] = hashlib.sha256(contract_data).hexdigest()
        self.layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

        with self.assertRaises(self.i.InstallError):
            self.i.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())

    def test_maintenance_recovery_rejects_live_pair_mode_drift(self):
        for target, drift_mode in (("helper", 0o700), ("contract", 0o600)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )
                self.i.install_helper(
                    layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
                )

                def crash_after_staging(phase, transaction):
                    if phase == "staged":
                        raise Crash()

                with self.assertRaises(Crash):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash,
                        owner_uid=os.getuid(), phase_hook=crash_after_staging,
                    )
                drift_path = layout.helper_path if target == "helper" else layout.contract_path
                drift_path.chmod(drift_mode)

                with self.assertRaises(self.i.InstallError):
                    self.i.recover_helper_maintenance(layout, owner_uid=os.getuid())
                self.assertTrue(layout.maintenance_recovery_marker.is_file())
                self.assertTrue(layout.maintenance_transaction_path.is_file())

    def test_maintenance_recovery_rejects_phase_ahead_of_live_pair(self):
        for forged_phase in ("helper-installed", "contract-installed", "committed"):
            with self.subTest(phase=forged_phase), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )

                def crash_after_staging(phase, transaction):
                    if phase == "staged":
                        raise Crash()

                with self.assertRaises(Crash):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash,
                        owner_uid=os.getuid(), phase_hook=crash_after_staging,
                    )
                self.assertFalse(layout.helper_path.exists())
                self.assertFalse(layout.contract_path.exists())
                transaction = json.loads(layout.maintenance_transaction_path.read_text())
                transaction["phase"] = forged_phase
                layout.maintenance_transaction_path.write_text(json.dumps(transaction) + "\n")

                with self.assertRaises(self.i.InstallError):
                    self.i.recover_helper_maintenance(layout, owner_uid=os.getuid())
                self.assertTrue(layout.maintenance_recovery_marker.is_file())
                self.assertTrue(layout.maintenance_transaction_path.is_file())
                self.assertFalse(layout.helper_path.exists())
                self.assertFalse(layout.contract_path.exists())

    def test_maintenance_recovery_accepts_one_write_ahead_of_durable_phase(self):
        cases = ("helper-write-before-phase", "contract-write-before-phase")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                layout = self.h.Layout.for_test_root(Path(temporary))
                self.i.bootstrap_host(
                    layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
                    container_config_root="/etc/caddy",
                )
                crash_phase = "staged" if case == "helper-write-before-phase" else "helper-installed"

                def crash(phase, transaction):
                    if phase == crash_phase:
                        raise Crash()

                with self.assertRaises(Crash):
                    self.i.install_helper(
                        layout, HELPER_PATH, self.approved_hash,
                        owner_uid=os.getuid(), phase_hook=crash,
                    )
                transaction = json.loads(layout.maintenance_transaction_path.read_text())
                stage = layout.maintenance_root / transaction["transaction_id"]
                if case == "helper-write-before-phase":
                    layout.helper_path.write_bytes((stage / "new-helper").read_bytes())
                    layout.helper_path.chmod(0o755)
                else:
                    layout.contract_path.write_bytes((stage / "new-contract.json").read_bytes())
                    layout.contract_path.chmod(0o644)

                self.i.recover_helper_maintenance(layout, owner_uid=os.getuid())
                self.assertFalse(layout.maintenance_transaction_path.exists())
                self.assertFalse(layout.maintenance_recovery_marker.exists())
                if case == "helper-write-before-phase":
                    self.assertFalse(layout.helper_path.exists())
                    self.assertFalse(layout.contract_path.exists())
                else:
                    contract = self.h.read_json(layout.contract_path)
                    self.assertEqual(self.h.sha256_file(layout.helper_path), contract["helper_sha256"])

    def test_maintenance_recovery_revalidates_lock_manifest_after_wait(self):
        self.bootstrap()
        self.install()
        self.i.provision_deployments(
            self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        before_helper = self.layout.helper_path.read_bytes()
        before_contract = self.layout.contract_path.read_bytes()

        def crash_after_staging(phase, transaction):
            if phase == "staged":
                raise Crash()

        with self.assertRaises(Crash):
            self.i.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_after_staging,
            )
        self.assertTrue(self.layout.maintenance_transaction_path.exists())

        project_lock = self.layout.project_lock(DEPLOYMENT_ID)
        original_flock = self.i.fcntl.flock
        injected = [False]

        def drift_after_lock(descriptor, operation):
            result = original_flock(descriptor, operation)
            if operation == self.i.fcntl.LOCK_EX and not injected[0]:
                os.chmod(project_lock, 0o640)
                injected[0] = True
            return result

        self.i.fcntl.flock = drift_after_lock
        try:
            with self.assertRaisesRegex(
                self.i.InstallError, "recorded lock metadata drift",
            ):
                self.i.recover_helper_maintenance(
                    self.layout, owner_uid=os.getuid(),
                )
        finally:
            self.i.fcntl.flock = original_flock
        self.assertTrue(injected[0])
        self.assertEqual(before_helper, self.layout.helper_path.read_bytes())
        self.assertEqual(before_contract, self.layout.contract_path.read_bytes())
        self.assertTrue(self.layout.maintenance_transaction_path.exists())


@unittest.skipUnless(HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "package not implemented")
class FinalWaveEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.h = load(HELPER_PATH, "final_evidence_helper")
        self.i = load(INSTALLER_PATH, "final_evidence_installer")
        self.temporary = tempfile.TemporaryDirectory()
        self.layout = self.h.Layout.for_test_root(Path(self.temporary.name))
        self.i.bootstrap_host(
            self.layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
            container_config_root="/etc/caddy",
        )
        self.i.install_helper(
            self.layout, HELPER_PATH,
            hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(), owner_uid=os.getuid(),
        )
        self.i.provision_deployments(
            self.layout, [DEPLOYMENT_ID], owner_uid=os.getuid(),
            release_uid=os.getuid(), release_gid=os.getgid(),
        )
        self.bundle_id = install_fixture_bundle(self.h, self.layout, FIXTURE, DEPLOYMENT_ID)
        self.runtime = Runtime()

    def tearDown(self):
        self.temporary.cleanup()

    def apply(self, phase_hook=None):
        subject = self.h.SharedCaddyHelper(
            self.layout, runtime=self.runtime,
            trust=self.h.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path, phase_hook=phase_hook,
        )
        with self.layout.release_lock(DEPLOYMENT_ID).open("r+") as release_lock:
            fcntl.flock(release_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return subject.apply(DEPLOYMENT_ID, self.bundle_id)

    @property
    def external_manifest_path(self):
        return self.layout.bundle_dir(DEPLOYMENT_ID, self.bundle_id) / "server-manifest.json"

    def test_receipt_preserves_the_full_git_archive_manifest_transaction_chain(self):
        receipt = self.apply()
        external = json.loads(self.external_manifest_path.read_text())
        for field in (
            "project_id", "environment", "deployment_id", "source_repo", "git_sha",
            "bundle_id", "declaration_sha256", "fragment_sha256", "compose_sha256",
            "helper_requirement_sha256", "internal_provenance_sha256", "helper_sha256",
        ):
            external_field = "deploy_bundle_sha256" if field == "bundle_id" else field
            self.assertEqual(external[external_field], receipt[field])

    def test_external_git_or_source_evidence_cannot_change_while_reusing_archive_id(self):
        original = json.loads(self.external_manifest_path.read_text())
        mutations = {
            "git_sha": "2" * 40,
            "source_repo": "https://code.example/teams/renamed-app",
            "helper_sha256": "3" * 64,
            "internal_provenance_sha256": "4" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field] = value
                self.external_manifest_path.write_text(json.dumps(changed, sort_keys=True) + "\n")
                with self.assertRaises((self.h.ContractError, self.h.SecurityError)):
                    self.apply()
                self.external_manifest_path.write_text(json.dumps(original, sort_keys=True) + "\n")

    def _crash_committed(self):
        def crash(phase, transaction):
            if phase == "committed":
                raise Crash()

        with self.assertRaises(Crash):
            self.apply(crash)
        return json.loads(self.layout.transaction_path.read_text())

    def test_committed_receipt_repair_revalidates_generation_provenance_and_runtime(self):
        transaction = self._crash_committed()
        intake = self.layout.intake_root / transaction["transaction_id"]
        self.assertTrue(intake.is_dir(), "committed crash discarded required recovery evidence")
        self.apply()
        self.assertFalse(self.layout.recovery_marker.exists())
        self.assertTrue(self.layout.receipt_path(transaction["transaction_id"]).is_file())
        self.assertTrue(self.runtime.network_checks)

    def test_committed_repair_tamper_sets_recovery_marker(self):
        tamper_cases = (
            "generation-fragment", "external-manifest", "internal-provenance",
            "helper-drift", "contract-drift", "runtime",
        )
        for case in tamper_cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                self.tearDown()
                self.setUp()
                transaction = self._crash_committed()
                intake = self.layout.intake_root / transaction["transaction_id"]
                if case == "generation-fragment":
                    fragment = self.layout.generations_root / transaction["new_generation"] / "sites" / f"{DEPLOYMENT_ID}.caddy"
                    os.chmod(fragment, 0o600)
                    fragment.write_text("tampered\n")
                    os.chmod(fragment, 0o400)
                elif case == "external-manifest":
                    manifest = intake / "server-manifest.json"
                    value = json.loads(manifest.read_text())
                    value["git_sha"] = "2" * 40
                    manifest.write_text(json.dumps(value) + "\n")
                elif case == "internal-provenance":
                    provenance = intake / "caddy" / "bundle-provenance.json"
                    value = json.loads(provenance.read_text())
                    value["git_sha"] = "2" * 40
                    provenance.write_text(json.dumps(value) + "\n")
                elif case == "helper-drift":
                    self.layout.helper_path.write_bytes(
                        self.layout.helper_path.read_bytes() + b"\n# drift\n"
                    )
                elif case == "contract-drift":
                    contract = json.loads(self.layout.contract_path.read_text())
                    del contract["helper_sha256"]
                    self.layout.contract_path.write_text(json.dumps(contract) + "\n")
                else:
                    self.runtime.runtime_ok = False
                with self.assertRaises(self.h.RecoveryRequired):
                    self.apply()
                self.assertTrue(self.layout.recovery_marker.is_file())


if __name__ == "__main__":
    unittest.main()
