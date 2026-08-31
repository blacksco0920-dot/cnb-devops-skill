import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
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
DEPLOYMENT_ID = "ecat-energy--test"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Runtime:
    def __init__(self):
        self.validations = []
        self.failure = None

    def validate_candidate(self, current, intake, manifest):
        self.validations.append((Path(current), Path(intake), dict(manifest)))
        if self.failure is not None:
            raise self.failure


@unittest.skipUnless(
    HELPER_PATH.is_file() and INSTALLER_PATH.is_file(), "helper not implemented yet",
)
class SharedCaddyPreflightTests(unittest.TestCase):
    def setUp(self):
        self.h = load(HELPER_PATH, "preflight_helper")
        self.i = load(INSTALLER_PATH, "preflight_installer")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = self.h.Layout.for_test_root(self.root)
        self.fixture = self.root / "fixture"
        shutil.copytree(FIXTURE, self.fixture)
        self._retarget_fixture_to_ecat()
        self.i.bootstrap_host(self.layout, owner_uid=os.getuid())
        self.i.install_helper(
            self.layout,
            HELPER_PATH,
            hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(),
            owner_uid=os.getuid(),
        )
        self.i.provision_deployments(
            self.layout,
            [DEPLOYMENT_ID],
            owner_uid=os.getuid(),
            release_uid=os.getuid(),
            release_gid=os.getgid(),
        )
        self.bundle_id = install_fixture_bundle(
            self.h, self.layout, self.fixture, DEPLOYMENT_ID,
        )
        self.runtime = Runtime()
        self.helper = self.h.SharedCaddyHelper(
            self.layout,
            runtime=self.runtime,
            trust=self.h.TrustPolicy(owner_uid=os.getuid()),
            executable_path=self.layout.helper_path,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _retarget_fixture_to_ecat(self):
        declaration_path = self.fixture / "bundle" / "caddy" / "declaration.json"
        declaration = json.loads(declaration_path.read_text())
        declaration.update({
            "project_id": "ecat-energy",
            "environment": "test",
            "deployment_id": DEPLOYMENT_ID,
            "source_repo": "https://cnb.cool/ecat/energy",
        })
        declaration_path.write_text(json.dumps(declaration, sort_keys=True) + "\n")

        manifest_path = self.fixture / "bundle" / "caddy" / "server-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for field in ("project_id", "environment", "deployment_id", "source_repo"):
            manifest[field] = declaration[field]
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")

        compose_path = self.fixture / "bundle" / "runtime" / "compose.json"
        compose = json.loads(compose_path.read_text())
        compose["services"]["web"]["labels"]["com.deploydesk.deployment-id"] = DEPLOYMENT_ID
        compose_path.write_text(json.dumps(compose, sort_keys=True) + "\n")

    def preflight(self):
        with self.layout.release_lock(DEPLOYMENT_ID).open("r+") as release_lock:
            fcntl.flock(release_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self.helper.preflight(DEPLOYMENT_ID, self.bundle_id)

    def snapshot_live_state(self):
        paths = (
            self.layout.infra_root,
            self.layout.managed_root,
            self.layout.state_root,
        )
        snapshot = {"current": os.readlink(self.layout.current_link)}
        for root in paths:
            for path in (root, *root.rglob("*")):
                relative = str(path.relative_to(self.root))
                info = os.lstat(path)
                if stat.S_ISREG(info.st_mode):
                    snapshot[relative] = (stat.S_IMODE(info.st_mode), path.read_bytes())
                elif stat.S_ISLNK(info.st_mode):
                    snapshot[relative] = ("link", os.readlink(path))
                elif stat.S_ISDIR(info.st_mode):
                    snapshot[relative] = ("dir", stat.S_IMODE(info.st_mode))
        return snapshot

    @contextlib.contextmanager
    def editable_generation(self):
        generation = self.layout.current_generation()
        os.chmod(generation, 0o700)
        os.chmod(generation / "sites", 0o700)
        os.chmod(generation / "manifests", 0o700)
        try:
            yield generation
        finally:
            for path in generation.rglob("*"):
                if path.is_file():
                    os.chmod(path, 0o400)
            os.chmod(generation / "sites", 0o500)
            os.chmod(generation / "manifests", 0o500)
            os.chmod(generation, 0o500)

    def write_live_owner(
        self, deployment_id, host, *, fragment=None, manifest_updates=None,
    ):
        fragment = fragment or f"{host} {{\n    respond 200\n}}\n"
        project_id, environment = deployment_id.split("--", 1)
        manifest = {
            "schema_version": "shared-caddy-server-manifest/v1",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": "a" * 64,
            "project_id": project_id,
            "environment": environment,
            "deployment_id": deployment_id,
            "source_repo": f"https://code.example/teams/{project_id}",
            "hosts": [host],
            "git_sha": "1" * 40,
            "deploy_bundle_sha256": "2" * 64,
            "declaration_sha256": "3" * 64,
            "fragment_sha256": hashlib.sha256(fragment.encode()).hexdigest(),
            "compose_sha256": "4" * 64,
            "helper_requirement_sha256": "5" * 64,
            "internal_provenance_sha256": "6" * 64,
            "source": {"kind": "bundle"},
        }
        if manifest_updates:
            manifest.update(manifest_updates)
        with self.editable_generation() as generation:
            (generation / "sites" / f"{deployment_id}.caddy").write_text(fragment)
            (generation / "manifests" / f"{deployment_id}.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n"
            )
        return manifest

    def test_bundle_preflight_is_root_only_non_live_and_canonical(self):
        before = self.snapshot_live_state()
        receipt_count = len(list(self.layout.receipts_root.glob("*.json")))

        result = self.preflight()

        self.assertEqual(
            set(result),
            {
                "bundle_id", "contract_version", "deployment_id", "generation_id",
                "helper_sha256", "helper_version", "schema_version", "status",
            },
        )
        self.assertEqual("shared-caddy-preflight/v1", result["schema_version"])
        self.assertEqual("passed", result["status"])
        self.assertEqual(self.bundle_id, result["bundle_id"])
        self.assertEqual(DEPLOYMENT_ID, result["deployment_id"])
        self.assertEqual(before, self.snapshot_live_state())
        self.assertEqual(
            receipt_count, len(list(self.layout.receipts_root.glob("*.json"))),
        )
        self.assertEqual(1, len(self.runtime.validations))
        self.assertEqual([], list(self.layout.intake_root.iterdir()))

    def test_preflight_requires_the_callers_release_lock(self):
        with self.assertRaises(self.h.SecurityError):
            self.helper.preflight(DEPLOYMENT_ID, self.bundle_id)

    def test_parser_rejects_abbreviation_missing_and_extra_arguments(self):
        parser = self.h.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "--pre", "--deployment-id", DEPLOYMENT_ID,
                "--bundle-id", self.bundle_id,
            ])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--preflight", "--bundle-id", self.bundle_id])
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "--preflight", "--deployment-id", DEPLOYMENT_ID,
                "--bundle-id", self.bundle_id, "--path", "/tmp/escape",
            ])
        with self.assertRaises(self.h.ContractError):
            self.h.main(["--preflight", "--deployment-id", DEPLOYMENT_ID])
        with self.assertRaises(self.h.ContractError):
            self.h.main(["--deployment-id", DEPLOYMENT_ID])

    def test_cli_rejects_non_root_before_constructing_the_helper(self):
        output = io.StringIO()
        with (
            mock.patch.object(self.h.os, "geteuid", return_value=1),
            mock.patch.object(self.h, "SharedCaddyHelper") as helper_class,
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(self.h.SecurityError, "must run as root"),
        ):
            self.h.main([
                "--preflight", "--deployment-id", DEPLOYMENT_ID,
                "--bundle-id", self.bundle_id,
            ])
        helper_class.assert_not_called()
        self.assertEqual("", output.getvalue())

    def test_cli_dispatches_exact_ecat_preflight_and_emits_one_canonical_json(self):
        expected = {
            "schema_version": "shared-caddy-preflight/v1",
            "status": "passed",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": "a" * 64,
            "deployment_id": DEPLOYMENT_ID,
            "bundle_id": self.bundle_id,
            "generation_id": self.layout.current_generation().name,
        }
        fake_helper = mock.Mock()
        fake_helper.preflight.return_value = expected
        output = io.StringIO()
        with (
            mock.patch.object(self.h.os, "geteuid", return_value=0),
            mock.patch.object(self.h.Layout, "for_host", return_value=self.layout),
            mock.patch.object(self.h, "SharedCaddyHelper", return_value=fake_helper),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(0, self.h.main([
                "--preflight", "--deployment-id", DEPLOYMENT_ID,
                "--bundle-id", self.bundle_id,
            ]))
        fake_helper.preflight.assert_called_once_with(DEPLOYMENT_ID, self.bundle_id)
        self.assertEqual(
            json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
            output.getvalue(),
        )

    def test_preflight_rejects_maintenance_and_recovery_state_without_cleanup_leaks(self):
        markers = (
            self.layout.maintenance_transaction_path,
            self.layout.maintenance_recovery_marker,
            self.layout.transaction_path,
            self.layout.recovery_marker,
        )
        for marker in markers:
            with self.subTest(marker=marker.name):
                marker.write_text("retained state\n")
                os.chmod(marker, 0o600)
                try:
                    with self.assertRaises(self.h.RecoveryRequired):
                        self.preflight()
                    self.assertEqual([], list(self.layout.intake_root.iterdir()))
                finally:
                    marker.unlink(missing_ok=True)

    def test_preflight_rejects_malformed_unrelated_manifest(self):
        with self.editable_generation() as generation:
            (generation / "sites" / "other-app--test.caddy").write_text(
                "other.example.test { respond 200 }\n"
            )
            (generation / "manifests" / "other-app--test.json").write_text("{broken\n")
        with self.assertRaises(self.h.ContractError):
            self.preflight()

    def test_preflight_rejects_site_manifest_mismatch(self):
        with self.editable_generation() as generation:
            (generation / "sites" / "orphan-app--test.caddy").write_text(
                "orphan.example.test { respond 200 }\n"
            )
        with self.assertRaisesRegex(self.h.OwnershipError, "exactly one owner manifest"):
            self.preflight()

    def test_preflight_rejects_live_fragment_hash_drift(self):
        self.write_live_owner(
            "other-app--test", "other.example.test",
            manifest_updates={"fragment_sha256": "f" * 64},
        )
        with self.assertRaisesRegex(self.h.OwnershipError, "owner manifest hash"):
            self.preflight()

    def test_preflight_rejects_legacy_fragment_hash_drift(self):
        fragment = "legacy.example.test { respond 200 }\n"
        self.write_live_owner(
            "legacy-app--test", "legacy.example.test", fragment=fragment,
            manifest_updates={
                "source": {"kind": "legacy_opaque", "legacy_fragment_sha256": "e" * 64},
            },
        )
        with self.assertRaisesRegex(self.h.OwnershipError, "legacy opaque fragment"):
            self.preflight()

    def test_preflight_rejects_duplicate_hosts_already_in_the_global_config(self):
        self.write_live_owner("first-app--test", "shared.example.test")
        self.write_live_owner("second-app--test", "shared.example.test")
        with self.assertRaisesRegex(self.h.OwnershipError, "already owned"):
            self.preflight()

    def test_preflight_rejects_incoming_ecat_host_conflict(self):
        self.write_live_owner("other-app--test", "app.example.test")
        with self.assertRaisesRegex(self.h.OwnershipError, "already owned"):
            self.preflight()

    def test_preflight_rejects_ownership_identity_change(self):
        self.write_live_owner(
            DEPLOYMENT_ID, "app.example.test",
            manifest_updates={"source_repo": "https://code.example/other/ecat-energy"},
        )
        with self.assertRaisesRegex(self.h.MaintenanceRequired, "identity change"):
            self.preflight()

    def test_invalid_candidate_caddy_cleans_intake_and_writes_no_receipt(self):
        self.runtime.failure = self.h.TransactionError("invalid candidate Caddy")
        output = io.StringIO()
        receipts_before = list(self.layout.receipts_root.iterdir())
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(
            self.h.TransactionError, "invalid candidate Caddy",
        ):
            self.preflight()
        self.assertEqual("", output.getvalue())
        self.assertEqual([], list(self.layout.intake_root.iterdir()))
        self.assertEqual(receipts_before, list(self.layout.receipts_root.iterdir()))


class DockerCandidateValidationTests(unittest.TestCase):
    def setUp(self):
        self.h = load(HELPER_PATH, "preflight_runtime")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = self.h.Layout.for_test_root(self.root)
        self.layout.infra_root.mkdir(parents=True)
        self.generation = self.layout.generations_root / ("gen-" + "1" * 32)
        (self.generation / "sites").mkdir(parents=True)
        self.current_site = self.generation / "sites" / "other-app--test.caddy"
        self.current_site.write_text("other.example.test { respond 200 }\n")
        os.chmod(self.current_site, 0o400)
        os.chmod(self.generation / "sites", 0o500)
        os.chmod(self.generation, 0o500)
        self.intake = self.layout.state_root / "intake" / "preflight-fixture"
        (self.intake / "caddy").mkdir(parents=True)
        (self.intake / "caddy" / "site.caddy").write_text(
            "app.example.test { respond 200 }\n"
        )
        self.runtime = self.h.DockerRuntime({
            "caddy_container": "shared-caddy",
            "container_config_root": "/etc/caddy",
        }, self.layout)

    def tearDown(self):
        os.chmod(self.generation, 0o700)
        os.chmod(self.generation / "sites", 0o700)
        self.temporary.cleanup()

    def test_candidate_validation_uses_root_private_copies_and_fixed_container_command(self):
        observed = {}

        def inspect_candidate(arguments):
            self.assertEqual(
                ["/usr/bin/docker", "exec", "shared-caddy", "caddy", "validate"],
                arguments[:5],
            )
            config_name = Path(arguments[6]).name
            caddyfile = self.layout.infra_root / config_name
            observed["caddyfile"] = caddyfile
            observed["caddyfile_mode"] = stat.S_IMODE(caddyfile.stat().st_mode)
            imported = caddyfile.read_text().splitlines()[1]
            candidate_name = Path(imported.removeprefix("import ")).parts[-2]
            candidate = self.layout.infra_root / candidate_name
            observed["candidate"] = candidate
            observed["candidate_mode"] = stat.S_IMODE(candidate.stat().st_mode)
            observed["sites"] = {
                path.name: (stat.S_IMODE(path.stat().st_mode), path.read_text())
                for path in candidate.glob("*.caddy")
            }

        self.runtime._run = inspect_candidate
        self.runtime.validate_candidate(
            self.generation,
            self.intake,
            {"deployment_id": DEPLOYMENT_ID},
        )

        self.assertEqual(0o600, observed["caddyfile_mode"])
        self.assertEqual(0o700, observed["candidate_mode"])
        self.assertEqual(
            {"other-app--test.caddy", f"{DEPLOYMENT_ID}.caddy"},
            set(observed["sites"]),
        )
        self.assertTrue(all(mode == 0o600 for mode, _ in observed["sites"].values()))
        self.assertEqual(0o500, stat.S_IMODE(self.generation.stat().st_mode))
        self.assertEqual(0o400, stat.S_IMODE(self.current_site.stat().st_mode))
        self.assertFalse(observed["caddyfile"].exists())
        self.assertFalse(observed["candidate"].exists())

    def test_candidate_validation_removes_private_objects_after_caddy_failure(self):
        observed = []

        def reject_candidate(arguments):
            caddyfile = self.layout.infra_root / Path(arguments[6]).name
            candidate_name = Path(caddyfile.read_text().splitlines()[1].split()[1]).parts[-2]
            observed.extend((caddyfile, self.layout.infra_root / candidate_name))
            raise self.h.TransactionError("fixed Caddy operation failed")

        self.runtime._run = reject_candidate
        with self.assertRaises(self.h.TransactionError):
            self.runtime.validate_candidate(
                self.generation,
                self.intake,
                {"deployment_id": DEPLOYMENT_ID},
            )
        self.assertTrue(observed)
        self.assertTrue(all(not path.exists() for path in observed))

    def test_fixed_caddy_failure_with_empty_output_is_still_an_error(self):
        result = mock.Mock(returncode=1, stdout="")
        with (
            mock.patch.object(self.h.subprocess, "run", return_value=result),
            self.assertRaisesRegex(self.h.TransactionError, "fixed Caddy operation failed"),
        ):
            self.runtime._run(["/usr/bin/docker", "exec", "shared-caddy"])


if __name__ == "__main__":
    unittest.main()
