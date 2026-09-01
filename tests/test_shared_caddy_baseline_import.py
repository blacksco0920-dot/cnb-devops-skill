import copy
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "scripts" / "install_shared_caddy_helper.py"
HELPER_PATH = ROOT / "scripts" / "deploydesk_caddy_apply.py"

ARCHIVE_FILES = (
    "caddy/declaration.json",
    "caddy/site.caddy",
    "caddy/helper-requirement.json",
    "caddy/bundle-provenance.json",
    "runtime/compose.json",
)
COMPATIBILITY_PAIRS = (
    ("ecat.swifteng.com.cn", "www.dianqimao.vip"),
    ("ecatadmin.swifteng.com.cn", "admin.dianqimao.vip"),
    ("ecatapi.swifteng.com.cn", "api.dianqimao.vip"),
)
EXACT_FRAGMENT = (
    b"ecat.swifteng.com.cn {\n"
    b"    encode zstd gzip\n"
    b"    reverse_proxy https://www.dianqimao.vip {\n"
    b"        header_up Host www.dianqimao.vip\n"
    b"        transport http {\n"
    b"            tls_server_name www.dianqimao.vip\n"
    b"        }\n"
    b"    }\n"
    b"}\n\n"
    b"ecatadmin.swifteng.com.cn {\n"
    b"    encode zstd gzip\n"
    b"    reverse_proxy https://admin.dianqimao.vip {\n"
    b"        header_up Host admin.dianqimao.vip\n"
    b"        transport http {\n"
    b"            tls_server_name admin.dianqimao.vip\n"
    b"        }\n"
    b"    }\n"
    b"}\n\n"
    b"ecatapi.swifteng.com.cn {\n"
    b"    encode zstd gzip\n"
    b"    reverse_proxy https://api.dianqimao.vip {\n"
    b"        header_up Host api.dianqimao.vip\n"
    b"        transport http {\n"
    b"            tls_server_name api.dianqimao.vip\n"
    b"        }\n"
    b"    }\n"
    b"}\n"
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_bytes(members, names=ARCHIVE_FILES):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name in names:
                data = members[name]
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o644
                member.mtime = 0
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


@unittest.skipUnless(INSTALLER_PATH.is_file() and HELPER_PATH.is_file(), "package not implemented")
class LegacyBaselineArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = load(INSTALLER_PATH, "legacy_baseline_installer")
        cls.normal_helper = load(HELPER_PATH, "legacy_baseline_normal_helper")

    def declaration(self):
        return {
            "contract_version": "shared-caddy-contract/v1",
            "project_id": "ecat-energy",
            "environment": "legacy-edge",
            "deployment_id": "ecat-energy--legacy-edge",
            "source_repo": "https://github.com/blacksco0920-dot/ecat-energy",
            "compose_path": "runtime/compose.json",
            "routes": [
                {"type": "https_proxy", "host": source, "target_host": target}
                for source, target in COMPATIBILITY_PAIRS
            ],
        }

    def artifacts(self, helper_sha256="a" * 64, git_sha="1" * 40):
        declaration = self.declaration()
        declaration_bytes = canonical_bytes(declaration)
        compose_facts = {"services": {}, "networks": {}}
        compose_bytes = canonical_bytes(compose_facts)
        helper_requirement = {
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": helper_sha256,
        }
        helper_requirement_bytes = canonical_bytes(helper_requirement)
        provenance = {
            "schema_version": "shared-caddy-baseline-provenance/v1",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": helper_sha256,
            "project_id": declaration["project_id"],
            "environment": declaration["environment"],
            "deployment_id": declaration["deployment_id"],
            "source_repo": declaration["source_repo"],
            "hosts": [source for source, _ in COMPATIBILITY_PAIRS],
            "git_sha": git_sha,
            "declaration_sha256": digest(declaration_bytes),
            "fragment_sha256": digest(EXACT_FRAGMENT),
            "compose_facts": compose_facts,
            "compose_sha256": digest(compose_bytes),
            "helper_requirement_sha256": digest(helper_requirement_bytes),
            "source": {
                "kind": "legacy_opaque",
                "legacy_fragment_sha256": digest(EXACT_FRAGMENT),
            },
        }
        provenance_bytes = canonical_bytes(provenance)
        archive = archive_bytes({
            "caddy/declaration.json": declaration_bytes,
            "caddy/site.caddy": EXACT_FRAGMENT,
            "caddy/helper-requirement.json": helper_requirement_bytes,
            "caddy/bundle-provenance.json": provenance_bytes,
            "runtime/compose.json": compose_bytes,
        })
        archive_id = digest(archive)
        manifest = {
            "schema_version": "shared-caddy-server-manifest/v1",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": helper_sha256,
            "project_id": declaration["project_id"],
            "environment": declaration["environment"],
            "deployment_id": declaration["deployment_id"],
            "source_repo": declaration["source_repo"],
            "hosts": provenance["hosts"],
            "git_sha": provenance["git_sha"],
            "deploy_bundle_sha256": archive_id,
            "declaration_sha256": provenance["declaration_sha256"],
            "fragment_sha256": provenance["fragment_sha256"],
            "compose_sha256": provenance["compose_sha256"],
            "helper_requirement_sha256": provenance["helper_requirement_sha256"],
            "internal_provenance_sha256": digest(provenance_bytes),
            "source": provenance["source"],
        }
        manifest_bytes = canonical_bytes(manifest)
        transaction = {
            "schema_version": "shared-caddy-baseline-transaction/v1",
            "phase": "committed",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": helper_sha256,
            "transaction_id": "tx-" + "2" * 32,
            "project_id": declaration["project_id"],
            "environment": declaration["environment"],
            "deployment_id": declaration["deployment_id"],
            "source_repo": declaration["source_repo"],
            "archive_id": archive_id,
            "git_sha": provenance["git_sha"],
            "declaration_sha256": provenance["declaration_sha256"],
            "fragment_sha256": provenance["fragment_sha256"],
            "compose_sha256": provenance["compose_sha256"],
            "helper_requirement_sha256": provenance["helper_requirement_sha256"],
            "baseline_provenance_sha256": digest(provenance_bytes),
            "server_manifest_sha256": digest(manifest_bytes),
            "old_generation": "gen-" + "3" * 32,
            "new_generation": "gen-" + "4" * 32,
            "hosts": provenance["hosts"],
        }
        receipt = {
            "schema_version": "shared-caddy-baseline-receipt/v1",
            "status": "committed",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": "a" * 64,
            "transaction_id": transaction["transaction_id"],
            "project_id": declaration["project_id"],
            "environment": declaration["environment"],
            "deployment_id": declaration["deployment_id"],
            "source_repo": declaration["source_repo"],
            "archive_id": archive_id,
            "git_sha": provenance["git_sha"],
            "declaration_sha256": provenance["declaration_sha256"],
            "fragment_sha256": provenance["fragment_sha256"],
            "compose_sha256": provenance["compose_sha256"],
            "helper_requirement_sha256": provenance["helper_requirement_sha256"],
            "baseline_provenance_sha256": digest(provenance_bytes),
            "server_manifest_sha256": digest(manifest_bytes),
            "old_generation": transaction["old_generation"],
            "generation_id": transaction["new_generation"],
            "hosts": provenance["hosts"],
        }
        return {
            "archive": archive,
            "archive_id": archive_id,
            "compose_facts": compose_facts,
            "declaration": declaration,
            "helper_requirement": helper_requirement,
            "manifest": manifest,
            "provenance": provenance,
            "receipt": receipt,
            "transaction": transaction,
        }

    def validate_artifact_chain(self, artifacts):
        self.installer.validate_legacy_baseline_artifact_chain(
            artifacts["declaration"], EXACT_FRAGMENT, artifacts["compose_facts"],
            artifacts["helper_requirement"], artifacts["provenance"], artifacts["manifest"],
            artifacts["archive"], artifacts["transaction"], artifacts["receipt"],
        )

    def test_renders_the_exact_three_route_external_https_fragment(self):
        declaration = self.declaration()
        self.assertEqual(EXACT_FRAGMENT, self.installer.render_legacy_baseline_fragment(declaration))
        self.installer.reconcile_legacy_baseline_fragment(declaration, EXACT_FRAGMENT)
        self.assertEqual(
            [source for source, _ in COMPATIBILITY_PAIRS],
            [route["host"] for route in declaration["routes"]],
        )

    def test_rejects_nonbaseline_routes_owned_targets_and_arbitrary_caddy_bytes(self):
        cases = []
        redirect = self.declaration()
        redirect["routes"][0] = {
            "type": "redirect", "host": "ecat.swifteng.com.cn",
            "target_host": "www.dianqimao.vip", "preserve_uri": True, "redirect_code": 308,
        }
        cases.append(redirect)
        docker = self.declaration()
        docker["routes"][0] = {
            "type": "docker_proxy", "host": "ecat.swifteng.com.cn",
            "service": "web", "upstream": "web", "port": 443, "network": "shared-edge",
        }
        cases.append(docker)
        owned_target = self.declaration()
        owned_target["routes"][0]["target_host"] = "ecatadmin.swifteng.com.cn"
        cases.append(owned_target)
        duplicate = self.declaration()
        duplicate["routes"][1]["host"] = "ecat.swifteng.com.cn"
        cases.append(duplicate)
        extra = self.declaration()
        extra["routes"].append({
            "type": "https_proxy", "host": "extra.swifteng.com.cn", "target_host": "extra.dianqimao.vip",
        })
        cases.append(extra)
        reordered = self.declaration()
        reordered["routes"].reverse()
        cases.append(reordered)
        alternate_target = self.declaration()
        alternate_target["routes"][0]["target_host"] = "other.dianqimao.vip"
        cases.append(alternate_target)
        alternate_identity = self.declaration()
        alternate_identity.update({
            "project_id": "other-project", "environment": "other-edge",
            "deployment_id": "other-project--other-edge",
            "source_repo": "https://github.com/example/other-project",
        })
        cases.append(alternate_identity)
        wildcard = self.declaration()
        wildcard["routes"][0]["host"] = "*.swifteng.com.cn"
        cases.append(wildcard)
        bare_listener = self.declaration()
        bare_listener["routes"][0]["host"] = ":443"
        cases.append(bare_listener)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(self.installer.ContractError):
                    self.installer.validate_legacy_baseline_declaration(value)
        with self.assertRaises(self.installer.ContractError):
            self.installer.reconcile_legacy_baseline_fragment(
                self.declaration(), EXACT_FRAGMENT + b"\n:443 { respond 200 }\n",
            )

    def test_validates_cross_artifact_hashes_empty_compose_and_exact_archive_members(self):
        artifacts = self.artifacts()
        self.installer.validate_legacy_baseline_declaration(artifacts["declaration"])
        self.installer.validate_baseline_provenance(artifacts["provenance"])
        self.installer.validate_baseline_transaction(artifacts["transaction"])
        self.installer.validate_baseline_receipt(artifacts["receipt"])
        self.normal_helper.validate_manifest(artifacts["manifest"])
        self.validate_artifact_chain(artifacts)
        with tarfile.open(fileobj=io.BytesIO(artifacts["archive"]), mode="r:gz") as archive:
            self.assertEqual(ARCHIVE_FILES, tuple(member.name for member in archive.getmembers()))
        for artifact in (artifacts["manifest"], artifacts["transaction"], artifacts["receipt"]):
            self.assertEqual(artifacts["archive_id"], artifact.get("archive_id", artifact.get("deploy_bundle_sha256")))
        for field in (
            "declaration_sha256", "fragment_sha256", "compose_sha256", "helper_requirement_sha256",
        ):
            self.assertEqual(artifacts["provenance"][field], artifacts["manifest"][field])
            self.assertEqual(artifacts["provenance"][field], artifacts["transaction"][field])
            self.assertEqual(artifacts["provenance"][field], artifacts["receipt"][field])
        self.assertEqual(artifacts["provenance"]["source"], artifacts["manifest"]["source"])
        self.assertEqual(
            artifacts["provenance"]["fragment_sha256"],
            artifacts["manifest"]["source"]["legacy_fragment_sha256"],
        )
        nonempty = json.loads(json.dumps(artifacts["provenance"]))
        nonempty["compose_facts"]["services"]["web"] = {}
        with self.assertRaises(self.installer.ContractError):
            self.installer.validate_baseline_provenance(nonempty)
        wrong_source = json.loads(json.dumps(artifacts["provenance"]))
        wrong_source["source"] = {"kind": "baseline_import"}
        with self.assertRaises(self.installer.ContractError):
            self.installer.validate_baseline_provenance(wrong_source)
        mismatched_transaction = copy.deepcopy(artifacts)
        mismatched_transaction["transaction"]["archive_id"] = "f" * 64
        self.installer.validate_baseline_transaction(mismatched_transaction["transaction"])
        with self.assertRaises(self.installer.ContractError):
            self.validate_artifact_chain(mismatched_transaction)
        mismatched_receipt = copy.deepcopy(artifacts)
        mismatched_receipt["receipt"]["transaction_id"] = "tx-" + "f" * 32
        self.installer.validate_baseline_receipt(mismatched_receipt["receipt"])
        with self.assertRaises(self.installer.ContractError):
            self.validate_artifact_chain(mismatched_receipt)
        wrong_manifest_source = copy.deepcopy(artifacts)
        wrong_manifest_source["manifest"]["source"] = {"kind": "baseline_import"}
        self.normal_helper.validate_manifest(wrong_manifest_source["manifest"])
        with self.assertRaises(self.installer.ContractError):
            self.validate_artifact_chain(wrong_manifest_source)
        uncommitted_transaction = copy.deepcopy(artifacts)
        uncommitted_transaction["transaction"]["phase"] = "prepared"
        self.installer.validate_baseline_transaction(uncommitted_transaction["transaction"])
        with self.assertRaises(self.installer.ContractError):
            self.validate_artifact_chain(uncommitted_transaction)
        extra_member = copy.deepcopy(artifacts)
        archive_members = {
            "caddy/declaration.json": canonical_bytes(extra_member["declaration"]),
            "caddy/site.caddy": EXACT_FRAGMENT,
            "caddy/helper-requirement.json": canonical_bytes(extra_member["helper_requirement"]),
            "caddy/bundle-provenance.json": canonical_bytes(extra_member["provenance"]),
            "runtime/compose.json": canonical_bytes(extra_member["compose_facts"]),
            "unexpected.txt": b"unexpected\n",
        }
        extra_member["archive"] = archive_bytes(
            archive_members, (*ARCHIVE_FILES, "unexpected.txt"),
        )
        extra_member["archive_id"] = digest(extra_member["archive"])
        extra_member["manifest"]["deploy_bundle_sha256"] = extra_member["archive_id"]
        extra_member["transaction"]["archive_id"] = extra_member["archive_id"]
        extra_member["receipt"]["archive_id"] = extra_member["archive_id"]
        with self.assertRaises(self.installer.ContractError):
            self.validate_artifact_chain(extra_member)
        oversized_member = copy.deepcopy(artifacts)
        archive_members = {
            "caddy/declaration.json": canonical_bytes(oversized_member["declaration"]),
            "caddy/site.caddy": b"x" * (8 * 1024 * 1024 + 1),
            "caddy/helper-requirement.json": canonical_bytes(oversized_member["helper_requirement"]),
            "caddy/bundle-provenance.json": canonical_bytes(oversized_member["provenance"]),
            "runtime/compose.json": canonical_bytes(oversized_member["compose_facts"]),
        }
        oversized_member["archive"] = archive_bytes(archive_members)
        oversized_member["archive_id"] = digest(oversized_member["archive"])
        oversized_member["manifest"]["deploy_bundle_sha256"] = oversized_member["archive_id"]
        oversized_member["transaction"]["archive_id"] = oversized_member["archive_id"]
        oversized_member["receipt"]["archive_id"] = oversized_member["archive_id"]
        with self.assertRaises(self.installer.ContractError):
            self.installer._read_legacy_baseline_archive(oversized_member["archive"])

    def test_archive_reader_rejects_a_sixth_member_without_materializing_members(self):
        raw_archive = archive_bytes(
            {name: b"" for name in (*ARCHIVE_FILES, "unexpected.txt")},
            (*ARCHIVE_FILES, "unexpected.txt"),
        )
        with mock.patch.object(tarfile.TarFile, "getmembers", side_effect=AssertionError):
            with self.assertRaises(self.installer.ContractError):
                self.installer._read_legacy_baseline_archive(raw_archive)

    def test_normal_bundle_loader_remains_closed_to_external_targets_and_baseline_provenance(self):
        artifacts = self.artifacts()
        with self.assertRaises(self.normal_helper.ContractError):
            self.normal_helper.validate_declaration(artifacts["declaration"])
        with self.assertRaises(self.normal_helper.ContractError):
            self.normal_helper.validate_internal_provenance(artifacts["provenance"])

    def test_baseline_transaction_records_all_durable_phases_and_receipt_requires_commit(self):
        artifacts = self.artifacts()
        for phase in ("prepared", "current-switched", "reloaded", "smoked", "verified", "committed"):
            with self.subTest(phase=phase):
                transaction = dict(artifacts["transaction"], phase=phase)
                self.installer.validate_baseline_transaction(transaction)
        transaction = dict(artifacts["transaction"], phase="wrong")
        with self.assertRaises(self.installer.ContractError):
            self.installer.validate_baseline_transaction(transaction)
        receipt = dict(artifacts["receipt"], status="smoked")
        with self.assertRaises(self.installer.ContractError):
            self.installer.validate_baseline_receipt(receipt)


class Crash(BaseException):
    pass


class BaselineRuntime:
    def __init__(self, *, fail_validate=False, fail_reload=False, fail_smoke=False,
                 crash_after_smoke=False):
        self.fail_validate = fail_validate
        self.fail_reload = fail_reload
        self.fail_smoke = fail_smoke
        self.crash_after_smoke = crash_after_smoke
        self.validations = []
        self.reloads = 0
        self.smokes = []

    def validate(self, generation):
        self.validations.append(Path(generation).name)
        if self.fail_validate:
            raise RuntimeError("injected baseline validation failure")

    def reload(self):
        self.reloads += 1
        if self.fail_reload:
            raise RuntimeError("injected baseline reload failure")

    def smoke(self, hosts):
        self.smokes.append(tuple(hosts))
        if self.fail_smoke and hosts:
            raise RuntimeError("injected baseline smoke failure")
        if self.crash_after_smoke:
            raise Crash()


@unittest.skipUnless(INSTALLER_PATH.is_file() and HELPER_PATH.is_file(), "package not implemented")
class BaselineImportMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = load(INSTALLER_PATH, "baseline_import_maintenance_installer")
        cls.normal_helper = load(HELPER_PATH, "baseline_import_frozen_normal_helper")
        cls.approved_hash = digest(HELPER_PATH.read_bytes())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = self.installer.Layout.for_test_root(self.root)
        self.installer.bootstrap_host(
            self.layout, owner_uid=os.getuid(), caddy_container="shared-caddy",
            container_config_root="/etc/caddy",
        )
        self.installer.install_helper(
            self.layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
        )
        self.artifact_factory = LegacyBaselineArtifactTests()
        self.artifacts = self.artifact_factory.artifacts(self.approved_hash)
        self.input_dir = self._write_input(self.artifacts)

    def tearDown(self):
        self.temporary.cleanup()

    def _write_input(self, artifacts):
        input_root = self.layout.maintenance_root / "baseline-input"
        input_dir = input_root / artifacts["archive_id"]
        input_dir.mkdir(parents=True, mode=0o700)
        os.chmod(input_root, 0o700)
        os.chmod(input_dir, 0o700)
        archive_path = input_dir / "deploy-bundle.tar.gz"
        manifest_path = input_dir / "server-manifest.json"
        archive_path.write_bytes(artifacts["archive"])
        manifest_path.write_bytes(canonical_bytes(artifacts["manifest"]))
        os.chmod(archive_path, 0o600)
        os.chmod(manifest_path, 0o600)
        return input_dir

    def _root_call(self, function, *args, **kwargs):
        with mock.patch.object(self.installer.os, "geteuid", return_value=0):
            return function(*args, **kwargs)

    def _import(self, runtime=None, phase_hook=None, bundle_id=None):
        return self._root_call(
            self.installer.import_baseline, self.layout,
            bundle_id or self.artifacts["archive_id"], owner_uid=os.getuid(),
            runtime=runtime or BaselineRuntime(), phase_hook=phase_hook,
        )

    def _recover(self, runtime=None, phase_hook=None):
        return self._root_call(
            self.installer.recover_baseline_maintenance, self.layout,
            owner_uid=os.getuid(), runtime=runtime or BaselineRuntime(),
            phase_hook=phase_hook,
        )

    def _assert_initial_current(self):
        evidence = json.loads(self.layout.bootstrap_attestation_path.read_text())
        self.assertEqual(evidence["initial_current_target"], os.readlink(self.layout.current_link))

    def _assert_frozen_normal_release_is_blocked(self):
        before_current = os.readlink(self.layout.current_link)
        for action in ("preflight", "apply"):
            subject = self.normal_helper.SharedCaddyHelper(
                self.layout, runtime=BaselineRuntime(),
                trust=self.normal_helper.TrustPolicy(owner_uid=os.getuid()),
                executable_path=self.layout.helper_path,
            )
            with self.assertRaises(self.normal_helper.RecoveryRequired):
                getattr(subject, action)("sample-app--staging", "a" * 64)
        self.assertEqual(before_current, os.readlink(self.layout.current_link))
        self.assertFalse(self.layout.transaction_path.exists())
        self.assertFalse(self.layout.recovery_marker.exists())

    def _assert_terminal_marker_blocks_other_root_authorities(self):
        marker_bytes = self.layout.maintenance_recovery_marker.read_bytes()
        with self.assertRaises(self.installer.InstallError):
            self._import()
        with self.assertRaises(self.installer.InstallError):
            self.installer.install_helper(
                self.layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
            )
        with self.assertRaises(self.installer.InstallError):
            self.installer.provision_deployments(
                self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
                release_uid=os.getuid(), release_gid=os.getgid(),
            )
        with self.assertRaises(self.installer.InstallError):
            self.installer.recover_helper_maintenance(
                self.layout, owner_uid=os.getuid(),
            )
        self.assertEqual(marker_bytes, self.layout.maintenance_recovery_marker.read_bytes())

    def test_import_is_root_only_and_cli_accepts_only_the_two_exact_authorities(self):
        with mock.patch.object(self.installer.os, "geteuid", return_value=os.getuid() or 501):
            with self.assertRaisesRegex(self.installer.InstallError, "root"):
                self.installer.import_baseline(
                    self.layout, self.artifacts["archive_id"], owner_uid=os.getuid(),
                    runtime=BaselineRuntime(),
                )

        parser = self.installer.build_parser()
        imported = parser.parse_args([
            "--maintenance-action", "import-baseline",
            "--baseline-bundle-id", self.artifacts["archive_id"],
        ])
        self.assertEqual("import-baseline", imported.maintenance_action)
        self.assertEqual(self.artifacts["archive_id"], imported.baseline_bundle_id)
        recovered = parser.parse_args([
            "--maintenance-action", "recover-baseline-maintenance",
        ])
        self.assertEqual("recover-baseline-maintenance", recovered.maintenance_action)
        rejected = (
            ["--maintenance-act", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"]],
            ["--maintenance-action", "import-basel", "--baseline-bundle-id", self.artifacts["archive_id"]],
            ["--maintenance-action", "import-baseline"],
            ["--maintenance-action", "recover-baseline-maintenance", "--baseline-bundle-id", self.artifacts["archive_id"]],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--expected-helper-sha256", self.approved_hash],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--deployment-id", "ecat-energy--legacy-edge"],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--caddy-container", "other-caddy"],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--input-path", "/tmp/input"],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--hostname", "ecat.swifteng.com.cn"],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--source-repo", "https://example.invalid/repo"],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--smoke-url", "https://ecat.swifteng.com.cn/"],
            ["--maintenance-action", "import-baseline", "--maintenance-action", "import-baseline",
             "--baseline-bundle-id", self.artifacts["archive_id"]],
            ["--maintenance-action", "import-baseline", "--baseline-bundle-id", self.artifacts["archive_id"],
             "--baseline-bundle-id", self.artifacts["archive_id"]],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                parser.parse_args(arguments)

        self.assertEqual(
            (
                "Cmnd_Alias ECAT_CADDY_PREFLIGHT = /usr/local/sbin/deploydesk-caddy-apply "
                "^--preflight --deployment-id ecat-energy--test --bundle-id [0-9a-f]{64}$\n"
                "Cmnd_Alias ECAT_CADDY_APPLY = /usr/local/sbin/deploydesk-caddy-apply "
                "^--deployment-id ecat-energy--test --bundle-id [0-9a-f]{64}$\n"
                "ubuntu ALL=(root) NOPASSWD: ECAT_CADDY_PREFLIGHT, ECAT_CADDY_APPLY\n"
            ),
            self.installer.render_deployment_sudoers("ecat-energy--test", "ubuntu", "ECAT"),
        )

    def test_import_refuses_noninitial_nonempty_provisioned_or_drifted_host_authority(self):
        cases = (
            "noninitial", "nonempty", "provisioned", "helper-drift", "contract-drift",
            "bootstrap-drift", "replaced-shared-lock",
        )
        for case in cases:
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                if case == "noninitial":
                    generation = self.layout.generations_root / ("gen-" + "f" * 32)
                    (generation / "sites").mkdir(parents=True)
                    (generation / "manifests").mkdir()
                    os.chmod(generation / "sites", 0o500)
                    os.chmod(generation / "manifests", 0o500)
                    os.chmod(generation, 0o500)
                    self.layout.current_link.unlink()
                    self.layout.current_link.symlink_to("generations/" + generation.name)
                elif case == "nonempty":
                    current = self.layout.current_generation()
                    os.chmod(current / "sites", 0o700)
                    (current / "sites" / "unexpected.caddy").write_text("unexpected\n")
                    os.chmod(current / "sites" / "unexpected.caddy", 0o400)
                    os.chmod(current / "sites", 0o500)
                elif case == "provisioned":
                    self.installer.provision_deployments(
                        self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
                        release_uid=os.getuid(), release_gid=os.getgid(),
                    )
                elif case == "helper-drift":
                    self.layout.helper_path.write_bytes(self.layout.helper_path.read_bytes() + b"\n# drift\n")
                elif case == "contract-drift":
                    contract = json.loads(self.layout.contract_path.read_text())
                    contract["caddy_container"] = "other-caddy"
                    self.layout.contract_path.write_bytes(canonical_bytes(contract))
                elif case == "bootstrap-drift":
                    evidence = json.loads(self.layout.bootstrap_attestation_path.read_text())
                    evidence["root_config_sha256"] = "f" * 64
                    self.layout.bootstrap_attestation_path.write_bytes(canonical_bytes(evidence))
                else:
                    self.layout.shared_lock.unlink()
                    self.layout.shared_lock.write_bytes(b"")
                    os.chmod(self.layout.shared_lock, 0o600)
                before_current = os.readlink(self.layout.current_link)
                with self.assertRaises(self.installer.InstallError):
                    self._import()
                self.assertEqual(before_current, os.readlink(self.layout.current_link))
                self.assertFalse(self.layout.baseline_receipt_path.exists())

    def test_import_refuses_every_existing_transaction_marker_and_untrusted_input(self):
        blocker_names = (
            "transaction_path", "recovery_marker", "maintenance_transaction_path",
            "maintenance_recovery_marker",
        )
        input_cases = ("ancestor-mode", "extra-file", "symlink", "hardlink", "archive-id")
        for case in (*blocker_names, *input_cases):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                if case in blocker_names:
                    getattr(self.layout, case).write_text("blocked\n")
                elif case == "ancestor-mode":
                    os.chmod(self.input_dir.parent, 0o755)
                elif case == "extra-file":
                    extra = self.input_dir / "unexpected"
                    extra.write_text("unexpected\n")
                    os.chmod(extra, 0o600)
                elif case == "symlink":
                    archive = self.input_dir / "deploy-bundle.tar.gz"
                    retained = self.root / "retained-archive"
                    archive.rename(retained)
                    archive.symlink_to(retained)
                elif case == "hardlink":
                    os.link(
                        self.input_dir / "deploy-bundle.tar.gz",
                        self.root / "outside-hardlink",
                    )
                else:
                    archive = self.input_dir / "deploy-bundle.tar.gz"
                    archive.write_bytes(archive.read_bytes() + b"drift")
                    os.chmod(archive, 0o600)
                with self.assertRaises(self.installer.InstallError):
                    self._import()
                self._assert_initial_current()
                self.assertFalse(self.layout.baseline_receipt_path.exists())

    def test_import_uses_full_artifact_validator_and_rejects_extra_archive_member(self):
        members = self.installer._read_legacy_baseline_archive(self.artifacts["archive"])
        members["unexpected.txt"] = b"unexpected\n"
        raw_archive = archive_bytes(members, (*ARCHIVE_FILES, "unexpected.txt"))
        archive_id = digest(raw_archive)
        changed = copy.deepcopy(self.artifacts)
        changed["archive"] = raw_archive
        changed["archive_id"] = archive_id
        changed["manifest"]["deploy_bundle_sha256"] = archive_id
        input_dir = self.layout.maintenance_root / "baseline-input" / archive_id
        input_dir.mkdir(mode=0o700)
        (input_dir / "deploy-bundle.tar.gz").write_bytes(raw_archive)
        (input_dir / "server-manifest.json").write_bytes(canonical_bytes(changed["manifest"]))
        for path in input_dir.iterdir():
            os.chmod(path, 0o600)
        with self.assertRaises(self.installer.InstallError):
            self._import(bundle_id=archive_id)
        self._assert_initial_current()

    def test_shared_lock_wait_re_attests_lock_and_stable_input_before_mutation(self):
        for case in ("input-replaced", "lock-replaced"):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                original_flock = self.installer.fcntl.flock
                injected = [False]

                def replace_while_waiting(descriptor, operation):
                    result = original_flock(descriptor, operation)
                    if operation == self.installer.fcntl.LOCK_EX and not injected[0]:
                        injected[0] = True
                        if case == "input-replaced":
                            archive = self.input_dir / "deploy-bundle.tar.gz"
                            archive.write_bytes(archive.read_bytes() + b"changed while waiting")
                            os.chmod(archive, 0o600)
                        else:
                            self.layout.shared_lock.unlink()
                            self.layout.shared_lock.write_bytes(b"")
                            os.chmod(self.layout.shared_lock, 0o600)
                    return result

                with mock.patch.object(self.installer.fcntl, "flock", replace_while_waiting):
                    with self.assertRaises(self.installer.InstallError):
                        self._import()
                self.assertTrue(injected[0])
                self._assert_initial_current()
                self.assertFalse(self.layout.maintenance_transaction_path.exists())
                self.assertFalse(self.layout.baseline_receipt_path.exists())

    def test_success_is_durable_frozen_canonical_and_one_time_only(self):
        runtime = BaselineRuntime()
        phases = []
        before_input = {
            path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode), path.stat().st_ino)
            for path in self.input_dir.iterdir()
        }
        receipt = self._import(runtime=runtime, phase_hook=lambda phase, value: phases.append(phase))
        self.assertEqual(
            ["prepared", "current-switched", "reloaded", "smoked", "verified", "committed"],
            phases,
        )
        self.assertEqual(1, len(runtime.validations))
        self.assertEqual(1, runtime.reloads)
        self.assertEqual([tuple(source for source, _ in COMPATIBILITY_PAIRS)], runtime.smokes)
        self.assertEqual(receipt, json.loads(self.layout.baseline_receipt_path.read_text()))
        self.assertEqual(canonical_bytes(receipt), self.layout.baseline_receipt_path.read_bytes())
        self.assertFalse(self.layout.maintenance_transaction_path.exists())
        current = self.layout.current_generation()
        self.assertEqual(receipt["generation_id"], current.name)
        self.assertEqual(
            {"sites", "manifests"}, {path.name for path in current.iterdir()},
        )
        self.assertEqual(
            EXACT_FRAGMENT,
            (current / "sites" / "ecat-energy--legacy-edge.caddy").read_bytes(),
        )
        for path in (current, current / "sites", current / "manifests"):
            self.assertEqual(0o500, stat.S_IMODE(path.stat().st_mode))
        for path in (current / "sites").iterdir():
            self.assertEqual(0o400, stat.S_IMODE(path.stat().st_mode))
        for path in (current / "manifests").iterdir():
            self.assertEqual(0o400, stat.S_IMODE(path.stat().st_mode))
        after_input = {
            path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode), path.stat().st_ino)
            for path in self.input_dir.iterdir()
        }
        self.assertEqual(before_input, after_input)
        with self.assertRaisesRegex(self.installer.InstallError, "already imported"):
            self._import()

    def test_every_durable_phase_has_deterministic_recovery(self):
        rollback_phases = {"prepared", "current-switched", "reloaded"}
        for crash_phase in (
            "prepared", "current-switched", "reloaded", "smoked", "verified", "committed",
        ):
            with self.subTest(phase=crash_phase):
                self.tearDown()
                self.setUp()
                runtime = BaselineRuntime()

                def crash(phase, transaction):
                    if phase == crash_phase:
                        raise Crash()

                with self.assertRaises(Crash):
                    self._import(runtime=runtime, phase_hook=crash)
                transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
                self.assertEqual(crash_phase, transaction["phase"])
                recovered_runtime = BaselineRuntime()
                result = self._recover(runtime=recovered_runtime)
                self.assertFalse(self.layout.maintenance_transaction_path.exists())
                self.assertFalse(self.layout.maintenance_recovery_marker.exists())
                if crash_phase in rollback_phases:
                    self.assertEqual("rolled-back", result["status"])
                    self._assert_initial_current()
                    self.assertFalse(self.layout.baseline_receipt_path.exists())
                    self.assertFalse(
                        (self.layout.generations_root / transaction["new_generation"]).exists()
                    )
                    self.assertEqual([()], recovered_runtime.smokes)
                else:
                    self.assertEqual("committed", result["status"])
                    self.assertTrue(self.layout.baseline_receipt_path.is_file())
                    self.assertEqual(transaction["new_generation"], self.layout.current_generation().name)
                    self.assertEqual(
                        [tuple(source for source, _ in COMPATIBILITY_PAIRS)],
                        recovered_runtime.smokes,
                    )

    def test_pointer_one_write_ahead_and_unrecorded_successful_smoke_roll_back(self):
        for case in ("pointer-ahead", "smoke-before-smoked"):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                runtime = BaselineRuntime(crash_after_smoke=(case == "smoke-before-smoked"))
                if case == "pointer-ahead":
                    original = self.installer.TrustedInstallerWalker.replace_symlink

                    def crash_after_switch(walker, path, target):
                        result = original(walker, path, target)
                        if Path(path) == self.layout.current_link:
                            raise Crash()
                        return result

                    with mock.patch.object(
                        self.installer.TrustedInstallerWalker, "replace_symlink", crash_after_switch,
                    ), self.assertRaises(Crash):
                        self._import(runtime=runtime)
                else:
                    with self.assertRaises(Crash):
                        self._import(runtime=runtime)
                transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
                self.assertEqual("prepared" if case == "pointer-ahead" else "reloaded", transaction["phase"])
                recovered_runtime = BaselineRuntime()
                result = self._recover(runtime=recovered_runtime)
                self.assertEqual("rolled-back", result["status"])
                self._assert_initial_current()
                self.assertEqual([()], recovered_runtime.smokes)

    def test_process_death_before_prepared_is_discoverable_and_recoverable(self):
        original_phase = self.installer._phase_baseline

        def crash_before_prepared(walker, layout, transaction, phase, phase_hook):
            if phase == "prepared":
                raise Crash()
            return original_phase(walker, layout, transaction, phase, phase_hook)

        with mock.patch.object(
            self.installer, "_phase_baseline", crash_before_prepared,
        ), self.assertRaises(Crash):
            self._import()
        self.assertFalse(self.layout.maintenance_transaction_path.exists())
        self.assertEqual(2, len(tuple(self.layout.generations_root.iterdir())))
        result = self._recover()
        self.assertEqual("rolled-back", result["status"])
        self._assert_initial_current()
        self.assertEqual(1, len(tuple(self.layout.generations_root.iterdir())))
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())

    def test_crossed_recovery_action_does_not_poison_a_valid_transaction(self):
        def crash_prepared(phase, transaction):
            if phase == "prepared":
                raise Crash()

        with self.assertRaises(Crash):
            self._import(phase_hook=crash_prepared)
        with self.assertRaisesRegex(self.installer.InstallError, "baseline recovery action"):
            self.installer.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
        self.assertEqual("rolled-back", self._recover()["status"])

        self.tearDown()
        self.setUp()

        def crash_staged(phase, transaction):
            if phase == "staged":
                raise Crash()

        with self.assertRaises(Crash):
            self.installer.install_helper(
                self.layout, HELPER_PATH, self.approved_hash,
                owner_uid=os.getuid(), phase_hook=crash_staged,
            )
        with self.assertRaisesRegex(self.installer.InstallError, "helper recovery action"):
            self._recover()
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
        self.installer.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertFalse(self.layout.maintenance_transaction_path.exists())

    def test_smoke_failure_rolls_back_without_commit_or_recovery_marker(self):
        runtime = BaselineRuntime(fail_smoke=True)
        with self.assertRaises(self.installer.InstallError):
            self._import(runtime=runtime)
        self._assert_initial_current()
        self.assertFalse(self.layout.maintenance_transaction_path.exists())
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
        self.assertFalse(self.layout.baseline_receipt_path.exists())
        self.assertEqual(
            [tuple(source for source, _ in COMPATIBILITY_PAIRS), ()], runtime.smokes,
        )

    def test_committed_receipt_recovery_is_idempotent_and_canonical(self):
        def crash(phase, transaction):
            if phase == "committed":
                raise Crash()

        with self.assertRaises(Crash):
            self._import(phase_hook=crash)
        receipt = self._recover()
        before = self.layout.baseline_receipt_path.read_bytes()
        repeated = self._recover()
        self.assertEqual(receipt, repeated)
        self.assertEqual(before, self.layout.baseline_receipt_path.read_bytes())
        self.assertEqual(canonical_bytes(receipt), before)

    def test_recovery_rolls_back_provable_failures_and_marks_ambiguous_state(self):
        for case in (
            "pointer", "runtime", "runtime-smoke", "evidence",
            "old-nonempty", "old-mode", "old-missing",
        ):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()

                def crash(phase, transaction):
                    target = "current-switched" if case.startswith("old-") or case == "pointer" else "smoked"
                    if phase == target:
                        raise Crash()

                with self.assertRaises(Crash):
                    self._import(phase_hook=crash)
                transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
                runtime = BaselineRuntime(
                    fail_validate=(case == "runtime"),
                    fail_smoke=(case == "runtime-smoke"),
                )
                if case == "pointer":
                    generation = self.layout.generations_root / ("gen-" + "e" * 32)
                    (generation / "sites").mkdir(parents=True)
                    (generation / "manifests").mkdir()
                    os.chmod(generation / "sites", 0o500)
                    os.chmod(generation / "manifests", 0o500)
                    os.chmod(generation, 0o500)
                    self.layout.current_link.unlink()
                    self.layout.current_link.symlink_to("generations/" + generation.name)
                elif case == "evidence":
                    fragment = (
                        self.layout.generations_root / transaction["new_generation"] / "sites" /
                        "ecat-energy--legacy-edge.caddy"
                    )
                    os.chmod(fragment, 0o600)
                    fragment.write_text("tampered\n")
                    os.chmod(fragment, 0o400)
                elif case.startswith("old-"):
                    old_sites = (
                        self.layout.generations_root / transaction["old_generation"] / "sites"
                    )
                    if case == "old-nonempty":
                        os.chmod(old_sites, 0o700)
                        unexpected = old_sites / "unexpected.caddy"
                        unexpected.write_text("tampered old generation\n")
                        os.chmod(unexpected, 0o400)
                        os.chmod(old_sites, 0o500)
                    elif case == "old-mode":
                        os.chmod(old_sites, 0o700)
                    else:
                        old_generation = old_sites.parent
                        os.chmod(old_generation, 0o700)
                        old_sites.rmdir()
                        os.chmod(old_generation, 0o500)
                if case in ("pointer", "old-nonempty", "old-mode", "old-missing"):
                    with self.assertRaises(self.installer.InstallError):
                        self._recover(runtime=runtime)
                    self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
                    self.assertTrue(self.layout.maintenance_transaction_path.is_file())
                else:
                    result = self._recover(runtime=runtime)
                    self.assertEqual("rolled-back", result["status"])
                    self._assert_initial_current()
                    self.assertFalse(self.layout.maintenance_recovery_marker.exists())
                    self.assertFalse(self.layout.maintenance_transaction_path.exists())

    def test_rollback_is_resumable_after_every_mutation(self):
        for fault in (
            "pointer-restored", "reloaded", "smoked", "candidate-removed",
            "transaction-removed", "receipt-written", "ledger-removed",
            "marker-remove-before", "marker-removed",
        ):
            with self.subTest(fault=fault):
                self.tearDown()
                self.setUp()

                def crash_smoked(phase, transaction):
                    if phase == "smoked":
                        raise Crash()

                with self.assertRaises(Crash):
                    self._import(phase_hook=crash_smoked)
                transaction = json.loads(self.layout.maintenance_transaction_path.read_text())

                if fault == "marker-removed":
                    with self.assertRaises(self.installer.InstallError):
                        self._recover(runtime=BaselineRuntime(
                            fail_validate=True, fail_reload=True,
                        ))
                    self.assertTrue(self.layout.maintenance_recovery_marker.is_file())

                injected = [False]
                patches = []
                runtime = BaselineRuntime(fail_validate=True)
                if fault == "pointer-restored":
                    original = self.installer.TrustedInstallerWalker.replace_symlink

                    def crash_after_pointer(walker, path, target):
                        result = original(walker, path, target)
                        if Path(path) == self.layout.current_link and not injected[0]:
                            injected[0] = True
                            raise Crash()
                        return result

                    patches.append(mock.patch.object(
                        self.installer.TrustedInstallerWalker,
                        "replace_symlink", crash_after_pointer,
                    ))
                elif fault in ("reloaded", "smoked"):
                    base_runtime = runtime

                    class CrashAfterRuntimeMutation(BaselineRuntime):
                        def validate(inner_self, generation):
                            base_runtime.validate(generation)

                        def reload(inner_self):
                            base_runtime.reload()
                            if fault == "reloaded" and not injected[0]:
                                injected[0] = True
                                raise Crash()

                        def smoke(inner_self, hosts):
                            base_runtime.smoke(hosts)
                            if fault == "smoked" and not injected[0]:
                                injected[0] = True
                                raise Crash()

                    runtime = CrashAfterRuntimeMutation()
                elif fault == "candidate-removed":
                    original = self.installer._thaw_and_remove_baseline_generation

                    def crash_after_candidate(walker, generation):
                        result = original(walker, generation)
                        if not injected[0]:
                            injected[0] = True
                            raise Crash()
                        return result

                    patches.append(mock.patch.object(
                        self.installer, "_thaw_and_remove_baseline_generation",
                        crash_after_candidate,
                    ))
                elif fault == "receipt-written":
                    original = self.installer.TrustedInstallerWalker.write_json

                    def crash_after_receipt(walker, path, value, mode=0o600):
                        result = original(walker, path, value, mode)
                        if (
                            Path(path) == self.layout.baseline_rollback_receipt_path
                            and not injected[0]
                        ):
                            injected[0] = True
                            raise Crash()
                        return result

                    patches.append(mock.patch.object(
                        self.installer.TrustedInstallerWalker,
                        "write_json", crash_after_receipt,
                    ))
                else:
                    original = self.installer.TrustedInstallerWalker.remove_file
                    targets = {
                        "transaction-removed": self.layout.maintenance_transaction_path,
                        "marker-remove-before": self.layout.maintenance_recovery_marker,
                        "marker-removed": self.layout.maintenance_recovery_marker,
                        "ledger-removed": self.layout.baseline_rollback_path,
                    }
                    target = targets[fault]

                    def crash_after_file_removal(walker, path, missing_ok=False):
                        if (
                            Path(path) == target and fault == "marker-remove-before"
                            and not injected[0]
                        ):
                            injected[0] = True
                            raise Crash()
                        result = original(walker, path, missing_ok=missing_ok)
                        if Path(path) == target and not injected[0]:
                            injected[0] = True
                            raise Crash()
                        return result

                    patches.append(mock.patch.object(
                        self.installer.TrustedInstallerWalker,
                        "remove_file", crash_after_file_removal,
                    ))

                with contextlib.ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    with self.assertRaises(Crash):
                        self._recover(runtime=runtime)
                self.assertTrue(injected[0])

                terminal_faults = {
                    "receipt-written", "ledger-removed",
                    "marker-remove-before", "marker-removed",
                }
                if fault in terminal_faults:
                    rollback_receipt = self.layout.baseline_rollback_receipt_path
                    self.assertTrue(rollback_receipt.is_file())
                    receipt_value = json.loads(rollback_receipt.read_bytes())
                    self.assertEqual(canonical_bytes(receipt_value), rollback_receipt.read_bytes())
                    self.assertEqual(0o600, stat.S_IMODE(rollback_receipt.stat().st_mode))
                    if fault == "receipt-written":
                        self.assertTrue(self.layout.baseline_rollback_path.is_file())
                    else:
                        self.assertFalse(self.layout.baseline_rollback_path.exists())
                    if fault == "marker-removed":
                        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
                    else:
                        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
                        self._assert_frozen_normal_release_is_blocked()
                        if fault in {"ledger-removed", "marker-remove-before"}:
                            self._assert_terminal_marker_blocks_other_root_authorities()

                if fault == "ledger-removed":
                    unrelated = self.layout.generations_root / ("gen-" + "9" * 32)
                    (unrelated / "sites").mkdir(parents=True)
                    (unrelated / "manifests").mkdir()
                    os.chmod(unrelated / "sites", 0o500)
                    os.chmod(unrelated / "manifests", 0o500)
                    os.chmod(unrelated, 0o500)

                result = self._recover()
                self.assertEqual("rolled-back", result["status"])
                self.assertEqual(transaction["transaction_id"], result["transaction_id"])
                self._assert_initial_current()
                self.assertFalse(self.layout.maintenance_transaction_path.exists())
                self.assertFalse(self.layout.maintenance_recovery_marker.exists())
                self.assertFalse(self.layout.baseline_rollback_path.exists())
                rollback_receipt = self.layout.baseline_rollback_receipt_path
                receipt_value = json.loads(rollback_receipt.read_bytes())
                self.assertEqual(
                    {
                        "schema_version": "shared-caddy-baseline-rollback-receipt/v1",
                        "status": "rolled-back",
                        "transaction_id": transaction["transaction_id"],
                        "archive_id": transaction["archive_id"],
                        "old_generation": transaction["old_generation"],
                        "new_generation": transaction["new_generation"],
                    },
                    receipt_value,
                )
                self.assertEqual(canonical_bytes(receipt_value), rollback_receipt.read_bytes())
                self.assertEqual(0o600, stat.S_IMODE(rollback_receipt.stat().st_mode))
                self.assertFalse(
                    (self.layout.generations_root / transaction["new_generation"]).exists()
                )
                if fault == "ledger-removed":
                    os.chmod(unrelated, 0o700)
                    os.chmod(unrelated / "sites", 0o700)
                    os.chmod(unrelated / "manifests", 0o700)
                    shutil.rmtree(unrelated)
                    committed = self._import()
                    self.assertEqual("committed", committed["status"])
                    self.assertFalse(self.layout.baseline_rollback_receipt_path.exists())

    def test_live_rollback_ledger_uses_one_canonical_path_and_blocks_other_authorities(self):
        def crash_smoked(phase, transaction):
            if phase == "smoked":
                raise Crash()

        with self.assertRaises(Crash):
            self._import(phase_hook=crash_smoked)
        original = self.installer._phase_baseline_rollback

        def crash_after_pointer_phase(walker, layout, rollback, step):
            result = original(walker, layout, rollback, step)
            if step == "pointer-restored":
                raise Crash()
            return result

        with mock.patch.object(
            self.installer, "_phase_baseline_rollback", crash_after_pointer_phase,
        ):
            with self.assertRaises(Crash):
                self._recover(runtime=BaselineRuntime(fail_validate=True))

        rollback_path = self.layout.baseline_rollback_path
        self.assertEqual(rollback_path, self.installer._baseline_rollback_path(self.layout))
        self.assertTrue(rollback_path.is_file())
        rollback = json.loads(rollback_path.read_bytes())
        self.assertEqual(canonical_bytes(rollback), rollback_path.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(rollback_path.stat().st_mode))

        self.layout.maintenance_transaction_path.unlink()
        self.layout.maintenance_recovery_marker.unlink()
        with self.assertRaises(self.installer.InstallError):
            self._import()
        with self.assertRaises(self.installer.InstallError):
            self.installer.install_helper(
                self.layout, HELPER_PATH, self.approved_hash, owner_uid=os.getuid(),
            )
        with self.assertRaises(self.installer.InstallError):
            self.installer.provision_deployments(
                self.layout, ["sample-app--staging"], owner_uid=os.getuid(),
                release_uid=os.getuid(), release_gid=os.getgid(),
            )
        with self.assertRaises(self.installer.CrossedMaintenanceRecovery):
            self.installer.recover_helper_maintenance(
                self.layout, owner_uid=os.getuid(),
            )

    def test_matching_baseline_marker_allows_repair_but_crossed_recovery_stays_blocked(self):
        def crash_current_switched(phase, transaction):
            if phase == "current-switched":
                raise Crash()

        with self.assertRaises(Crash):
            self._import(phase_hook=crash_current_switched)
        transaction = json.loads(self.layout.maintenance_transaction_path.read_text())
        old_sites = self.layout.generations_root / transaction["old_generation"] / "sites"
        os.chmod(old_sites, 0o700)
        with self.assertRaises(self.installer.InstallError):
            self._recover()
        marker_bytes = self.layout.maintenance_recovery_marker.read_bytes()
        marker = json.loads(marker_bytes)
        self.assertEqual(transaction["transaction_id"], marker["transaction_id"])

        mismatched = dict(marker, transaction_id="tx-" + "f" * 32)
        self.layout.maintenance_recovery_marker.write_bytes(canonical_bytes(mismatched))
        with self.assertRaises(self.installer.InstallError):
            self._recover()
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())
        self.layout.maintenance_recovery_marker.write_bytes(marker_bytes)

        with self.assertRaises(self.installer.InstallError):
            self.installer.recover_helper_maintenance(self.layout, owner_uid=os.getuid())
        self.assertEqual(marker_bytes, self.layout.maintenance_recovery_marker.read_bytes())
        self.assertTrue(self.layout.maintenance_transaction_path.is_file())

        os.chmod(old_sites, 0o500)

        class MarkerObservingRuntime(BaselineRuntime):
            def reload(inner_self):
                self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
                super().reload()

            def smoke(inner_self, hosts):
                self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
                super().smoke(hosts)

        result = self._recover(runtime=MarkerObservingRuntime())
        self.assertEqual("rolled-back", result["status"])
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
        self.assertFalse(self.layout.maintenance_transaction_path.exists())

    def test_automatic_recovery_returns_a_forward_committed_receipt(self):
        runtime = BaselineRuntime()

        def ordinary_failure_after_smoked(phase, transaction):
            if phase == "smoked":
                raise RuntimeError("ordinary post-smoke failure")

        receipt = self._import(runtime=runtime, phase_hook=ordinary_failure_after_smoked)
        self.assertEqual("committed", receipt["status"])
        self.assertEqual(receipt, json.loads(self.layout.baseline_receipt_path.read_text()))
        self.assertEqual(receipt["generation_id"], self.layout.current_generation().name)
        self.assertFalse(self.layout.maintenance_transaction_path.exists())
        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
        self.assertEqual(2, len(runtime.smokes))

    def test_input_bytes_are_bound_to_entries_and_member_set_through_retained_directory_fd(self):
        for attack in ("aba", "member-churn"):
            with self.subTest(attack=attack):
                self.tearDown()
                self.setUp()
                real_open = self.installer.os.open
                input_identity = (
                    self.input_dir.stat().st_dev, self.input_dir.stat().st_ino,
                )
                archive = self.input_dir / "deploy-bundle.tar.gz"
                manifest = self.input_dir / "server-manifest.json"
                injected = [False]
                replacement = self.root / "aba-replacement"
                backup = self.input_dir / ".aba-original"
                if attack == "aba":
                    replacement.write_bytes(archive.read_bytes())
                    os.chmod(replacement, 0o600)

                real_lstat = self.installer.TrustedInstallerWalker._lstat
                aba_info = [None]

                def attacked_lstat(walker, parent, name):
                    is_input = (parent.device, parent.inode) == input_identity
                    if attack == "aba" and is_input and name == archive.name:
                        if not injected[0]:
                            info = real_lstat(walker, parent, name)
                            aba_info[0] = info
                            archive.rename(backup)
                            replacement.rename(archive)
                            injected[0] = True
                            return info
                        if backup.exists():
                            archive.unlink()
                            backup.rename(archive)
                            return aba_info[0]
                    return real_lstat(walker, parent, name)

                def attacked_open(path, flags, mode=0o777, *, dir_fd=None):
                    is_input = False
                    if dir_fd is not None:
                        info = os.fstat(dir_fd)
                        is_input = (info.st_dev, info.st_ino) == input_identity
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                    if attack == "member-churn" and is_input:
                        extra = self.input_dir / "unexpected"
                        if path == archive.name and not extra.exists():
                            extra.write_bytes(b"churn\n")
                            os.chmod(extra, 0o600)
                            injected[0] = True
                        elif path == manifest.name and extra.exists():
                            extra.unlink()
                    return descriptor

                try:
                    with mock.patch.object(
                        self.installer.TrustedInstallerWalker, "_lstat", attacked_lstat,
                    ), mock.patch.object(self.installer.os, "open", attacked_open):
                        with self.assertRaises(self.installer.InstallError):
                            self._import()
                finally:
                    if backup.exists():
                        if archive.exists():
                            archive.unlink()
                        backup.rename(archive)
                self.assertTrue(injected[0])
                self._assert_initial_current()
                self.assertFalse(self.layout.baseline_receipt_path.exists())

    def test_candidate_validation_rejects_replaced_retained_temp_parent_before_subprocess(self):
        real_open = self.installer.os.open
        displaced = self.root / "infra-displaced"
        injected = [False]

        def replace_parent_after_temp_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if Path(path).name.startswith(".baseline-validate-") and not injected[0]:
                injected[0] = True
                self.layout.infra_root.rename(displaced)
                self.layout.infra_root.mkdir(mode=0o755)
            return descriptor

        completed = mock.Mock(returncode=0, stdout="")
        try:
            with mock.patch.object(self.installer.os, "open", replace_parent_after_temp_open), \
                    mock.patch.object(self.installer.subprocess, "run", return_value=completed) as run:
                with self.assertRaises(self.installer.InstallError):
                    self._root_call(
                        self.installer.import_baseline, self.layout, self.artifacts["archive_id"],
                        owner_uid=os.getuid(), runtime=None,
                    )
            self.assertTrue(injected[0])
            self.assertEqual(0, run.call_count)
        finally:
            if displaced.exists():
                shutil.rmtree(self.layout.infra_root)
                displaced.rename(self.layout.infra_root)

    def test_prepared_orphan_selection_uses_full_evidence_and_never_deletes_collisions(self):
        for case in (
            "other-staged-prefix", "unrelated-generation", "corrupt-matching-input",
            "forced-generation-collision",
        ):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                original_phase = self.installer._phase_baseline

                def crash_before_prepared(walker, layout, transaction, phase, phase_hook):
                    if phase == "prepared":
                        raise Crash()
                    return original_phase(walker, layout, transaction, phase, phase_hook)

                with mock.patch.object(
                    self.installer, "_phase_baseline", crash_before_prepared,
                ), self.assertRaises(Crash):
                    self._import()
                initial_generation = json.loads(
                    self.layout.bootstrap_attestation_path.read_text()
                )["initial_generation"]
                orphan_names = {
                    path.name for path in self.layout.generations_root.iterdir()
                    if path.name != initial_generation
                }
                self.assertEqual(1, len(orphan_names))
                orphan_name = orphan_names.pop()

                patcher = contextlib.nullcontext()
                unrelated = None
                if case == "other-staged-prefix":
                    other_id = self.artifacts["archive_id"][:32] + (
                        "0" if self.artifacts["archive_id"][32] != "0" else "1"
                    ) + self.artifacts["archive_id"][33:]
                    other_dir = self.layout.baseline_input_root / other_id
                    other_dir.mkdir(mode=0o700)
                    for name in ("deploy-bundle.tar.gz", "server-manifest.json"):
                        path = other_dir / name
                        path.write_bytes(b"unselected staged input\n")
                        os.chmod(path, 0o600)
                elif case == "unrelated-generation":
                    unrelated = self.layout.generations_root / ("gen-" + "e" * 32)
                    (unrelated / "sites").mkdir(parents=True)
                    (unrelated / "manifests").mkdir()
                    os.chmod(unrelated / "sites", 0o500)
                    os.chmod(unrelated / "manifests", 0o500)
                    os.chmod(unrelated, 0o500)
                elif case == "corrupt-matching-input":
                    archive = self.input_dir / "deploy-bundle.tar.gz"
                    archive.write_bytes(archive.read_bytes() + b"corrupt")
                    os.chmod(archive, 0o600)
                else:
                    second = self.artifact_factory.artifacts(
                        self.approved_hash, git_sha="2" * 40,
                    )
                    self._write_input(second)
                    patcher = mock.patch.object(
                        self.installer, "_baseline_generation_id",
                        return_value=orphan_name,
                    )

                with patcher:
                    if case in ("corrupt-matching-input", "forced-generation-collision"):
                        with self.assertRaises(self.installer.InstallError):
                            self._recover()
                        self.assertTrue(
                            (self.layout.generations_root / orphan_name).is_dir()
                        )
                        self.assertTrue(self.layout.maintenance_recovery_marker.is_file())
                    else:
                        result = self._recover()
                        self.assertEqual("rolled-back", result["status"])
                        self.assertFalse(
                            (self.layout.generations_root / orphan_name).exists()
                        )
                        self.assertFalse(self.layout.maintenance_recovery_marker.exists())
                        if unrelated is not None:
                            self.assertTrue(unrelated.is_dir())

    def test_baseline_docker_validate_and_reload_timeouts_are_bounded_install_errors(self):
        for action in ("validate", "reload"):
            with self.subTest(action=action):
                self.tearDown()
                self.setUp()
                contract = json.loads(self.layout.contract_path.read_text())
                expired = self.installer.subprocess.TimeoutExpired(
                    cmd=["/usr/bin/docker"], timeout=30,
                )
                with mock.patch.object(
                    self.installer.subprocess, "run", side_effect=expired,
                ) as run:
                    if action == "validate":
                        with self.assertRaises(self.installer.InstallError):
                            self._root_call(
                                self.installer.import_baseline, self.layout,
                                self.artifacts["archive_id"], owner_uid=os.getuid(), runtime=None,
                            )
                    else:
                        runtime = self.installer.BaselineDockerRuntime(contract, self.layout)
                        with self.assertRaises(self.installer.InstallError):
                            runtime.reload()
                self.assertEqual(1, run.call_count)
                arguments, keywords = run.call_args
                self.assertEqual(
                    {
                        "check": False,
                        "text": True,
                        "timeout": 30,
                        "stdout": self.installer.subprocess.PIPE,
                        "stderr": self.installer.subprocess.STDOUT,
                    },
                    keywords,
                )
                command = arguments[0]
                if action == "validate":
                    self.assertEqual(
                        [
                            "/usr/bin/docker", "exec", "shared-caddy", "caddy", "validate",
                            "--config",
                        ],
                        command[:6],
                    )
                    self.assertRegex(
                        command[6],
                        r"^/etc/caddy/\.baseline-validate-[0-9a-f]{32}\.Caddyfile$",
                    )
                    self.assertEqual(["--adapter", "caddyfile"], command[7:])
                else:
                    self.assertEqual(
                        [
                            "/usr/bin/docker", "exec", "shared-caddy", "caddy", "reload",
                            "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
                        ],
                        command,
                    )


if __name__ == "__main__":
    unittest.main()
