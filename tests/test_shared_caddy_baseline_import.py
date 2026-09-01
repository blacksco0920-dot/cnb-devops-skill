import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
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

    def artifacts(self):
        declaration = self.declaration()
        declaration_bytes = canonical_bytes(declaration)
        compose_facts = {"services": {}, "networks": {}}
        compose_bytes = canonical_bytes(compose_facts)
        helper_requirement = {
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": "a" * 64,
        }
        helper_requirement_bytes = canonical_bytes(helper_requirement)
        provenance = {
            "schema_version": "shared-caddy-baseline-provenance/v1",
            "contract_version": "shared-caddy-contract/v1",
            "helper_version": "1.0.0",
            "helper_sha256": "a" * 64,
            "project_id": declaration["project_id"],
            "environment": declaration["environment"],
            "deployment_id": declaration["deployment_id"],
            "source_repo": declaration["source_repo"],
            "hosts": [source for source, _ in COMPATIBILITY_PAIRS],
            "git_sha": "1" * 40,
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
            "helper_sha256": "a" * 64,
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
            "helper_sha256": "a" * 64,
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


if __name__ == "__main__":
    unittest.main()
