import importlib.util
import json
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "deploydesk_caddy_apply.py"
INSTALLER_PATH = ROOT / "scripts" / "install_shared_caddy_helper.py"
SCHEMA_ROOT = ROOT / "references" / "shared-caddy-v1" / "schemas"
EXAMPLE_ROOT = ROOT / "references" / "shared-caddy-v1" / "examples"


def load_helper():
    spec = importlib.util.spec_from_file_location("deploydesk_caddy_apply", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_installer():
    spec = importlib.util.spec_from_file_location("install_shared_caddy_helper", INSTALLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def optional_full_validator(schema):
    if importlib.util.find_spec("jsonschema") is None:
        return None, None
    import jsonschema

    return jsonschema.Draft202012Validator(schema), jsonschema.ValidationError


class SharedCaddyArtifactPresenceTests(unittest.TestCase):
    def test_reference_package_and_helper_exist(self):
        required = [
            HELPER_PATH,
            ROOT / "scripts" / "install_shared_caddy_helper.py",
            ROOT / "references" / "shared-caddy-v1" / "contract.md",
            ROOT / "references" / "shared-caddy-v1" / "host-handoff.md",
            EXAMPLE_ROOT / "bootstrap-attestation.json",
            EXAMPLE_ROOT / "lock-inodes.json",
        ]
        required.extend(SCHEMA_ROOT / name for name in (
            "declaration.schema.json",
            "helper-requirement.schema.json",
            "server-contract.schema.json",
            "server-manifest.schema.json",
            "internal-provenance.schema.json",
            "transaction.schema.json",
            "receipt.schema.json",
            "baseline-provenance.schema.json",
            "baseline-transaction.schema.json",
            "baseline-receipt.schema.json",
        ))
        self.assertEqual([], [str(path.relative_to(ROOT)) for path in required if not path.is_file()])


@unittest.skipUnless(HELPER_PATH.is_file(), "helper not implemented yet")
class SharedCaddySchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()
        cls.installer = load_installer()

    def load_json(self, path: Path):
        return json.loads(path.read_text(encoding="utf-8"))

    def test_all_schemas_are_strict_draft_2020_12_documents(self):
        for schema_path in sorted(SCHEMA_ROOT.glob("*.json")):
            schema = self.load_json(schema_path)
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertFalse(schema.get("additionalProperties", True), schema_path.name)
            self.assertIn("$id", schema)

    def test_examples_validate_against_their_schemas(self):
        pairs = {
            "declaration.json": "declaration.schema.json",
            "helper-requirement.json": "helper-requirement.schema.json",
            "server-contract.json": "server-contract.schema.json",
            "baseline-manifest.json": "server-manifest.schema.json",
            "bundle-provenance.json": "internal-provenance.schema.json",
            "transaction.json": "transaction.schema.json",
            "receipt.json": "receipt.schema.json",
            "baseline-provenance.json": "baseline-provenance.schema.json",
            "baseline-transaction.json": "baseline-transaction.schema.json",
            "baseline-receipt.json": "baseline-receipt.schema.json",
        }
        runtime_validators = {
            "declaration.json": self.helper.validate_declaration,
            "helper-requirement.json": self.helper.validate_requirement,
            "server-contract.json": self.helper.validate_server_contract,
            "baseline-manifest.json": self.helper.validate_manifest,
            "bundle-provenance.json": self.helper.validate_internal_provenance,
            "transaction.json": self.helper.validate_transaction,
            "receipt.json": self.helper.validate_receipt,
            "baseline-provenance.json": self.installer.validate_baseline_provenance,
            "baseline-transaction.json": self.installer.validate_baseline_transaction,
            "baseline-receipt.json": self.installer.validate_baseline_receipt,
        }
        for example_name, schema_name in pairs.items():
            instance = self.load_json(EXAMPLE_ROOT / example_name)
            self.helper.validate_json_schema_instance(
                self.load_json(SCHEMA_ROOT / schema_name),
                instance,
            )
            runtime_validators[example_name](instance)

    def test_baseline_transaction_and_receipt_examples_describe_one_committed_transaction(self):
        transaction = self.load_json(EXAMPLE_ROOT / "baseline-transaction.json")
        receipt = self.load_json(EXAMPLE_ROOT / "baseline-receipt.json")
        self.assertEqual("committed", transaction["phase"])
        self.assertEqual("committed", receipt["status"])
        self.assertEqual(transaction["transaction_id"], receipt["transaction_id"])
        self.assertEqual(transaction["new_generation"], receipt["generation_id"])
        self.assertEqual(transaction["old_generation"], receipt["old_generation"])

    def test_legacy_baseline_schemas_and_runtime_accept_normalized_nonfixture_topology(self):
        runtime_validators = {
            "baseline-provenance.json": self.installer.validate_baseline_provenance,
            "baseline-transaction.json": self.installer.validate_baseline_transaction,
            "baseline-receipt.json": self.installer.validate_baseline_receipt,
        }
        schema_names = {
            "baseline-provenance.json": "baseline-provenance.schema.json",
            "baseline-transaction.json": "baseline-transaction.schema.json",
            "baseline-receipt.json": "baseline-receipt.schema.json",
        }
        for example_name, validator in runtime_validators.items():
            with self.subTest(example=example_name):
                artifact = self.load_json(EXAMPLE_ROOT / example_name)
                artifact.update({
                    "project_id": "docs-portal",
                    "environment": "isolated-edge",
                    "deployment_id": "docs-portal--isolated-edge",
                    "source_repo": "https://code.example.invalid/platform/docs-portal",
                    "hosts": [
                        "docs.alt.example.invalid",
                        "status.alt.example.invalid",
                    ],
                })
                schema = self.load_json(SCHEMA_ROOT / schema_names[example_name])
                self.helper.validate_json_schema_instance(schema, artifact)
                validator(artifact)

    def test_examples_validate_with_full_draft_2020_12_validator(self):
        if importlib.util.find_spec("jsonschema") is None:
            if os.environ.get("REQUIRE_FULL_JSONSCHEMA") == "1":
                self.fail("pinned CI full Draft 2020-12 validator is unavailable")
            self.skipTest("jsonschema is a pinned CI-only dependency")
        import jsonschema

        pairs = {
            "declaration.json": "declaration.schema.json",
            "helper-requirement.json": "helper-requirement.schema.json",
            "server-contract.json": "server-contract.schema.json",
            "baseline-manifest.json": "server-manifest.schema.json",
            "bundle-provenance.json": "internal-provenance.schema.json",
            "transaction.json": "transaction.schema.json",
            "receipt.json": "receipt.schema.json",
            "baseline-provenance.json": "baseline-provenance.schema.json",
            "baseline-transaction.json": "baseline-transaction.schema.json",
            "baseline-receipt.json": "baseline-receipt.schema.json",
        }
        for example_name, schema_name in pairs.items():
            schema = self.load_json(SCHEMA_ROOT / schema_name)
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.Draft202012Validator(schema).validate(
                self.load_json(EXAMPLE_ROOT / example_name)
            )

    def test_host_lock_examples_bind_ctime_with_device_and_inode(self):
        bootstrap = self.load_json(EXAMPLE_ROOT / "bootstrap-attestation.json")
        locks = self.load_json(EXAMPLE_ROOT / "lock-inodes.json")
        self.helper.validate_bootstrap_attestation(bootstrap)
        self.assertEqual("shared-caddy-lock-inodes/v1", locks["schema_version"])
        identities = [locks["shared"]]
        for deployment in locks["deployments"].values():
            self.assertEqual({"project", "release"}, set(deployment))
            identities.extend((deployment["project"], deployment["release"]))
        for identity in identities:
            self.assertEqual({"device", "inode", "ctime_ns"}, set(identity))
            for value in identity.values():
                self.assertIsInstance(value, int)
                self.assertNotIsInstance(value, bool)
                self.assertGreaterEqual(value, 0)
        self.assertEqual(
            locks["shared"],
            {
                "device": bootstrap["shared_lock_device"],
                "inode": bootstrap["shared_lock_inode"],
                "ctime_ns": bootstrap["shared_lock_ctime_ns"],
            },
        )

    def test_declaration_rejects_unknown_fields_wildcards_and_path_ids(self):
        declaration = self.load_json(EXAMPLE_ROOT / "declaration.json")
        bad = json.loads(json.dumps(declaration))
        bad["unexpected"] = True
        with self.assertRaises(self.helper.ContractError):
            self.helper.validate_declaration(bad)

    def test_declaration_schema_and_runtime_reject_the_same_load_bearing_values(self):
        schema = self.load_json(SCHEMA_ROOT / "declaration.schema.json")
        full_validator, full_error = optional_full_validator(schema)
        declaration = self.load_json(EXAMPLE_ROOT / "declaration.json")
        overlong_host = "a." * 127 + "a"
        mutations = (
            ("project_id", "UPPER"),
            ("environment", "x" * 33),
            ("deployment_id", "bad"),
            ("source_repo", "https://CODE.example/teams/sample-app"),
            ("source_repo", "https://code.example/teams/sample-app/"),
            ("source_repo", "https://" + overlong_host + "/sample-app"),
            ("host", "bad..example.test"),
            ("host", overlong_host),
            ("upstream", "bad_host"),
            ("upstream", overlong_host),
            ("port", 0),
            ("port", 65536),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                changed = json.loads(json.dumps(declaration))
                if field in changed:
                    changed[field] = value
                else:
                    changed["routes"][0][field] = value
                with self.assertRaises(self.helper.ContractError):
                    self.helper.validate_declaration(changed)
                with self.assertRaises(self.helper.ContractError):
                    self.helper.validate_json_schema_instance(schema, changed)
                if full_validator is not None:
                    with self.assertRaises(full_error):
                        full_validator.validate(changed)
        mismatch = json.loads(json.dumps(declaration))
        mismatch["deployment_id"] = "sample-app--other"
        with self.assertRaises(self.helper.ContractError):
            self.helper.validate_declaration(mismatch)
        for bad_host in ("*.example.test", ":443", "EXAMPLE.test."):
            bad = json.loads(json.dumps(declaration))
            bad["routes"][0]["host"] = bad_host
            with self.assertRaises(self.helper.ContractError):
                self.helper.validate_declaration(bad)
        bad = json.loads(json.dumps(declaration))
        bad["deployment_id"] = "../sample--staging"
        with self.assertRaises(self.helper.ContractError):
            self.helper.validate_declaration(bad)

    def test_hostname_normalization_is_lowercase_trailing_dot_free_idna(self):
        self.assertEqual("xn--bcher-kva.example", self.helper.normalize_hostname("B\u00dcCHER.example."))

    def test_fragment_is_derived_and_rejects_extended_caddy_behavior(self):
        declaration = self.load_json(EXAMPLE_ROOT / "declaration.json")
        rendered = self.helper.render_fragment(declaration)
        self.helper.reconcile_fragment(declaration, rendered.encode("utf-8"))
        with self.assertRaises(self.helper.ContractError):
            self.helper.reconcile_fragment(
                declaration,
                (rendered + "\n:443 { respond \"surprise\" }\n").encode("utf-8"),
            )

    def test_receipt_and_transaction_schemas_reject_load_bearing_mutations(self):
        common = {
            "contract_version": "shared-caddy-contract/v1", "helper_version": "1.0.0",
            "helper_sha256": "1" * 64, "transaction_id": "tx-" + "2" * 32,
            "project_id": "sample-app", "environment": "staging",
            "deployment_id": "sample-app--staging", "source_repo": "https://code.example/teams/sample-app",
            "bundle_id": "3" * 64,
            "git_sha": "4" * 40, "declaration_sha256": "5" * 64,
            "fragment_sha256": "6" * 64, "compose_sha256": "7" * 64,
            "helper_requirement_sha256": "a" * 64, "internal_provenance_sha256": "b" * 64,
            "old_generation": "gen-" + "8" * 32,
            "hosts": ["app.example.test"],
        }
        artifacts = {
            "transaction.schema.json": dict(
                common, schema_version="shared-caddy-transaction/v1", phase="prepared",
                new_generation="gen-" + "9" * 32,
                network_attachment_intents=[{"network": "shared-edge", "pre_transaction_state": "absent"}],
            ),
            "receipt.schema.json": dict(
                common, schema_version="shared-caddy-receipt/v1", status="committed",
                generation_id="gen-" + "9" * 32,
            ),
        }
        bad_values = {
            "contract_version": "wrong", "helper_version": "9.9.9", "helper_sha256": "x",
            "transaction_id": "bad", "project_id": "UPPER", "environment": "UPPER",
            "deployment_id": "bad", "source_repo": "https://CODE.example/x", "bundle_id": "x",
            "git_sha": "x", "declaration_sha256": "x", "fragment_sha256": "x",
            "compose_sha256": "x", "helper_requirement_sha256": "x",
            "internal_provenance_sha256": "x", "old_generation": "bad", "hosts": ["UPPER.example"],
        }
        for schema_name, artifact in artifacts.items():
            schema = self.load_json(SCHEMA_ROOT / schema_name)
            full_validator, full_error = optional_full_validator(schema)
            self.helper.validate_json_schema_instance(schema, artifact)
            runtime_validator = (
                self.helper.validate_transaction
                if schema_name.startswith("transaction")
                else self.helper.validate_receipt
            )
            runtime_validator(artifact)
            per_artifact = dict(bad_values)
            if schema_name.startswith("transaction"):
                per_artifact.update(
                    schema_version="wrong", phase="wrong", new_generation="bad",
                    network_attachment_intents=[{"network": "bad/name", "pre_transaction_state": "present"}],
                )
            else:
                per_artifact.update(schema_version="wrong", status="wrong", generation_id="bad")
            for field, value in per_artifact.items():
                with self.subTest(schema=schema_name, field=field):
                    changed = json.loads(json.dumps(artifact))
                    changed[field] = value
                    with self.assertRaises(self.helper.ContractError):
                        self.helper.validate_json_schema_instance(schema, changed)
                    if full_validator is not None:
                        with self.assertRaises(full_error):
                            full_validator.validate(changed)
                    with self.assertRaises((self.helper.ContractError, self.helper.RecoveryRequired)):
                        runtime_validator(changed)

    def test_manifest_and_internal_provenance_reject_load_bearing_mutations_in_both_paths(self):
        artifacts = {
            "server-manifest.schema.json": (
                self.load_json(EXAMPLE_ROOT / "baseline-manifest.json"),
                self.helper.validate_manifest,
            ),
            "internal-provenance.schema.json": (
                self.load_json(EXAMPLE_ROOT / "bundle-provenance.json"),
                self.helper.validate_internal_provenance,
            ),
        }
        common = {
            "contract_version": "wrong", "helper_version": "9.9.9",
            "helper_sha256": "x", "project_id": "UPPER", "environment": "UPPER",
            "deployment_id": "bad", "source_repo": "https://CODE.example/x",
            "hosts": ["UPPER.example"], "git_sha": "x",
            "declaration_sha256": "x", "fragment_sha256": "x",
            "compose_sha256": "x", "helper_requirement_sha256": "x",
        }
        for schema_name, (artifact, runtime_validator) in artifacts.items():
            schema = self.load_json(SCHEMA_ROOT / schema_name)
            full_validator, full_error = optional_full_validator(schema)
            self.helper.validate_json_schema_instance(schema, artifact)
            runtime_validator(artifact)
            mutations = dict(common)
            if schema_name.startswith("server-manifest"):
                mutations.update(
                    schema_version="wrong", deploy_bundle_sha256="x",
                    internal_provenance_sha256="x",
                    source={"kind": "legacy_opaque"},
                )
            else:
                mutations.update(
                    schema_version="wrong", source={"kind": "baseline_import"},
                )
            for field, value in mutations.items():
                with self.subTest(schema=schema_name, field=field):
                    changed = json.loads(json.dumps(artifact))
                    changed[field] = value
                    with self.assertRaises(self.helper.ContractError):
                        self.helper.validate_json_schema_instance(schema, changed)
                    if full_validator is not None:
                        with self.assertRaises(full_error):
                            full_validator.validate(changed)
                    with self.assertRaises(self.helper.ContractError):
                        runtime_validator(changed)


if __name__ == "__main__":
    unittest.main()
