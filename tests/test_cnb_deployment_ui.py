import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "cnb-deployment-ui.md"
EXAMPLE_ROOT = ROOT / "references" / "cnb-deployment-ui" / "examples"


class CnbDeploymentUiTests(unittest.TestCase):
    def load_json(self, name: str):
        return json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))

    def load_yaml(self, name: str):
        # JSON is valid YAML, so the examples remain CNB-compatible without a
        # test-only parser dependency.
        return json.loads((EXAMPLE_ROOT / name).read_text(encoding="utf-8"))

    def test_candidate_example_is_complete_digest_evidence_with_no_fixed_service_count(self):
        path = EXAMPLE_ROOT / "candidate-manifest.json"
        raw = path.read_bytes()
        candidate = json.loads(raw)

        self.assertEqual("candidate-manifest/v1", candidate["schema"])
        self.assertEqual("sample-project", candidate["project_id"])
        self.assertEqual("production", candidate["environment"])
        self.assertRegex(candidate["candidate_tag"], r"^[a-z0-9][a-z0-9-]+$")
        self.assertRegex(candidate["application_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(candidate["controller_commit"], r"^[0-9a-f]{40}$")
        self.assertTrue(candidate["services"])
        for role, image in candidate["services"].items():
            self.assertRegex(role, r"^[a-z][a-z0-9-]*$")
            self.assertRegex(image, r"^[^@\s]+@sha256:[0-9a-f]{64}$")
        self.assertEqual(
            {"build", "runtime", "public"}, set(candidate["evidence"])
        )
        for plane in candidate["evidence"].values():
            self.assertEqual("passed", plane["status"])

        self.assertNotIn("manifest_sha256", candidate)
        canonical_payload = json.dumps(
            candidate,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        self.assertEqual(canonical_payload, raw)
        self.assertRegex(hashlib.sha256(raw).hexdigest(), r"^[0-9a-f]{64}$")

    def test_tag_page_separates_readiness_execution_and_approval(self):
        config = self.load_yaml("tag_deploy.yml")
        environments = config["environments"]
        self.assertEqual(1, len(environments))
        production = environments[0]

        self.assertEqual("production", production["name"])
        self.assertEqual(["owner"], production["permissions"]["roles"])
        self.assertEqual(1, len(production["button"]))
        self.assertEqual(
            "web_trigger_production_readiness",
            production["button"][0]["event"],
        )
        self.assertEqual(["owner"], production["button"][0]["permissions"]["roles"])
        self.assertEqual(1, len(production["deploy"]))
        self.assertNotIn("inputs", production["deploy"][0])
        self.assertNotIn("env", production["deploy"][0])

        approvers = [item for item in production["require"] if "approver" in item]
        self.assertEqual(1, len(approvers))
        self.assertEqual(["owner"], approvers[0]["approver"]["roles"])

    def test_tag_page_static_gate_requires_all_candidate_and_readiness_annotations(self):
        production = self.load_yaml("tag_deploy.yml")["environments"][0]
        annotations = {
            item["annotation"]: item.get("expect")
            for item in production["require"]
            if "annotation" in item
        }

        self.assertEqual(
            {
                "candidate_status": {"eq": "ready"},
                "candidate_format": {"eq": "candidate-manifest/v1"},
                "candidate_manifest_sha256": {"reg": "^[0-9a-f]{64}$"},
                "candidate_commit": {"reg": "^[0-9a-f]{40}$"},
                "test_build_status": {"eq": "passed"},
                "test_runtime_status": {"eq": "passed"},
                "test_public_status": {"eq": "passed"},
                "production_readiness": {"eq": "passed"},
            },
            annotations,
        )

    def test_pipeline_example_is_candidate_scoped_and_fails_closed_by_default(self):
        config = self.load_yaml("candidate-production-gates.yml")
        self.assertEqual(["release-candidate-*"], list(config))
        candidate = config["release-candidate-*"]
        self.assertEqual(
            {"web_trigger_production_readiness", "tag_deploy.production"},
            set(candidate),
        )
        for event in candidate.values():
            self.assertEqual(1, len(event))
            stages = event[0]["stages"]
            self.assertGreaterEqual(len(stages), 1)
            self.assertTrue(all("exit 1" in stage["script"] for stage in stages))

    def test_behavior_matrix_enforces_create_only_fresh_approval_and_same_membership(self):
        matrix = self.load_json("gate-behavior-cases.json")
        self.assertEqual("production-gate-behavior/v1", matrix["schema"])

        for case in matrix["candidate_retry_cases"]:
            if (
                not case["remote_exists"]
                and not case["force_requested"]
                and case["annotation_state"] == "not_applicable"
            ):
                actual = "create"
            elif (
                case["remote_exists"]
                and not case["force_requested"]
                and case["peeled_commit_matches"]
                and case["message_bytes_match"]
            ):
                actual = {
                    "empty": "resume",
                    "exact_non_ready_prefix": "resume",
                    "exact_ready": "no_write",
                }.get(case["annotation_state"], "block")
            else:
                actual = "block"
            with self.subTest(candidate_retry=case["name"]):
                self.assertEqual(case["expected"], actual)

        defaults = matrix["production_defaults"]
        maximum_age = matrix["readiness_max_age_seconds"]
        for case in matrix["production_cases"]:
            values = {**defaults, **case["overrides"]}
            allowed = all(
                (
                    values["candidate_format"] == "candidate-manifest/v1",
                    values["candidate_status"] == "ready",
                    values["candidate_tag_matches_prefix"],
                    values["canonical_manifest_valid"],
                    values["selected_candidate_tag"] == values["candidate_tag"],
                    values["peeled_commit"] == values["candidate_commit"],
                    values["candidate_controller_commit"]
                    == values["expected_controller_commit"],
                    values["annotation_manifest_sha256"]
                    == values["candidate_manifest_sha256"],
                    values["computed_manifest_sha256"]
                    == values["candidate_manifest_sha256"],
                    values["candidate_project_id"] == values["expected_project_id"],
                    values["candidate_environment"] == values["selected_environment"],
                    values["governed_branch_contains_candidate"],
                    values["source_mirrors_match"],
                    values["readiness_status"] == "passed",
                    0 <= values["readiness_age_seconds"] <= maximum_age,
                    values["readiness_candidate_tag"] == values["candidate_tag"],
                    values["readiness_manifest_sha256"]
                    == values["candidate_manifest_sha256"],
                    values["readiness_policy_version"] == values["policy_version"],
                    values["readiness_verifier_version"] == values["verifier_version"],
                    values["approval_generation"]
                    == values["required_approval_generation"],
                    not values["recovery_required"],
                    not values["unresolved_transaction"],
                    not values["maintenance_blocker"],
                    values["handoff_status"] == "accepted",
                    values["handoff_candidate_tag"] == values["candidate_tag"],
                    values["handoff_environment"] == values["selected_environment"],
                    values["handoff_policy_version"] == values["policy_version"],
                    values["handoff_adapter_kind"] == values["adapter_kind"],
                    values["handoff_adapter_version"] == values["adapter_version"],
                    values["adapter_status"] == "enabled",
                    values["adapter_kind"] == values["enabled_adapter_kind"],
                    values["adapter_version"] == values["enabled_adapter_version"],
                    set(values["candidate_services"])
                    == set(values["expected_service_roles"]),
                    all(
                        image.split("@sha256:", 1)[0]
                        == values["expected_service_repositories"].get(role)
                        for role, image in values["candidate_services"].items()
                    ),
                    values["candidate_services"] == values["selected_services"],
                )
            )
            with self.subTest(production_gate=case["name"]):
                self.assertEqual(case["expected"] == "allow", allowed)

    def test_pending_handoff_and_disabled_adapter_keep_production_blocked(self):
        handoff = self.load_json("production-handoff.pending.json")
        adapter = self.load_json("execution-adapter.disabled.json")

        self.assertEqual("production-handoff/v1", handoff["schema"])
        self.assertEqual("pending", handoff["status"])
        self.assertEqual("production-execution-adapter/v1", adapter["schema"])
        self.assertEqual("disabled", adapter["status"])

    def test_annotation_readback_only_seeds_the_first_empty_snapshot(self):
        stages = self.load_yaml("annotation-readback.yml")["stages"]
        image = (
            "cnbcool/annotations:v1.0.0@sha256:"
            "bfd02b627f3b49082aa7dbbac1999560b4d66c7d85682084d0747eabecd75818"
        )

        initial_path = ".release/annotations-before-add.json"
        final_path = ".release/annotations-after-add.json"
        initializer, first_get, first_validate, add, second_get, second_validate = stages

        self.assertIn("umask 077", initializer["script"])
        self.assertIn("printf '{}\\n'", initializer["script"])
        self.assertIn(initial_path, initializer["script"])
        self.assertIn("chmod 600", initializer["script"])

        self.assertEqual(image, first_get["image"])
        self.assertEqual("GET", first_get["settings"]["type"])
        self.assertEqual("${CANDIDATE_TAG}", first_get["settings"]["tag"])
        self.assertEqual(initial_path, first_get["settings"]["toFile"])
        self.assertEqual(image, first_validate["image"])
        self.assertIn("stat -c '%a'", first_validate["script"])
        self.assertIn('raw !== "{}\\n"', first_validate["script"])
        self.assertIn("JSON.parse(raw)", first_validate["script"])
        self.assertIn(initial_path, first_validate["script"])

        self.assertEqual(image, add["image"])
        self.assertEqual("ADD", add["settings"]["type"])
        self.assertEqual("${CANDIDATE_TAG}", add["settings"]["tag"])
        self.assertIn("data", add["settings"])
        self.assertEqual(image, second_get["image"])
        self.assertEqual("GET", second_get["settings"]["type"])
        self.assertEqual("${CANDIDATE_TAG}", second_get["settings"]["tag"])
        self.assertEqual(final_path, second_get["settings"]["toFile"])
        self.assertNotIn(final_path, initializer["script"])
        self.assertIn("test -s", second_validate["script"])
        self.assertEqual(image, second_validate["image"])
        self.assertIn("JSON.parse(raw)", second_validate["script"])
        self.assertIn("candidate-manifest/v1", second_validate["script"])
        self.assertIn("chmod 600", second_validate["script"])
        self.assertIn("stat -c '%a'", second_validate["script"])
        self.assertIn(final_path, second_validate["script"])
        self.assertNotIn("printf '{}'", second_validate["script"])

    @unittest.skipUnless(shutil.which("node"), "Node is required by the pinned validation image")
    def test_annotation_validation_rejects_missing_malformed_wrong_or_insecure_snapshots(self):
        stages = self.load_yaml("annotation-readback.yml")["stages"]
        initializer, _, first_validate, _, _, second_validate = stages

        def run(script, cwd):
            return subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=cwd,
                env={**os.environ, "CANDIDATE_TAG": "release-candidate-example"},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial = root / ".release" / "annotations-before-add.json"
            final = root / ".release" / "annotations-after-add.json"

            self.assertEqual(0, run(initializer["script"], root).returncode)
            self.assertEqual(0, run(first_validate["script"], root).returncode)

            initial.write_text('{"unexpected":"value"}\n', encoding="utf-8")
            initial.chmod(0o600)
            self.assertNotEqual(0, run(first_validate["script"], root).returncode)

            initial.write_text("{}\n", encoding="utf-8")
            initial.chmod(0o644)
            self.assertNotEqual(0, run(first_validate["script"], root).returncode)

            self.assertNotEqual(0, run(second_validate["script"], root).returncode)
            final.write_text("not-json", encoding="utf-8")
            self.assertNotEqual(0, run(second_validate["script"], root).returncode)
            final.write_text('{"candidate_format":"wrong"}', encoding="utf-8")
            self.assertNotEqual(0, run(second_validate["script"], root).returncode)

            final.write_text(
                '{\n  "candidate_format": "candidate-manifest/v1"\n}',
                encoding="utf-8",
            )
            final.chmod(0o644)
            self.assertEqual(0, run(second_validate["script"], root).returncode)
            self.assertEqual(0o600, stat.S_IMODE(final.stat().st_mode))

    def test_reference_defines_portable_ready_last_and_dual_gate_contract(self):
        reference = REFERENCE.read_text(encoding="utf-8")
        normalized = " ".join(reference.split())
        for phrase in (
            "ready-last",
            "static gate",
            "dynamic gate",
            "24 hours",
            "Tag details page",
            "approval and execution",
            "same digest",
            "recovery-required",
            "new approval",
            "service roles and repositories",
            "governed branch",
            "candidate prefix",
            "execution adapter",
            "RFC 8785",
            "outside the manifest",
            "exact canonical payload bytes",
            "create-only",
            "peeled commit",
            "passed status last",
            "no older than 24 hours",
            "invalidate the prior readiness and approval",
            "complete project-defined service role/digest map",
            "freshly created candidate",
            "exact-ready",
            "candidate-bound control record",
            "must not modify the selected Tag's Git object",
        ):
            self.assertIn(phrase, normalized)

        for name in (
            "candidate-manifest.json",
            "tag_deploy.yml",
            "candidate-production-gates.yml",
            "production-handoff.pending.json",
            "execution-adapter.disabled.json",
            "annotation-readback.yml",
            "gate-behavior-cases.json",
        ):
            self.assertIn(f"](cnb-deployment-ui/examples/{name})", reference)

    def test_new_public_assets_contain_no_business_or_target_identifiers(self):
        paths = [REFERENCE, *sorted(EXAMPLE_ROOT.glob("*"))]
        public = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        product_marker = "e" + "cat"
        account_marker = "black" + "sco"
        for pattern in (
            rf"(?i)\b{product_marker}(?:-energy)?\b",
            rf"(?i)\b{account_marker}[0-9a-z-]*\b",
            r"\b(?:lh)?ins-[a-z0-9]{6,}\b",
            r"\btat:inv-[A-Za-z0-9-]+\b",
            r"\bAKID[A-Za-z0-9]{12,}\b",
            r"/(?:Users|home)/[^/\s]+/",
        ):
            self.assertNotRegex(public, pattern)

        self.assertFalse(any(path.suffix in {".py", ".sh"} for path in paths))


if __name__ == "__main__":
    unittest.main()
