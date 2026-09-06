import json
from datetime import datetime
from pathlib import Path
import re
import subprocess
import unittest
import tempfile


ROOT = Path(__file__).resolve().parents[1]


class SkillPackageTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def public_package_text(self) -> str:
        texts = []
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT)
            if ".git" in relative.parts or ".worktrees" in relative.parts:
                continue
            ignored = subprocess.run(
                ["git", "check-ignore", "--quiet", "--no-index", "--", str(relative)],
                cwd=ROOT, check=False,
            )
            if ignored.returncode == 0:
                continue
            raw = path.read_bytes()
            if b"\0" in raw:
                continue
            try:
                texts.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return "\n".join(texts)

    def test_entrypoint_is_concise_and_routes_heavy_detail(self):
        skill = self.text("SKILL.md")
        self.assertLessEqual(len(skill.splitlines()), 60)
        self.assertRegex(skill, r"(?m)^description: Use when ")
        for reference in (
            "references/release-safety.md",
            "references/human-handoffs.md",
            "references/cnb-openapi.md",
            "references/cnb-deployment-ui.md",
            "references/shared-caddy-v1/contract.md",
        ):
            self.assertIn(f"]({reference})", skill)

    def test_entrypoint_contains_no_product_or_project_leakage(self):
        skill = self.text("SKILL.md").lower()
        for forbidden in (
            "scripts/" + "cnb.py",
            ".codex",
            "quick commands",
            "快速命令",
        ):
            self.assertNotIn(forbidden, skill)

    def test_release_contract_requires_exact_evidence(self):
        safety = self.text("references/release-safety.md")
        required = (
            "full application commit",
            "controller commit",
            "build identity",
            "candidate identity",
            "repository@sha256:digest",
            "recovery-required",
            "build evidence",
            "runtime evidence",
            "public evidence",
        )
        for phrase in required:
            self.assertIn(phrase, safety)

    def test_existing_host_controller_compatibility_is_fail_closed(self):
        safety = " ".join(
            self.text("references/release-safety.md").split()
        )
        handoffs = " ".join(
            self.text("references/human-handoffs.md").split()
        )

        for phrase in (
            "new or stricter deployment controller",
            "read-only compatibility preflight",
            "numeric UID/GID",
            "exact mode and ACL",
            "parent-directory traversal",
            "mount writability, capacity, and inodes",
            "lock, transaction, and recovery state",
            "atomic file-operation compatibility",
            "old controller",
            "descriptor-bound",
            "no-follow",
            "inode reread",
            "fchmod` or `fchown",
            "fsync and readback",
            "compatibility receipt",
            "no migration or transaction began",
            "recovery review",
        ):
            self.assertIn(phrase, safety)

        for phrase in (
            "controller path contract",
            "numeric UID/GID",
            "compatibility receipt",
            "Last verified: 2026-09-03",
        ):
            self.assertIn(phrase, handoffs)

    def test_compatibility_receipt_scope_and_maintenance_are_fail_closed(self):
        safety = " ".join(
            self.text("references/release-safety.md").lower().split()
        )
        handoffs = " ".join(
            self.text("references/human-handoffs.md").lower().split()
        )

        for phrase in (
            "separately authorized",
            "root maintenance",
            "same application release lock",
            "never auto-repair",
            "never relax",
            "target-scope commitment",
            "control-record id",
            "exact path-contract digest",
            "target host set, path metadata or acl, mount, required capability, "
            "controller, or path contract invalidates",
            "freshness, target scope, and drift",
            "any maintenance invalidates",
            "full read-only compatibility preflight",
            "fresh passed `compatibility receipt`",
            "only when both",
            "explicit acl mismatch",
            "fd-safe maintenance",
            "remains blocked",
        ):
            self.assertIn(phrase, safety)

        for phrase in (
            "target-host owner/operator",
            "named in the handoff manifest",
            "control-record id",
            "target-scope commitment",
            "exact path-contract digest",
            "issue and expiry times",
            "raw target ids or paths",
            "target-set, metadata, acl, mount, required-capability, controller, "
            "or contract drift",
            "freshness, scope, and drift",
        ):
            self.assertIn(phrase, handoffs)

    def test_handoffs_cover_roles_artifacts_and_free_tcr_path(self):
        handoffs = self.text("references/human-handoffs.md")
        for phrase in (
            "Application owner",
            "CNB and TCR administrator",
            "Customer Tencent Cloud administrator",
            "DNS and ICP administrator",
            "Data owner",
            "Production approver",
            "handoff manifest",
            "secret receipt",
            "release evidence",
            "TCR Personal",
            "PullRepositoryPersonal",
            "cross-account role",
            "Last verified: 2026-09-03",
        ):
            self.assertIn(phrase, handoffs)

    def test_handoffs_cover_lighthouse_and_the_fixed_tat_command_contract(self):
        handoffs = " ".join(self.text("references/human-handoffs.md").split())
        for phrase in (
            "CVM",
            "Lighthouse",
            "tat:DescribeCommands",
            "tat:InvokeCommand",
            "tat:DescribeInvocations",
            "tat:DescribeInvocationTasks",
            "CommandId",
            "exact target InstanceIds",
            "approved project-owned adapter/control record",
            "arbitrary script text",
            "harmless TAT preflight",
        ):
            self.assertIn(phrase, handoffs)
        self.assertNotIn("tat:Run" + "Command", handoffs)
        self.assertNotIn("tat:DescribeAutomationAgentStatus", handoffs)

    def test_secret_reference_rules_distinguish_script_and_plugin_tasks(self):
        openapi = self.text("references/cnb-openapi.md")
        handoffs = self.text("references/human-handoffs.md")
        scenarios = self.text("tests/skill-scenarios.md")
        normalized_openapi = " ".join(openapi.split())

        for phrase in (
            "a job that has both `image` and `script` is still a script task",
            "A pipeline-level `image` is also an execution environment, not a plugin",
            "A plugin-level `imports` reference triggers `allow_images` authorization",
            "does not pass imported custom variables into the plugin",
            "`settingsFrom` directly loads plugin parameters",
            "treat it as exposed",
            "never echo the value",
        ):
            self.assertIn(phrase, normalized_openapi)

        self.assertIn("omit `allow_images`", handoffs)
        self.assertIn("CNB_SECRET_TASK_TYPE", scenarios)

        self.assertNotIn(
            "`allow_slugs`, `allow_events`, `allow_branches`, and `allow_images` fields",
            openapi,
        )
        self.assertNotIn(
            "`allow_slugs`, `allow_events`, `allow_branches`, and `allow_images` rules",
            handoffs,
        )

    def test_cnb_openapi_routes_the_native_deployment_ui_contract(self):
        openapi = self.text("references/cnb-openapi.md")
        route = "cnb-deployment-ui.md"
        self.assertIn(f"]({route})", openapi)
        self.assertTrue((ROOT / "references" / route).is_file())

        normalized = " ".join(openapi.split())
        for phrase in (
            "prints `未获取到元数据` and returns before creating `toFile`",
            "pre-create only the first empty snapshot",
            "canonical `{}`",
            "mode `0600`",
            "A missing post-write snapshot remains an error",
            "never generalize missing file as empty",
            "do not accept arbitrary non-empty content",
            "strictly parse the exact JSON object",
            "compare every expected key and value",
        ):
            self.assertIn(phrase, normalized)

    def test_native_deployment_ui_adds_no_generator_cli_or_server_script(self):
        example_root = ROOT / "references" / "cnb-deployment-ui" / "examples"
        self.assertTrue(example_root.is_dir())
        self.assertFalse(
            any(path.suffix in {".py", ".sh"} for path in example_root.rglob("*"))
        )
        for relative in (
            "scripts/create_candidate.py",
            "scripts/publish_candidate_tag.sh",
            "scripts/production_gate.py",
            "scripts/deploy_production.sh",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_native_deployment_ui_is_routed_through_package_guidance(self):
        readme = self.text("README.md")
        safety = self.text("references/release-safety.md")
        handoffs = self.text("references/human-handoffs.md")
        normalized_handoffs = handoffs.lower()
        scenarios = self.text("tests/skill-scenarios.md")

        self.assertIn(
            "](references/cnb-deployment-ui.md)",
            readme,
        )
        for phrase in (
            "ready-last",
            "24 hours",
            "production-handoff/v1",
            "same digest",
            "recovery-required",
            "RFC 8785",
            "outside the manifest",
        ):
            self.assertIn(phrase, safety)
        for phrase in (
            "readiness receipt",
            "versioned production handoff",
            "approval and execution are separate",
            "new approval",
        ):
            self.assertIn(phrase, normalized_handoffs)
        self.assertIn("CNB_NATIVE_DEPLOYMENT_GATE", scenarios)

    def test_project_adoption_contract_routes_documents_and_safe_defaults(self):
        skill = self.text("SKILL.md")
        readme = self.text("README.md")
        adoption = self.text("references/project-adoption.md")
        safety = self.text("references/release-safety.md")
        deployment_ui = self.text("references/cnb-deployment-ui.md")
        handoffs = self.text("references/human-handoffs.md")
        scenarios = self.text("tests/skill-scenarios.md")

        for source in (skill, readme):
            self.assertIn("](references/project-adoption.md)", source)

        for phrase in (
            "docs/DEPLOYMENT.md",
            "docs/PROJECT_STATUS.md",
            ".env.example",
            ".cnb/secret.example.yml",
            "observed",
            "supplied",
            "unknown",
            "not-applicable",
            "simple host",
            "shared Caddy",
            "Saved Command",
            "readiness",
            "apply",
            "approval does not execute production",
            "server publication does not imply client publication",
            "Default to the business repository",
        ):
            self.assertIn(phrase, adoption)

        routed_contract = " ".join(
            "\n".join((safety, deployment_ui, handoffs)).lower().split()
        )
        for phrase in (
            "dedicated direct cam identities",
            "fixed, pre-created tat saved commands",
            "readiness",
            "apply",
            "cross-account role/sts is optional",
            "normalized non-secret release identity",
            "complete digest map",
            "arbitrary script text",
        ):
            self.assertIn(phrase, routed_contract)

        for scenario in (
            "NEW_PROJECT_REPO_ONLY",
            "NEW_PROJECT_EXISTING_SHARED_HOST",
            "NEW_PROJECT_CUSTOMER_PRODUCTION",
        ):
            self.assertIn(scenario, scenarios)

    def test_status_example_carries_a_usable_value_free_resume_checkpoint(self):
        import yaml

        adoption = self.text("references/project-adoption.md")
        match = re.search(r"```yaml\n(.*?)\n```", adoption, re.DOTALL)
        self.assertIsNotNone(match, "adoption needs one usable PROJECT_STATUS example")
        status = yaml.safe_load(match.group(1))
        required = {
            "last_verified_at", "source", "candidate", "services", "evidence",
            "effective_decisions", "completed_maintenance_receipts",
            "invalidated_evidence", "unresolved_state", "next_authorized_action",
        }
        self.assertTrue(required <= status.keys())
        self.assertIsNotNone(datetime.fromisoformat(status["last_verified_at"]).tzinfo)
        for field in ("application_commit", "controller_commit"):
            self.assertRegex(status["source"][field], r"^[0-9a-f]{40}$")
        self.assertTrue(status["candidate"]["state"])
        self.assertTrue(status["services"])
        for image in status["services"].values():
            self.assertRegex(image, r"^registry\.example\.test/[^@]+@sha256:[0-9a-f]{64}$")
        self.assertEqual({"build", "runtime", "public"}, status["evidence"].keys())
        self.assertTrue(all(status["evidence"].values()))
        decisions = status["effective_decisions"]
        self.assertTrue(decisions)
        for decision in decisions:
            self.assertTrue({"source", "scope", "status"} <= decision.keys())
        self.assertTrue(status["completed_maintenance_receipts"])
        self.assertIsInstance(status["invalidated_evidence"], list)
        self.assertTrue({"transaction", "recovery", "source"} <= status["unresolved_state"].keys())
        action = status["next_authorized_action"]
        self.assertEqual({"action", "authorization_source", "owner", "acceptance"}, action.keys())
        self.assertTrue(all(action.values()))
        self.assertIn(action["authorization_source"], {item["source"] for item in decisions})
        self.assertNotRegex(match.group(1), r"(?i)TODO|SecretKey|InstanceIds|RoleArn|https?://")

    def test_resume_contract_covers_refresh_conflicts_and_existing_authority(self):
        adoption = self.text("references/project-adoption.md")
        resume = re.search(r"## Resume an existing project\n(.*?)(?=\n## |\Z)", adoption, re.DOTALL)
        self.assertIsNotNone(resume, "resumption needs an ordered evidence reconciliation contract")
        text = " ".join(resume.group(1).lower().split())
        for term in (
            "index", "control records", "receipts", "expiry", "blocked",
            "immutable candidate", "completed maintenance", "existing authorization",
            "readiness", "approval", "release result", "failure", "recovery",
            "policy decision", "handoff",
        ):
            with self.subTest(term=term):
                self.assertIn(term, text)
        self.assertGreaterEqual(len(re.findall(r"(?m)^\d+\. ", resume.group(1))), 3)
        scenarios = self.text("tests/skill-scenarios.md")
        for scenario in ("RESUME_STALE_STATUS", "RESUME_VALID_AUTHORIZATION"):
            self.assertIn(scenario, scenarios)

    def test_source_handoff_has_native_and_observed_sync_acceptance_branches(self):
        handoffs = self.text("references/human-handoffs.md")
        for heading, terms in (
            ("CNB-native source", ("not-applicable", "CNB_PUSH_TOKEN", "full SHA", "clean build")),
            ("GitHub-to-CNB synchronization", ("governed", "CNB_PUSH_TOKEN", "same full SHA", "--mirror")),
        ):
            with self.subTest(branch=heading):
                branch = re.search(r"#### " + re.escape(heading) + r"\n(.*?)(?=\n###|\Z)", handoffs, re.DOTALL)
                self.assertIsNotNone(branch, "source topology needs separate scoped acceptance")
                for term in terms:
                    self.assertIn(term, " ".join(branch.group(1).split()))
        scenarios = self.text("tests/skill-scenarios.md")
        for scenario in ("CNB_NATIVE_SOURCE", "GITHUB_SYNC_SOURCE"):
            self.assertIn(scenario, scenarios)

    def test_direct_cam_default_does_not_require_optional_sts(self):
        handoffs = " ".join(self.text("references/human-handoffs.md").split())
        for phrase in (
            "dedicated direct CAM identity",
            "does not require an STS temporary credential triple",
            "full temporary credential triple is required only when the optional role path is used",
        ):
            self.assertIn(phrase, handoffs)

    def test_shared_caddy_routing_requires_shared_route_evidence(self):
        skill = self.text("SKILL.md")
        self.assertIn("multiple independently managed projects", skill)
        self.assertNotIn("multi-container Docker host", skill)

    def test_shared_caddy_routing_does_not_treat_a_visible_single_project_route_as_shared(self):
        skill = self.text("SKILL.md")
        self.assertIn("opaque Caddy", skill)
        self.assertIn("shared route ownership", skill)
        self.assertNotIn("legacy " + "HTTPS routes", skill)

    def test_legacy_baseline_topology_is_separately_authorized_not_a_cnb_release_input(self):
        handoff = " ".join(self.text("references/shared-caddy-v1/host-handoff.md").split())
        self.assertIn("separately approved baseline/control material", handoff)
        self.assertIn("CNB ordinary release cannot supply or alter", handoff)

    def test_fixed_tat_commands_keep_scripts_and_targets_out_of_cnb_inputs(self):
        release_safety = self.text("references/release-safety.md")
        deployment_ui = self.text("references/cnb-deployment-ui.md")
        handoffs = self.text("references/human-handoffs.md")
        adoption = self.text("references/project-adoption.md")

        authoritative = " ".join(release_safety.lower().split())
        for phrase in (
            "fixed, pre-created tat saved commands",
            "approved project-owned adapter/control record",
            "arbitrary script text", "exact target instanceids",
            "normalized non-secret release identity", "complete digest map",
            "fixed reviewed command content/controller", "invocation evidence",
        ):
            self.assertIn(phrase, authoritative)
        for source in (deployment_ui, handoffs, adoption):
            self.assertIn("](release-safety.md#credentials-and-execution)", source)
            self.assertIn("arbitrary script text", source)
            self.assertIn("targets", source)

        for phrase in (
            "tat:DescribeCommands",
            "tat:InvokeCommand",
            "tat:DescribeInvocations",
            "tat:DescribeInvocationTasks",
        ):
            self.assertIn(phrase, handoffs)
        self.assertNotIn("tat:Run" + "Command", handoffs)

    def test_public_package_has_no_project_specific_fixture_facts(self):
        public = self.public_package_text().lower()
        for forbidden in (
            "e" + "cat",
            "e" + "-cat",
            "swift" + "eng",
            "dianqi" + "mao",
            "blacksco" + "0920",
        ):
            self.assertNotIn(forbidden, public)

    def test_public_runtime_has_no_network_cli_or_vendor_wrapper(self):
        forbidden = (
            "scripts/" + "cnb.py",
            "scripts/install-local.sh",
            "tests/test_cnb.py",
            "references/deployment-playbook.md",
            "references/endpoints.md",
            "agents/openai.yaml",
        )
        for relative in forbidden:
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_scenario_catalog_mappings_resolve(self):
        from scenario_support import validate_catalog
        validate_catalog(self.text("tests/skill-scenarios.md"),
                         json.loads(self.text("tests/scenario-mappings.json")), ROOT)

    def test_scenario_mapping_rejects_missing_duplicate_and_unresolved_entries(self):
        from scenario_support import validate_catalog
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/test_example.py").write_text(
                "class ExampleTests:\n    def test_example(self): pass\n")
            catalog = "## EXAMPLE\n\n```text\nprompt\n```\n\nExpected: refuse.\n"
            reference = "tests.test_example.ExampleTests.test_example"
            good = [{"scenario_id": "EXAMPLE", "tests": [reference]}]
            validate_catalog(catalog, good, root)
            for bad_catalog, bad_mapping in (
                (catalog, []),
                (catalog + catalog, good),
                (catalog.replace("EXAMPLE", ""), good),
                (catalog, good + good),
                (catalog, [{"scenario_id": "OTHER", "tests": [reference]}]),
                (catalog, [{"scenario_id": "EXAMPLE", "tests": []}]),
                (catalog, [{"scenario_id": "EXAMPLE", "tests": [reference, reference]}]),
                (catalog, [{"scenario_id": "EXAMPLE", "tests": ["tests.test_missing.C.test_x"]}]),
                (catalog, [{"scenario_id": "EXAMPLE", "tests": ["tests.test_example.Missing.test_example"]}]),
                (catalog, [{"scenario_id": "EXAMPLE", "tests": ["tests.test_example.ExampleTests.test_missing"]}]),
                (catalog.replace("```text", "```python"), good),
                (catalog.replace("Expected:", "Result:"), good),
                (catalog.replace("prompt", ""), good),
                (catalog.replace("refuse.", ""), good),
                (catalog, [{"scenario_id": "EXAMPLE"}]),
            ):
                with self.subTest(catalog=bad_catalog, mapping=bad_mapping):
                    with self.assertRaises(ValueError):
                        validate_catalog(bad_catalog, bad_mapping, root)

    def test_usage_fixtures_have_safe_paths_and_linked_scenario_ids(self):
        from scenario_support import validate_fixture
        mappings = json.loads(self.text("tests/scenario-mappings.json"))
        scenario_ids = {entry["scenario_id"] for entry in mappings}
        fixtures = list((ROOT / "tests/fixtures/skill-usage").glob("*.json"))
        self.assertTrue(fixtures)
        seen = set()
        catalog = self.text("tests/skill-scenarios.md")
        for path in fixtures:
            fixture = json.loads(path.read_text())
            validate_fixture(fixture, scenario_ids)
            self.assertNotIn(fixture["scenario_id"], seen)
            seen.add(fixture["scenario_id"])
            self.assertIn("fixtures/skill-usage/" + path.name, catalog)

    def test_usage_fixture_rejects_escaping_paths_and_unknown_scenarios(self):
        from scenario_support import validate_fixture
        good = {"scenario_id": "EXAMPLE", "task_root": ".", "read_only_paths": [],
                "user_request": "Inspect only", "files": {"app.py": "pass"}}
        validate_fixture(good, {"EXAMPLE"})
        for changes in ({"scenario_id": "UNKNOWN"}, {"task_root": "/absolute"},
                        {"files": {"../escape": "pass"}},
                        {"read_only_paths": ["../escape"]},
                        {"read_only_paths": ["missing"]},
                        {"task_root": "missing"}, {"user_request": ""}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    validate_fixture(dict(good, **changes), {"EXAMPLE"})

    def test_shared_caddy_preflight_guidance_requires_the_exact_safe_boundary(self):
        skill = self.text("SKILL.md")
        skill_routes = re.findall(r"\[[^]]+\]\(([^)]+)\)", skill)
        contract_route = "references/shared-caddy-v1/contract.md"
        self.assertIn(contract_route, skill_routes)
        contract_path = (ROOT / contract_route).resolve()
        contract = contract_path.read_text(encoding="utf-8")
        contract_routes = re.findall(r"\[[^]]+\]\(([^)]+)\)", contract)
        handoff_route = "host-handoff.md#per-deployment-sudo-boundary"
        sudoers_route = "examples/deploydesk-caddy-apply.sudoers"
        self.assertIn(handoff_route, contract_routes)
        self.assertIn(sudoers_route, contract_routes)
        handoff_path = (contract_path.parent / handoff_route.split("#", 1)[0]).resolve()
        sudoers_path = (contract_path.parent / sudoers_route).resolve()
        self.assertTrue(handoff_path.is_file())
        self.assertTrue(sudoers_path.is_file())
        handoff = handoff_path.read_text(encoding="utf-8")
        handoff_routes = re.findall(r"\[[^]]+\]\(([^)]+)\)", handoff)
        self.assertIn(sudoers_route, handoff_routes)
        self.assertEqual(
            sudoers_path,
            (handoff_path.parent / sudoers_route).resolve(),
        )
        sudoers = sudoers_path.read_text(encoding="utf-8")
        for phrase in (
            "immutable bundle publication",
            "exact sudo bundle preflight",
            "pull/backup/migrate/up",
            "exact sudo apply",
            "semantic probes",
            "immutable evidence",
            "root-private",
            "incoming hostname",
            "before live mutation",
            "third privileged artifact",
        ):
            self.assertIn(phrase, contract)
        self.assertIn(
            "Cmnd_Alias SAMPLE_APP_CADDY_PREFLIGHT = /usr/local/sbin/deploydesk-caddy-apply "
            "^--preflight --deployment-id sample-app--test --bundle-id [0-9a-f]{64}$",
            sudoers,
        )
        self.assertIn(
            "Cmnd_Alias SAMPLE_APP_CADDY_APPLY = /usr/local/sbin/deploydesk-caddy-apply "
            "^--deployment-id sample-app--test --bundle-id [0-9a-f]{64}$",
            sudoers,
        )
        self.assertIn(
            "ubuntu ALL=(root) NOPASSWD: SAMPLE_APP_CADDY_PREFLIGHT, SAMPLE_APP_CADDY_APPLY",
            sudoers,
        )

    def test_handoff_role_routes(self):
        handoffs = self.text("references/human-handoffs.md")
        index = handoffs.split("## Shared artifacts", 1)[0]
        for anchor in (
            "shared-artifacts", "target-host-owneroperator",
            "shared-caddy-host-administrator", "application-owner",
            "cnb-and-tcr-administrator", "customer-tencent-cloud-administrator",
            "dns-and-icp-administrator", "data-owner", "production-approver",
            "cnb-secret-repository-operation",
        ):
            self.assertIn(f"](#{anchor})", index)

    def test_inventory_material_routes(self):
        host = self.text("references/shared-caddy-v1/host-handoff.md")
        for target in (
            "../../scripts/inspect_docker_host_v2.py",
            "../docker-host-inventory-v2/request.example.json",
            "../docker-host-inventory-v2/inventory.schema.json",
        ):
            self.assertIn(f"]({target})", host)

    def test_link_checker_rejects_missing_targets_and_renamed_anchors(self):
        from markdown_link_support import local_link_errors
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.md"
            target = root / "target.md"
            target.write_text("# New heading\n## Repeated\n## Repeated\n```md\n# Fake\n```\n")
            for link in ("missing.md", "target.md#old-heading", "#absent", "target.md#fake"):
                with self.subTest(link=link):
                    source.write_text(f"# Source\n[route]({link})\n")
                    self.assertEqual(1, len(local_link_errors(source)))
            source.write_text(
                "# Source\n[local](#source)\n[heading](target.md#new-heading)\n"
                "[duplicate](target.md#repeated-1)\n[external](https://example.test/x#y)\n"
            )
            self.assertEqual([], local_link_errors(source))

    def test_markdown_local_links_resolve(self):
        from markdown_link_support import local_link_errors
        markdown_files = [
            ROOT / "SKILL.md", ROOT / "README.md",
            *sorted((ROOT / "references").rglob("*.md")),
            ROOT / "tests/skill-scenarios.md",
            *sorted((ROOT / "tests/evaluations").rglob("*.md")),
            *sorted((ROOT / "docs/history").rglob("*.md")),
        ]
        for source in markdown_files:
            self.assertEqual([], local_link_errors(source), str(source))

    def test_public_package_has_no_sensitive_identifier_shapes(self):
        public = self.public_package_text()
        for pattern in (
            r"/(?:Users|home)/[^/\s]+/",
            r"\b\d{10,12}\b",
            r"\b(?:lh)?ins-[a-z0-9]{6,}\b",
            r"\bAKID[A-Za-z0-9]{12,}\b",
            r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{12,}\b",
        ):
            self.assertNotRegex(public, pattern)


if __name__ == "__main__":
    unittest.main()
