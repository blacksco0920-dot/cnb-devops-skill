import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SkillPackageTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_entrypoint_is_concise_and_routes_heavy_detail(self):
        skill = self.text("SKILL.md")
        self.assertLessEqual(len(skill.splitlines()), 60)
        self.assertRegex(skill, r"(?m)^description: Use when ")
        for reference in (
            "references/release-safety.md",
            "references/human-handoffs.md",
            "references/cnb-openapi.md",
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

    def test_handoffs_cover_lighthouse_and_the_pinned_tat_runtime_contract(self):
        handoffs = self.text("references/human-handoffs.md")
        for phrase in (
            "CVM",
            "Lighthouse",
            "tat:RunCommand",
            "tat:DescribeInvocations",
            "tat:DescribeInvocationTasks",
            "tencentcom/tcloud-cmd:v1.2.0@sha256:04824cba6a59858a2c78d6ddfc75c63a30941c219c85f414b379f425c43e8845",
            "/app/index.js",
            "Repeat this inspection whenever the selected digest changes",
            "PLUGIN_TOKEN",
            "credential expiration",
            "worst-case remote timeout",
            "harmless TAT preflight",
        ):
            self.assertIn(phrase, handoffs)
        self.assertNotIn("tat:DescribeAutomationAgentStatus", handoffs)
        self.assertNotIn("accepts only `secret_id` and `secret_key`", handoffs)
        self.assertNotIn("current two-field plugin is not sufficient", handoffs)

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
        self.assertIn("GREEN evaluation date: 2026-09-02", scenarios)
        self.assertIn("fresh-context evaluator", scenarios)

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
        self.assertIn("## CNB native deployment page regression", scenarios)
        self.assertIn("CNB_NATIVE_DEPLOYMENT_GATE", scenarios)

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

    def test_shared_caddy_pressure_scenarios_map_to_real_behavior_tests(self):
        scenarios = self.text("tests/skill-scenarios.md")
        mappings = re.findall(
            r"(?m)^\| `[A-Z_]+` \| `([^`]+)` \| (?:PASS|FAIL) \|$",
            scenarios,
        )
        self.assertEqual(13, len(mappings))
        self.assertEqual(len(mappings), len(set(mappings)))
        for test_id in mappings:
            module_name, class_name, method_name = test_id.rsplit(".", 2)
            source = ROOT / (module_name.replace(".", "/") + ".py")
            self.assertTrue(source.is_file(), test_id)
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            classes = {
                node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
            }
            self.assertIn(class_name, classes, test_id)
            methods = {
                node.name for node in classes[class_name].body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self.assertIn(method_name, methods, test_id)

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
            "Cmnd_Alias ECAT_CADDY_PREFLIGHT = /usr/local/sbin/deploydesk-caddy-apply "
            "^--preflight --deployment-id ecat-energy--test --bundle-id [0-9a-f]{64}$",
            sudoers,
        )
        self.assertIn(
            "Cmnd_Alias ECAT_CADDY_APPLY = /usr/local/sbin/deploydesk-caddy-apply "
            "^--deployment-id ecat-energy--test --bundle-id [0-9a-f]{64}$",
            sudoers,
        )
        self.assertIn(
            "ubuntu ALL=(root) NOPASSWD: ECAT_CADDY_PREFLIGHT, ECAT_CADDY_APPLY",
            sudoers,
        )

    def test_markdown_local_links_resolve(self):
        markdown_files = [
            ROOT / "SKILL.md",
            ROOT / "README.md",
            *sorted((ROOT / "references").rglob("*.md")),
        ]
        for source in markdown_files:
            for target in re.findall(
                r"\[[^]]+\]\(([^)]+)\)", source.read_text(encoding="utf-8")
            ):
                if "://" in target or target.startswith("#"):
                    continue
                resolved = (source.parent / target.split("#", 1)[0]).resolve()
                self.assertTrue(resolved.exists(), f"{source}: {target}")

    def test_public_package_has_no_sensitive_identifier_shapes(self):
        public = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(ROOT.rglob("*"))
            if path.is_file()
            and ".git" not in path.parts
            and ".worktrees" not in path.parts
            and path.suffix in {".json", ".md", ".py", ".sh", ".yaml", ".yml"}
        )
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
