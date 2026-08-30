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
            "Last verified: 2026-08-30",
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
            "PLUGIN_TOKEN",
            "harmless TAT preflight",
        ):
            self.assertIn(phrase, handoffs)
        self.assertNotIn("tat:DescribeAutomationAgentStatus", handoffs)
        self.assertNotIn("accepts only `secret_id` and `secret_key`", handoffs)
        self.assertNotIn("current two-field plugin is not sufficient", handoffs)

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

    def test_markdown_local_links_resolve(self):
        markdown_files = [
            ROOT / "SKILL.md",
            ROOT / "README.md",
            *sorted((ROOT / "references").glob("*.md")),
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
