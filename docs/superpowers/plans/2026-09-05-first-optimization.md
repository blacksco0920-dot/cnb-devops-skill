# First Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Repair two confirmed runtime defects and make project adoption resumable across conversations and source-hosting arrangements.

**Architecture:** Keep runtime changes in the existing helper and extend the current adoption/handoff references. Maintain existing privileged interfaces, release records, schemas, and project-document ownership.

**Tech Stack:** Python standard library, unittest, jsonschema, PyYAML, Agent Skills Markdown.

## Global Constraints

- Docker calls and project/shared lock waits each have a fixed 30-second deadline.
- No new privileged CLI parameters or server-contract fields; preserve lock order and identity verification.
- Uncertain Docker outcomes after a durable transaction retain evidence and require recovery; never retry mutations or initiate automatic rollback for an uncertain timeout.
- Upstream names use lowercase DNS labels of at most 63 characters and total length at most 253.
- Preserve immutable candidates, complete digest maps, evidence planes, authorization scope, and production readiness/approval validity.
- Public examples contain only synthetic non-secret data. Keep SKILL.md at most 60 lines.
- Integrate into the local Skill repository only after verification; no remote push or host deployment is part of this change.

### Task 1: Bound shared-Caddy execution and align upstream validation

**Files:** Modify `scripts/deploydesk_caddy_apply.py`, `references/shared-caddy-v1/contract.md`; create `tests/test_shared_caddy_runtime_bounds.py`; extend relevant existing transaction tests only if needed.

**Interfaces:** Consume existing `DockerRuntime`, `_locked`, `SharedCaddyHelper` and fixture helpers. Produce a single bounded Docker runner, finite lock acquisition, explicit timeout outcome handling, and a shared upstream validator while retaining public signatures.

- [ ] Add regressions for lock contention, all subprocess paths, pretransaction timeout cleanup, durable-transaction timeout retention, recovery timeout retention, and upstream positive/negative boundaries.
- [ ] Run `python -m unittest discover -s tests -p 'test_shared_caddy_runtime_bounds.py' -v`; record expected failures before editing production code.
- [ ] Implement the fixed deadlines and outcome handling, replacing every ordinary-helper Docker subprocess site with the common runner.
- [ ] Run the new regressions plus shared-Caddy transaction, security, preflight and schema tests; inspect state, pointer, marker, receipt and lock assertions.
- [ ] Record tests and self-review; obtain independent spec and quality review, then commit the scoped changes.

### Task 2: Make adoption resumable and conditional on source topology

**Files:** Modify `references/project-adoption.md`, `references/human-handoffs.md`, `tests/test_skill_package.py`, `tests/skill-scenarios.md`; keep routing changes minimal if needed.

**Interfaces:** Consume existing two-document contract, approved control receipts, governed source paths, and release policy. Produce a compact status example, deterministic resumption order, and CNB-native/GitHub-synchronized acceptance branches.

- [ ] Add failing package assertions for a minimal status example, refresh events, conflict handling, and conditional synchronization; add stale-state, valid-resumption, CNB-native and synchronized-source scenarios.
- [ ] Run `python -m unittest discover -s tests -p 'test_skill_package.py' -v`; record RED before editing references.
- [ ] Extend the existing references with the example and ordered rules; replace unconditional GitHub requirements with observed-topology branches.
- [ ] Run package assertions and Skill validation; have an independent reviewer exercise the scenarios and record the evaluation method and limitations.
- [ ] Record tests and self-review; obtain independent spec and quality review, then commit the scoped changes.

### Task 3: Integrate and verify

**Files:** Update this plan's completion checks and final validation record.

- [ ] Review the combined diff and resolve material findings.
- [ ] Run `REQUIRE_FULL_JSONSCHEMA=1 python -m unittest discover -s tests -v`, compile the two Caddy scripts, run `python tests/quick_validate.py .`, and parse the sudoers example with `visudo -cf`.
- [ ] Record exact results and review coverage, then fast-forward the clean local checkout to the verified commit.
- [ ] Confirm the installed Skill resolves to the local checkout and reads its updated files; confirm clean Git state. No production validation is claimed.
