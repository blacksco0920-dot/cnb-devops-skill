# Post-release Closeout Implementation Plan

> **For agentic workers:** Use subagent-driven-development for the independent release and coexistence entries; keep integration, state writes and live checks sequential. Follow the approved [scope](../specs/2026-09-11-post-release-closeout.md).

**Goal:** Replace temporary post-release verification and state reconciliation with fixed reusable entries.

**Architecture:** Extend the local release session, add a declaration-driven read-only coexistence checker, and compose their receipts into the project's existing state/document. Reuse host and CI validators; no installed controller change.

**Tech Stack:** Node.js 22, Python 3.11+, existing TAT SDK, strict SSH and HTTPS, local JSON/Markdown.

## Global Constraints

- Only local implementation and read-only live validation are in scope; no Invoke, release, reinstall, credential creation or source application write.
- Preserve signatures, immutable image identities, failed records, raw receipts, private permissions and existing project authorization.
- Historical deployment proof does not establish current runtime or complete business acceptance.
- Do not add business-specific logic, a global operations platform or a second project status document.

## Task 1 — Production result verification

Files: `scripts/release-session.mjs`, optional `scripts/release-deployment.mjs`, `tests/test_release_session.mjs`, `tests/test_release_deployment.mjs`.

- [x] Reproduce missing terminal deployment state and expired historical approval behavior in tests.
- [x] Implement `verify` with existing standard validators and only read-only external APIs; persist raw evidence and receipt atomically.
- [x] Verify rejection of wrong request/target/digest, failed/incomplete output and invalid execution-time signatures; repeated verification performs no deployment.

Produces `session/deployment-verification/receipt.json`, schema `cnb-deployment-verification/v1`, identity and evidence hashes; evidence paths are relative to the receipt directory.

## Task 2 — Shared-host coexistence

Files: `scripts/verify-coexistence.py`, `tests/test_verify_coexistence.py`.

- [x] Write behavioral fixtures for renamed projects, varying service sets and preserved neighboring resources.
- [x] Implement strict spec preview, fixed read-only collection, identity/health/baseline comparison and bounded receipts.
- [x] Verify neighbor drift, wrong project digest, unsafe inputs and fixture/live distinction; collect into a new directory each run.

Produces `coexistence.receipt.json`, schema `cnb-coexistence-verification/v1`, live/fixture source, candidate identity, checks and evidence hashes.

## Task 3 — Existing project state reconciliation

Files: `scripts/reconcile-project-state.py`, `tests/test_reconcile_project_state.py`.

- [x] Test incomplete acceptance, wrong hashes/identities, stale aliases, independent metadata preservation and repeat execution.
- [x] Implement preview, canonical per-environment current state, safe document block and locked resumable local transaction.
- [x] Test interrupted writes, changed unowned document, unsafe paths and no secret content in public summaries.

Consumes pinned deployment/check receipts; produces a local closeout receipt, updated existing state and original status document. No receipt or configuration acts as new release authority.

## Task 4 — Integration, real read-only validation and guidance

- [x] Run appropriate Node/Python regression checks and package/link checks; independently review integrations.
- [x] Verify the existing completed production invocation through the new entry; perform actual read-only coexistence collection.
- [x] Preview and apply local reconciliation, then repeat without rewriting accepted state; verify hashes and live scope.
- [x] Update `SKILL.md`, `references/bootstrap-inputs.md`, `references/project-adoption.md` and concise validation history. Preserve bundle version and host artifacts.
- [x] Commit reviewed changes and update the installed local Skill; report actual checks and remaining limits.

## Validation record

See [real read-only closeout and scoped checks](../../history/2026-09-11-post-release-closeout.md). The first package validation used the system Python without PyYAML; rerunning with the existing Skill tools environment passed. Package scanning also caught a synthetic instance label shaped like a real resource ID; the fixture now explicitly uses SYNTHETIC. No cloud writes or host bundle changes were made. The local Skill checkout is fast-forwarded after these checks; application status changes remain local.
