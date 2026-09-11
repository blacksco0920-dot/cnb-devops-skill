# Failed Test Release Repair Implementation Plan

> **For agentic workers:** Use subagent-driven-development for bounded implementation and independent review. Shared interfaces are below; only root performs live operations.

**Goal:** Preserve the failed test deployment's data and evidence, verify a real isolated restore, and permit one precisely bound repair through the fixed TAT entry.

**Architecture:** Extend the existing recovery source model and retain the release lock and transaction protocol. A reviewed controller upgrade installs the new fixed implementation without changing runtime policy, Compose, credentials or empty baseline. A root-owned short-lived permit binds the failed source, restored data and new release request; the ordinary caller has no new arbitrary-command capability.

**Tech Stack:** Python standard library host and local controllers; existing Node TAT caller and CNB generated YAML; unittest and node:test.

## Global Constraints

- Test environment only; source transaction must be canonical v2, failed/probe, with healthy exact running services.
- Preserve the original database, uploads, failure record and snapshot; never fabricate a passed record or delete the blocker to retry.
- New application commit and all service digests must come from one complete verified build; migration files and command must be unchanged.
- Existing production flow, project ownership, secrets, Caddy and other projects remain outside this upgrade.
- Preview before mutation; bind hashes and exact identities, record before side effects, stop on drift or ambiguous interruption.
- Failed-source restoration verifies all existing data, including empty business tables; it is not successful business acceptance.

## Task 1: Failed-source export and isolated restore

Files: `assets/cnb-tcr-tat/host/recover-project.py`, `scripts/rehearse-recovery.py`, focused recovery tests.
Interface: `source_record(host, account, failed_transaction_sha256=None) -> (raw, record)`; CLI opt-in `--failed-transaction-sha256`. Existing passed-only source API and v1 receipts remain compatible. Failed mode uses v2 evidence with `source_kind=failed-test-release`, `source_baseline_sha256`, actual failed transaction as source, and `public_identity_verified=false`.

- [x] Reproduce the failed/probe source rejection with a temporary real transaction and snapshot fixture.
- [x] Add exact failed-source, baseline, snapshot, runtime and export journal checks.
- [x] Reuse export/restore while retaining application marker and all actual data; preserve interrupted export resume.
- [x] Test wrong pin/phase/production, source drift, archive checksums, unchanged marker and original-container resume.

## Task 2: Reviewed fixed-controller upgrade

Files: new fixed host/local upgrade entries, installer/rehearsal integration only if required, focused upgrade tests.
Interface: old accepted installation + old/new fully pinned bundles + exact failed transaction; output new installation receipt and independent upgrade receipt linking old/new identities. Runtime policy, Compose, recovery policy and empty baseline must remain byte-identical.

- [x] Reproduce rejection of an active-controller change by the first-install path; keep that rejection intact.
- [x] Implement strict old/new runtime inventory and durable administrator upgrade journal under the same release lock.
- [x] Install only reviewed fixed program/shim/manifest files; interruption leaves release blocked and resumes only exact recorded inputs.
- [x] Verify all installed bytes and preserve original app transaction/config/data; test interruption and mismatched retry.

## Task 3: Single-use failed-test repair transaction

Files: `assets/cnb-tcr-tat/host/tat-deploy-test.py`, fixed administrator permit entry, focused transaction tests.
Interface: ordinary `cnb-release-request/v1` remains unchanged. The repair adapter sends the same eight fields under test-only `cnb-test-repair-request/v1`, which requires an exact failed transaction and root permit and cannot fall back to ordinary deployment or replay after success. The permit hashes the normalized ordinary request and binds recovered source/data identity, unchanged Prisma migration review and expiry. No caller-supplied executable command.

- [x] Reproduce ordinary blocked retry and missing repair path; keep ordinary no-permit rejection.
- [x] Validate root permit, source runtime/data and original snapshot before any new runtime mutation.
- [x] Permanently archive parent transaction/snapshot binding, then atomically transition to a linked child transaction while holding original lock.
- [x] Reuse backup/start/probe/record logic. Verify identical Prisma files, schema, provider lock and complete database migration history, then skip the entire already-completed migration argv. Failure stays blocked; success writes a real passed record only after all checks.
- [x] Test expired/mismatched/reused permits, migration changes, interruption, retention protection, and source drift.

## Task 4: Reusable orchestration and CNB repair event

Files: fixed local repair-session entry, `assets/cnb-tcr-tat/templates/render.py`, small CI request adapter and focused tests; bundle hashes/version and reference docs.
Interface: administrator prepares a reviewed request from the complete verified build; API-triggered test repair reuses that build's exact SHA/build/images, existing TAT and candidate stages. It does not rebuild application images or require the user to assemble commands.

- [x] Verify the request is bound to the current commit, generated controller/config and complete service set.
- [x] Add fixed repair preparation/publish flow and generated `api_trigger` event that omits build stages only for this bound repair path.
- [x] Validate normal push/production output and candidate checks remain effective.
- [x] Update discoverable Skill guidance with one recovery decision path; retain honest boundaries.

## Task 5: Independent review and real CRM validation

- [x] Run focused regression tests, generated-bundle validation and relevant existing controller/recovery/CI tests.
- [x] Independent whole-change review; fix actionable findings and rerun affected checks.
- [x] Regenerate CRM bundle, pin exact new controller and TAT binding, then execute reviewed test upgrade.
- [x] Export failed source and restore on local isolated daemon; verify all actual tables/sequences/uploads and preserved source.
- [x] Build repaired CRM once, grant scoped repair, invoke fixed test event and verify candidate.
- [x] Finish shared-host acceptance after correcting the new Web container's initial DNS startup restart; the existing project's baseline checks pass.
- [x] Complete actual CRM test login/business/browser/recovery/update acceptance; production remains uninstalled and subject to separate preparation and user branch/candidate governance.

## Execution record

2026-09-11: the approved repair flow is implemented at Skill commit `76595bb`. Controller upgrade, failed-source restore, fixed TAT update, complete source build and repair event passed. Accepted application is `8ddd8b73b45fd9e05d66229bc966253a4407f14c` / `cnb-qu8-1k26vakd2`; repair execution is `cnb-7ao-1k270ffpv`. Original failure/history/snapshots and the consumed permit remain independently verified. Real business and representative-data restore passed. Minimal mobile/startup fixes then passed ordinary update `c1210e8a` / `cnb-0ih-1k271p8iu`, real UI, shared-host checks, preserved data and another isolated restore. Production has not been installed or released. Exact scope and timing are recorded in [shared-host validation](../../history/2026-09-09-shared-host-preparation.md).
