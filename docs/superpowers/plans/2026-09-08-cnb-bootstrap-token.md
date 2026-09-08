# CNB initialization token implementation plan

> Execute in the existing isolated worktree using subagent-driven development.
> The user approved this design on 2026-09-08 after the public API research.

**Goal:** Let AI continue repository setup with an explicitly selected private
initialization token when the official CLI login lacks write scope.

**Architecture:** Keep the pinned official CLI and existing reconciliation
journal. Add `--token-file` as an explicit alternative to OAuth. A small
standard-library Python command saves a token through non-echoing terminal
input; it does not create, inspect or validate cloud credentials. Account
creation, OAuth application registration and live credential issuance are
outside this implementation.

**Constraints:** No token values in arguments, specs, receipts or errors; no
implicit environment credential selection; official CNB API destination only.
Private directory 0700, owned regular single-link file 0600, no symlink targets.
Raw ASCII bearer token, 1–8192 bytes, one optional terminal newline when read.
Do not alter the deployment runtime or existing cloud resources.

## 1. Explicit credential input

- [x] Add failing regression cases in `tests/test_configure_cnb.mjs` for private
  file input without an OAuth profile, unsafe files, selected-token failure,
  child environment isolation and secret-free output.
- [x] Implement `CnbCliClient(bin, {run, tokenFile})` and CLI `--token-file` in
  `scripts/configure-cnb.mjs`; pass the value only in the child's `CNB_TOKEN`.
- [x] Preserve default OAuth behavior, scope diagnostics, uncertain creation
  journal and exact resource readbacks; never switch identity automatically.
- [x] Run `node --test tests/test_configure_cnb.mjs` and inspect the result.

## 2. Private terminal save

- [x] Write failing tests in `tests/test_save_cnb_token.py`, including a real
  PTY check, redirected input refusal, exclusive output and private permissions.
- [x] Implement `python3 scripts/save-cnb-token.py --output <private-path>`
  using non-echoing terminal input, fixed diagnostics and atomic private output.
- [x] Verify that saved output is accepted by the Node reader, without a real
  token or network request. Saving is not proof of cloud permission or expiry.

## 3. User and AI guidance

- [x] Update README and routed API/handoff references: reuse an accepted token,
  or prepare one concentrated official-page creation and private import step.
- [x] State only the needed API scopes; do not promise that a resource selector
  can bind an uncreated repository. Record actual scope and expiry privately.
- [x] Preserve necessary Secret Web saves and clearly separate local acceptance
  from the still-pending live PAT repository creation check.

## Acceptance

- [x] Review the implementation and the novice handoff independently.
- [x] Run affected tests, public package checks and an isolated transport check
  with the fixed official CLI. No real account mutation is needed for these.
- [x] Commit reviewed changes and fast-forward the clean local main checkout;
  the installed Skill symlink then selects the updated implementation.

## Validation result

Node configuration regressions: 27 passed. Python importer: 10 passed, including
a real PTY proving input is not echoed and terminal settings are restored.
Public package checks: 32 passed; Skill format and bundle hashes passed.
The importer output was accepted by the Node client in a separate format check.

The fixed official CLI 1.15.18 was also executed against an isolated, stateful
fetch boundary: OAuth scope refusal, explicit-file private/Secret creation,
build-setting readback and an unchanged repeat all passed using the same
journal. A conflicting pre-existing OAuth host did not redirect the PAT, and
the profile remained unchanged. This check used synthetic tokens and made no
network requests; it is not live PAT or Secret creation evidence.

An independent reviewer checked the implementation and four novice handoff
paths. Clarified the fallback when no safe import channel exists, and the
handling of unknown scope/expiry. No cloud resources or deployed runtime
artifacts were changed. Live PAT repository creation remains pending.

Subsequent live verification on 2026-09-08 passed repository creation,
build-setting writes/readbacks and an unchanged repeat. This later cloud run,
including its initial permission handoff failure, is recorded in the
[API validation follow-up](../../history/2026-09-07-api-live-validation.md#pat-followup).
