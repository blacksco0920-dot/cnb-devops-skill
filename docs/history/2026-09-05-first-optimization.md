# First optimization — completed historical record

Archived on 2026-09-05 from
`docs/superpowers/specs/2026-09-05-first-optimization-design.md` and
`docs/superpowers/plans/2026-09-05-first-optimization.md` (retained in Git history
at `a0b0772`). Code verification was bound to `fba02bc`; delivery was local only.

The change bounded ordinary shared-Caddy Docker calls and lock waits to
30 seconds while retaining descriptor/identity checks and project-before-shared
lock order. A Docker client timeout can leave the daemon's outcome unknown:
pretransaction read-only timeout cleanup was separated from timeout after a
durable transaction, which retained evidence and required recovery without
mutation retries or automatic rollback. Known failures kept their existing
recovery behavior. A shared lowercase-DNS predicate aligned declaration and
runtime upstream validation (63 characters per label, 253 total), without
changing network/container identity rules or privileged interfaces.

The documentation change made PROJECT_STATUS an index of accepted current
control records, not an authority overriding them. Resumption retained immutable
candidates, completed maintenance, durable decisions and existing valid scoped
authorization while exposing expiry, conflicts and unresolved recovery. Source
discovery made GitHub synchronization conditional: CNB-native projects did not
need GitHub credentials; actual governed GitHub-to-CNB paths retained complete
SHA equality, scoped tokens and rejection of destructive mirror pushes.

Current contracts are maintained in the
[Shared Caddy contract](../../references/shared-caddy-v1/contract.md),
[project adoption](../../references/project-adoption.md), and
[human handoffs](../../references/human-handoffs.md). Host helper installation
still requires its separate maintenance process; this change did not deploy it.

## Verification record (preserved verbatim)

- Baseline: 319 tests passed before implementation.
- Runtime regressions: expected failures observed before implementation; the final runtime module has 18 passing tests. The successful-lock deadline regression was independently reproduced and then closed in scoped review.
- Adoption package: three new tests failed before reference edits; 26 package tests passed afterward.
- Final code validation at `fba02bc`: 340 tests passed with `REQUIRE_FULL_JSONSCHEMA=1` under Python 3.12.9, jsonschema 4.25.1 and PyYAML 6.0.2. Python compile, Skill quick validation, sudoers syntax, and diff checks passed.
- Independent specification and quality review approved both tasks; the acceptance-stage wording and successful-lock deadline findings were resolved and re-reviewed.
- Four adoption scenarios passed an independent review walkthrough. The evaluator was an existing agent with task history, so this is not a fresh-context experiment or a live project acceptance result.
- No real Docker, cloud execution, host-helper installation, or production deployment was performed.
- Local integration: the reviewed branch was fast-forwarded into `main`; the installed Skill symlink resolved to that checkout and read the updated SKILL.md. The integrated tree matched the reviewed branch, the working tree was clean, and Skill validation passed.
