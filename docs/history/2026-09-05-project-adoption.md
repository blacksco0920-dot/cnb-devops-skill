# Project adoption — completed implementation, historical record

Archived on 2026-09-05 from the project-adoption design/plan pair formerly in
`docs/superpowers/specs/2026-09-05-project-adoption-design.md` and
`docs/superpowers/plans/2026-09-05-project-adoption.md`. Their original text is
retained in Git history (present at `0ad4754` and `a0b0772`). The implementation
was already present at those snapshots; this archive does not establish its
original completion commit or convert the unchecked verification plan to results.

The change made ordinary project adoption part of the existing Skill instead of
creating another Skill, repository, portal or CLI. The business repository kept
ownership of application code, pipelines, controller and project facts. A short
entrypoint routed to one adoption reference: project-local instructions and
read-only discovery came first, missing documents were drafted from observable
facts, and only unavailable human deliverables were requested.

The design introduced stable deployment documentation plus a living status
index and value-free variable inventories. It chose a simple host as the normal
path and reserved shared-Caddy takeover for observed shared/opaque routing.
Dedicated least-privilege CAM identities and fixed readiness/apply TAT Saved
Commands became the default; cross-account STS remained optional. Source,
build, staging runtime/public proof, immutable candidate, governed merge,
production readiness, approval, execution and external-client publication stayed
separate. Secrets and project-specific facts remained outside the public Skill;
completed maintenance was not an ordinary repeatable release step.

The original plan called for failing package assertions, the full suite, Skill
validation and a fresh-context adoption evaluation. It did not record results
for those steps. In particular, the planned fresh-context evaluation is
**unverified**, not a completed PASS. Visible implementation and available
scenario prompts are not evidence that the planned evaluation ran. The later
[first optimization](2026-09-05-first-optimization.md) has its own distinct
verification record and must not be substituted for that missing evidence.

Current guidance lives in [project adoption](../../references/project-adoption.md),
[release safety](../../references/release-safety.md), and
[human handoffs](../../references/human-handoffs.md). This historical rationale
is not a second operational contract; current failure/recovery routing continues
to apply independently of topology.
