# First Optimization Design

## Scope

Improve four accepted areas: bounded shared-Caddy execution, consistent upstream validation, project-document resumption, and topology-dependent source synchronization. Keep the short Skill entrypoint, existing release authority, immutable candidates, evidence planes, and maintenance boundaries.

## Runtime design

All Docker subprocess calls in the ordinary shared-Caddy helper use one runner with a fixed 30-second deadline. Project and shared lock acquisition use a monotonic 30-second deadline, retain descriptor/identity checks, and preserve lock order. No new privileged CLI arguments or server-contract fields are introduced.

A read-only validation timeout before a durable transaction discards only private preflight/staging artifacts and releases locks. A Docker timeout after a durable transaction may represent an operation whose daemon-side outcome is unknown: retain transaction and intake evidence, set recovery-required, and block normal publication. Do not retry Docker mutations or run automatic rollback after this uncertain outcome. A timeout during recovery also preserves the blocker and retained evidence. Explicitly distinguish this from ordinary known failures, whose existing recovery behavior remains in force.

Use one upstream predicate for declaration, runtime ensure, and runtime recovery verification. It accepts lowercase DNS labels of at most 63 characters and total length at most 253, including valid multi-label names longer than 63; keep network/container identity rules separate.

## Project-document design

Extend the existing adoption reference with a compact, value-free PROJECT_STATUS example and an ordered resumption recipe. Include current source/candidate/service evidence, verification time, effective decisions and their durable sources, completed maintenance receipts, invalidated or expired evidence, unresolved transaction/recovery state, and one next authorized action with owner and acceptance condition. Project documents are an index; current accepted control records and actual state determine whether an action is still valid.

Refresh status after release outcomes, failures, recovery, relevant decisions, and handoff. Reuse effective authorization within its recorded scope, and refresh production readiness/approval when existing release policy requires it. Mark conflicts as blocked until resolved against evidence; do not rewrite immutable candidates or repeat completed maintenance by inference.

## Source-topology design

Discover the authoritative code repository and actual governed synchronization paths. For CNB-native repositories, synchronization is not applicable and no GitHub credential is requested. For GitHub-to-CNB projects, retain scoped tokens, complete SHA equality on actual governed paths, and protection against destructive mirror pushes. All paths retain clean-build and candidate evidence requirements.

## Validation

Write and observe failing regressions before implementation. Runtime coverage includes finite lock contention, every Docker command path, pretransaction cleanup, uncertain mutation timeout retention, recovery timeout retention, and upstream length/label boundaries. Document coverage includes the status template, stale-state and valid-resumption scenarios, and CNB-native versus synchronized source paths. Run targeted tests, independent spec/quality review, the complete CI suite, Skill validation, compile checks, and sudoers parsing. Public artifacts use synthetic data only.

## Delivery

Implement in an isolated local worktree, then integrate the verified commits into the local repository used by the installed Skill. This change does not install a host helper or run a deployment; helper updates on a real host continue to require the existing maintenance process.
