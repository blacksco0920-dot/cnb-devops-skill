# Open-source usability — accepted historical record

The implementation and whole-change quality review were accepted at `e7c717e`.
This record consolidates the design and plan formerly at
`docs/superpowers/specs/2026-09-05-open-source-usability-design.md` and
`docs/superpowers/plans/2026-09-05-open-source-usability.md`; their original text
is preserved in Git at that revision.

The change serves AI coding beginners establishing a complete CNB pipeline and
one owner operating multiple independent projects. The Chinese README offers
natural-language starting requests. The AI reads technical guidance, authors
configuration, performs authorized checks and maintains technical records;
people supply unavailable decisions or concrete account/access/secret-entry
actions, with a destination and observable completion condition. One person may
hold multiple roles; production authorization retains its existing boundaries.

Detailed rules now have authoritative homes with short reminders and links at
calling steps. Role navigation and host-inventory tooling are easier to find.
Project B can reuse templates and valid accepted shared maintenance without
repeating setup or inheriting A's identities, credentials, data, routes,
candidates or release authority. Project-specific locks remain isolated while
the host-wide shared-Caddy lock remains shared. Resumption reconciles current
accepted records and can finish with no next authorized action. Local setup,
build, runtime/public proof, candidate readiness, approval, execution and client
publication remain distinct; unknown prerequisites keep integration disabled.

Fresh-context local exercises exposed two remaining handoff problems: earlier
second-project and resume replies assigned technical receipts/record registration
to people despite correct local technical work. Later revisions kept that work
with the AI. A further scoped clarification made the human action concrete when
a private location was unknown, without inventing a fixed URL. The refined novice
baseline already succeeded at local setup; these observations do not establish
a general or across-model improvement. Per-revision outcomes, baseline confounds,
failed handoffs and corrections are retained in the
[qualitative evaluation record](../../tests/evaluations/2026-09-05-open-source-usability.md).

The [current catalog](../../tests/skill-scenarios.md) separates prompts, neutral
project fixtures and AST-resolvable test mappings from historical results.
Negative checks cover broken links/anchors, missing or duplicate scenario IDs
and mappings, unresolved test references and invalid fixture paths. Historical
records preserve the reported 12/12 result alongside its 13 listed rows without
inventing a corrected outcome. The previous two completed design/plan pairs were
also consolidated; the first optimization's verification block remains verbatim,
and initial adoption's unevidenced fresh-context verification remains unverified.

Verification used Python 3.12.9, jsonschema 4.25.1 and PyYAML 6.0.2:

- Baseline: 340 deterministic tests passed.
- At `e43e072`: 346 tests passed in 19.960 seconds with
  `REQUIRE_FULL_JSONSCHEMA=1`. Python compile checks, Skill quick validation,
  sudoers parsing and diff checks passed. Protected runtime/resource and fixture
  equality checks passed; no runtime scripts, schemas, runtime example behavior,
  approval, recovery or credential boundaries changed. No runtime dependency,
  portal, generic CLI, sidecar repository or global secret store was added.
- At `e7c717e`: 32 affected package checks passed after correcting the resumed
  fixture's expected next action to `none` and explicitly stating the public
  evaluation evidence's custody and audit limits. Independent scoped review
  accepted both corrections and approved Task 3 specification and whole-change
  quality. The full-suite result remains bound to `e43e072`.

The linked fresh-context evaluations are qualitative text/local-artifact
exercises at their listed revisions, not complete live-pipeline acceptance or
fresh runs of every case on the final revision. Original reports and generated
trees remain maintainer-local and unbundled; public inputs allow repetition but
not inspection of those original outputs from this package. No live Docker,
cloud, host maintenance, production approval or production execution is claimed.
