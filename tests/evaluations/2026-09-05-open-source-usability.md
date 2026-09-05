# Qualitative usage evaluations — 2026-09-05

These were independent fresh-context Codex subagents explicitly requested with model gpt-6-astra. They used the supplied Skill and routed references plus local synthetic projects, not the proposed answer or review rubric. Inputs, tools and side effects were limited per case. Root inspected reported outputs and relevant actual artifacts. This is qualitative evidence, not a statistical comparison or live CNB/TCR/TAT/host acceptance.

## Baseline limitations and observations

- Initial novice and portfolio runs at 0ad4754 let evaluators construct their own synthetic projects. Novice then requested a real repository and inferred a second approver. The repository request was a harness confound; the approver inference was not reproduced with explicit supplied policy. Do not report these as proven universal Skill defects.
- Refined novice baseline at 0ad4754 used an existing on-disk project and its accepted PROJECT_FACTS.md. It generated local CNB entrypoints and blocked unconfigured stages, ran the supplied Python test (1 passed), respected the recorded one-owner/distinct-approval policy and reported absent live integration honestly. Preserve this success; no measured across-model improvement is claimed.

## Forward observations

| Case / Skill revision | Actual outcome | Assessment |
| --- | --- | --- |
| NOVICE_LOCAL_PIPELINE / ddf48ae | Created local configuration and project records; existing Python check passed (1 test); external integration stayed disabled and missing implementations were explicit; user got a concrete future Secret-location action rather than YAML work | Local setup/scope/AI-ownership criteria met; generated release configuration itself was not validated in a live CNB environment |
| SECOND_PROJECT_REUSE / ddf48ae | B-only artifacts, 1 existing test passed, A hashes unchanged, accepted host maintenance retained, no A bindings borrowed | Technical/scope behavior preserved; human reply still asked for an administrator-supplied technical receipt |
| RESUME_STALE_STATUS / ddf48ae | Only status document changed; expiry, invalidated approval and unresolved recovery retained; candidate/digests/receipts preserved | State reconciliation correct; human follow-up still delegated technical record registration |
| SECOND_PROJECT_REUSE / c028c18 | B-only drafts and 1 existing test passed; A directory unchanged; accepted shared maintenance reused, B bindings/provisioning unresolved, no A defaults copied; AI explicitly retained technical preparation and acceptance-record work | Previous technical-record handoff corrected; later focused clarification checks concreteness when the private location is unknown |
| RESUME_STALE_STATUS / c028c18 | Only status document changed; current accepted records superseded stale readiness/approval, transaction/receipts retained, next authorized action none | Authorized work completed without another setup/permission request or manual technical-record assignment |
| Novice handoff clarification / a0b0772 | After removal of duplicate instructions, a fresh reader explained that the private location is not a known fixed URL, gave one concrete CNB login/open-B/read-only connection action and acceptance, kept AI responsible for technical work, preserved A and completed shared setup | Focused retrieval/human-action criteria met; read-only text exercise, no project or cloud mutation |

The local-artifact cases are bound to their listed revisions. The final small a0b0772 refactor was additionally checked by independent scoped review and 39 affected automated tests; do not relabel all earlier artifact runs as performed on that commit.

## Raw evidence and repeatability

Local reports and generated project trees are retained outside the public Skill in this assessment directory and the recorded temporary directories. Neutral reusable inputs are linked from the [current catalog](../skill-scenarios.md). It must distinguish test mappings from historical fresh-context results, retain the failed first handoffs and their correction, and avoid implying that a Python health-function test proves runtime/public evidence.

No evaluator performed network, Docker, cloud, host, Git push, purchase, maintenance, production approval or production execution. No real secrets were used. The final handoff clarification is an additional scoped exercise, not a fourth complete pipeline deployment.
