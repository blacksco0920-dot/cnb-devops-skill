# Open-source Usability Implementation Plan

> For agentic workers: use subagent-driven-development with bounded briefs and independent review. This is the active plan; completed plans are archived at closeout.

**Goal:** Make the existing Skill understandable to an AI coding beginner and reusable across an owner's projects while preserving its release contract.

**Architecture:** A Chinese README explains purpose and starting requests; SKILL routes AI work to focused references. Detailed rules have one maintenance location; durable project records stay per project. Current scenarios are separate from historical experiments.

**Tech stack:** Markdown, existing Python unittest suite, jsonschema and PyYAML for validation only.

## Global Constraints

- No changes to scripts, schemas, example runtime behavior, production approvals, recovery semantics or credential boundaries.
- No deployment portal, generic CLI, sidecar repository, global secret store, or new runtime dependency.
- Local authorized documentation/configuration work proceeds without repeated permission prompts. External authorization remains bounded by project, environment, action and current accepted records.
- Technical references may stay in English; human onboarding and sample user requests use clear Chinese. Do not add parallel translations of every rule.
- Preserve confirmed validation limits, including the earlier 340-test run and the existing-agent nature of four adoption walkthroughs; do not claim live infrastructure validation.

### Task 1: Consolidate technical guidance and make references discoverable

**Files:** Seven references Markdown files, `tests/test_skill_package.py`; a small test utility/module only if needed for link/anchor checks.

**Interfaces:** Preserve existing reference paths and headings used as anchors where practical. Full fixed-TAT input/target contract belongs to `release-safety.md#credentials-and-execution`. Secret task classification and empty GET compatibility belong to existing `cnb-openapi.md` sections. Shared-host maintenance handoff belongs to its existing dedicated file. Current scenario extraction is reserved for Task 3.

- [ ] Replace four-document duplicated-keyword requirements with authoritative-rule plus caller-route/short-boundary checks. First demonstrate failures for missing role/inventory routing and broken or renamed anchors; exercise the link checker against synthetic invalid targets as meaningful negative cases.
- [ ] Remove repeated full definitions while preserving unique setup, permissions, retry, expiry, receipt, and local step constraints. Keep the exact ready-last, immutable-candidate, recovery and fixed-command semantics.
- [ ] Add a concise role/issue index to human-handoffs. Link inventory v2 collector, request example and Schema from host-handoff with its scope and output boundary. Avoid new reference directories.
- [ ] Check relevant package/CNB example tests and local links. Record covered constraints, exact commands and outcomes; commit and obtain task review.

### Task 2: Make the beginner and multi-project delivery model explicit

**Files:** `README.md`, `SKILL.md`, `references/project-adoption.md`; targeted package tests only for meaningful document contracts.

**Interfaces:** Reuse Task 1's authoritative links. Preserve PROJECT_STATUS example keys required by existing consumers. SKILL remains a short router; README is the human entrypoint and references are AI instructions.

- [ ] Review bounded pre-edit novice and second-project observations. Identify actual output gaps; add regression scenarios/expectations to the evaluation brief before changing the instructions. Preserve successful baseline behavior.
- [ ] Rewrite README in clear Chinese: who it serves, how to start through a compatible AI tool, natural-language prompts for first setup/add-project/resume, what the AI does, what only the person must do, and honest delivery/validation scope. Keep technical configuration out of the human start path.
- [ ] Update SKILL purpose and routes, including direct CNB UI routing. Update adoption with AI-owned local deliverables, plain human handoffs, one-person/multiple-role handling, complete release lifecycle and per-project reuse/isolation. Retain scope-based authorization and no false completion claims.
- [ ] Run affected tests and independent fresh-context local-artifact evaluations against the edited Skill. Record actual outputs and limitations; commit and obtain task review.

### Task 3: Separate current scenarios from historical evidence and archive completed plans

**Files:** `tests/skill-scenarios.md`, `tests/evaluations/`, scenario mapping data if justified, `tests/test_skill_package.py`, `docs/superpowers/`, `docs/history/`; README validation link only if needed.

**Interfaces:** Current scenario IDs stay stable. New scenarios cover novice full-pipeline setup, second-project reuse/isolation and resumption. Historical PASS claims remain attributed to their actual evidence, never inferred from a test mapping.

- [ ] Replace fixed headings/dates/table layouts and hard-coded mapping count with stable scenario IDs plus valid unique AST-resolvable test mappings. Include negative missing/duplicate/unresolved mapping checks without broadening runtime tests.
- [ ] Keep prompt, expected behavior and mapping in the active catalog. Move historical RED/GREEN records to clearly historical evaluations, retaining unique observations and known dates/versions/limits. Mark the 12-versus-13 evidence mismatch without inventing results. Keep one current takeover order including credential rotation.
- [ ] Consolidate the two completed historical spec/plan pairs into two change records, removing obsolete imperative steps and false pending status. Preserve first-optimization verification exactly. Fold this iteration's design/plan into a third completed history record only after acceptance.
- [ ] Run affected documentation/scenario tests and full deterministic suite with full jsonschema, quick validation, link/anchor checks and diff checks. Obtain independent whole-change review and resolve material findings.
- [ ] Record final evidence and limits, fast-forward the clean main checkout locally, verify installed Skill symlink and clean Git state. Leave the remote unchanged.
