# Open-source Usability Design

Status: approved direction from the user's documentation audit follow-up; implementation in progress.

## Purpose and audience

The Skill serves one owner operating multiple independent projects and beginners using an AI coding tool to establish a complete CNB release pipeline. The AI reads technical references, authors project configuration, runs authorized checks, and maintains durable project records. The person supplies decisions and completes account or secret-entry actions that the AI cannot perform through an authorized capability.

README is a concise Chinese human entrypoint. SKILL and references are concise operational instructions for the AI; examples and scripts are machine-facing technical material. A reader need not understand YAML, command-line tools, receipts, or deployment-controller internals to begin.

## Design

- Keep existing top-level Skill/reference/script/test separation. Preserve the portable package and existing runtime behavior.
- Give each detailed rule an explicit home. Keep short, relevant boundary reminders at calling steps and link the detailed rule. Improve role/section navigation and inventory-tool discoverability.
- Explain first setup, continuing a project, and adding another project. Reuse verified infrastructure capabilities and templates within scope; keep project identities, data, secrets, routes, candidates, receipts, and approvals isolated.
- AI completes authorized, discoverable work and produces reviewable configuration before asking for a genuinely missing human deliverable. One person may own multiple roles. Describe any required human action in plain language with a destination and observable completion result.
- Distinguish configured locally, build verified, staging verified, candidate ready, production ready, approved, executed, and client publication. Unknown prerequisites keep generated integration disabled; no invented resource, credential, deployment evidence, or claim of a working pipeline.
- Separate current behavioral scenarios from historical evaluations. Preserve known dates, versions, observations and limits; mark evidence gaps instead of upgrading claims. Consolidate completed design/plan pairs into concise history.
- Improve documentation tests to check reachable authoritative rules, local file/anchor validity, structured examples and stable scenario-to-test mappings. Do not maintain copies solely to satisfy literal text checks.

## Constraints

- No changes to scripts, schemas, example runtime behavior, production approvals, recovery semantics or credential boundaries.
- No deployment portal, generic CLI, sidecar repository, global secret store, or new runtime dependency.
- Local authorized documentation/configuration work proceeds without repeated permission prompts. External authorization remains bounded by project, environment, action and current accepted records.
- Technical references may stay in English; human onboarding and sample user requests use clear Chinese. Do not add parallel translations of every rule.
- Preserve confirmed validation limits, including the earlier 340-test run and the existing-agent nature of four adoption walkthroughs; do not claim live infrastructure validation.

## Acceptance

1. A novice can start with a natural-language request; the AI does repository work and asks for only concrete missing actions, without assigning YAML/receipt authoring to the person.
2. Adding project B can reuse accepted shared-host maintenance without replaying it or borrowing project A's data, secrets, routes or release authority.
3. Resume, local-only requests, unknown resources and production authorization retain their distinct limits.
4. Current scenario definitions and historical evaluation results are clearly separated and mechanically locatable. All local document links and anchors resolve.
5. Changed package tests, meaningful negative link/mapping cases and the full deterministic suite pass. Bounded fresh-context, text/local-artifact evaluations report observed outcomes separately from static checks and live validation.

## Closeout

Keep transient briefs and raw evaluation output outside the public Skill. At completion, fold this design and its plan into one concise historical change record with actual verification results. Integrate locally only; publishing is outside this request.
