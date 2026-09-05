# Existing Skill Project Adoption Design

## Goal

Update the existing `cnb-devops-skill` so a fresh AI can inspect a new project,
identify only missing human deliverables, and reach a minimal staging and
production release path without inventing another repository, CLI, portal, or
Skill.

## Scope

- Keep `SKILL.md` as the concise authorization, state, and routing entrypoint.
- Add one project-adoption reference containing the required project-document
  contract, first-read order, discovery output, minimum rollout ladder, human
  deliverables, and configuration boundaries.
- Make ordinary single-project onboarding the default. Load legacy shared-Caddy
  takeover rules only when a shared/opaque Caddy host or route ownership work is
  actually observed.
- Update Tencent guidance to prefer dedicated least-privilege CAM identities and
  fixed TAT Saved Commands for readiness and apply. Cross-account STS remains an
  optional organizational pattern, not a universal prerequisite.
- State explicitly that source completion, staging deployment, candidate
  readiness, governed-branch merge, production readiness, approval, production
  execution, and external-client publication are distinct states.
- Keep all pilot-specific accounts, hosts, paths, domains, credentials, topology,
  hashes, incidents, and business facts out of the public Skill.

## Project document contract

A target project uses two living documents:

- `docs/DEPLOYMENT.md` for stable topology, branches, build and release flow,
  probes, configuration classes, data, backup, rollback, and optional shared-host
  rules.
- `docs/PROJECT_STATUS.md` for exact current commits, build/candidate identities,
  digest map, environment evidence, readiness/approval/execution state, blockers,
  and the single next action.

Projects also expose value-free variable inventories through `.env.example` and,
when CNB Secret data is used, `.cnb/secret.example.yml`. Missing files are drafted
from observable repository facts before asking a human for unknowns.

## First-contact behavior

The AI first reads repository-local instructions and the two living documents,
then performs read-only discovery. Its output classifies each fact as `observed`,
`supplied`, `unknown`, or `not-applicable`, selects `simple host` or `shared Caddy`,
lists only missing human deliverables, and stops before mutation unless the user
has requested the corresponding change.

## Minimal release ladder

1. Document and inspect without mutation.
2. Build once, push immutable OCI images, deploy staging, and record build,
   runtime, and public evidence.
3. Publish a ready-last candidate bound to the full digest map.
4. Merge/confirm governed source ancestry without rebuilding.
5. Refresh short-lived production readiness, obtain independent approval, and
   explicitly execute production with the same digests.
6. Treat client packages and external platform review/publication as a separate
   delivery surface.
7. Add shared-host takeover, recovery, or retention hardening only when the
   project's observed topology requires it.

## Security and ownership

The business repository owns project code, pipelines, controller, Compose,
probes, and deployment contract. The public Skill owns reusable policy and
templates only. CNB Secret repositories hold pipeline credentials and sensitive
targets; root-private host files hold runtime-only values. Receipts record names,
scope, owner, and verification state without secret values. Completed bootstrap
or migration operations are marked completed and never inferred as repeatable
release steps.

## Verification

- Add failing static and behavioral scenarios before changing the Skill.
- Run the entire package test suite after the documentation changes.
- Ask a fresh-context AI to solve a new-project handoff using only the updated
  package and verify that it follows the short path without leaking values or
  invoking advanced takeover by default.
