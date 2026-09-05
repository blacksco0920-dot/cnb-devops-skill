# Project Adoption

Use this reference to adopt an ordinary project without creating another
repository, portal, CLI, Skill, or operational sidecar: `server-ops is prohibited`.
The business repository remains the sole home for project code,
pipelines, controller, topology, and deployment state.

## First read

Read repository-local instructions, then `docs/DEPLOYMENT.md` and
`docs/PROJECT_STATUS.md` when present. Do not ask a human to repeat a fact that
the repository, its accepted receipts, or a supplied control record can show.
Read [release safety](release-safety.md) for candidate/evidence rules,
[human handoffs](human-handoffs.md) for ownership, and the [CNB deployment
page](cnb-deployment-ui.md) only when the project uses that control surface.

## Read-only discovery

Before any mutation, inspect only the requested repository and approved
read-only records. Report a fact/status table with source, status, owner, and
next action. Each fact is exactly one of:

| Status | Meaning |
| --- | --- |
| `observed` | Found in a read-only project or approved control record. |
| `supplied` | Delivered by the responsible human with a durable destination. |
| `unknown` | Not discoverable; request one specific owner deliverable. |
| `not-applicable` | Deliberately outside this project's observed topology. |

Stop after discovery unless the user explicitly requests the matching
configuration, build, deployment, or production action. A proposed production
approval does not execute production.

## Project document contract

Maintain two living documents in the business repository:

- `docs/DEPLOYMENT.md`: stable topology, governed branches, build/release flow,
  probes, configuration classes, data/backup/rollback, and only applicable
  shared-host rules.
- `docs/PROJECT_STATUS.md`: current commits, build/candidate identities, full
  digest map, evidence, readiness/approval/execution state, blockers, and one
  next action.

Expose names and classifications—not values—in `.env.example` and, when CNB
Secret data is used, `.cnb/secret.example.yml`. Classify a secret as `build`,
`pipeline`, or `runtime` by where it is consumed. Record a value-free receipt
with name, storage location, owner, rotation/expiry, and validation state; never
put a value or complete environment file in chat, an ordinary repository, a
handoff manifest, or a public report. Draft missing documents from observed
facts before requesting only their undiscoverable inputs.

## Host and account classification

Classify a single-project target as a `simple host` unless read-only evidence
shows shared route ownership, opaque Caddy, or multiple independently managed
projects. Classify those observed conditions as `shared Caddy` and route to the
shared-Caddy contract before any takeover. Do not begin a shared-Caddy
bootstrap, baseline import, direct Caddy change, or ordinary release merely
because a project is new.

For both operator-owned testing and customer-owned production, use dedicated
direct CAM identities with two fixed, pre-created TAT Saved Commands: one for
readiness and one for apply. Each Saved Command owns fixed reviewed command
content/controller. Exact target InstanceIds come only from an approved
project-owned adapter/control record and CAM resource scope, never from CNB.
CNB supplies only normalized non-secret release identity and the complete digest
map; it never supplies arbitrary script text, paths, targets, or credentials.
The adapter reads back the fixed command, invokes its CommandId, and records
invocation evidence. Cross-account role/STS is optional when an organization
needs a separate delegation boundary and invokes the same fixed commands. Return
missing setup work as one owner, destination, and acceptance result, never as
secret-value questions.

## Minimal release ladder

1. Document and inspect without mutation.
2. Build once, record immutable OCI `repository@sha256:digest` images, deploy
   staging, and record separate build, runtime, and public evidence.
3. Create a ready-last immutable candidate bound to the complete digest map.
4. Confirm the candidate is in the governed branch without rebuilding.
5. Run the fixed readiness Saved Command, refresh production readiness, and
   obtain independent approval for that exact candidate.
6. Explicitly execute the fixed apply Saved Command with the same digest map;
   approval does not execute production.
7. Record actual production runtime and public evidence before marking the
   server delivery complete.

## Independent client delivery

Client packages, platform review, store publication, and customer communication
are a separate delivery surface. A server publication does not imply client publication,
and client publication does not change the server candidate or
production approval.

## Optional advanced paths

Load shared-Caddy takeover, existing-host controller compatibility, recovery,
retention, or cross-account delegation guidance only when observed topology or
organization policy requires it. Completed bootstrap or migration work is a
recorded maintenance result, not an ordinary release step to infer or repeat.
