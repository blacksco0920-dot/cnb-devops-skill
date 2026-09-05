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

## AI-owned setup and human handoffs

For an authorized setup request, complete the applicable local work from the
actual project: deployment documents, pipeline/build and runtime configuration,
value-free variable inventories, and reviewed project-owned controller and fixed
execution integrations. Adapt the linked contracts to the observed topology;
run the available project tests and configuration checks. Keep unavailable cloud
integrations disabled with a recorded reason, while completing independent work.
Index generated files, actual check results and remaining blockers in the status
document. Local generation or passing checks do not establish live acceptance.

Read role details only for the current dependency. The AI prepares technical
configuration and value-free receipts from verifiable records. Tell the human,
in plain language, one immediate action: where to go, what to do, and how
completion will be checked. Request only facts or account/console actions that
cannot be completed through available authorized access. Keep sensitive inputs
in the designated private store. One person may hold several roles; enforce
actor separation only as required by actual project policy. Approval remains a
distinct candidate-bound decision and never executes production.

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

## Resume an existing project

1. Read the local instructions and both project documents. Treat the documents
   as an index: check the current approved control records and accepted receipts
   for source/controller commits, candidate identity, complete service digests,
   evidence bindings and expiry, and transaction/recovery state. Use only the
   supplied records and authorized read-only access.
2. Resolve old decisions against their current durable sources. Mark conflicting,
   expired, invalidated, or unverified evidence and the affected action `blocked`
   until the current records resolve it. Update the index; a new policy decision
   does not rewrite an immutable candidate. Preserve unresolved transaction and
   recovery evidence and follow [release safety](release-safety.md).
3. Retain completed maintenance receipts and valid secret receipts. Do not
   repeat completed maintenance by inference or ask for already accepted setup.
   Reuse existing authorization while its recorded scope remains valid; do not
   ask for the same permission again. Production readiness and approval still
   require the existing policy's freshness, binding and recovery checks.
4. Record exactly one next authorized action with its authorization source,
   owner, destination and acceptance condition. Perform it when its checks pass;
   if none remains, record `none`. An unresolved prerequisite gets one specific
   owner deliverable, not inferred permission for release or maintenance.

Refresh `docs/PROJECT_STATUS.md` after a release result, failure, recovery,
policy decision, or handoff. Record the last verification time and evidence
sources even when an attempted action remains blocked.

This compact synthetic example is a PROJECT_STATUS index, not a new receipt
schema. Replace it with observed project facts; use explicit `unknown` or
`not-applicable` when appropriate. Evidence/decision references resolve in the
project's approved records; never copy credential values or sensitive targets.

```yaml
last_verified_at: "2026-09-05T08:00:00+00:00"
source:
  application_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  controller_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
candidate: {state: "not-created: staging verification pending", identity: not-applicable}
services:
  web: registry.example.test/example/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
evidence:
  build: "passed: build-receipt-example-1"
  runtime: "unknown: current readback pending"
  public: "unknown: current readback pending"
effective_decisions:
  - {source: decision-example-1, scope: "reconcile staging records into docs/PROJECT_STATUS.md", status: accepted}
completed_maintenance_receipts: [maintenance-receipt-example-1]
invalidated_evidence: [] # None found in the records checked so far.
unresolved_state:
  transaction: "unknown: current readback pending"
  recovery: "unknown: current readback pending"
  source: control-record-example-1
next_authorized_action:
  action: "Reconcile staging records into docs/PROJECT_STATUS.md"
  authorization_source: decision-example-1
  owner: release-operator
  acceptance: "Current transaction/recovery state and complete runtime/public evidence are indexed; unresolved checks remain blocked."
```

## Add another project

Apply the same Skill independently in each business repository. Reuse verified
configuration patterns and accepted shared-host capabilities, checking that their
scope, freshness and compatibility still cover this project. Maintain separate
project/environment identities, Secret bindings, image namespaces, routes, data,
locks and release records. Authorization for one project does not cover another.

Retain completed shared-host bootstrap and maintenance receipts; adding a project
does not replay that work. Missing per-project provisioning is a separately
scoped maintenance dependency under the host handoff, not an ordinary release
permission. Prepare independent local setup while it is pending. Each repository
keeps its own deployment/status documents; no global operational repository or
global secret store is needed. Customer-account deployment is optional.

## Source topology

Identify the authoritative source repository and actual governed synchronization
paths from read-only evidence. CNB-native source needs no external synchronization;
GitHub-to-CNB requirements apply only to an observed synchronization path. Use
the [application-owner handoff](human-handoffs.md#application-owner) for each
path's setup and acceptance. Full commits, real clean builds, complete digest
maps and release evidence remain required for every topology.

## Host and account classification

Classify a single-project target as a `simple host` unless read-only evidence
shows shared route ownership, opaque Caddy, or multiple independently managed
projects. Classify those observed conditions as `shared Caddy` and route to the
shared-Caddy contract before any takeover. Do not begin a shared-Caddy
bootstrap, baseline import, direct Caddy change, or ordinary release merely
because a project is new.

For both operator-owned testing and customer-owned production, use dedicated
direct CAM identities with fixed readiness and apply Saved Commands; keep the
read-only check separate from release execution. Follow the
[fixed TAT execution contract](release-safety.md#credentials-and-execution): CNB
must not supply arbitrary script text or caller-selected targets.
Cross-account role/STS remains optional. Return missing setup work as one owner,
destination, and acceptance result, never as secret-value questions.

## Release lifecycle

1. Inspect without mutation, then complete authorized local setup and checks.
   Record source completion separately from deployment acceptance.
2. Build once, record immutable OCI `repository@sha256:digest` images, deploy
   staging, and record separate build, runtime, and public evidence.
3. Create a ready-last immutable candidate bound to the complete digest map.
4. Confirm the candidate is in the governed branch without rebuilding.
5. Run the fixed readiness Saved Command, refresh production readiness, and
   obtain independent approval for that exact candidate under the project
   policy, including its actor-separation requirements.
6. Explicitly execute the fixed apply Saved Command with the same digest map;
   approval does not execute production.
7. Record actual production runtime and public evidence before marking the
   server delivery complete. On failure, index the transaction and recovery
   state and follow [release safety](release-safety.md) before another release.

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
