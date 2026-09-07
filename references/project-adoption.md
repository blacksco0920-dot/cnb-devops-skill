# Project Adoption

Default to the business repository for project code, pipelines, controller,
topology, and deployment records. Respect an existing or explicitly authorized
project-specific control repository when the project's access requirements
justify it; record the reason and link it from both project documents. Do not
create a global operations repository, portal, CLI, Skill, or operational sidecar
as a setup prerequisite. A separate repository is not proof of permission
isolation; verify the [actual execution boundary](release-safety.md#credentials-and-execution).

## First read

For initial setup, first follow the [standard workflow](standard-workflow.md).
Reuse its CNB → TCR → TAT route and available artifacts before designing new
execution code. Keep an existing accepted topology unless the user requests a
change or an observed incompatibility requires one; adopting this default does
not authorize migrating a working registry or deployment system.

Read repository-local instructions, then `docs/DEPLOYMENT.md` and
`docs/PROJECT_STATUS.md` when present. Do not ask a human to repeat a fact that
the repository, its accepted receipts, or a supplied control record can show.
Read [release safety](release-safety.md) for the current candidate/evidence rules,
the applicable [human handoff](human-handoffs.md) when an input or human action is
missing, and the [CNB deployment page](cnb-deployment-ui.md) when that control is used.

## Read-only discovery

Before any mutation, inspect only the requested repository and approved
read-only records. Report a fact/status table with source, status, owner, and
next action. Each fact is exactly one of:

| Status | Meaning |
| --- | --- |
| `observed` | Found in a read-only project or approved control record. |
| `supplied` | Delivered by the responsible human with a durable destination. |
| `unknown` | Not discoverable; identify the smallest missing fact or necessary human action. |
| `not-applicable` | Deliberately outside this project's observed topology. |

Stop after discovery unless the user explicitly requests the matching
configuration, build, deployment, or production action. A proposed production
approval does not execute production.

## AI-owned setup and human handoffs

For authorized setup, generate the standard project artifacts, adapt actual
differences, and run applicable project/configuration checks. Use the
[standard artifact mapping](human-handoffs.md#standard-artifacts) to fill existing
topology, path, UID/GID, mode and execution-contract requirements from the policy,
Compose, versioned installer and accepted receipts. Add only observed missing
requirements; do not create another platform or contract duplicating these files.
Index generated files, actual checks and remaining blockers in the project
documents. Keep unavailable integrations disabled while completing independent
work; local generation or passing checks do not establish live acceptance.

For the current dependency, follow the [human handoff process](human-handoffs.md):
the AI prepares technical materials and records actual authorized acceptance;
the human performs or confirms only necessary real-world actions. Keep sensitive
inputs in the designated private store. Apply the project's approval policy;
approval remains a distinct candidate-bound decision and never executes production.

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
   if none remains, record `none`. For an unresolved prerequisite, prepare the
   reviewable draft and request only the missing fact, action or confirmation
   through the human handoff process; it does not authorize release or maintenance.

Refresh `docs/PROJECT_STATUS.md` after a release result, failure, recovery,
policy decision, or handoff. Record the last verification time and evidence
sources even when an attempted action remains blocked.

Keep this document as the current index; move phase history into linked records
instead of accumulating competing resume files. Index private evidence by its
approved location, custodian, and checksum. A new session or machine must verify
access to those files; a path in the index does not make them available. Append
later acceptance evidence without rewriting an earlier immutable receipt.

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

**Across business repositories:** reuse the Skill and verified configuration
patterns independently. Each project keeps its own identities, Secret bindings,
image namespaces, routes, data, release locks and deployment/status records.
Authorization and sensitive inputs remain project-specific; classify each actual
target host separately. No global operational repository or secret store is needed.

**On an actually shared host:** also verify that accepted host capabilities still
cover the new project's scope, freshness and compatibility. Retain completed
bootstrap/maintenance receipts. Missing per-project provisioning requires its
scoped host-maintenance authorization; prepare independent local work meanwhile.
Shared Caddy requires the [host-wide lock and handoff](shared-caddy-v1/contract.md)
in addition to project locks. Customer-account deployment remains optional.

## Source topology

Identify the authoritative source repository and actual governed synchronization
paths from read-only evidence. CNB-native source needs no external synchronization;
GitHub-to-CNB requirements apply only to an observed synchronization path. Use
the [application-owner handoff](human-handoffs.md#application-owner) for each
path's setup and acceptance. Full commits, real clean builds, complete digest
maps and release evidence remain required for every topology.

## Host and account classification

Newly purchased hosts may include cloud-provider preinstalled components; their
presence alone does not establish a need to reinstall. First use read-only
evidence to identify actual port, resource, and ownership conflicts, and preserve
components the user asks to retain. Reinstallation or wiping requires separate
explicit authorization; if the user withdraws it, stop that operation immediately.

Classify a single-project target as a `simple host` unless read-only evidence
shows shared route ownership, opaque Caddy, or multiple independently managed
projects. Classify those observed conditions as `shared Caddy` and route to the
shared-Caddy contract before any takeover. Do not begin a shared-Caddy
bootstrap, baseline import, direct Caddy change, or ordinary release merely
because a project is new.

Inventory and pin runtime dependency images, including databases and caches,
alongside application images; verify registry access from the target host.
Successful CNB builds do not prove host pull access. If an actual pull fails,
copy the selected upstream image to an approved reachable registry while
preserving its digest, then verify the destination digest and platform before
using it. Do not rebuild an image to repair a host-to-registry network failure.

For both operator-owned testing and customer-owned production, use dedicated
direct CAM identities with fixed readiness and apply Saved Commands; keep the
read-only check separate from release execution. Follow the
[fixed TAT execution contract](release-safety.md#credentials-and-execution): CNB
must not supply arbitrary script text or caller-selected targets.
Cross-account role/STS remains optional. Prepare missing setup through the human
handoff process, with one accountable owner, destination and acceptance condition;
never request secret values in chat.

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

Use [standard recovery](bootstrap-inputs.md#recovery) for the configured data scope.
Read legacy/shared-Caddy takeover, existing-host controller compatibility or
cross-account delegation details only when actual topology or project policy
requires them. Retain required maintenance, recovery and approval gates; completed
bootstrap or migration is a recorded result to reuse while valid.
