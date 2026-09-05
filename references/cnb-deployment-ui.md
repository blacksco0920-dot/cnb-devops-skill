# CNB Native Deployment Page and Candidate Gate

Last verified: 2026-09-02

Use this reference when a project wants a visible CNB production flow without
inventing a separate deployment portal. The page belongs to the candidate
**Tag details page**. `.cnb/tag_deploy.yml` supplies the controls and static
requirements; the selected Tag's `.cnb.yml` supplies the readiness and
production events.

The page is a control surface, not release evidence. Production remains
fail-closed until the immutable candidate, current project policy, versioned
handoff, fresh readiness, approval, and project-owned execution adapter all
agree.

## Project inputs

Decide these inputs for each repository; do not inherit another project's
names or topology.

| Input | Required decision |
| --- | --- |
| service roles and repositories | The exact project-defined role-to-allowed-OCI-repository map. No fixed count, universal role names, or caller-selected repositories. |
| governed branch | The branch whose current full commit must contain the candidate before production. Do not assume `main`. |
| candidate prefix | A project-specific immutable Tag prefix and glob. Do not share one global prefix across unrelated release contracts. |
| repository roles | Choose page operator, readiness operator, and production approver independently from CNB's supported roles or explicit users. CNB roles are not upward-inclusive. |
| controller identity | The exact controller commit and hashes. If controller and application share a repository, bind both commits to the same full SHA. |
| execution adapter | A reviewed project-owned production adapter and its owner. Keep it disabled until its versioned handoff is accepted. |
| readiness lifetime | At most **24 hours** from the successful candidate-bound dynamic check. A project may choose a shorter lifetime. |

The examples use `production`, `owner`, `release-candidate-*`, two illustrative
service roles, and disabled execution only to remain concrete. Replace every
project input, then validate the resulting `.cnb/tag_deploy.yml` against CNB's
live schema. Do not copy the example values as policy.

## Candidate state machine

```text
staging evidence passed
  → canonical manifest created
  → create-only annotated candidate Tag
  → non-ready annotations written
  → Tag, manifest, commit, digest map, and annotations read back
  → candidate_status=ready written last
  → production readiness may be requested
```

This is the **ready-last** rule. Never create or retain `candidate_status=ready`
before every immutable field and all three evidence planes have been read back
successfully. A later default-branch edit cannot repair or unlock an older Tag:
the candidate pipeline and deployment events execute from the selected Tag.

### Candidate manifest

The canonical manifest records:

- versioned schema, project identity, target environment, candidate Tag,
  application commit, and controller commit;
- build identity and creation time;
- the complete project-defined map of service role to
  `repository@sha256:digest`;
- separate passed build, runtime, and public evidence with non-secret
  references.

`candidate-manifest/v1` uses an unambiguous hash domain: reject duplicate
object keys and non-I-JSON input, serialize the manifest with **RFC 8785**,
then append exactly one LF byte. That result is the canonical payload. Compute
SHA-256 over the exact canonical payload bytes and store it in the
`candidate_manifest_sha256` annotation **outside the manifest**. Never embed a
manifest's own digest inside the bytes being hashed. An implementation that
cannot reproduce this framing and canonicalization must fail closed.

Strictly reject unknown, duplicate, missing, empty, malformed, or mismatched
fields, a partial service map, a role mapped to any repository other than the
project's configured allowed repository, mutable image references, and evidence
from a different build or runtime attempt. The [candidate example](cnb-deployment-ui/examples/candidate-manifest.json)
is illustrative data, not a replacement for a project validator.

### Candidate Tag

Create the candidate Tag exactly once. Its annotated message is the exact
canonical payload bytes. A retry may proceed only after the remote Tag, peeled
commit, and message are read back and found byte-identical. Then classify its
annotations: empty or the exact completed subset at a prefix boundary of the
deterministic non-ready write sequence may resume; an exact-ready state returns
success with no write; every
unknown, mismatched, out-of-order, or incomplete-ready state blocks. Never
force, move, or silently replace a candidate Tag.

“Prefix” describes which writes have completed, not the serialized order of
keys returned by the annotation backend. Parse the result as a map and compare
its exact key/value set with one allowed completed state.

Write candidate annotations in this order:

1. For a freshly created candidate only, before its very first GET, account for
   the pinned annotation plugin's empty-result behavior using the safe
   compatibility sequence below.
2. Write manifest format, manifest hash, candidate commit, and the separate build,
   runtime, and public results;
3. read every annotation back and compare it with the manifest;
4. write `candidate_status=ready` last;
5. read back the ready state before reporting the candidate available.

Export one explicit `CANDIDATE_TAG` value from the create/readback stage and
verify it equals `manifest.candidate_tag`. Use that value for every candidate
annotation operation in a branch pipeline. `CNB_BRANCH` names the triggering
branch in that context and must not be substituted for the new candidate Tag.

For pinned `cnbcool/annotations:v1.0.0`, an empty GET returns successfully
without creating `toFile`. Immediately before that first GET, use `umask 077`
and pre-create its exact path as canonical `{}` with mode `0600`; existing data
will overwrite it. This is not a general missing-file fallback. Every GET after
an ADD uses a fresh, non-precreated path and fails closed if the file is absent
or empty. The [annotation readback example](cnb-deployment-ui/examples/annotation-readback.yml)
shows only the freshly created candidate boundary without adding a reusable CLI
or server script. An existing exact candidate must first use the retry-state
classification above; do not route it through the fresh-empty assertion.

## Two production gates

### Static gate in CNB

The **static gate** is the `require` list in `.cnb/tag_deploy.yml`. Require all
candidate and staging annotations, a candidate-bound production-readiness
annotation, and an explicit approver. Configure environment and custom-button
permissions in addition to repository write access.

Keep the readiness button and deployment button separate. The readiness button
triggers a `web_trigger_*` event; the deployment button triggers
`tag_deploy.<environment>`. Do not accept free-form production inputs or an
alternate image map on the deployment button. See the safe
[tag-deploy example](cnb-deployment-ui/examples/tag_deploy.yml).

### Dynamic gate in the selected Tag

The **dynamic gate** runs on every readiness request and again at the start of
production execution. It reloads immutable data from the selected Tag plus the
exact candidate-bound control records described below and must verify all of
the following before any production call:

- Tag prefix, peeled commit, canonical manifest, manifest hash, complete
  service map, and ready-last annotations agree;
- the candidate commit is still permitted by the configured governed branch
  and any required source mirrors;
- the versioned production handoff is accepted and bound to this candidate,
  environment, policy version, and adapter version;
- the configured execution adapter is enabled, reviewed, and matches that
  handoff;
- no `recovery-required`, unresolved transaction, or maintenance blocker
  exists;
- the successful readiness result belongs to this candidate and is no older
  than 24 hours when execution begins.

Only after these checks pass may the readiness event publish
`production_readiness=passed`, together with candidate identity, manifest hash,
policy version, verifier version, and `verified_at`. Publish the passed status
last. Missing, stale, mismatched, or malformed data leaves readiness absent or
failed and returns nonzero.

CNB's 24-hour deployment-build replay restriction is not a substitute for this
candidate-bound readiness lifetime. After 24 hours, or when another authorized
operator must act, start again from the Tag details page and repeat readiness
and approval.

## Handoff and adapter boundary

The ordinary repository may contain non-secret pending/disabled templates.
Sensitive target values remain in the approved Secret repository or target
control system.

Candidate-bound acceptance state is created only after the immutable candidate
exists. Store an accepted handoff, enabled-adapter receipt, readiness receipt,
and approval generation as a **candidate-bound control record** outside the
selected Tag's Git object—for example, strictly read-back CNB Tag annotations
or an approved control/Secret store keyed by the exact candidate. The dynamic
gate reads those records by candidate identity; it never substitutes the latest
default-branch record. It **must not modify the selected Tag's Git object**,
force-move the Tag, or create a replacement candidate merely to unlock one.
Committing an accepted record that names candidate A creates a new commit and
therefore cannot unlock candidate A; doing so would create a self-reference
loop.

A `production-handoff/v1` record begins `pending`. Its accepted form names only
non-secret identity and policy fields: exact candidate, environment, handoff
schema/version, selected execution-adapter kind and version, responsible role,
acceptance time, and validation result. Target IDs, addresses, role secrets,
and credentials never enter the record.

A `production-execution-adapter/v1` record begins `disabled`. Enabling it
requires the separately accepted handoff and a harmless adapter-specific
preflight. Unknown schemas, a pending handoff, a disabled adapter, or an
adapter/handoff mismatch blocks before credentials are loaded or an external
production call is made.

For TAT, the project-owned adapter selects fixed, pre-created TAT Saved Commands
named for readiness and apply. Each Saved Command owns fixed reviewed command
content/controller. Exact target InstanceIds come only from an approved
project-owned adapter/control record and CAM resource scope, never from CNB.
CNB passes only normalized non-secret release identity and the complete digest
map. It must not pass arbitrary script text, paths, targets, credentials, or an
alternate image map. The adapter reads back the fixed command, invokes its
CommandId, and records invocation evidence.

Start projects from the [pending handoff](cnb-deployment-ui/examples/production-handoff.pending.json)
and [disabled adapter](cnb-deployment-ui/examples/execution-adapter.disabled.json)
examples. They deliberately cannot deploy.

## Approval, execution, and recovery

CNB approval and execution are separate authorities. Approval names one exact
candidate after a fresh readiness result; the deployment event must still run
the dynamic gate before invoking the adapter. Repository merge approval,
readiness permission, and production approval do not imply one another.

Production promotes the **same digest** for every project-defined service role.
It does not rebuild, retag mutable images, change service membership, or infer
a missing digest. After execution, compare the actual production role/digest
map and public result with the complete project-defined service role/digest map
before recording success atomically.

If execution crosses the project's failure boundary, record
`recovery-required`, preserve the candidate and recovery material, and stop.
After recovery, invalidate the prior readiness and approval. A retry requires a
new readiness result and **new approval**, even when the candidate digest map is
unchanged.

## Safe example boundary

The [candidate-production gate example](cnb-deployment-ui/examples/candidate-production-gates.yml)
is candidate-scoped and exits nonzero by default. It demonstrates the CNB event
locations without inventing a universal generator, CLI, server script, or
execution adapter. Replace each blocked stage only with the project's reviewed
validator/adapter boundary. Until then, production stays fail-closed.

Use the [gate behavior cases](cnb-deployment-ui/examples/gate-behavior-cases.json)
as a minimum project-validator regression matrix. It fixes create-only and
exact-ready retry decisions; candidate, manifest, project, environment,
controller, governed-branch, policy, and verifier bindings; the configured
role-to-repository map; inclusive 24-hour
freshness; handoff/adapter agreement; transaction, maintenance, and recovery
blockers; approval generation; and exact service membership/digest comparison
without choosing a target adapter.

Before enabling a project:

1. Adapt all project inputs and the complete service map.
2. Validate `.cnb/tag_deploy.yml` with the live CNB schema.
3. Prove create-only Tag publication and ready-last readback on a disposable
   candidate.
4. Prove every missing, stale, mismatched, pending, disabled, and recovery case
   fails before the adapter.
5. Prove the adapter receives only the selected candidate's same digest map.
6. Ask the configured roles to test readiness, approval, and execution as
   separate actions. Do not perform a production mutation for this test.

Official CNB references:

- <https://docs.cnb.cool/zh/build/deploy.html>
- <https://docs.cnb.cool/zh/build/trigger-rule.html>
- <https://docs.cnb.cool/zh/repo/annotations.html>
- <https://docs.cnb.cool/tag-deploy-schema-zh.json>
