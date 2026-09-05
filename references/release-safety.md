# Release Safety

Last verified: 2026-09-03

## Evidence planes

- **build evidence** proves the expected source and controller inputs produced a
  complete, immutable service image set under one traceable build.
- **runtime evidence** proves the target environment is running that exact image
  set by digest and that its required health checks pass.
- **public evidence** proves the intended public routes, TLS, and application
  behavior work from outside the runtime boundary.

None of these planes implies another. Record each result and its verifier
separately; a build result alone is never a deployment result.

## Candidate manifest

A candidate manifest is immutable release evidence. It contains:

- manifest format and version;
- project and environment identity;
- full application commit and exact controller commit;
- build identity and candidate identity;
- a complete service map whose every value is
  `repository@sha256:digest`;
- the three evidence-plane results, timestamps, and non-secret evidence links.

The manifest contains no credential values, complete environment files, or
customer target identifiers that are not needed to identify the evidence.

## Candidate creation

Parse the candidate manifest strictly. Reject unknown, duplicate, missing,
empty, malformed, or mismatched fields. Reject a partial service map and any
mutable image reference. Create the candidate only after the real staging
deployment has passed build, runtime, and public evidence checks.

Define the hash domain without circularity: serialize the manifest using RFC 8785,
append the contract's single LF framing byte, and hash those exact bytes.
Store the resulting SHA-256 in a candidate annotation outside the manifest;
never insert the digest into the payload it identifies.

A source tag, branch, approval, or successful pipeline is not a substitute for
the candidate manifest.

Publish a candidate Tag create-only, then read back its peeled commit and exact
canonical manifest message. Write manifest, commit, and separate evidence-plane
annotations first; read them back; publish `candidate_status=ready` last. This
**ready-last** order prevents a partial or later-repaired candidate from
appearing deployable. Never force-move or overwrite a candidate Tag.

For CNB's Tag-details control surface and safe examples, read
[CNB native deployment page and candidate gate](cnb-deployment-ui.md).

## Production readiness

The CNB page's annotation and approver requirements are a static gate. A
project-owned dynamic gate runs both when readiness is requested and at the
start of deployment. It reloads the selected Tag, canonical manifest, complete
service set, annotations, governed-branch ancestry, versioned
`production-handoff/v1`, selected adapter status, and recovery state.

A passed readiness result is bound to one candidate, manifest hash, policy, and
verifier. It expires after at most **24 hours**. A pending handoff, disabled or
mismatched adapter, stale readiness, missing evidence, or `recovery-required`
state blocks before production credentials are loaded or an external call is
made.

## Production promotion

Reload the stored candidate evidence at approval time. Compare the complete
service set and every digest with the staging record, require an explicit
production request and the configured approval, then deploy the same digests.
Never rebuild, retag a mutable image as evidence, or infer a missing digest.

Approval and execution are separate: the execution path re-runs the dynamic
gate after approval and promotes the **same digest** for every configured
service role. Any candidate, membership, digest, handoff, adapter, or policy
change invalidates the earlier readiness and approval.

After deployment, compare the actual production service set and digests with
the candidate before recording success.

## Credentials and execution

Use separate least-privilege identities for build-push, staging TAT, production
role assumption, Git read, and business builds. Do not reuse one credential
across trust domains. Pin executable and plugin images by digest.

For ordinary operator-owned testing and customer-owned production, the pragmatic
default is dedicated direct CAM identities with fixed, pre-created TAT Saved Commands: one value-free readiness command and one value-free apply command.
Each command has a project-reviewed target and fixed action; it accepts no
caller-supplied script, path, target, or credential. A cross-account role/STS is optional when an organization needs that delegation boundary, not a prerequisite
for a simple project. CNB supplies only normalized non-secret release identity
and the complete digest map to the selected Saved Command boundary; it does not
send arbitrary scripts, paths, targets, credentials, or an alternate image map.

Load credentials from their approved secure location only for the operation
that needs them. Remove temporary Git and registry authentication before
entering the next trust domain. Never place a token in a URL, remote, argument,
log, ordinary repository, handoff manifest, or example value.

## Existing-host controller compatibility

Before the first run of a new or stricter deployment controller against
existing application state, complete a read-only compatibility preflight for
every controller-managed path. Verify object kind and absence of symlinks;
numeric UID/GID; exact mode and ACL where applicable; parent-directory
traversal by the actual runtime identity; mount writability, capacity, and
inodes; lock, transaction, and recovery state; and every required atomic
file-operation compatibility. Success with an old controller is not evidence
that the existing host satisfies the incoming controller's path contract.

If a legitimate existing path has only a numeric UID/GID or mode mismatch, stop
the ordinary release. Use a separately authorized, one-time root maintenance
action under the same application release lock. Keep the operation
descriptor-bound with no-follow semantics, perform an inode reread before
mutation, narrow the change to the required `fchmod` or `fchown`, then require
fsync and readback. This repair path covers only numeric ownership and mode. An
explicit ACL mismatch requires separately designed and reviewed fd-safe
maintenance; without it, the release remains blocked. Never auto-repair path
metadata during an ordinary release. Never relax the incoming controller to
accept legacy state.

Record a value-free compatibility receipt containing an opaque target-scope
commitment and control-record ID, the exact controller identity and exact
path-contract digest, verifier, issue and expiry times, and per-check
pass/block status. The approved control record holds the real target set and
path data; keep credentials, raw target IDs or paths, metadata values, and file
contents out of the receipt. A change to the target host set, path metadata or
ACL, mount, required capability, controller, or path contract invalidates the
receipt; any maintenance invalidates it as well. Immediately before release
execution, recheck receipt freshness, target scope, and drift against the
control record and fail closed on uncertainty.

After any maintenance, rerun the full read-only compatibility preflight and
issue a fresh passed `compatibility receipt`. Retry the complete staging
release only when both that fresh receipt and retained proof that no migration
or transaction began are present. Otherwise preserve the evidence and require
recovery review.

## Host transaction

The application caller holds its pre-created release lock across runtime and
proxy changes. For shared Caddy, the controlled helper then takes the
root-owned project Caddy lock before the root-owned shared Caddy lock and holds
the shared lock across recovery, full-tree validation, activation, reload,
smoke, receipt, and rollback. Never invert or omit that order. Preserve the
previous configuration and release evidence until the new transaction is fully
accepted. Read [shared Caddy v1](shared-caddy-v1/contract.md) for the fixed
normal interface and durable phase rules.

All three lock classes use the persistent, root-owned
`/var/lib/deploydesk/locks` tree. Never place identity-pinned release coordination
under volatile `/var/lock` or `/run/lock` state.

Host bootstrap, helper/contract installation or recovery, and project lock
provisioning are separate maintenance authorities. A helper install requires a
completed bootstrap attestation, changes only the helper/contract pair under a
durable maintenance transaction, and cannot create application state. Any
application or helper-maintenance transaction/recovery marker blocks new normal
release mutation until the exact retained evidence is resolved.

## Failure boundary

Before downtime or migration begins, restore configuration safely and record
the failed attempt. After writers stop or a migration may have begun, write a
`recovery-required` state atomically, preserve backup and rollback material,
block the next release, and assign recovery review. Never guess at, automate,
or imply a database rollback from an image rollback.

After recovery, clear neither the blocker nor the historical record by
assumption. Complete the configured recovery review, produce a new readiness
result, and obtain new approval before any retry, even when the candidate's
digest map is unchanged.

## Atomic records and retention

Update current, previous, and append-only history records atomically. A failed
record update means the release is not complete. Preserve every digest
referenced by current staging, current production, or any retained candidate.
Registry retention does not replace a tested, off-host database backup.

## Diagnosis order

Diagnose one boundary at a time:

```text
Git sync → CNB rule → verify → image build → registry push → TAT/host
→ runtime health → proxy/DNS/TLS → HTTP behavior
```

Do not rebuild an image to repair a later boundary unless a reproduced image
defect actually requires a new commit and a new candidate.
