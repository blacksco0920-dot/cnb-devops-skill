# Shared Caddy Contract v1

Use this contract when independent projects share one host-level Caddy and an
application release needs to add or update only its own routes.

## Authority boundary

Normal application release authority is one exact interface:

```text
/usr/local/sbin/deploydesk-caddy-apply --deployment-id <project--environment> --bundle-id <64-lowercase-hex>
```

It accepts no path, command, container, hostname, or configuration argument.
The caller holds the pre-created application release lock before invocation.
The helper independently opens and locks the pre-created root-owned project
Caddy lock, then the pre-created root-owned shared Caddy lock. This order is
mandatory: application release lock (caller) → project Caddy lock (helper) →
shared Caddy lock (helper). The helper never acquires the application lock and
never acquires the shared lock first.

Host bootstrap, helper/server-contract installation or recovery, project lock
provisioning, baseline import, hostname deletion/transfer, and legacy takeover
are distinct, separately approved host-maintenance actions. `install-helper`
requires a completed bootstrap attestation and can replace only the helper and
contract pair. The installer never imports or executes the candidate helper;
it installs only the exact stable-read bytes matching the independently
approved SHA-256. It cannot create deployments or mutate the root Caddyfile,
server options, bootstrap attestation, generations, or `managed/current`.
Normal release bundles cannot perform any of these maintenance actions.

## Bundle preflight before live mutation

The release identity must not read a root-owned generation or relax its
`root:root 0500` permissions. Instead it holds its already-provisioned release
lock and invokes the same fixed root helper with the verified bundle identity:

```text
/usr/local/sbin/deploydesk-caddy-apply --preflight --deployment-id <project--environment> --bundle-id <64-lowercase-hex>
```

Preflight is root-only, bundle-aware, and non-live. It attests the installed
helper, contract, and pinned lock identities; snapshots the verified bundle in
root-private intake; then takes the project Caddy lock followed by the shared
Caddy lock. Under those locks it verifies every existing manifest and global
hostname ownership, including the incoming hostname set. A conflict, identity
change, malformed generation, retained recovery state, or invalid candidate
fails before live mutation. Its private intake and candidate-validation files
are removed; it does not write a generation, pointer, receipt, history entry,
or recovery marker.

The controller uses this complete order for each release:

```text
non-root project/env/evidence checks
  -> immutable bundle publication
  -> exact sudo bundle preflight
  -> pull/backup/migrate/up
  -> exact sudo apply
  -> semantic probes
  -> immutable evidence
```

`pull/backup/migrate/up` belongs to the application controller, not to the
shared-Caddy helper. Do not wait for normal apply to discover incoming hostname
conflicts after a migration, and do not invent a third privileged artifact or
wrapper. The only privileged boundaries are the exact preflight and exact apply
rules for that deployment; apply repeats attestation and ownership checks under
the same lock order immediately before its Caddy mutation.

## Fixed server layout

The v1 reference implementation derives inputs and outputs from these trusted
anchors; a host-specific bootstrap may record a different mount view for the
Caddy container, but projects never choose it:

```text
/opt/infra/caddy/Caddyfile
/opt/infra/caddy/server-options.caddy
/opt/infra/caddy/contract.json
/opt/infra/caddy/bootstrap-attestation.json
/opt/infra/caddy/managed/current -> generations/<generation-id>
/opt/infra/caddy/managed/generations/<generation-id>/{sites,manifests}/
/var/lib/deploydesk/bundles/<deployment-id>/<bundle-id>/
/var/lib/deploydesk/caddy/{history.jsonl,transaction.json,receipts,intake}/
/var/lib/deploydesk/caddy/lock-inodes.json
/var/lib/deploydesk/caddy/maintenance/
/var/lib/deploydesk/caddy/{maintenance-transaction.json,maintenance-recovery-required}
/var/lib/deploydesk/locks/releases/<deployment-id>.release.lock
/var/lib/deploydesk/locks/projects/<deployment-id>.caddy.lock
/var/lib/deploydesk/locks/shared-caddy.lock
```

All trusted anchors, lock files, state, completed generations, the helper, and
the server contract are root-owned and not writable by a release identity.
Every trusted component is checked with `lstat`; unexpected symlinks,
hardlinks, writable parents, owner drift, mount crossing, and replaced lock
identities fail closed. The root-owned lock manifest pins exact
`device`/`inode`/`ctime_ns` identities for the shared, project, and release
locks across invocations; the nanosecond change time distinguishes an
unlink/create replacement even when Linux immediately reuses the same inode.
Ordinary open and `flock` do not change this evidence. Provisioning records a
release lock only after its approved ownership/mode handoff; any later
`chmod`/`chown`, disappearance, or replacement is drift. Maintenance may only
append a genuinely new, explicitly provisioned deployment. All three lock
classes live under the persistent, root-owned
`/var/lib/deploydesk/locks` tree on the same trusted local filesystem as the
other `/var/lib/deploydesk` state. `/var/lock` and `/run/lock` are deliberately
not used: on common Ubuntu hosts they resolve to volatile tmpfs state, so their
inodes do not survive reboot. No lock-path symlink is accepted.
`managed/current`
is the sole expected symlink and may name
only a real child of `managed/generations`.

## Bundle intake and attestation

The bundle directory is derived from the two validated IDs. The helper opens
the fixed raw archive and external server manifest beneath that anchor using component-by-component dirfd
opens with `O_NOFOLLOW`, verifies one regular link and one filesystem, copies
from those already-open file descriptors into a root-owned `0700` intake,
fsyncs it, and re-hashes the snapshot. The raw archive SHA-256 must equal the
bundle ID. Only five allowlisted, single regular tar members are extracted into
intake; duplicates, links, special files, PAX overrides, extra paths, and size
overflow are rejected. The members are `caddy/declaration.json`,
`caddy/site.caddy`, `caddy/helper-requirement.json`,
`caddy/bundle-provenance.json`, and `runtime/compose.json`. V1 accepts exactly
these five members, at most 8 MiB per compressed archive, at most 8 MiB per
member, and 16 MiB uncompressed in aggregate. Producers must satisfy all three
limits; a gzip expansion beyond the bounded input stream is rejected before
publication. Extraction uses immutable bytes
read once from the pinned no-follow archive descriptor: a first pass consumes
and validates every header, member byte, and canonical clean EOF without
writing; a second pass rechecks the same bytes, writes only to a private staging
tree, fsyncs it, and publishes controlled directories only after the complete
pass matches. Any validation, second-pass, staging, or publication failure
removes all extraction output. It compares pre/post inode, size,
mtime, and ctime so replacement, truncation, or rewrite fails. Validation and
apply use only the intake snapshot.

This is the portable trust assumption: the host kernel must provide dirfd
relative `open`, `O_DIRECTORY`, `O_NOFOLLOW`, stable inode metadata, atomic
rename/symlink replacement, `flock`, and file/directory `fsync` on one local
filesystem. The production helper exits before mutation when those primitives
are unavailable, and the host-maintenance installer enforces the same gate
before reading a candidate or opening a trusted root. Filesystems that do not
honor those semantics are unsupported until a platform-specific
`openat2`/equivalent adapter is reviewed.

`contract.json`, the actual helper file SHA-256, and the bundle's
`helper-requirement.json` must agree on contract version, helper version, and
helper hash. A normal bundle can require a helper but cannot upgrade it.

The internal `bundle-provenance.json` binds project, environment, deployment,
normalized credential-free source repository, Git SHA, declaration, rendered
fragment, Compose facts, helper requirement, and helper hash to the raw archive.
The separately delivered external server manifest repeats the load-bearing
identity and artifact hashes and adds the raw archive SHA-256. The helper first
proves every internal artifact hash from the pinned archive bytes, then requires
exact agreement for every overlapping internal/external field. Those values are
copied without omission into the generation manifest, durable transaction, and
receipt; changing Git/source/helper/provenance evidence while reusing an archive
ID is rejected.

## Declaration and route reconciliation

The [declaration schema](schemas/declaration.schema.json) fixes identity,
credential-free normalized source repository, Compose facts path, and routes.
Hosts are lower-case, trailing-dot-free IDNA ASCII and globally exclusive per
server. Wildcards, catch-alls, bare listeners, path sharing, and undeclared
hosts are forbidden.

The only route kinds are:

- `docker_proxy`: service, container DNS name, internal port, and declared
  shared network must exist in the snapshotted Compose JSON facts, and the
  service must carry the exact deployment-ownership label; under the shared
  lock the helper verifies the live container carries the same label and
  connects/rechecks Caddy on that network;
- `https_proxy`: target host is owned by the same deployment; Host and TLS SNI
  are derived from that host;
- `redirect`: target host is owned by the same deployment, URI is preserved,
  and the status is permanent.

The helper renders the one canonical v1 fragment from the declaration and
requires byte equality. Proxy blocks always use `encode zstd gzip`. Arbitrary
headers, `handle`, `route`, `respond`, `file_server`, `import`, global options,
binds, scripts, and other directives cannot pass reconciliation.

## Ownership and generations

Every generation has one fragment and one strict server manifest per managed
deployment. Before switching, the helper validates every manifest and rejects
duplicate normalized hosts. It may replace only the invoked deployment. A
manifest marked `legacy_opaque` is preserved byte-for-byte and hash-bound;
normal release cannot update or claim it. `baseline_import` takeover and any
change to project, environment, deployment, repository, or host ownership need
the separate maintenance handoff.

Even when canonical route bytes are unchanged, a release creates a new
generation and manifest with new Git/bundle provenance, then validates,
reloads, smokes, and issues a new receipt. An old receipt cannot evidence a
new candidate.

The helper smoke is a generic, non-redirecting `HEAD /` reachability check:
any original HTTP status below 500 is accepted, while the application release
controller must validate its exact public paths and application-specific health
evidence outside the helper before accepting the release.

## Durable transaction and recovery

Under the shared lock the helper first resolves any retained transaction, then:

1. copies the full current generation and changes only the invoking project;
2. validates the full staged tree, freezes it read-only, fsyncs each file again
   after metadata changes, then fsyncs `sites`, `manifests`, the generation,
   and the generations parent;
3. only then fsyncs `prepared`, atomically switches `current`, then fsyncs
   `current-switched`;
4. reloads and records `reloaded`, smokes all changed hosts and records
   `verified`, then records `committed`;
5. writes the receipt and history idempotently by transaction ID and removes
   the live transaction.

Recovery compares phase with the actual `current` target. `prepared` with the
old target discards staging. A switched, reloaded, or verified transaction
returns to the old generation and reloads/smokes it. A committed interruption
retains the intake archive and external manifest, reparses the raw archive,
requires every retained extracted member to match it, revalidates the full
internal/external provenance chain and transaction, proves the immutable
generation manifest and fragment, rechecks the current pointer, live Docker
ownership/network facts, validates/reloads the full tree, and smokes the
committed hosts before filling receipt/history once. Evidence, generation,
runtime, controller-helper, or pointer drift creates `caddy-recovery-required`
and blocks all normal releases for administrator repair. An unknown pointer,
failed rollback, failed second reload, failed smoke, malformed transaction, or
inconsistent receipt does the same.

Network attachment occurs only after `prepared`, before the pointer switch.
After live inspection proves Caddy was absent, the transaction durably records
a write-ahead attachment intent with `pre_transaction_state: absent` before it
invokes Docker connect. If the intent write fails, Docker is not called. A
crash before connect leaves an intent whose recovery inspection finds no live
membership; a crash after connect leaves the same durable ownership evidence,
so recovery can detach it. Rollback restores the old pointer, idempotently
disconnects only live networks covered by this transaction's intents, and then
reloads/smokes the old generation. An interrupted rollback resumes when it sees
either the old or new pointer. A network already attached during initial
inspection creates no intent and is never detached, so retained routes keep
their connectivity.

## Host-maintenance transaction

`bootstrap-host` is the only action that creates the fixed directory layout,
canonical root Caddyfile and server options, lock manifest and shared lock,
immutable initial generation and `managed/current`, and the bootstrap
attestation. It fsyncs every created file, directory, and published pointer
before recording completion. `provision-deployment` appends only explicitly
approved project/release lock identities after bootstrap and helper attestation.

`install-helper` refuses an unbootstrapped host, any application Caddy
transaction or recovery marker, and any retained helper-maintenance transaction
or marker before mutation. Under the pinned shared lock it stages and hashes
the new helper/contract pair and durably records `staged`, `helper-installed`,
`contract-installed`, then `committed`. Recovery restores the retained old pair
from `staged` or completes the already-started new pair from later phases;
malformed or irreconcilable evidence writes
`maintenance-recovery-required`. The installer retains trusted directory
descriptors for the whole action and reattests ancestor entry identity before
descriptor-relative reads, writes, renames, owner/mode changes, and fsyncs. It
rejects group/world-writable ancestors, links, replacements, and device
crossings. The persistent `/var/lib/deploydesk/locks` tree follows the same
no-symlink and single-local-filesystem rules as all other trusted state.
The helper and server contract are fixed at modes `0755` and `0644`. An
ordinary v1 helper upgrade may replace their approved bytes and hash only at
the same schema-fixed `helper_version`; changing that version is a separate
contract/schema migration.

Schemas for persisted evidence are [internal provenance](schemas/internal-provenance.schema.json),
[server manifest](schemas/server-manifest.schema.json),
[transaction](schemas/transaction.schema.json), and [receipt](schemas/receipt.schema.json).
The reference scripts are illustrative, fail-closed building blocks; review
the runtime adapter and filesystem semantics for each target OS before host
installation.
