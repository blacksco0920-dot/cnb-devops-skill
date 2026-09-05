# Shared Caddy v1 Host Handoff

This handoff belongs to a host infrastructure administrator. It is separate
from application release approval and must be completed independently for each
server.

## Inventory, snapshot, and credential gates

The administrator hands over durable records, not a newly invented command
list. Before root bootstrap, helper maintenance, baseline import/recovery,
provisioning, or a live application release, accept all of these non-secret
deliverables:

- A read-only, deterministic, stable/canonical route inventory: active Caddy
  writer/configuration and each hostname's compatibility owner; all containers,
  named and anonymous volumes, bind sources, published listeners, and the
  current/required proxy behavior. Group capacity and inodes by `st_dev` and
  count each device once. No ad-hoc or mutating discovery substitutes before
  external recovery proof. An opaque fragment remains `legacy_opaque`,
  byte/hash-bound, and unmerged.
- An external snapshot receipt: independent storage boundary, covered Caddy
  state/certificates and persistent application data, integrity/restore
  verification, retention, and recovery owner. It records no snapshot ID,
  address, credential, or payload. A same-host copy is insufficient.
- A credential-rotation receipt for every credential exposed to the takeover or
  new release: name/class, storage boundary, owner, rotation completion/date,
  expiry, and validation result—never its value.

These are hard gates. Do not use `docker volume rm`, any volume prune, or bind
source deletion to create capacity. Compatibility ownership is separate from a
new project's declaration, and neither baseline authority nor these gates may
be delegated through an application release or its sudoers entry. A
compatibility baseline owns only its normalized source hostname(s); upstream or
target names are traffic destinations and never host ownership or declaration
authority.

## Inputs

- Approved helper file, its independent SHA-256, helper version, and contract
  version.
- Fixed release identity and group, Caddy container identity, host/container
  config mount, persistent `/var/lib/deploydesk/locks` local-filesystem
  semantics with stable nanosecond ctime, and the complete live Caddy config.
- Every live hostname, route behavior, owning deployment, project,
  environment, normalized source repository, and smoke check.
- Confirmed maintenance window and proof that every old Caddy writer is
  stopped. Taking the new lock does not stop an old writer that does not know
  that lock.

Never put credentials, customer instance identifiers, private addresses, or
complete environment files in this handoff.

## Bootstrap

Run `--maintenance-action bootstrap-host` only on a host whose complete live
configuration and old writers are controlled by this maintenance window. It
creates the fixed layout, canonical root/server-options files, shared lock and
lock manifest, immutable empty initial generation, `managed/current`, and a
hash- and lock-identity-bound bootstrap attestation. Bootstrap stops there: it
must not install a helper, import a baseline, assign a hostname, provision a
project, or reload the live Caddy service. Keep its fsynced attestation as the
authority prerequisite for the later, separate actions below.

## Baseline import and recovery

After the accepted gates and bootstrap attestation, separately install and
attest the helper pair before baseline import. Bootstrapping alone never
authorizes import. Only then may the root host administrator choose one of
these two baseline maintenance CLI surfaces:

```text
install-shared-caddy-helper --maintenance-action import-baseline --baseline-bundle-id <64-lowercase-hex>
install-shared-caddy-helper --maintenance-action recover-baseline-maintenance
```

`import-baseline` requires exactly one `--baseline-bundle-id`; recovery accepts
no bundle ID or other mutation argument. The archive ID selects this fixed,
input hierarchy. Every directory from
`/var/lib/deploydesk/caddy/maintenance/baseline-input` through the archive ID
is root-owned and mode-`0700`; it contains exactly these root-owned, regular, single-link,
mode-`0600` files:

```text
/var/lib/deploydesk/caddy/maintenance/baseline-input/<64-lowercase-hex>/
  deploy-bundle.tar.gz
  server-manifest.json
```

The archive SHA-256 must equal the ID and the manifest is canonical.
This hierarchy is separately approved baseline/control material: a CNB ordinary
release cannot supply or alter its project identity, source, hosts, routes, or
target topology.
`import-baseline` accepts only its exact action plus that bundle ID;
`recover-baseline-maintenance` accepts only its exact action. Both reject
caller paths, hosts, containers, smoke/source arguments, extra arguments, and
crossed arguments. These actions are not normal release sudo interfaces. The
root order is fixed, not a menu:

```text
bootstrap-host → install-helper → import-baseline or recover-baseline-maintenance → provision-deployment
```

Baseline import maps every inventoried live host to a compatibility owner,
keeps unexpressible content `legacy_opaque` and byte/hash-bound, validates the
complete candidate, then durably switches/reloads/smokes every live host while
retaining the old root config and generation for observation. A retained
baseline transaction is recovered only by the second action and only with a
marker bound to that exact baseline transaction and archive identity. The
marker remains blocking throughout recovery; remove it only after the terminal
committed receipt or a proven restored empty initial generation. Ambiguous
evidence blocks provisioning and ordinary release.

## Helper installation or upgrade

Run `--maintenance-action install-helper` only in a separately approved root
maintenance stage after bootstrap. Pass only the approved helper hash; do not
accept a caller-selected destination, deployment, UID/GID, or runtime identity.
The installer is self-contained: it never imports or executes the candidate
helper. It opens the sibling file without following symlinks, stable-reads and
hashes its bytes, and installs those exact bytes only after the independent hash
matches.
Within this v1 package, “upgrade” means replacing the approved helper bytes and
hash while keeping the fixed `helper_version`. Changing `helper_version` or its
schemas is a separately designed contract migration, not this ordinary action.
The action validates the fixed paths and bootstrap attestation, then changes
only the helper and `contract.json` as a durable pair. It refuses application
transactions/recovery markers and helper-maintenance transactions/recovery
markers before mutation. It cannot modify the root Caddyfile, server options,
bootstrap attestation, generation tree, `managed/current`, or project locks.
The installed helper and contract use exact modes `0755` and `0644`; drift is
rejected before a new maintenance transaction is staged.

The maintenance transaction durably records `staged`, `helper-installed`,
`contract-installed`, and `committed` while retaining both the old and new
pairs. After a crash, invoke only
`--maintenance-action recover-helper-maintenance`: staged recovery restores the
old pair, while any later valid phase completes the new pair. Malformed or
irreconcilable evidence leaves `maintenance-recovery-required` and blocks
all release/provision/install actions for administrator repair.

Run `--maintenance-action provision-deployment` separately with the complete
approved deployment list and fixed release UID/GID. It creates project and
release lock files once under `/var/lib/deploydesk/locks/{projects,releases}`
and never deletes or replaces their inodes. The shared lock is a sibling at
`/var/lib/deploydesk/locks/shared-caddy.lock`. The release lock is root-owned
and group-readable so the release identity can open it read-only and hold
`flock`; it is not group-writable. The complete lock tree is persistent across
reboot and must never be placed under `/var/lock` or `/run/lock`.
Each manifest entry records exact device, inode, and `ctime_ns` after the final
approved ownership/mode handoff. Ordinary open and `flock` leave that identity
unchanged; later `chmod`/`chown` is drift, and `ctime_ns` detects an
unlink/create replacement even when Linux reuses the same inode. After the
lock manifest is durable, provisioning opens each project controller
directory with `O_NOFOLLOW`, hands that exact directory FD to the fixed release
UID/GID as private mode `0700`, and verifies the final entry and FD identity.
An interrupted root-owned controller handoff is retryable; an unexpected owner,
group, mode, device, inode, ctime, or link remains a hard failure.
An ordinary helper upgrade must preserve both the recorded Caddy container
identity and container config-root mount. Changing either is a separate,
explicitly reviewed runtime/baseline maintenance action. Before helper upgrade
or provisioning, compare every existing lock identity against
`lock-inodes.json`; never regenerate evidence around a replacement.

All actions retain trusted directory descriptors throughout the operation,
reattest parent entry identity before descriptor-relative reads and mutations,
and reject symlinks, hardlinks, group/world-writable ancestors, replacements,
and device crossings. The persistent lock tree has no symlink exception and
stays on the trusted `/var/lib/deploydesk` local filesystem.

## Per-deployment sudo boundary

Generate and review one pair of sudoers command aliases for each explicitly
provisioned deployment. It grants the fixed root helper only the exact
bundle-aware preflight and exact apply argument sequences for that deployment;
it does not grant generation read access, a wildcard deployment, appended
arguments, or a third privileged artifact/wrapper. The installer exposes the
pure `render_deployment_sudoers(deployment_id, release_identity, alias)` helper
to generate this text from normalized inputs, but never writes a sudoers file.

Use the [example](examples/deploydesk-caddy-apply.sudoers) as the reviewed
per-deployment form, then validate the installed file with `visudo`. Preflight
must run before `pull/backup/migrate/up`, while the release lock remains held;
apply runs only after that application stage and the controller then performs
semantic probes and records immutable evidence. The root helper reads
root-private generations and checks incoming hostname ownership, so do not
relax `root:root 0500` modes for the release identity.

The release identity must not write the helper, server contract, shared tree,
state, locks, root config, or certificate storage.

After installation, compare the actual helper hash and contract to the
project's value-free helper requirement. Installation is not permission to
deploy the project.

## Ownership maintenance

Deletion, hostname transfer, and first takeover from `baseline_import` or
`legacy_opaque` require a named old owner, new owner, complete normalized host
set, traffic/smoke evidence, rollback owner, and explicit approval. For a
baseline takeover, project ID, environment, deployment ID, source repository,
and full host set must first match exactly. Any change is a transfer, not an
ordinary update.

## Acceptance record

Record only non-secret evidence:

- server contract/helper versions and actual helper hash;
- bootstrap root/server-options hashes and shared-lock device/inode/ctime;
- helper-maintenance transaction/marker absence and recovered phase, if any;
- root config, server options, generation, manifest, and legacy hashes;
- fixed lock device/inode/ctime identities and verified owner/mode;
- old-writer stop evidence and complete host inventory;
- validate, reload, and per-host smoke results;
- current/previous generation and recovery-marker absence;
- administrator, maintenance window, and rollback owner.

Per-host helper smoke is only the generic, non-redirecting `HEAD /` check
(original HTTP status below 500); exact application paths and health semantics
remain outer release acceptance evidence owned by the application controller.

Normal application releases remain blocked until this record is accepted.
