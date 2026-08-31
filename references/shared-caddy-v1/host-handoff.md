# Shared Caddy v1 Host Handoff

This handoff belongs to a host infrastructure administrator. It is separate
from application release approval and must be completed independently for each
server.

## Inputs

- Approved helper file, its independent SHA-256, helper version, and contract
  version.
- Fixed release identity and group, Caddy container identity, host/container
  config mount, local-filesystem semantics, and the complete live Caddy config.
- Every live hostname, route behavior, owning deployment, project,
  environment, normalized source repository, and smoke check.
- Confirmed maintenance window and proof that every old Caddy writer is
  stopped. Taking the new lock does not stop an old writer that does not know
  that lock.

Never put credentials, customer instance identifiers, private addresses, or
complete environment files in this handoff.

## Bootstrap and baseline maintenance

Run `--maintenance-action bootstrap-host` only on a host whose complete live
configuration and old writers are controlled by this maintenance window. It
creates the fixed layout, canonical root/server-options files, shared lock and
lock manifest, immutable empty initial generation, `managed/current`, and a
hash- and inode-bound bootstrap attestation. It must not install a helper or
provision a project. Keep its fsynced attestation as the authority prerequisite
for the later, separate actions below.

1. Stop old writers and confirm no active release transaction.
2. Under the root-owned shared lock, re-read and hash the live root config.
3. Account for every normalized live host. Refuse duplicate or unowned hosts.
4. Create one manifest per owner. A route not yet expressible by v1 may be
   `legacy_opaque` only after conflict review and byte-hash binding.
5. Create the initial generation without changing route bytes. Validate the
   complete candidate configuration.
6. Use a durable baseline transaction to switch the root config and `current`,
   reload, and smoke every live host. Preserve the old root config and prior
   generation through the observation window.
7. If any switch/reload/smoke or recovery step fails, restore the old root and
   generation; write the recovery marker when restoration cannot be proven.

Do not let an application release perform baseline import, assign an unowned
host, or replace a legacy manifest.

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
release lock files once and never deletes or replaces their inodes. The release
lock is root-owned and group-readable so the release identity can open it
read-only and hold `flock`; it is not group-writable.
After the lock manifest is durable, provisioning opens each project controller
directory with `O_NOFOLLOW`, hands that exact directory FD to the fixed release
UID/GID as private mode `0700`, and verifies the final entry and FD identity.
An interrupted root-owned controller handoff is retryable; an unexpected owner,
group, mode, inode, link, or device remains a hard failure.
An ordinary helper upgrade must preserve both the recorded Caddy container
identity and container config-root mount. Changing either is a separate,
explicitly reviewed runtime/baseline maintenance action. Before helper upgrade
or provisioning, compare every existing lock inode against `lock-inodes.json`;
never regenerate evidence around a replacement inode.

All actions retain trusted directory descriptors throughout the operation,
reattest parent entry identity before descriptor-relative reads and mutations,
and reject symlinks, hardlinks, group/world-writable ancestors, replacements,
and device crossings. The one explicit compatibility case is the OS-owned
`/var/lock` alias to root-owned `/run/lock`; the resolved target becomes the
device anchor for controlled descendants.

Validate the sudoers example with `visudo`. The regex permits exactly the two
normal-release arguments; avoid wildcard argument rules that also match spaces
and appended options. The release identity must not write the helper, server
contract, shared tree, state, locks, root config, or certificate storage.

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
- bootstrap root/server-options hashes and shared-lock device/inode;
- helper-maintenance transaction/marker absence and recovered phase, if any;
- root config, server options, generation, manifest, and legacy hashes;
- fixed lock inode/device identities and verified owner/mode;
- old-writer stop evidence and complete host inventory;
- validate, reload, and per-host smoke results;
- current/previous generation and recovery-marker absence;
- administrator, maintenance window, and rollback owner.

Normal application releases remain blocked until this record is accepted.
