# Test host controller

`tat-deploy-test.py` extracts the snapshot, retention, request validation and transactional apply code from the pinned source `deploy/scripts/tat-deploy-test.py` at `f52eb1ddf928729b3a4db23d8b0de9211984c4d9`. The original snapshot descriptor checks, bounded dump validation, atomic publication, race detection, retention authority and migration failure markers remain in this controller. The source tests were ported into `tests/test_bundle_host_transactions.py`; their Docker and PostgreSQL boundaries are simulated.

Project-specific services, image repositories, paths, database identity, networks, environment mapping, health checks, migration argv and public probes come from the generated `host-policy.json`. Normal invocation reads this file only beside its installed controller, through root-owned non-writable ancestors. It accepts no policy path or environment override. A root-installed Compose file is bound by its exact SHA-256. No ordinary release changes proxy routes or shared infrastructure.

The TAT shim is rendered by `render_tat_template(policy, controller_sha256, policy_sha256)`. `tat-command.sh.tmpl` is its reviewable template; a test checks exact agreement with the embedded runtime constant. The command substitutes only `{{release_request_b64url}}`. The controller requires that exact shim, canonical JSON, the configured project/environment/controller, equal full application/controller commits, and every configured image as its exact repository plus digest. It reports the exact image map and sorted probe URLs only after runtime and public identity verification pass.

## Administrator installation

Generate a project bundle first. Review its artifact lock and the generated policy and Compose definitions. Transfer private runtime values through the administrator's existing protected channel. This installer has no cloud credential transport and prints no environment values.

```sh
python3 deploy/vendor/cnb-devops/host/install-project.py \
  --bundle-dir deploy/vendor/cnb-devops \
  --runtime-env /protected/project-test.env \
  --lock-sha256 REVIEWED_ARTIFACT_LOCK_SHA256
```

The default is an offline preview, which verifies the package and never reads the runtime environment file. On the authorized host, root adds `--apply`. An explicitly reviewed artifact-lock digest anchors a transfer directory; without that option, apply requires a root-owned non-writable local artifact-lock hierarchy. The loader executes captured verified controller bytes, never a re-opened transfer-path program.

Prerequisites must already exist: Ubuntu 24.04, Python 3.12 or later, Docker and Compose v2, curl, the non-root release account with Docker access, its private TCR pull credential file, external Docker networks, and the exact scoped PostgreSQL database and role. PostgreSQL server and dump/restore client major versions must agree. The database container's local administrator connection must work. The installed application needs its declared public routes and every service identity endpoint before release verification can pass. Optional Redis/proxy dependencies are validated by ordinary preflight when declared. This installer does not fetch dependencies, create databases, establish routes or enable production.

The private input contains runtime keys, not image identities. The installer derives `uninitialized` image slots from the generated service list. It proves the pre-existing database has no user schemas, relations, functions or types; it then installs a root-owned `empty-baseline.json` and identical private initial release record. This explicitly records an empty prior runtime (`images: {}`), not a fabricated prior deployment. Ordinary first apply independently verifies the baseline binding, initial environment hash and database emptiness. It runs the inherited PostgreSQL dump and archive-list validation, writes a filesystem snapshot, and preserves the baseline byte hash in the release transaction. Dump validation is not an isolated PostgreSQL restore rehearsal.

Before creating installation paths or authority, the installer rejects any running or stopped container with an exact configured application name. A nonempty application directory requires the exact root-owned empty baseline and immutable controller files from an interrupted install; its contents must consist only of matching expected files and declared empty mount directories. Unknown application files remain untouched even when PostgreSQL is empty.

The installation receipt is written last. An interrupted install can resume only matching files; different content, unsafe metadata or an existing application release blocks overwriting. Repeating a complete install verifies its fixed files and preserves active runtime environment and release records without re-running an empty-database check. A different controller version requires a separately reviewed installation path and adoption/upgrade work; this slice does not activate upgrades for existing applications.

After migration may have started, any failure retains the transaction and blocks another ordinary apply. No database rollback is inferred. A production adapter, existing-runtime baseline import and independent recovery/restore execution remain separate work.

For a test `failed/probe` transaction with healthy exact containers and completed unchanged Prisma migrations, `upgrade-controller.py` provides a separately reviewed fixed-program upgrade; `repair-test-release.py` grants a short-lived exact repair after failed-source export and an actual isolated restore. The explicit repair request cannot fall back to an ordinary release. It preserves the parent transaction and snapshots, skips the completed migration command, and still requires all runtime and public probes. Use the Skill's `references/failed-test-repair.md` and fixed local entry points; do not invoke the first installer to bypass a live failure.

For a new Ubuntu 24.04 host, `bootstrap-host.py` provides the bounded PostgreSQL 16 and optional dedicated Redis 7 preset. After project installation, `configure-native-caddy.py` can add the policy's HTTPS domains to an inventoried native Caddy service with no existing imports or environment substitution. Both default to preview and require explicit reviewed hashes for apply. The Caddy helper preserves the original configuration, checks active-config drift and conflicts, validates before writing, and restores its changes if reload fails. These are administrator setup tools; routine TAT releases never call them. See the skill's `references/bootstrap.md` for the setup sequence.

Local verification covers actual filesystem writes, snapshot/retention races, policy/request failures and simulated installer resumption. Root ownership, Docker, PostgreSQL operations and public endpoints are simulated in these tests. No clean-host installation, real database backup/restore or cloud deployment is claimed by that coverage.
