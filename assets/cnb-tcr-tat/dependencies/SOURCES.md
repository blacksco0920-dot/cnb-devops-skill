# CI extraction sources and limits

This record describes historical code provenance and licensing, not runtime prerequisites or current acceptance. Consult the bundle manifest for fixed-version validation; source history alone does not validate a new bundle revision. The original source project is `ecat-energy`, Git commit `f52eb1ddf928729b3a4db23d8b0de9211984c4d9`. Read source files with the immutable Git object, not its current working tree.

The source root has no LICENSE or NOTICE at that commit, and its package.json has `private: true`. These are historical source facts, not the current authorization status.

## Owner authorization (2026-09-11)

During preparation of this Skill's public preview, the owner of the source projects confirmed that they hold the right to authorize public redistribution of the deployment scripts extracted from `ecat-energy` and `FinAgent`, and authorized their inclusion in this Skill under its [MIT license](../../../LICENSE). This owner confirmation resolves the previously recorded unverified redistribution status for the source-derived files listed below, including the production adaptations.

The authorization covers the extracted deployment code in this Skill. It does not publish the full source applications, their configuration, credentials or data, and it does not change third-party dependency licenses. Preserve the provenance below and the separate [dependency notices](THIRD_PARTY.md). Authorization is based on the owner's express confirmation, not on repository access or successful deployment tests.

## CI source files

| Extracted file | Source path at pinned commit | Source SHA-256 |
| --- | --- | --- |
| `ci/release-request.mjs` | `deploy/scripts/release-request.mjs` | `32d8df0b3099517492d49e773c58b09df89bea450992de25e7d0670d777cf352` |
| `ci/release-identity.mjs` | `deploy/scripts/release-identity.mjs` | `81c0faf0e6402c8b35b87705d508b91d547a4b827de83217bd44e51b5f7e1d02` |
| `ci/run-tat-release.mjs` | `deploy/scripts/run-tat-release.mjs` | `dc45c718ec48a4b694fc2975293c73a95df28e7e8472851e4ab19fb6d27530e8` |
| `ci/candidate_manifest.py` | `deploy/scripts/candidate_manifest.py` | `a40dce8d15a9d018614f58e2bb390add0ca949535f836077cbeb8c937bc22a5f` |
| `ci/candidate_gate.py` | `deploy/scripts/candidate_gate.py` | `10333e38e3aad35a3c2dad66bbbe5853ea784e6aae85cd2b2b8daf1c747913e2` |
| `ci/publish-candidate-tag.sh` | `deploy/scripts/publish-candidate-tag.sh` | `f4ea00d9aafbcc26d3b4afc34b81553a96bfd7897d4bc60ba2bf4d32c0fae3e2` |
| `ci/extract-docker-push-digest.sh` | `scripts/extract-docker-push-digest.sh` | `369ef30856bc3832cb9705ccb25f5ff36984760aed6363cfbd0d7037a006c5e2` |
| `templates/github-sync.yml.tmpl` | `.github/workflows/sync-cnb.yml` | `f435cd0e9914ec720650633ad3841f9bf72951cd2b09f00671e3b52c2fe6603f` |

Preserved safeguards: exact release keys, immutable image digests, same-commit application/controller identity, bounded requests, exact Saved Command readback, exact invocation/target/parameters, read-only polling retries, no Invoke retry, create-only annotated Tags, byte-for-byte Tag payload readback, strict canonical candidate manifests and ready-last state checks. The request cap is deliberately raised from 4 KiB to 16 KiB to support the declared maximum of 16 services; it is still checked before Invoke and by the host decoder.

Generalized inputs: project, test environment, service/image/probe sets and CNB repository/prefix come from generated CI configuration. Target, Saved Command ID/content hash and controller/Compose/policy hashes come from the protected binding. No target, path or shell text is accepted in the release payload. `release-identity.mjs` keeps the original four identity fields under `cnb-release-identity/v1`; each configured service must expose this identity (or the configured API envelope) through its reviewed public probe.

Newly exercised behavior: terminal TAT SUCCESS is followed by exact invocation-task readback and a strict result receipt check. The task CommandDocument must equal the protected template after its single permitted parameter substitution, including command type, user, directory, timeout and empty COS output destinations. The SDK's real `Filters: invocation-id`, base64 `TaskResult.Output`, `Dropped: 0`, exit code and metadata are checked. A candidate binds the exact verified receipt SHA-256. Only deterministic prefixes of non-ready annotations may resume; ready requires all fields. At extraction time, preview.2 cloud evidence covered only test deployment and candidate publication. The subsequent production adapter requires explicit production configuration, root-installed authority and an administrator signature. Later production and recovery evidence is recorded separately in the bundle manifest against its exact accepted artifacts; staging evidence alone does not establish that acceptance.

Runtime: Node.js 22, Python 3.10+ standard library, Bash, Git, Docker for the generated build/host stages. `package.json` pins `tencentcloud-sdk-nodejs-tat` 4.1.241, the same exact SDK version and SHA-512 integrity as the source lockfile. `package-lock.json` freezes this extraction's complete npm dependency graph; do not substitute an unlocked install. Install with `npm ci --ignore-scripts --prefix deploy/vendor/cnb-devops/dependencies`. No business framework dependency is required by this CI code.

The SDK API shape and installed licenses were inspected locally from that pinned npm package. The SDK ships Apache-2.0. The lock graph also includes MIT, ISC, BSD-2-Clause and 0BSD packages. See THIRD_PARTY.md and the installed packages' own notices; the lockfile is the version/integrity authority. No node_modules directory is distributed.

Optional GitHub synchronization uses the source workflow with only the two managed branches and CNB repository replaced by generator tokens. It checks the checked-out SHA, rejects unowned refs, disables checkout credential persistence, scopes the CNB push token to ASKPASS with cleanup and pushes the matching branch without force. The source workflow retains `actions/checkout@v4` and `ubuntu-latest`; this extraction does not claim those moving workflow dependencies are immutable.

## Production source adaptation (2026-09-07)

The following local FinAgent source copies informed the bounded production adapter. Directory labels are provenance hints, **not verified Git commit identities**: `c66c488` did not resolve in the inspected Git object database, and the older controller copy has not been byte-matched to that deployment. The owner authorization above covers these source adaptations; it does not resolve their historical commit-identity limitations.

| Local source copy | SHA-256 | Reused behavior |
| --- | --- | --- |
| `trusted-production-c66c488/admin/sign-production-record.mjs` | `a7ca885631f21a62198873511620935551f8903e54489b09fa5797a682591d62` | Local Ed25519 signing after independent readiness readback; private key ownership/mode checks and create-only output |
| `trusted-production-c66c488/scripts/strict-json.mjs` | `edc1f147ba4f9fb07a8d2f848e7360a1751563394e5d2c60af31125cf1fe7afe` | Exact copied duplicate-key and bounded JSON scanner |
| `trusted-production-c66c488/scripts/run-production-deploy.mjs` | `bfbb1b85226cf171b58f1afd8b23079da3f7e9ec5f7286a8a5ce875a639aa4a8` | Executed-command and readiness/result identity attestation |
| `production-controller-bootstrap-9c1c71d/production-controller.py` | `4c8fd21e5292cf6e2d07b7c8c9bfaa126a52b0486c6dde23209b149d1d5b5b39` | OpenSSL verification, prepared-state fingerprint, bounded approval lifetime and replay audit |

New contracts use `cnb-production-approval-v1` plus a NUL signature domain and canonical sorted JSON with one LF. Candidate `manifest_sha256` keeps its existing unsigned/no-LF meaning; `candidate_bytes_sha256` separately binds the entire canonical Tag manifest. Approval binds candidate digests, prepared state, previous release and installed production authority. Public signed envelopes travel through the same repository's annotations; annotation presence cannot authorize signing. The fixed production entry invokes the existing transaction core under its release lock and records pending approval before mutation. A successful-core/audit interruption can reconcile only against the actual matching release record and managed backup; failed/pending releases remain blocked. No host Git credential, signing service or CI private key is introduced. Host signature verification additionally requires the installed `/usr/bin/openssl` Ed25519 implementation; Node and npm dependencies are unchanged.
