---
name: cnb-devops-skill
description: Use when setting up or operating CNB/cnb.cool build and deployment pipelines, deploying projects through Tencent Cloud TCR and TAT, promoting tested releases to production, verifying backups and recovery, or diagnosing CNB release failures and shared-host deployment issues.
---

# CNB DevOps

Help AI-assisted owners set up and reuse a project's build, test deployment, production release and recovery workflow. Own technical configuration, execution and evidence; give people only the necessary choices, personal account actions and approvals. Each project must be independently configured and verified.

## Start with the current task

- **First setup or another project:** first inspect the project's runtime and data needs. The fixed runtime requires PostgreSQL 16; database-free applications and other databases are not supported by this path. For a mismatch, explain it and save one brief checkpoint in the existing authoritative status document, or create `docs/PROJECT_STATUS.md` if none exists; run useful existing checks within scope, but defer release scaffolding and cloud setup. Do not add a database just to satisfy the bundle. For compatible projects, read the [standard workflow](references/standard-workflow.md), then [bootstrap](references/bootstrap.md); check local generator dependencies before preparing configuration. Use the generator for owned release events, Tag UI and vendor files, never handwrite blocked substitutes or ownership records. Missing external bindings stay pending; ask only for the next necessary human action using [human handoffs](references/human-handoffs.md).
- **Resume or update:** read the project's `docs/DEPLOYMENT.md` and its existing authoritative status document (for example, `PROJECT_STATE.md` or `docs/PROJECT_STATUS.md`), then the indexed session state and current stage's receipts. See [project adoption](references/project-adoption.md) for discovery and state format. Reuse accepted steps while their scope and evidence remain valid; do independent local preparation while CI runs.
- **Production or recovery:** use [bootstrap inputs](references/bootstrap-inputs.md) for the fixed `scripts/release-session.mjs` and `scripts/rehearse-recovery.py` entries. They compose the existing candidate, signing and recovery programs; resume their recorded stage instead of writing task-specific wrappers. Read the applicable [release-safety](references/release-safety.md) section for failures, expired evidence or controller upgrades. First-install tools do not upgrade active deployments.
- **Close out a completed release:** use [post-release closeout](references/post-release-closeout.md): `verify-test-deployment.mjs` checks historical test execution against its saved candidate, annotated Tag and TAT evidence; production uses `release-session.mjs verify`. `verify-coexistence.py` checks declared shared-host resources; `reconcile-project-state.py` updates the existing local status index for either environment. Historical execution can be verified after approval expiry; new signing or publishing still requires valid authorization. Resume from the document's managed environment block and private `environments.<env>.current`; report only the declared, verified acceptance scope.
- **Test release failed after migration:** use [failed test repair](references/failed-test-repair.md). The fixed path preserves the failed source, verifies an isolated restore, and reuses one fully checked build through a short-lived repair permit. It supports unchanged Prisma migrations and a healthy runtime whose final public probe failed; other failures remain recovery review.
- **Missing input or human action:** use [human handoffs](references/human-handoffs.md). Populate requirements from generated policies, installers and actual receipts; do not ask people to write commands or technical evidence.
- **CNB-specific issue:** read [deployment UI](references/cnb-deployment-ui.md) for candidates, readiness and approval; [OpenAPI](references/cnb-openapi.md) for API, token and Secret behavior.
- **Another project on existing hosts:** classify ownership using [project adoption](references/project-adoption.md#host-and-account-classification). Same-owner native systemd Caddy with exact Skill-managed imports can use [native shared setup](references/native-caddy-shared.md). Other shared Caddy or opaque routing uses the [contract](references/shared-caddy-v1/contract.md) and [host handoff](references/shared-caddy-v1/host-handoff.md). Preserve inventory, external restore verification, applicable credential review, administrator maintenance and baseline checks before ordinary releases. Application release authority never includes host takeover or direct Caddy mutation.

Files, shell, Git and HTTP/API are the normal execution tools. Check the [local execution environment](references/bootstrap.md#local-execution-environment) before cloud setup; native Windows is not supported by the full local entries. Browser automation is optional. Use existing pipeline stages and bundled scripts for repeated operations; do not recreate their work through interactive AI calls. Historical implementation projects and old conversations are not runtime dependencies.

## Authorization and completion

- Explanation and inspection are read-only. Configure, build or deploy only within the requested project and environment; staging never authorizes production.
- Production requires an explicit production request plus the project's configured approval. Reuse valid authorization without asking again; personal verification and candidate approval are distinct actions.
- Keep local generation, cloud setup, test deployment, candidate readiness, governed-branch merge, production readiness, approval, execution and client publication as distinct states. Report actual checks and missing work; do not equate generated files or a successful API call with a delivered environment.

## Release invariants

1. Identify the full application commit and exact deployment-controller commit.
2. Build each service once under a unique build identity; record every image as `repository@sha256:digest`.
3. Deploy those digests to testing and verify build, runtime and public evidence separately. Create a candidate only after all required evidence passes.
4. Promote the candidate's same service set and digests after approval; never rebuild for production. Use the bundled local signing and host verification flow, with no signing private key in CI or on the host.
5. Record the result atomically. If migration may have started, require recovery review instead of guessing a database rollback. Recovery success requires an actual isolated restore and reconciliation of the declared data scope.

Missing commit, digest, required evidence, approval or applicable human deliverable blocks the affected step. Complex-host maintenance and recovery gates remain mandatory when their conditions apply.

## Secret boundaries

Ordinary repositories contain non-secret definitions and variable names. CNB Secret repositories hold pipeline credentials and sensitive target data; hosts hold only required runtime values. Keep administrative credentials, signing keys and backup contents in approved private storage. Public Skill files and reports contain templates and evidence metadata only, never secret values or complete environment files.
