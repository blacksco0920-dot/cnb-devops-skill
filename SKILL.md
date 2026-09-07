---
name: cnb-devops-skill
description: Use when setting up or operating CNB/cnb.cool build and deployment pipelines, deploying projects through Tencent Cloud TCR and TAT, promoting tested releases to production, verifying backups and recovery, or diagnosing CNB release failures and shared-host deployment issues.
---

# CNB DevOps

Help AI-assisted owners set up and reuse a project's build, test deployment, production release and recovery workflow. Own technical configuration, execution and evidence; give people only the necessary choices, personal account actions and approvals. Each project must be independently configured and verified.

## Start with the current task

- **First setup or another project:** read the [standard workflow](references/standard-workflow.md), then [bootstrap](references/bootstrap.md). Use the bundled generator and fixed entry points; adapt project differences. The standard first-install path uses separate test and production hosts. Multiple projects do not imply a shared host.
- **Resume or update:** read the project's `docs/DEPLOYMENT.md` and `docs/PROJECT_STATUS.md`, then only the current stage's artifacts and receipts. See [project adoption](references/project-adoption.md) for discovery and state format. Reuse accepted steps while their scope and evidence remain valid.
- **Production, failure, recovery or controller upgrade:** read the applicable [release-safety](references/release-safety.md) section. Standard production and recovery commands are in [bootstrap inputs](references/bootstrap-inputs.md). First-install tools do not upgrade active deployments.
- **Missing input or human action:** use [human handoffs](references/human-handoffs.md). Populate requirements from generated policies, installers and actual receipts; do not ask people to write commands or technical evidence.
- **CNB-specific issue:** read [deployment UI](references/cnb-deployment-ui.md) for candidates, readiness and approval; [OpenAPI](references/cnb-openapi.md) for API, token and Secret behavior.
- **Observed shared or opaque host ownership:** first classify the host using [project adoption](references/project-adoption.md#host-and-account-classification); for shared Caddy or opaque routing use its [contract](references/shared-caddy-v1/contract.md) and [host handoff](references/shared-caddy-v1/host-handoff.md). Preserve the inventory → external restore verification → credential rotation → administrator bootstrap/maintenance → baseline/provision → ordinary release gates. Application release authority never includes host takeover or direct Caddy mutation.

Files, shell, Git and HTTP/API are the normal execution tools. Browser automation is optional. Use existing pipeline stages and bundled scripts for repeated operations; do not recreate their work through interactive AI calls. Historical implementation projects and old conversations are not runtime dependencies.

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
