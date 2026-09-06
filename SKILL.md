---
name: cnb-devops-skill
description: Use when work involves CNB/cnb.cool pipelines, Secret repositories, TCR or OCI images, Tencent Cloud TAT, Docker host migration, shared Caddy, backup or recovery, staging deployment, production promotion, or CNB release failures.
---

# CNB DevOps

Help AI-assisted owners deliver one or several projects through CNB, from local setup to verified release and recovery. Own configuration and evidence work; give people concrete handoffs. Promote tested evidence.

For setup or another project, start with the [standard workflow](references/standard-workflow.md): use the [bundle entry](references/bootstrap.md) to generate the CNB → TCR → TAT artifacts from project differences; preserve accepted existing deployments. Use files, shell, Git and HTTP/API; browser automation is optional. Do not replace pipeline stages with repeated interactive AI operations.

## Decide before acting

- Explanation and inspection are read-only. Do not mutate remote state for them.
- Configure, build, or deploy only when the user requested that environment-level change.
- A staging request never authorizes production.
- Production requires an explicit production request plus the project's configured approval.
- Keep source completion, staging deployment, candidate readiness, governed-branch merge, production readiness, approval, execution, and client publication as distinct states.

## Release contract

1. Identify the full application commit and exact deployment-controller commit.
2. Build each service once under a unique, traceable build identity.
3. Record every image as `repository@sha256:digest`.
4. Deploy those digests to staging and verify build, runtime, and public evidence separately.
5. Create a candidate only after all staging evidence passes.
6. Promote the candidate's same service set and digests after approval; never rebuild for production.
7. Record the result atomically. If migration may have started, require recovery review instead of guessing a database rollback.

Missing commit, digest, staging evidence, approval, or a required human deliverable blocks the affected release step.

## Legacy shared-host takeover

Only when read-only evidence shows opaque Caddy ownership, shared route ownership, or multiple independently managed projects, use [Shared Caddy v1](references/shared-caddy-v1/contract.md) and its [host handoff](references/shared-caddy-v1/host-handoff.md). Keep this order:

```text
route inventory (read-only/canonical; no ad-hoc mutation) → external restore-verified snapshot → credential-rotation receipt → root bootstrap → helper-pair maintenance → baseline import/recovery → provision → ordinary release
```

Only the root host administrator performs bootstrap, helper maintenance, baseline import/recovery, and provisioning; ordinary release uses only the exact preflight/apply boundary, never a direct Caddy change. Inventory is read-only, canonical evidence; count each device once and preserve every volume and bind source. Snapshot/restore then credential-rotation receipts are hard gates before destructive/live work. Never merge opaque Caddy or delegate baseline/import authority through an application release or its sudo boundary.

## Data boundaries

- Ordinary repository: non-secret build/deploy definitions and Secret variable names.
- CNB Secret repository: credentials and sensitive target data used by pipelines.
- Target host: only runtime values that must reside there.
- Public Skill and reports: templates and evidence metadata only; never secret values or complete environment files.

## Read only what the task needs

- Default setup sequence, actor responsibilities and artifact reuse: [standard workflow](references/standard-workflow.md); project state, resumption and host classification: [project adoption](references/project-adoption.md).
- Existing-host first release, controller upgrade, candidate, failure, recovery, audit, or retention: [release safety](references/release-safety.md).
- Human setup or missing information: [human handoffs](references/human-handoffs.md).
- CNB candidate Tag, deployment page, or production buttons: [CNB deployment UI](references/cnb-deployment-ui.md).
- CNB API, token, or Secret repository behavior: [CNB OpenAPI](references/cnb-openapi.md).
- Multiple projects sharing one host Caddy, route ownership, helper attestation,
  or recovery: [shared Caddy v1](references/shared-caddy-v1/contract.md).
