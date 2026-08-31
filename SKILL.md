---
name: cnb-devops-skill
description: Use when work involves CNB/cnb.cool pipelines, Secret repositories, TCR or OCI images, Tencent Cloud TAT, staging deployment, production promotion, or CNB release failures.
---

# CNB DevOps

Treat a release as promotion of tested evidence, not as a sequence of remembered commands.

## Decide before acting

- Explanation and inspection are read-only. Do not mutate remote state for them.
- Configure, build, or deploy only when the user requested that environment-level change.
- A staging request never authorizes production.
- Production requires an explicit production request plus the project's configured approval.

## Release contract

1. Identify the full application commit and exact deployment-controller commit.
2. Build each service once under a unique, traceable build identity.
3. Record every image as `repository@sha256:digest`.
4. Deploy those digests to staging and verify build, runtime, and public evidence separately.
5. Create a candidate only after all staging evidence passes.
6. Promote the candidate's same service set and digests after approval; never rebuild for production.
7. Record the result atomically. If migration may have started, require recovery review instead of guessing a database rollback.

Missing commit, digest, staging evidence, approval, or a required human deliverable blocks the affected release step.

## Data boundaries

- Ordinary repository: non-secret build/deploy definitions and Secret variable names.
- CNB Secret repository: credentials and sensitive target data used by pipelines.
- Target host: only runtime values that must reside there.
- Public Skill and reports: templates and evidence metadata only; never secret values or complete environment files.

## Read only what the task needs

- Candidate, failure, recovery, audit, or retention: [release safety](references/release-safety.md).
- Human setup or missing information: [human handoffs](references/human-handoffs.md).
- CNB API, token, Secret repository, or deployment UI behavior: [CNB OpenAPI](references/cnb-openapi.md).
- Multiple projects sharing one host Caddy, route ownership, helper attestation,
  or recovery: [shared Caddy v1](references/shared-caddy-v1/contract.md).
