# Existing Skill Project Adoption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing `cnb-devops-skill` sufficient for a fresh AI to adopt an ordinary new project quickly from project-local documents and reuse the proven CNB/TCR/TAT release model.

**Architecture:** Keep the entrypoint short and route ordinary onboarding to one new reference. Surgically correct the existing release, UI, and human-handoff references; preserve advanced shared-Caddy material behind observed-topology routing.

**Tech Stack:** Agent Skills Markdown, Python `unittest` package assertions, fresh-context behavioral evaluation.

## Global Constraints

- Update the existing `cnb-devops-skill`; do not create another Skill, product, portal, CLI, or `server-ops` repository.
- Public files contain no E-CAT-specific repository, account, host, path, domain, secret, digest, incident, or business fact.
- The business repository is the sole source for project-specific code, pipelines, controller, topology, and deployment state.
- Production reuses the exact staging-tested OCI digest map and never rebuilds.
- Readiness, approval, and production execution remain separate fail-closed actions.
- Ordinary project adoption must not enter shared-Caddy takeover unless shared or opaque routing is observed.
- Tests are changed first and observed failing before documentation implementation.

---

### Task 1: Add the reusable project-adoption contract

**Files:**
- Create: `references/project-adoption.md`
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `references/release-safety.md`
- Modify: `references/cnb-deployment-ui.md`
- Modify: `references/human-handoffs.md`
- Modify: `tests/test_skill_package.py`
- Modify: `tests/skill-scenarios.md`

**Interfaces:**
- Consumes: Existing authorization, immutable-candidate, evidence-plane, CNB UI, Tencent Cloud, and shared-Caddy contracts.
- Produces: One routed onboarding reference; two-file project documentation contract; first-contact discovery output; minimal release ladder; fixed-TAT default; explicit state vocabulary and configuration boundaries.

- [ ] **Step 1: Write the failing package tests and behavioral scenarios**

Add assertions requiring:

```text
references/project-adoption.md is linked from SKILL.md and README.md
docs/DEPLOYMENT.md, docs/PROJECT_STATUS.md, .env.example, .cnb/secret.example.yml
observed, supplied, unknown, not-applicable
simple host, shared Caddy
Saved Command, readiness, apply
approval does not execute production
server publication does not imply client publication
server-ops is prohibited
```

Add `NEW_PROJECT_REPO_ONLY`, `NEW_PROJECT_EXISTING_SHARED_HOST`, and
`NEW_PROJECT_CUSTOMER_PRODUCTION` fresh-context scenarios. Require read-only
discovery, only missing deliverables, no secret values, no premature shared-Caddy
takeover, and a concrete next owner/destination/acceptance result.

- [ ] **Step 2: Run the targeted test and verify RED**

Run:

```bash
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
```

Expected: failure because `references/project-adoption.md` and its routing and
contracts do not yet exist.

- [ ] **Step 3: Implement the minimal documentation change**

Create `references/project-adoption.md` with this order:

```text
first read → read-only discovery → fact/status table → project document contract
→ host/account classification → minimal staging loop → immutable candidate
→ governed branch without rebuild → readiness → approval → explicit production
→ independent client delivery → optional advanced paths
```

Update existing references so dedicated direct CAM identities plus fixed,
pre-created readiness/apply TAT Saved Commands are the pragmatic default for both
operator-owned testing and customer-owned production. Keep cross-account role/STS
as optional. State that CNB supplies only normalized non-secret release identity
and a complete digest map; it does not send arbitrary scripts, paths, targets, or
credentials. Add runtime/build/pipeline secret classification and value-free
receipts. Keep `SKILL.md` at no more than 60 lines.

- [ ] **Step 4: Run targeted and full tests and verify GREEN**

Run:

```bash
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
python3 tests/quick_validate.py .
python3 -m unittest discover -s tests -p 'test_*.py'
```

Expected: all commands exit `0`; full suite has no failures.

- [ ] **Step 5: Run fresh-context adoption evaluation**

Give a fresh AI only the updated Skill package plus a synthetic ordinary project
prompt. Verify its answer first reads target-project docs, distinguishes every
release state, asks only for undiscoverable facts, routes simple/shared host by
evidence, names fixed TAT readiness/apply commands, never requests secret values
in chat, and does not create another repository or Skill.

- [ ] **Step 6: Commit the reviewed result**

```bash
git add SKILL.md README.md references tests docs/superpowers
git commit -m "docs: streamline new project adoption"
```
