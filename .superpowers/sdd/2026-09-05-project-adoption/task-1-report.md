# Task 1 Report: Reusable Project-Adoption Contract

## Files changed

- `SKILL.md`: routes ordinary new-project work to the adoption contract, keeps
  release states distinct, and enters shared-Caddy takeover only from observed
  topology.
- `README.md`: exposes the project-adoption reference in the package map.
- `references/project-adoption.md`: adds the project-first, read-only adoption
  contract, fact/status vocabulary, document contract, host/account routing,
  minimal release ladder, and independent client delivery rule.
- `references/release-safety.md`: makes dedicated direct CAM identities plus
  fixed readiness/apply TAT Saved Commands the ordinary default and limits the
  CNB-to-command input boundary.
- `references/cnb-deployment-ui.md`: restricts the TAT adapter boundary to
  normalized non-secret release identity and the complete digest map.
- `references/human-handoffs.md`: adds secret-consumption classification and
  value-free receipts, changes customer TAT setup to fixed direct-CAM Saved
  Commands by default, and retains cross-account STS as optional.
- `tests/test_skill_package.py`: adds a package regression for the new routing,
  document/status contract, state distinctions, fixed command boundary, and
  fresh-context scenario IDs.
- `tests/skill-scenarios.md`: adds three fresh-context project-adoption
  scenarios: repository only, existing shared host, and customer production.
- `docs/superpowers/specs/2026-09-05-project-adoption-design.md` and
  `docs/superpowers/plans/2026-09-05-project-adoption.md`: approved task design
  and implementation plan included with this task commit.

## RED evidence

After changing the package test and behavioral scenarios but before adding the
new reference or routed documentation, this command failed as expected:

```text
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
```

The new `test_project_adoption_contract_routes_documents_and_safe_defaults`
errored with `FileNotFoundError` for `references/project-adoption.md`. The
existing tests passed, demonstrating that the new regression failed for the
missing contract rather than an unrelated baseline failure.

## GREEN evidence

The targeted package suite passed after implementation:

```text
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
Ran 19 tests ... OK
```

The initially selected Homebrew Python lacked PyYAML, so the unchanged quick
validator failed before reading the Skill. Root-cause inspection showed that the
system Python already provided PyYAML; running the same validator through that
available interpreter succeeded:

```text
PATH=/usr/bin:$PATH python3 tests/quick_validate.py .
Skill is valid!
```

The full suite then passed:

```text
python3 -m unittest discover -s tests -p 'test_*.py'
Ran 309 tests ... OK (skipped=1)
```

A separate fresh-context evaluator read only the updated public package and a
synthetic customer-production prompt. It passed all required checks: read target
project documents first; kept source, staging, candidate, governed branch,
readiness, approval, execution, and client publication distinct; asked only for
durable undiscoverable deliverables; classified the simple host by evidence;
named fixed TAT readiness/apply Saved Commands; requested no secret values; and
created neither a repository nor a Skill.

## Self-review

- `SKILL.md` is 55 lines, within the 60-line limit.
- Independent review found and the final regression covers one direct-CAM/STS
  inconsistency: direct CAM credentials are approved pipeline secrets with a
  value-free rotation receipt, and the temporary STS triple is required only
  for the optional role path.
- Independent review also found and the final regression prevents a
  single-project multi-container host from entering the shared-Caddy takeover
  path without opaque-routing, shared-route, or independently managed-project
  evidence.
- Shared-Caddy safeguards remain routed and unchanged in their advanced
  references; ordinary adoption now waits for observed shared/opaque topology.
- The normal TAT path is fixed-command and value-free. CNB cannot convey
  arbitrary scripts, paths, targets, credentials, or an alternate image map.
- Approval and execution remain separate, production reuses the complete
  staging-tested digest map, and client publication remains independent.
- The new and changed public wording contains no project-specific account,
  host, domain, path, incident, digest, business, or secret-value facts.
- `git diff --check` reported no whitespace errors before commit.

## Concerns

The default Homebrew `python3` on this host does not have PyYAML, although the
system `python3` does. The package itself is valid and the quick validator passed
using the available compatible interpreter. No repository dependency files were
changed because this task is documentation-only and the validation script's
dependency is an environment concern.

## Fix round 1: reviewer findings

### Changes

- Replaced every public shared-Caddy fixture, schema, helper constant, sudoers
  sample, and deterministic test reference that carried project-specific
  identifiers with neutral `sample` and `example.invalid` values.
- Replaced the retained dynamic TAT `RunCommand` model with fixed-command
  readback and invocation: `DescribeCommands`, `InvokeCommand`,
  `DescribeInvocations`, and `DescribeInvocationTasks`.
- Defined the ownership boundary in all four adoption references: a Saved
  Command owns reviewed command content/controller; exact target InstanceIds
  come from an approved project-owned adapter/control record and CAM resource
  scope; CNB supplies neither targets nor arbitrary script text.
- Restricted shared-Caddy takeover routing to opaque ownership, shared route
  ownership, or multiple independently managed projects. A visible
  single-project legacy route is not a takeover trigger.

### RED evidence

The expanded package suite first failed as intended: the fixed-command test
found the missing adapter/control-record boundary, and the shared-Caddy test
found `legacy HTTPS routes` still acting as an independent routing trigger.

After correcting the public-file scan to evaluate paths relative to the package
root, the sanitation regression failed on retained project-specific fixture
content. This proved the initial scan had been excluding the current worktree
rather than proving the package clean.

### GREEN evidence

The updated covering tests passed:

```text
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
Ran 22 tests ... OK

python3 -m unittest tests.test_shared_caddy_baseline_import \
  tests.test_shared_caddy_preflight tests.test_shared_caddy_installer \
  tests.test_shared_caddy_schemas -v
Ran 78 tests ... OK (skipped=1)
```

Residual scans completed with no matches for the retired project identifiers or
`tat:RunCommand`/`RunCommand`; `git diff --check` also completed without output.

### Final validation

```text
python3 -m unittest tests.test_skill_package.SkillPackageTests -v
Ran 22 tests ... OK

PATH=/usr/bin:$PATH python3 tests/quick_validate.py .
Skill is valid!

python3 -m unittest discover -s tests -p 'test_*.py'
Ran 314 tests ... OK (skipped=1)
```
