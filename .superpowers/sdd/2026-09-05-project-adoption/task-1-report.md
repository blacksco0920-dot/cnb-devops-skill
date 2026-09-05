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

## Fix round 2: scoped-review findings

### Changes

- Replaced the compiled legacy-baseline project, repository, hostname, route,
  and compatibility-pair constants with normalized declaration validation.
  The helper now derives the canonical fragment and active-generation filenames
  from the separately approved declaration, then requires exact identity,
  ordered-host, and hash agreement across declaration, provenance, manifest,
  transaction, receipt, and retained archive.
- Generalized the three legacy baseline JSON schemas from fixture `const` and
  fixed route-count fields to normalized identity/source/host patterns and a
  non-empty unique host list. Cross-artifact agreement remains runtime
  fail-closed validation rather than a schema fixture constant.
- Added an unrelated two-route synthetic topology and a generation-filename
  regression. Both prove reuse without allowing mismatched artifact evidence.
- Documented that baseline/control topology is separately authorized and CNB
  ordinary release cannot provide or alter it.
- Expanded the project-fact/privacy scan to every text file in the package,
  including root files, extensionless text, `.caddy`, and `.sudoers`. It skips
  only Git/worktree paths, ignored scratch material, and binary/non-UTF-8 files.
  The test source keeps prohibited strings split; the approved design and plan
  now refer only to pilot-specific facts.

### RED evidence

Before the helper and schemas changed, the new topology regressions failed:

```text
python3 -m unittest \
  tests.test_shared_caddy_baseline_import.LegacyBaselineArtifactTests.test_accepts_an_independent_approved_legacy_topology_and_rejects_cross_artifact_mismatch \
  tests.test_shared_caddy_schemas.SharedCaddySchemaTests.test_legacy_baseline_schemas_and_runtime_accept_normalized_nonfixture_topology \
  tests.test_skill_package.SkillPackageTests.test_public_package_has_no_project_specific_fixture_facts -v

FAILED (errors=4)
```

The helper rejected the alternate declaration as not the approved fixed
identity; each baseline schema rejected its alternate deployment ID because of
the fixture `const`. The expanded privacy scan passed in that RED run. A later
documentation-boundary test also failed until the handoff explicitly stated
that CNB ordinary release cannot supply or alter baseline topology.

### GREEN evidence

```text
python3 -m unittest tests.test_shared_caddy_baseline_import \
  tests.test_shared_caddy_schemas tests.test_skill_package -v
Ran 64 tests ... OK (skipped=1)
```

This covers baseline import/recovery, immutable active generations, a second
approved topology, cross-artifact mismatch rejection, all three schemas, and
the whole-package privacy and CNB-boundary regressions. `git diff --check`
completed without output; a tracked-file scan found no pilot/private identifier
outside the deliberately split regression source.

### Self-review

- The helper retains archive member limits, root-only actions, descriptor-safe
  input handling, immutable generation verification, transaction recovery, and
  source/target ownership restrictions.
- CNB still cannot supply baseline topology at release time; the root-only
  baseline-input hierarchy and control records remain the authorization source.
- `SKILL.md` remains 55 lines.

### Final validation and concerns

```text
PATH=/usr/bin:$PATH python3 tests/quick_validate.py .
Skill is valid!

python3 -m unittest discover -s tests -p 'test_*.py'
Ran 318 tests ... OK (skipped=1)
```

The expected argparse diagnostics printed by negative CLI tests are test output,
not failures. As in prior rounds, the default Homebrew Python lacks PyYAML, so
the quick validator was run with the available system Python. No functional
concerns remain.

## Final-review fix wave: schema/runtime normalization parity

### Changes

- Added `maxLength: 253` to every legacy-baseline hostname item schema.
- Tightened all three legacy-baseline `source_repo` patterns so `.` and `..`
  cannot be complete path segments, matching the existing runtime parser.
- Added schema/runtime parity regressions for overlong hosts and both dot-only
  repository path segments in provenance, transaction, and receipt artifacts.

### RED evidence

```text
python3 -m unittest \
  tests.test_shared_caddy_schemas.SharedCaddySchemaTests.test_legacy_baseline_schemas_match_runtime_hostname_and_source_repo_normalization -v
FAILED (failures=9)
```

The schema validator accepted all three malformed values for each baseline
artifact while its runtime validator rejected them, isolating the missing
schema constraints.

### GREEN evidence

```text
python3 -m unittest tests.test_shared_caddy_schemas \
  tests.test_shared_caddy_baseline_import -v
Ran 43 tests ... OK (skipped=1)

PATH=/usr/bin:$PATH python3 tests/quick_validate.py .
Skill is valid!

python3 -m unittest discover -s tests -p 'test_*.py'
Ran 319 tests ... OK (skipped=1)
```

Expected argparse diagnostics are negative-test output. The system Python was
used for the quick validator because the default Homebrew Python lacks PyYAML.
