# cnb-devops-skill

An Agent Skill for teams that use CNB/cnb.cool and need repeatable releases
without turning deployment into another command-line product.

It is written for independent developers, small delivery teams, and AI-assisted
workflows that manage several projects or customer environments. The Skill
teaches an AI to preserve authorization boundaries, collect durable handoffs,
and promote the exact OCI images already verified in staging.

## What it standardizes

- Separate build, runtime, and public evidence.
- One immutable service-to-digest candidate manifest.
- Explicit production approval without a production rebuild.
- Clear ordinary-repository, Secret-repository, and target-host boundaries.
- Role-owned setup and recovery information that survives a change of AI tool.
- A versioned shared-Caddy declaration, internal/external provenance chain,
  ownership and release transaction, plus separately authorized bootstrap,
  helper-pair maintenance, and project provisioning for multi-project hosts.

## Package map

- [SKILL.md](SKILL.md) — concise decision and routing contract.
- [Release safety](references/release-safety.md) — evidence, candidate,
  transaction, failure, and retention rules.
- [Human handoffs](references/human-handoffs.md) — detailed role deliverables
  and one-time console work.
- [CNB OpenAPI](references/cnb-openapi.md) — current CNB-specific facts and
  mutation boundaries.
- [Shared Caddy contract v1](references/shared-caddy-v1/contract.md) — schemas,
  canonical routes, persistent host locks, generation transactions, and recovery.
- [Shared Caddy host handoff](references/shared-caddy-v1/host-handoff.md) —
  separately authorized bootstrap, provisioning, baseline, ownership, and
  crash-recoverable helper maintenance.

## Data boundary

Reviewable deployment definitions and Secret variable names belong in the
ordinary project repository. Credentials and sensitive target data belong in a
CNB Secret repository. Runtime-only values belong on the target host. The
public Skill and its reports contain templates and non-secret evidence only.

## Compatibility and status

The package uses the portable Agent Skills Markdown format and has no runtime
client dependency. It can be referenced by Codex and by other AI products that
load Agent Skills or Markdown instructions. CNB, TCR, and TAT are the current
adapters; the release contract itself remains provider-neutral.

Repository CI runs the deterministic public-package test suite. Behavioral
pressure scenarios are recorded in [tests/skill-scenarios.md](tests/skill-scenarios.md).
The reference helper and installer are security-oriented examples that require
host filesystem and runtime-adapter review before maintenance installation.

## License

[MIT](LICENSE)
