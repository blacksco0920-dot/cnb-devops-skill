---
name: cnb-devops-skill
description: Use this skill when working with CNB/cnb.cool DevOps workflows: querying or creating CNB repositories, enabling cloud-native build auto triggers, triggering builds, checking build status or logs, wiring GitHub-to-CNB-to-server deployment, or troubleshooting CNB/TCR/SSH Docker Compose deployments for independent projects.
metadata:
  short-description: Operate CNB DevOps workflows
---

# CNB DevOps Skill

Use this skill to help users connect GitHub, CNB cloud-native build, Tencent TCR, and a lightweight server deployment based on Docker Compose.

## Default Workflow

1. Confirm the user has a CNB token available as `CNB_TOKEN`.
2. Prefer the bundled CLI for CNB API calls:

```bash
python scripts/cnb.py me
python scripts/cnb.py repos <owner-or-group>
python scripts/cnb.py settings <owner/repo>
python scripts/cnb.py enable-auto <owner/repo>
python scripts/cnb.py trigger <owner/repo> --branch main
python scripts/cnb.py status <owner/repo> <build-sn>
```

3. Never print tokens, passwords, SSH keys, or registry passwords.
4. For write operations, explain what will change before calling the command.
5. If an API returns `403`, identify the missing permission from the CNB endpoint:
   - `repo-manage:r` for reading build settings.
   - `repo-manage:rw` for updating build settings.
   - `repo-cnb-trigger:rw` for manual build triggers.
   - `group-resource:rw` for creating repositories under a group/user slug.
6. For deployment issues, check the chain in this order:

```text
GitHub push
-> GitHub sync workflow
-> CNB repository exists
-> CNB auto_trigger enabled
-> CNB build succeeds
-> image pushed to TCR
-> server can docker login / docker pull
-> /opt/server-ops exists
-> deploy script runs docker compose pull/up
-> reverse proxy routes domain correctly
```

## Common Commands

List repositories:

```bash
python scripts/cnb.py repos blacksco0920
```

Create a repository:

```bash
python scripts/cnb.py create-repo blacksco0920 FinAgentCrm
```

Enable cloud-native build auto trigger:

```bash
python scripts/cnb.py enable-auto blacksco0920/FinAgentCrm
```

Trigger a build:

```bash
python scripts/cnb.py trigger blacksco0920/FinAgentCrm --branch main
```

Get status:

```bash
python scripts/cnb.py status blacksco0920/FinAgentCrm <sn>
```

## References

Read `references/endpoints.md` when you need endpoint paths, permissions, request bodies, or troubleshooting notes.
