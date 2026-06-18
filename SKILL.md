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
2. Confirm secrets are loaded from a private env file or shell variables. Never ask the user to paste secrets again if they already exist locally.
3. Before pushing a deployment fix, run the same build surface that CNB/Docker will run:
   - Monorepo packages first, then app build.
   - For Nest, check `nest-cli.json` because it may use `tsconfig.build.json`, not `tsconfig.json`.
   - For Next, run `next build`, not only `tsc`.
   - If a failure only appears in Docker, inspect the Dockerfile command and reproduce that exact command or build the image locally.
4. Prefer the bundled CLI for CNB API calls:

```bash
python scripts/cnb.py me
python scripts/cnb.py repos <owner-or-group>
python scripts/cnb.py settings <owner/repo>
python scripts/cnb.py enable-auto <owner/repo>
python scripts/cnb.py trigger <owner/repo> --branch main
python scripts/cnb.py builds <owner/repo> --compact
python scripts/cnb.py status <owner/repo> <build-sn>
python scripts/cnb.py wait <owner/repo> <build-sn>
```

5. Never print tokens, passwords, SSH keys, or registry passwords.
6. For write operations, explain what will change before calling the command.
7. If an API returns `403`, identify the missing permission from the CNB endpoint:
   - `repo-manage:r` for reading build settings.
   - `repo-manage:rw` for updating build settings.
   - `repo-cnb-trigger:rw` for manual build triggers.
   - `group-resource:rw` for creating repositories under a group/user slug.
8. For deployment issues, check the chain in this order:

```text
GitHub push
-> GitHub sync workflow
-> CNB repository exists
-> CNB auto_trigger enabled
-> CNB build succeeds
-> Dockerfile command matches local verification
-> image pushed to TCR
-> server can docker login / docker pull
-> /opt/server-ops exists
-> deploy script runs docker compose pull/up
-> containers are healthy on the Docker network
-> reverse proxy routes domain correctly
```

## Deployment Lessons

- Treat CNB success as stage-based: `verify`, image build, image push, and server deploy can fail for different reasons.
- Do not trust a local app build to prove Docker build health. Docker often copies different files, runs different tsconfigs, and installs a clean dependency graph.
- When TypeScript reports a missing implicit type library such as `minimatch`, first constrain `compilerOptions.types` in the tsconfig actually used by the failing tool.
- For Nest builds, `nest-cli.json` decides the tsconfig path. Patch `tsconfig.build.json` when `nest build` fails.
- For Next builds, `next build` performs its own type validation. Patch the app tsconfig and rerun `next build`.
- After CNB says `success`, still verify server state with `docker ps`, image tags, health status, and reverse proxy reachability.
- If public domains are not resolved or not present in Caddy/Nginx, report "deployment succeeded, public route pending" instead of treating it as app failure.

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

List recent builds:

```bash
python scripts/cnb.py builds blacksco0920/FinAgentCrm --compact
```

Wait for a build:

```bash
python scripts/cnb.py wait blacksco0920/FinAgentCrm <sn>
```

## References

Read `references/endpoints.md` when you need endpoint paths, permissions, request bodies, or troubleshooting notes.
Read `references/deployment-playbook.md` when a build or server deployment fails after the basic CNB API call succeeds.
