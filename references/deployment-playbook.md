# CNB Deployment Playbook

Use this reference after CNB API access works and the remaining problem is build, image, server deploy, or public routing.

## Fast Triage

1. List recent builds:

```bash
python scripts/cnb.py builds <owner/repo> --compact
```

2. Wait for the latest build:

```bash
python scripts/cnb.py wait <owner/repo> <sn>
```

3. If it fails, download the runner log and read the last useful section:

```bash
python scripts/cnb.py runner-log <owner/repo> <sn>-001 > /tmp/cnb.log
tail -240 /tmp/cnb.log
```

4. Classify the failing stage:

```text
verify                  Local/CI build command mismatch or missing workspace package build.
build and push image    Dockerfile, clean install, tsconfig, generated files, or registry push.
deploy with server-ops  SSH, TCR login, server path, image env vars, compose, migrations.
public route            DNS or Caddy/Nginx config, not necessarily app deployment.
```

## Preflight Before Pushing Fixes

Run the nearest equivalent of the CNB commands locally before pushing:

```bash
rm -rf packages/*/dist apps/*/dist apps/*/.next
pnpm install --frozen-lockfile
pnpm db:generate
pnpm --filter <workspace-package> build
pnpm --filter <app> build
```

For Docker-only failures, inspect the Dockerfile and run the exact command:

```bash
rg -n "RUN .*build|nest build|next build|tsc" Dockerfile apps packages
```

If time permits, build the image locally with the same build args that CNB uses. This catches clean-install and copied-file differences earlier.

## TypeScript Failures Seen In Docker

Symptom:

```text
TS2688: Cannot find type definition file for 'minimatch'
Entry point for implicit type library 'minimatch'
```

Fix pattern:

```json
{
  "compilerOptions": {
    "types": ["node"]
  }
}
```

For React/Next apps:

```json
{
  "compilerOptions": {
    "types": ["node", "react", "react-dom"]
  }
}
```

Important checks:

- Nest may use `tsconfig.build.json` through `nest-cli.json`.
- Next uses the app `tsconfig.json` during `next build`.
- Workspace packages that extend a root tsconfig need the root config copied into the Docker build context before compilation.
- Avoid adding stub `@types/*` packages as the first fix. Constrain type roots/types first.

## Server Deploy Verification

After CNB reports success, verify on the server:

```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
```

Check that the deployed image tag matches the Git SHA used by CNB:

```bash
awk -F= '/IMAGE=/ {print $1"="$2}' /opt/apps/<app>/.env
```

If containers are not reachable from the host, check the Docker network instead of assuming failure:

```bash
docker network inspect apps --format '{{range .Containers}}{{.Name}} {{end}}'
docker exec infra-caddy wget -S --spider --timeout=5 http://<service-name>:<port>/ 2>&1
```

## Reverse Proxy Verification

Deployment can succeed before public routing exists. Check which Caddyfile is actually mounted:

```bash
docker inspect infra-caddy --format '{{json .Mounts}}'
```

Then inspect that file, not a stale copy:

```bash
sudo sed -n '1,240p' /path/from/docker/inspect/Caddyfile
```

Report these states separately:

```text
App deployed and healthy.
Reverse proxy network can reach the app.
Public DNS/domain route is not configured yet.
```
