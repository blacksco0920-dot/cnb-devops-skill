# CNB Endpoint Notes

Base URL:

```text
https://api.cnb.cool
```

Authentication:

```http
Authorization: Bearer <CNB_TOKEN>
Accept: application/vnd.cnb.api+json
Content-Type: application/json
```

Repository path parameters such as `owner/repo` must be URL encoded:

```text
blacksco0920/FinAgentCrm -> blacksco0920%2FFinAgentCrm
```

## Safe Read Endpoints

Current user:

```http
GET /user
```

List repositories:

```http
GET /{slug}/-/repos
```

Get cloud-native build settings:

```http
GET /{repo}/-/settings/cloud-native-build
```

Required permission:

```text
repo-manage:r
```

Get build status:

```http
GET /{repo}/-/build/status/{sn}
```

Download runner log:

```http
GET /{repo}/-/build/runner/download/log/{pipelineId}
```

## Write Endpoints

Create repository:

```http
POST /{slug}/-/repos
```

Required permission:

```text
group-resource:rw
```

Update cloud-native build settings:

```http
PUT /{repo}/-/settings/cloud-native-build
```

Example body:

```json
{
  "auto_trigger": true,
  "cron_auto_trigger": false,
  "forked_repo_auto_trigger": false
}
```

Required permission:

```text
repo-manage:rw
```

Start build:

```http
POST /{repo}/-/build/start
```

Example body:

```json
{
  "branch": "main",
  "event": "api_trigger_codex",
  "title": "Triggered by Codex",
  "sync": "false"
}
```

Required permission:

```text
repo-cnb-trigger:rw
```

## Troubleshooting

`403` from build trigger:

```text
The token usually lacks repo-cnb-trigger:rw.
```

`406` from settings endpoints:

```text
Check the Accept header and ensure owner/repo is URL encoded.
```

`docker pull unauthorized` on the server:

```text
This is a TCR login issue, not a CNB token issue.
Run docker login ccr.ccs.tencentyun.com on the deployment server.
```

Server deployment fails with missing `/opt/server-ops`:

```text
Clone or sync the deployment repository to /opt/server-ops, then rerun the CNB deployment.
```
