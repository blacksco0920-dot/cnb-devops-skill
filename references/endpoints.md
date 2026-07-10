# CNB OpenAPI 参考

## 连接约定

```text
Base URL: https://api.cnb.cool
Accept: application/vnd.cnb.api+json
Authorization: Bearer <CNB_TOKEN>
```

`owner/repo` 作为单个路径参数时必须整体 URL 编码：

```text
team/sample -> team%2Fsample
```

脚本只从环境变量读取 Token。禁止把 Token 放进命令参数、Git URL、remote 或普通配置文件。

## 只读端点

当前用户：

```http
GET /user
```

列出组织或用户仓库：

```http
GET /{slug}/-/repos
```

读取云原生构建设置，需要 `repo-manage:r`：

```http
GET /{encoded-owner/repo}/-/settings/cloud-native-build
```

读取仓库默认分支，需要 `repo-code:r`：

```http
GET /{encoded-owner/repo}/-/git/head
```

当前受支持的 OpenAPI 没有修改默认分支的端点。新建空仓库应先推送 `main`；若历史仓库默认分支错误，在 CNB Web 的仓库基础设置中切换后，再删除旧分支。

读取构建状态和记录：

```http
GET /{encoded-owner/repo}/-/build/status/{sn}
GET /{encoded-owner/repo}/-/build/logs?size=5
GET /{encoded-owner/repo}/-/build/runner/download/log/{pipelineId}
```

## 写入端点

创建普通仓库，需要 `group-resource:rw`：

```http
POST /{slug}/-/repos
```

```json
{
  "name": "sample",
  "description": "",
  "visibility": "private"
}
```

CLI 默认 `private`，只有显式 `--public` 才创建公开仓库。优先使用 `ensure-repo`，避免重试时创建失败或重复操作。

更新构建设置，需要 `repo-manage:rw`：

```http
PUT /{encoded-owner/repo}/-/settings/cloud-native-build
```

```json
{
  "auto_trigger": true,
  "cron_auto_trigger": false,
  "forked_repo_auto_trigger": false
}
```

触发构建，需要 `repo-cnb-trigger:rw`：

```http
POST /{encoded-owner/repo}/-/build/start
```

测试事件：

```json
{
  "branch": "main",
  "event": "api_trigger_staging",
  "title": "Build release candidate",
  "sync": "false"
}
```

生产晋级必须传完整提交 SHA：

```json
{
  "branch": "main",
  "event": "api_trigger_production",
  "title": "Promote verified commit",
  "sha": "0123456789abcdef0123456789abcdef01234567",
  "sync": "false"
}
```

## Secret 仓库限制

Secret 类型仓库目前需要在 CNB Web 创建和编辑，不能 clone，也没有受支持的 OpenAPI 用于写入 `envs.yml`。API 助手不得把 Secret 仓库当成普通仓库创建，也不得尝试本地 push。

推荐让工具生成字段模板，再让用户在 Web 端一次性填写。参考 CNB 官方文档：

- <https://docs.cnb.cool/zh/repo/secret.html>
- <https://docs.cnb.cool/zh/develops/openapi.html>

## 常见响应

`403` 且提示 `repo-cnb-trigger:rw`：Token 可以读或推送代码，但不能调用手动构建端点。重新创建最小权限 Token，或使用已经开启的普通 push 自动触发测试规则。

同仓库生产审批可以在专用分支的 `push` 流水线中使用 `cnb:apply`，对当前提交触发 `api_trigger_production`；它不等同于跨仓库 `cnb:trigger`。参考 CNB 官方[内置任务文档](https://docs.cnb.cool/zh/build/internal-steps.html#apply)。

`406`：确认 `Accept` Header，并确认 `owner/repo` 已整体 URL 编码。

`docker pull unauthorized`：这是 TCR 登录问题，不是 CNB Token 问题。检查流水线和服务器各自的 TCR 凭据。

CNB `success` 但域名失败：继续检查服务器容器、Caddy 网络、DNS、443 与证书，不要直接重新构建镜像。
