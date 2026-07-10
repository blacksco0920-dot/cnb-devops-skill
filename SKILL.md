---
name: cnb-devops-skill
description: 安全操作 CNB/cnb.cool DevOps：查询或幂等创建仓库、启用云原生构建、同步 GitHub、触发并追踪构建、以同一提交和不可变镜像晋级生产，以及排查 CNB、TCR、SSH、Docker Compose、Caddy 和 HTTPS。用户提到 CNB API、自动部署、构建日志、密钥仓库或国内服务器发布时使用。
---

# CNB DevOps

用确定性脚本操作 CNB API，并把构建成功、服务器健康和公网可访问作为三个独立验收面。

## 标准流程

1. 读取本机已有的 `CNB_TOKEN`，不要要求用户重复粘贴已保存的令牌。
2. 先运行项目真实构建命令和 Docker 构建，再修改或触发远程流水线。
3. 用 `ensure-repo` 幂等创建普通 CNB 仓库；默认私有，只有用户明确要求时才传 `--public`。
4. 用临时 Git HTTP Header 同步代码。禁止把令牌放进 Git URL、remote 或磁盘配置。
5. 测试环境构建 `sha-<完整提交>` 镜像，部署后记录 registry digest，并标记为已验证候选。
6. 生产环境只晋级测试通过的同一完整提交和同一镜像摘要，不重新构建。
7. 生产发布需要明确审批；失败时只恢复上一个 `.release.env`，不回滚数据库或删除持久卷。
8. CNB 成功后继续检查容器、Caddy 网络、DNS、443 和 HTTPS 响应。

## 快速命令

```bash
python scripts/cnb.py me
python scripts/cnb.py repos <owner>
python scripts/cnb.py ensure-repo <owner> <repo>
python scripts/cnb.py settings <owner/repo>
python scripts/cnb.py enable-auto <owner/repo>
python scripts/cnb.py trigger <owner/repo> --branch main --event api_trigger_staging
python scripts/cnb.py builds <owner/repo> --compact
python scripts/cnb.py wait <owner/repo> <build-sn>
python scripts/cnb.py promote <owner/repo> --branch main --sha <完整提交SHA>
```

`promote` 只接受 40 或 64 位完整 SHA。不要用 `latest`、分支名、短 SHA 或重新构建的镜像代替生产候选。

## 令牌权限

- `repo-manage:r`：读取构建设置。
- `repo-manage:rw`：更新构建设置。
- `repo-cnb-trigger:rw`：手动触发测试或生产事件。
- `group-resource:rw`：创建仓库。

手动触发返回 `403` 且缺少 `repo-cnb-trigger:rw` 时，可在已启用自动触发且不会影响业务主仓库的前提下，通过普通 Git push 触发分支规则；不要绕过生产审批。

## 密钥仓库边界

CNB Secret 类型仓库目前需要用户在 CNB Web 创建和编辑，不能 clone，也没有受支持的 OpenAPI 用来写入文件。应生成带中文说明的 `secret.example.yml`，引导用户一次性填入 Web 页面；不要伪造 API、浏览器脚本或把密钥提交到普通仓库。

流水线只引用变量名。禁止打印 Token、TCR 密码、SSH 私钥、业务密钥或完整环境文件。

## SSH 与 Caddy

- 为每个项目生成独立 Ed25519 流水线身份，只把公钥安装到服务器。
- 首次连接让用户确认主机指纹；保存完整 `known_hosts`，后续启用 `StrictHostKeyChecking=yes`。
- 禁止不校验指纹地直接信任 `ssh-keyscan` 结果。
- 默认使用统一 Caddy 容器管理反向代理和自动 HTTPS；应用容器不直接占用宿主机 80/443。
- DNS 未解析或证书尚未签发时，报告“应用已部署，公网路由待处理”，不要重新构建镜像。

## 故障定位

按以下顺序检查，避免在错误层反复修改业务代码：

```text
Git 同步 -> CNB 规则 -> verify -> Docker 构建 -> TCR push
-> SSH/known_hosts -> Docker Compose 健康 -> Caddy 网络
-> DNS -> 443/证书 -> HTTP 响应
```

本地构建不能替代 Docker 构建。Nest 需确认 `nest-cli.json` 实际使用的 tsconfig；Next 需运行 `next build`；monorepo 需在干净依赖图中构建被引用包。

需要端点、权限和请求体时读取 `references/endpoints.md`。需要构建、服务器或公网故障排查时读取 `references/deployment-playbook.md`。
