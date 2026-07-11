---
name: cnb-devops-skill
description: 安全操作 CNB/cnb.cool DevOps：查询或幂等创建仓库、启用云原生构建、触发并追踪构建、通过候选标签和审批把同一提交及不可变 OCI 镜像晋级生产，以及排查 CNB、镜像仓库、SSH、Docker Compose、Caddy 和 HTTPS。用户提到 CNB API、自动部署、构建日志、密钥仓库、TCR 或国内服务器发布时使用。
---

# CNB DevOps

用确定性脚本操作 CNB API，并把构建成功、服务器健康和公网可访问作为三个独立验收面。

## 标准流程

1. 读取本机已有的 `CNB_TOKEN`，不要要求用户重复粘贴已保存的令牌。
2. 先运行项目真实构建命令和 Docker 构建，再修改或触发远程流水线。
3. 调用 `GET /user/groups` 获取当前账号加入的组织。`GET /user` 返回的 `username` 只是登录身份，禁止把它当作仓库所属组织。
4. 单个可写组织可自动选择；多个组织必须显式选择。再用 `ensure-repo` 按组织幂等复用或创建普通 CNB 仓库；匹配已有仓库名时忽略大小写并保留远端实际路径。默认私有，只有用户明确要求时才传 `--public`。
5. 新建空仓库时先同步 `main`，再同步功能分支和标签；首个推送分支可能被 CNB 设为默认分支。
6. 用 `head` 校验默认分支。若历史仓库不是 `main`，先在 CNB Web 切换，再删除旧分支；当前受支持的 OpenAPI 只提供读取能力。
7. 用临时 Git HTTP Header 同步代码。禁止把令牌放进 Git URL、remote 或磁盘配置。
8. 功能分支只做开发；`main` 表示已合并的唯一代码基线，不直接代表生产版本。
9. 测试环境构建 `sha-<完整提交>` 镜像，部署并通过健康检查后记录 registry digest，再创建 `deploydesk-<完整提交>` 候选标签。
10. 使用 `.cnb/tag_deploy.yml` 暴露 CNB 原生测试/生产环境。生产审批后只调用共用的生产部署流水线，不重新构建。
11. 生产环境必须使用候选测试运行记录中的同一完整提交、服务集合和镜像摘要；缺少摘要或任一摘要不一致时阻断发布。
12. CNB Web、手机 H5 或桌面端发起的生产发布必须落到同一流水线，并按构建序号和完整 SHA 回写同一发布审计记录。
13. 生产发布失败时只恢复上一个 `.release.env`，不回滚数据库或删除持久卷。
14. CNB 成功后继续检查容器、Caddy 网络、DNS、443 和 HTTPS 响应。

## 快速命令

```bash
python scripts/cnb.py me
python scripts/cnb.py groups
python scripts/cnb.py repos <owner>
python scripts/cnb.py ensure-repo <owner> <repo>
python scripts/cnb.py head <owner/repo>
python scripts/cnb.py settings <owner/repo>
python scripts/cnb.py enable-auto <owner/repo>
python scripts/cnb.py trigger <owner/repo> --branch main --event api_trigger_staging
python scripts/cnb.py builds <owner/repo> --compact
python scripts/cnb.py wait <owner/repo> <build-sn>
python scripts/cnb.py promote <owner/repo> --branch main --sha <完整提交SHA>
```

`promote` 只接受 40 或 64 位完整 SHA。不要用 `latest`、分支名、短 SHA 或重新构建的镜像代替生产候选。新项目优先使用候选标签和 CNB 原生部署审批；`promote` 保留给桌面端或兼容旧流水线的 API 入口，两者必须调用同一个生产部署定义。

## 令牌权限

- `repo-manage:r`：读取构建设置。
- `repo-manage:rw`：更新构建设置。
- `repo-cnb-trigger:rw`：手动触发测试或生产事件。
- `group-resource:rw`：创建仓库。

手动触发返回 `403` 且缺少 `repo-cnb-trigger:rw` 时：

- 测试环境可在已启用自动触发的前提下，通过普通 Git push 触发分支规则。
- 新项目优先让用户在 CNB 的候选标签部署页审批生产；旧项目可暂时用专用审批分支执行 `cnb:apply`，但必须对候选完整提交触发共用的 `api_trigger_production`。
- 跨仓库 `cnb:trigger` 仍需要具备对应权限的 Token。

不要为了绕过权限而让 `main` 自动部署生产，也不要让审批分支重新构建镜像。

## 密钥仓库边界

CNB Secret 类型仓库目前需要用户在 CNB Web 创建和编辑，不能 clone，也没有受支持的 OpenAPI 用来写入文件。应生成带中文说明的 `secret.example.yml`，引导用户一次性填入 Web 页面；不要伪造 API、浏览器脚本或把密钥提交到普通仓库。

流水线只引用变量名。禁止打印 Token、TCR 密码、SSH 私钥、业务密钥或完整环境文件。

## 提供商边界

- 把 CNB 视为首版 `pipeline` 适配器，不让业务清单依赖 CNB 私有字段；后续可增加 Gitee、GitLab 或其他国内流水线适配器。
- 把 TCR 视为首版推荐的 OCI Registry 适配器，不是部署核心的硬依赖。其他云厂商或自建 Harbor 只要支持 OCI push/pull 即可接入。
- Registry 配置必须区分 `push endpoint` 与 `pull endpoint`。构建端推送地址和服务器拉取地址可能因地域、内网或云厂商不同而不相同。
- 把运行时、密钥、DNS、审批和反向代理分别建模；不得用一个“腾讯云”开关把所有能力绑死。
- 同一物理服务器上的镜像构建可并行；Docker Compose 切换、Caddy 网络连接和热加载使用服务器级文件锁串行执行，避免多项目互相覆盖。

## SSH 与 Caddy

- 为每个项目生成独立 Ed25519 流水线身份，只把公钥安装到服务器。
- 首次连接让用户确认主机指纹；保存完整 `known_hosts`，后续启用 `StrictHostKeyChecking=yes`。
- 禁止不校验指纹地直接信任 `ssh-keyscan` 结果。
- 默认使用统一 Caddy 容器管理反向代理和自动 HTTPS；应用容器不直接占用宿主机 80/443。
- 已有统一 Caddy 时优先复用：为其挂载 `/etc/caddy/sites` 并在主配置导入 `sites/*.caddy`；部署工具只管理独立片段，不重写主 Caddyfile，也不启动第二个代理。
- 统一 Caddy 必须动态加入项目独立网络，热加载前先执行 `caddy validate`；失败时恢复原路由片段。
- DNS 未解析或证书尚未签发时，报告“应用已部署，公网路由待处理”，不要重新构建镜像。

## 发布审计

- 每次部署成功后从服务器读取 `$HOME/.deploydesk/apps/<project>/<environment>/.release.env`，只提取 `image@sha256:<digest>`，不要回传或保存其他环境变量。
- 记录项目、环境、完整 SHA、候选标签、CNB 构建序号、服务名、镜像仓库和摘要。
- 从 CNB 最近构建同步 `tag_deploy.staging` 与 `tag_deploy.production`，使手机端审批也能出现在桌面端历史中。
- 生产完成后重新读取服务器摘要，并逐服务对比测试候选。缺少测试记录、缺少摘要或摘要不一致都应进入“需要处理”，不能显示成功。

## 故障定位

按以下顺序检查，避免在错误层反复修改业务代码：

```text
Git 同步 -> CNB 规则 -> verify -> Docker 构建 -> TCR push
-> SSH/known_hosts -> Docker Compose 健康 -> Caddy 网络
-> DNS -> 443/证书 -> HTTP 响应
```

本地构建不能替代 Docker 构建。Nest 需确认 `nest-cli.json` 实际使用的 tsconfig；Next 需运行 `next build`；monorepo 需在干净依赖图中构建被引用包。

需要端点、权限和请求体时读取 `references/endpoints.md`。需要构建、服务器或公网故障排查时读取 `references/deployment-playbook.md`。
