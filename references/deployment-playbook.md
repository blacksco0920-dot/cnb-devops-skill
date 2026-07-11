# CNB 部署排查手册

当 API 已可访问，但构建、镜像、服务器或公网链路失败时使用本手册。

## 1. 先定位失败层

首次同步空仓库前，先建立并推送 `main`，再同步其他分支和标签。完成后校验：

```bash
python3 scripts/cnb.py head <owner/repo>
```

若默认分支不是 `main`，先在 CNB Web 切换默认分支。不要直接删除当前默认分支，也不要依赖首次功能分支推送来初始化仓库。

```bash
python3 scripts/cnb.py builds <owner/repo> --compact
python3 scripts/cnb.py wait <owner/repo> <build-sn>
python3 scripts/cnb.py runner-log <owner/repo> <pipeline-id> > /tmp/cnb.log
tail -240 /tmp/cnb.log
```

按阶段分类：

```text
verify          依赖、monorepo 顺序或真实构建命令不一致
image build     Dockerfile、构建上下文、干净安装或平台架构
registry push   TCR 登录、命名空间、配额或网络
server deploy   SSH 指纹、私钥、TCR 登录、Compose、迁移或健康检查
public route    Caddy 网络、DNS、443、证书或应用 5xx
```

## 2. 复现流水线真实命令

不要用单独 `tsc` 代替框架构建。读取 `.cnb.yml` 和 Dockerfile 后，运行完全相同的命令：

```bash
pnpm install --frozen-lockfile
pnpm --filter <workspace-package> build
pnpm --filter <app> build
docker build -f <Dockerfile> -t <local-test-tag> <context>
```

常见差异：

- Nest 的 `nest-cli.json` 可能指向 `tsconfig.build.json`。
- Next 的 `next build` 会执行额外类型和路由检查。
- Docker 使用干净依赖图，本机缓存可能掩盖 lockfile 或隐式依赖问题。
- monorepo 必须先复制并构建被应用引用的 workspace 包。
- 跨平台桌面项目要在 Windows、macOS、Linux CI 分别编译。

## 3. 确认不可变镜像与候选版本

测试环境镜像使用完整提交标识，例如 `sha-<commit>`。测试通过后记录 registry digest：

```bash
docker buildx imagetools inspect <registry>/<image>:sha-<commit>
```

生产环境应引用：

```text
<registry>/<image>@sha256:<digest>
```

禁止生产重新构建，也不要依赖 `latest`。生产晋级后核对容器实际 image digest 与测试候选一致。

测试部署和健康检查都通过后，再为同一完整提交创建候选标签：

```text
deploydesk-<完整提交SHA>
```

候选标签是“这次测试结果可申请生产”的凭据，不是第二份代码。通过 `.cnb/tag_deploy.yml` 为生产环境配置审批，并让原生 `tag_deploy.production` 与桌面端 `api_trigger_production` 调用同一个生产流水线。无论用户在 CNB Web、手机 H5 还是桌面端点击发布，生产都只读取候选测试记录里的镜像摘要。

发布审计至少保存：

```text
project + environment + commit SHA + candidate tag + build SN
+ service + image repository + sha256 digest
```

部署后只从服务器 `.release.env` 提取 `image@sha256:<digest>`。禁止读取、回传或记录同文件中的业务密钥。生产服务集合或任一摘要与测试候选不一致时，应阻断成功状态并报告可恢复的错误码。

## 4. 检查镜像通道

TCR 是国内首版推荐项，但流水线应使用通用 OCI Registry 契约：

```text
provider
push endpoint
pull endpoint
namespace
username env name
password env name
```

CNB 构建节点登录并推送到 `push endpoint`，服务器从 `pull endpoint` 按摘要拉取。两者可能相同，也可能因跨地域、内网或云厂商而不同。接入其他云厂商 Registry 或 Harbor 时，只替换适配器和连接配置，不修改发布语义。

## 5. 检查 SSH 身份

首次接入：

1. 为项目生成独立 Ed25519 密钥。
2. 把公钥加入服务器 `authorized_keys`。
3. 通过可信渠道展示服务器主机指纹，让用户确认。
4. 保存确认后的完整 `known_hosts` 内容。

流水线连接必须包含：

```text
BatchMode=yes
StrictHostKeyChecking=yes
UserKnownHostsFile=<managed-known-hosts>
```

`ssh-keyscan` 只能采集候选公钥，不能独立建立信任。若流水线必须临时扫描，应先计算指纹并与已固定值严格比较。

## 6. 检查服务器运行面

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker compose --env-file .release.env -f docker-compose.yml config --quiet
docker compose --env-file .release.env -f docker-compose.yml ps
```

重点确认：

- 服务器已登录 TCR，且能按 digest 拉取镜像。
- 容器是 `healthy`，不是仅仅 `running`。
- 数据库迁移在应用切流前成功。
- 数据目录使用命名卷或明确挂载，发布不会删除持久卷。
- 回滚仅恢复上一个 `.release.env`；迁移后的数据库需要单独评估兼容性。
- 每台服务器存在独立部署锁；项目构建可以并行，但 Compose 切换、Caddy 网络变更和热加载必须串行。

## 7. 检查统一 Caddy

应用容器加入项目独立网络，统一 Caddy 同时加入该网络。先从 Caddy 容器内访问服务：

```bash
docker exec <caddy-container> wget -S --spider --timeout=5 \
  http://<service-alias>:<port>/health
```

再验证并热加载真实挂载的 Caddyfile：

```bash
docker exec <caddy-container> caddy validate \
  --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec <caddy-container> caddy reload \
  --config /etc/caddy/Caddyfile --adapter caddyfile
```

不要额外启动第二个反向代理占用 80/443。

若服务器已经有统一 Caddy，推荐建立稳定适配契约：

```text
/etc/caddy/Caddyfile       主配置，由基础设施仓库维护
/etc/caddy/sites/*.caddy   项目独立路由，由部署工具管理
```

主配置只需导入一次 `sites/*.caddy`。部署工具应记录实际 Caddy 容器名和宿主机路由目录，连接项目网络后先校验、再热加载；校验或热加载失败必须恢复原片段。

## 8. 分离公网诊断

依次检查：

```text
域名是否解析到目标服务器
TCP 443 是否可达
Caddy 是否成功签发证书
HTTPS 是否返回预期状态
应用是否返回 5xx
```

状态应分别报告：

```text
应用已部署并健康。
Caddy 已能访问应用。
DNS 尚未生效，公网路由待处理。
```

DNS、443 或证书修复后只重查公网路由，不重建镜像。

## 9. 发布完成验收

- 构建记录对应预期完整 SHA。
- 测试与生产的镜像 digest 一致。
- Compose 服务 healthy。
- Caddy 配置校验通过并可访问服务别名。
- DNS 指向正确服务器。
- HTTPS 证书有效，页面和 API 均无 5xx。
- 发布历史保留最近若干个 `.release.env`，手动回滚可用。
- 桌面端能按 CNB 构建序号同步由 Web 或手机 H5 发起的发布记录。
