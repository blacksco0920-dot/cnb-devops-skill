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

## 3. 确认不可变镜像

测试环境镜像使用完整提交标识，例如 `sha-<commit>`。测试通过后记录 registry digest：

```bash
docker buildx imagetools inspect <registry>/<image>:sha-<commit>
```

生产环境应引用：

```text
<registry>/<image>@sha256:<digest>
```

禁止生产重新构建，也不要依赖 `latest`。生产晋级后核对容器实际 image digest 与测试候选一致。

## 4. 检查 SSH 身份

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

## 5. 检查服务器运行面

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

## 6. 检查统一 Caddy

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

## 7. 分离公网诊断

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

## 8. 发布完成验收

- 构建记录对应预期完整 SHA。
- 测试与生产的镜像 digest 一致。
- Compose 服务 healthy。
- Caddy 配置校验通过并可访问服务别名。
- DNS 指向正确服务器。
- HTTPS 证书有效，页面和 API 均无 5xx。
- 发布历史保留最近若干个 `.release.env`，手动回滚可用。
