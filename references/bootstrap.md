# 使用可复用发布包

AI 接入兼容项目时先运行生成器，不重新编写发布控制器。用户只需提供业务选择、完成必须本人操作的步骤；本页的命令和配置由 AI 处理。

当前 0.2 包提供**测试与候选、显式配置的生产、SSH 首装和隔离恢复**入口，本地可运行及接口检查已通过，完整云端链路仍待验。此前 FinAgent 的 0.1 测试与候选结果见[执行包实测](../docs/history/2026-09-06-bundle-staging-rehearsal.md)，不能替代本版生产验收。支持 Ubuntu 24.04、Docker Compose、PostgreSQL、同仓同提交的应用与发布程序；已有共享主机仍需按实际拓扑核对。不兼容时列出具体差异。

## 1．生成项目文件

从项目读取 Dockerfile、构建上下文、验证命令、服务、数据迁移和公网地址，填入[项目配置示例](../assets/cnb-tcr-tat/project.example.yml)。GitHub 为源码入口时显式设置 `github_sync: true`，生成同 SHA 同步工作流；CNB 原生项目保持 false。保存为业务仓库的 `deploy/project.yml`；这是唯一需要维护的非秘密差异配置。服务名和数量由配置决定。

```sh
# SKILL_DIR 指向已经加载的 Skill；PROJECT_DIR 指向业务仓库。
python3 -m pip install PyYAML==6.0.2 jsonschema==4.25.1
python3 "$SKILL_DIR/scripts/prepare-project.py" \
  --project-root "$PROJECT_DIR" --config "$PROJECT_DIR/deploy/project.yml" --diff
# 核对差异后应用本地文件，不调用任何云 API。
python3 "$SKILL_DIR/scripts/prepare-project.py" \
  --project-root "$PROJECT_DIR" --config "$PROJECT_DIR/deploy/project.yml" --apply
```

生成的 `deploy/vendor/cnb-devops/` 包含 CI/主机核心、依赖锁、项目策略、Compose、TAT 命令及工件摘要。配置 `production.host`、`production.tat_import`、Ed25519 SPKI PEM 格式的 `production.approval_public_key`，并按需填写 `production.services` 的环境差异后，同次生成独立的 `production/` 子包及生产事件；不配置生产则保持门禁阻断。私钥不进项目、主机或 CI。配置 `recovery` 声明全部持久目录的 `backup/rebuild` 分类和必须非空的业务表。

`.cnb.yml` 保留无关任务；同名任务冲突或手改核心会明确阻断。已有项目文档保留，AI 补充实际结果。普通配置更新重新预览/应用；公共核心升级需检查版本差异，不追随远程 main 自动更新。

构建用 `GIT_SHA`、`BUILD_ID` 两个 Docker build args。每个服务必须暴露精确的发布身份：`schema=cnb-release-identity/v1`、`service`、`git_sha`、`build_id`，可以用随包的 `ci/release-identity.mjs` 生成静态 JSON；动态 API 按配置提供同样数据。`unknown/development` 仅供本地开发，不能通过部署验收。身份文件如何随应用提供是必要的业务适配，不改发布核心。

## 2．一次核对账号和主机

AI 先形成一批具体材料，避免逐个猜测、重复申请：

| 位置 | 材料与核验 |
| --- | --- |
| CNB 业务仓库 | 测试分支、候选 Tag 写入权限；按需接入已有 GitHub 同步工作流 |
| TCR | 各服务镜像仓库；CNB 推送身份与主机只读拉取身份分开 |
| 腾讯云 | 已授权实例和地域、TAT Agent 可用；管理员配置身份与日常 Invoke/Describe 身份分开 |
| 主机 | 每台主机的 SSH host/port/user、私密 identity_file 和已核验 known_hosts_file；项目独立数据库、网络、域名与拉取凭据 |
| 生产授权 | 本机 Ed25519 私钥及匹配公钥；发布授权 annotations 的本机 PAT 限定目标仓库并具备 `repo-release:rw`，与 TAT 云凭据分开 |
| 应用 | 真实迁移命令或明确无迁移、每服务身份探针、必要业务验收和其他持久数据范围 |

新服务器先盘点预装服务和端口。AI 用 `scripts/setup-host.py` 串联已有 bootstrap、installer 和原生 Caddy 入口，分别安装 test/production 子包；默认只预览，不连接 SSH。私密 target JSON 恰好包含上表五个 SSH 字段，文件 0600；运行用户须有无交互 sudo 或使用 root。StrictHostKeyChecking/BatchMode 固定开启，root 先核验捕获代码摘要再执行，秘密通过 SSH stdin 传输。

```sh
python3 "$SKILL_DIR/scripts/setup-host.py" \
  --bundle-dir "$ENV_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --target "$PRIVATE_DIR/ssh-target.json" --bootstrap-spec "$PRIVATE_DIR/bootstrap-spec.json" \
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json" \
  --caddy-baseline-sha256 "$INVENTORIED_CADDYFILE_SHA256"
# 预览通过后，在已有安装授权内加 --apply；每个环境使用自己的包、spec 和目标。
```

已有 Caddy 必须给已审 baseline，保留不升级；缺失 Caddy 时，可在受审 spec 的 `docker_packages.caddy` 固定实际 APT 版本，由 driver 首次安装并记录默认 baseline，此时可省略 baseline 参数。匹配的已安装版本重复调用不会重装，漂移停止。setup 的 ready 只表示配置完成，仍需实际发布、HTTPS 和业务验收。其他共享拓扑按[共享 Caddy 契约](shared-caddy-v1/contract.md)接入。

运行秘密通过已有管理员安全通道写入受保护文件，能在主机生成的值就在主机生成。TAT 正文、普通仓库和聊天不承载秘密；不新增凭据网页或传输服务。首次空库与接管现有数据必须显式区分，不能因为找不到历史回执就假定是空项目。

### 首次安装运行依赖

`setup-host` 使用 `host/bootstrap-host.py`：填写与该环境 policy 摘要绑定的 `bootstrap-spec.json`，固定 PostgreSQL 16 / Redis 7 的 TCR 摘要及盘点得到的 APT 版本，`generate_env` 声明在主机生成的随机值。它安装缺失的 Docker/Compose，建立独立网络、数据库/用户和可选 Redis；秘密留在主机，已有资源必须属于同一安装记录。也可通过已授权管理员通道单独预览此固定入口：

```sh
python3 "$HOST_BUNDLE_DIR/host/bootstrap-host.py" \
  --bundle-dir "$HOST_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --spec "$BOOTSTRAP_SPEC" --spec-sha256 "$REVIEWED_BOOTSTRAP_SPEC_SHA256"
# 在已授权管理员通道加 sudo 和 --apply 执行；输出受保护 runtime.env 的路径，供下一步使用。
```

持久目录使用服务 `mounts`，source 仅填写项目目录下的一层名称；原生宿主 Caddy 使用 `loopback_port`，服务必须声明唯一 `expose` 端口，仅绑定 `127.0.0.1`。管理员一次配置域名路由，普通发布不修改入口。OCR 等慢启动服务可配置 `healthcheck.start_period` 和 `host.startup_timeout_seconds`（默认 300 秒，最高 1200 秒）。

### 安装本项目的固定发布入口

`setup-host` 在依赖就绪后调用 `host/install-project.py`。单独调用时，test/production 均要求对应项目数据库确认为空，工件清单摘要从本机审阅结果单独核对：

```sh
python3 "$HOST_BUNDLE_DIR/host/install-project.py" \
  --bundle-dir "$HOST_BUNDLE_DIR" --runtime-env "$PRIVATE_RUNTIME_ENV"
sudo python3 "$HOST_BUNDLE_DIR/host/install-project.py" \
  --bundle-dir "$HOST_BUNDLE_DIR" --runtime-env "$PRIVATE_RUNTIME_ENV" \
  --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" --apply
```

安装器校验依赖、完整工件、权限和数据库起点，再安装固定程序与显式空库记录；不会创建数据库、重装公共组件或接管已有应用。重复调用不会覆盖运行中的项目配置，内容漂移停止。迁移后的失败保留事务现场，不能自动改回旧镜像假装恢复。0.1 已实际完成空库安装与后续测试发布；本版完整重复安装、中断续接及共享主机第二项目仍需各自验收。安装器没有版本升级入口，不能用首次安装接管已部署版本。

### 原生 Caddy 的首次域名接入

若盘点确认 Ubuntu 24.04 使用系统服务 Caddy、现有配置没有 import 或环境替换，可在项目安装后使用包内固定入口。它从已安装策略读取 HTTPS 域名和回环端口，保留原配置，追加本项目的独立配置文件；现有域名冲突或运行配置漂移时停止。其他共享入口按共享 Caddy 契约处理。

```sh
sudo python3 "$HOST_BUNDLE_DIR/host/configure-native-caddy.py" \
  --project "$PROJECT_ID" --environment "$ENVIRONMENT" --policy-sha256 "$REVIEWED_POLICY_SHA256" \
  --baseline-sha256 "$INVENTORIED_CADDYFILE_SHA256"
# 预览符合已授权范围后加 --apply；只在首次接入执行，普通发布不调用。
```

0.1 的该入口已在 Caddy 2.11.4 云主机完成接入，保留默认站点并核对文件与运行配置，三个测试域名的 HTTPS、可用性和发布身份通过。这只覆盖历史记录中的拓扑，本版各环境仍需实际访问与业务验收。

## 3．配置固定 TAT 命令

将每个环境生成的 `tat-spec.template.json` 复制到本机任务私密目录，AI 从已授权盘点结果填写 `target.region` 和 `target.instance_id`，分别创建固定命令和绑定。模板故意没有真实云目标；不能直接拿空模板创建命令。正文及程序/策略/Compose 摘要已生成，避免人工拼接。

```sh
npm ci --ignore-scripts --prefix "$PROJECT_DIR/deploy/vendor/cnb-devops/dependencies"
node "$SKILL_DIR/scripts/configure-tat.mjs" \
  --spec "$PRIVATE_DIR/tat-spec.json"
# 仅在目标命令配置已获授权后，使用管理员环境凭据或受保护凭据文件。
node "$SKILL_DIR/scripts/configure-tat.mjs" \
  --spec "$PRIVATE_DIR/tat-spec.json" --apply \
  --sdk-root "$PROJECT_DIR/deploy/vendor/cnb-devops/dependencies" \
  --output "$PRIVATE_DIR/tat-binding.json"
```

工具先 Describe：同版本同内容复用，不一致停止；不存在才 Create，再回读内容和全部相关元数据。创建结果不确定时不重试写入；下一次先查询。输出文件不覆盖已有文件，重查时使用新的证据文件名。绑定中的三项摘要是**预期工件**，命令配置成功仍不等于主机已安装或部署成功。
模板显式约束唯一参数 `release_request_b64url=INVALID` 及空描述；按[官方 CreateCommand 接口](https://cloud.tencent.com/document/api/1340/52684)的互斥要求，创建只发送 `DefaultParameterConfs`，回读仍精确校验它与规范 `DefaultParameters`，额外参数、默认值或描述变化均拒绝。

## 4．人只完成必须的控制台步骤

AI 按 `secrets.tcr_import`、`secrets.tat_import` 和生产的 `production.tat_import` 准备 CNB Secret 文件、对应仓库/ref/event 范围及校验步骤：

- TCR 文件提供 `TCR_USERNAME`、`TCR_PASSWORD`。
- TAT 文件提供 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`、`CNB_TAT_BINDING_JSON`，后者来自上一步受保护绑定。
- 候选 Tag 使用该仓库受支持的 `CNB_TOKEN`，可选 `CNB_TOKEN_USER_NAME`；不把管理员云凭据用于 Git 推送。

[CNB Secret](https://docs.cnb.cool/zh/repo/secret.html)要求在 Web 编辑，不能用 Git 本地推送替代。用户完成实名、验证码及这类没有可用 API 的配置，AI 负责材料和验收。这里不依赖 AI 操作浏览器；普通终端、Git、HTTP/API 能完成其余已支持步骤。

## 5．发布、续接和验收

主机安装及权限核验通过后，按项目授权推送测试分支。CNB 自动执行检查→构建/TCR→TAT→运行与公网核验→候选 Tag→annotations 回读，最后才设 ready。只修失败阶段的实际问题；不手工创建候选绕过流水线，不把 TAT SUCCESS 单独当成验收。

依赖使用锁文件、配置的国内 npm 源和已有缓存；不会在发布前清理全局镜像缓存。首次依赖/镜像下载与后续缓存命中的时间分开记录；缓存不能替代同提交检查或镜像 digest。

后续会话只读项目的 `docs/DEPLOYMENT.md`、`docs/PROJECT_STATUS.md`，再按当前阶段读取固定工件和最新证据。状态分别记录首装、新项目开通、测试、候选、生产、恢复、升级和中断；未运行的项写“未验证”，不引用来源项目的历史成功充当本项目成功。

本包的版本、来源与缺口见 [bundle.json](../assets/cnb-tcr-tat/bundle.json)，云端结果绑定[实测记录](../docs/history/2026-09-06-bundle-staging-rehearsal.md)中的固定提交与工件锁。文档或验证元数据更新不会自动验收新生成的工件锁，也不要求重发已验证的应用。来源应用代码的外部分发许可尚未记录，正式开源发布前需完成代码归属核对。

## 6．生产发布同一候选

AI 将已测试候选提交纳入配置的 `production_branch`（通常 main），保留原候选 Tag 与 digest。在 Tag 页面触发 `web_trigger_production_readiness`，流水线核验分支祖先、清单和固定 TAT 就绪回执。取得明确生产意图后，AI 在本机运行生产子包的 `admin/sign-production-approval.mjs`，用 `--readiness-invocation-id` 独立回读 TAT，带 `--authorize-production-apply` 签发绑定 prepared 的限时授权。

随后本机运行 `admin/publish-production-approval.mjs`，先预览，再用 `--apply` 和私密环境中的项目 PAT（`CNB_TOKEN`，含 `repo-release:rw`）发布并逐项回读授权，最后才标记 signed。CNB owner 在同一 Tag 批准发布，`tag_deploy.production` 校验签名后调用固定生产入口，使用候选的同一组镜像。原生审批不会替代或生成本机 Ed25519 签名，CI 不接触私钥；已有具体授权仍有效时不要求用户重复确认。

## 7．导出、下载与隔离恢复

已安装 `recovery` 策略时，AI 在授权的短暂停写窗口调用固定 `host/recover-project.py export`，传入项目、环境及 core/policy/recovery-policy 三摘要和唯一 export-id；先预览，`--apply` 才暂停应用、导出数据库与声明目录并恢复源服务。通过已授权 SSH/SFTP 下载私密导出包及回执，核对 archive/manifest 摘要；没有另一个 download 子命令。

```sh
python3 "$ENV_BUNDLE_DIR/host/recover-project.py" restore-local \
  --archive "$PRIVATE_ARCHIVE" --archive-sha256 "$ARCHIVE_SHA256" \
  --manifest-sha256 "$MANIFEST_SHA256" --destination "$NEW_PRIVATE_RESTORE_DIR"
# 预览后按授权加 --apply；本机须已拉取导出记录中同摘要的 PostgreSQL 镜像。
```

恢复使用与源端不同的本机 Docker daemon、独立卷、无网络/无端口容器，核对全部表、序列和备份目录内容；成功停止隔离容器并保留卷及回执。只有实际恢复对账通过才记录恢复成功；这不是整机或未声明数据的恢复证明。
