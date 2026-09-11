# 使用可复用发布包

AI 接入兼容项目时先运行生成器，不重新编写发布控制器。用户只需提供业务选择、完成必须本人操作的步骤；本页的命令和配置由 AI 处理。

AI 执行时配合[完整输入与命令](bootstrap-inputs.md)：包含双环境包路径、SSH/APT 盘点、bootstrap spec、Docker 拉取配置、生产签名与导出下载。示例只用非秘密占位；实际值留在项目批准的私密目录，沿用已有阶段授权。

标准首装使用两台独立的 Ubuntu 24.04 / Linux amd64 主机、Docker Compose、必需的 PostgreSQL 16 和可选 Redis 7；应用与发布程序同仓同提交。无数据库项目和其他数据库不在当前固定运行包支持范围内；不通过新增无业务需要的数据库来适配。包内覆盖**测试与候选、显式配置的生产、SSH 首装和隔离恢复**。只请求测试时只配置、操作该环境；已有数据、活动版本升级或复杂共享主机先列出差异，按对应入口处理。

用户要求在既有两台服务器追加项目时，符合原生 Caddy 条件的采用[同主机追加流程](native-caddy-shared.md)，保留旧项目并分别验证共存；不要默认替换已有环境。

## 1．生成项目文件

<a id="generator-preflight"></a>
### 生成前检查

先确认项目适用，再用本次实际使用的 Python 检查 `import yaml, jsonschema`；优先复用已提供或已有的工具虚拟环境。依赖缺失时，在允许安装的范围内由 AI 准备独立虚拟环境并安装下列锁定版本，不改系统 Python。禁止联网或安装时记录这一局部限制，不反复重试生成器、不让用户排查 Python；它不等于项目配置校验失败。

接着核对本次生成所需的非秘密输入。能从代码、已授权账号或已有记录得到的由 AI 填写，缺失项保留在状态文档，按[人员交接](human-handoffs.md#把当前动作交给人)只请求当前必要信息。示例值不能冒充已存在的仓库、目标或资源；只有明确的离线演练可用标明为合成的值做本地生成，产物不能用于真实发布。

### 适配并生成

从[完整配置示例](../assets/cnb-tcr-tat/project.full.example.yml)开始：一个 Web 服务、PostgreSQL 和 uploads，包含隔离的测试/生产配置与恢复范围。它是供 AI 适配的配置起点，不附带业务应用，也不创建云资源。按实际项目改写仓库、域名、Dockerfile、构建上下文、验证/迁移命令、服务端口、身份探针和业务表；不能把示例表名当作已存在或已验收的数据。

完整示例的生产公钥故意使用待填标记，原样生成会被拒绝。先按[生产密钥准备](bootstrap-inputs.md#production-key)复用或生成项目专用密钥，只填入公钥；私钥留在本机私密存储。仅接测试时移除 `production`，保留实际需要的测试与恢复配置。[最小示例](../assets/cnb-tcr-tat/project.example.yml)只展示测试文件生成，不覆盖标准首装、生产和恢复。

GitHub 为源码入口时显式设置 `github_sync: true`，生成同 SHA 同步工作流；CNB 原生项目保持 false。保存为业务仓库的 `deploy/project.yml`，集中维护非秘密项目差异；服务名和数量由配置决定。

```sh
# SKILL_DIR 指向已加载的 Skill；PROJECT_DIR 指向业务仓库。
# GENERATOR_PYTHON 指向已核验依赖的 Python；需安装时在独立虚拟环境运行：
# "$GENERATOR_PYTHON" -m pip install PyYAML==6.0.2 jsonschema==4.25.1
"$GENERATOR_PYTHON" -c 'import yaml, jsonschema'
"$GENERATOR_PYTHON" "$SKILL_DIR/scripts/prepare-project.py" \
  --project-root "$PROJECT_DIR" --config "$PROJECT_DIR/deploy/project.yml" --diff
# 核对差异后应用本地文件，不调用任何云 API。
"$GENERATOR_PYTHON" "$SKILL_DIR/scripts/prepare-project.py" \
  --project-root "$PROJECT_DIR" --config "$PROJECT_DIR/deploy/project.yml" --apply
```

生成的 `deploy/vendor/cnb-devops/` 包含 CI/主机核心、依赖锁、项目策略、Compose、TAT 命令及工件摘要。配置 `production.host`、`production.tat_import`、Ed25519 SPKI PEM 格式的 `production.approval_public_key`，并按需填写 `production.services` 的环境差异后，同次生成独立的 `production/` 子包及生产事件；不配置生产则保持门禁阻断。私钥不进项目、主机或 CI。配置 `recovery` 声明全部持久目录的 `backup/rebuild` 分类和必须非空的业务表。

生成器维护 `.cnb.yml` 中自己的事件、`.cnb/tag_deploy.yml`、`deploy/vendor/cnb-devops/` 及其中的 `generation-lock.json`。它保留无关任务，同名事件无归属或受管文件漂移会阻断。生成前不要手写这些位置的发布草稿，即使内容只是退出失败；不伪造锁，也不删除已有项目的配置来绕过冲突。已有冲突先核对来源与差异。已有项目文档保留，AI 补充实际结果；普通配置更新重新预览/应用，公共核心升级检查版本差异，不追随远程 main 自动更新。

构建用 `GIT_SHA`、`BUILD_ID` 两个 Docker build args。每个服务必须暴露精确的发布身份：`schema=cnb-release-identity/v1`、`service`、`git_sha`、`build_id`，可以用随包的 `ci/release-identity.mjs` 生成静态 JSON；动态 API 按配置提供同样数据。`unknown/development` 仅供本地开发，不能通过部署验收。身份文件如何随应用提供是必要的业务适配，不改发布核心。

## 2．一次核对账号和主机

新账号或权限缺口按[账号与 API 接入](api-onboarding.md)复用官方登录，核对仓库与构建设置。CNB 默认 CLI 的仓库创建权限限制按该入口处理；腾讯云临时会话导出的私密三元组可直接作为下述配置器的 `--credentials`。有效登录和成功资源不重复建立。

AI 先形成一批具体材料，避免逐个猜测、重复申请：

| 位置 | 材料与核验 |
| --- | --- |
| CNB 业务仓库 | 测试分支、候选 Tag 写入权限；按需接入已有 GitHub 同步工作流 |
| TCR | 各服务镜像仓库；CNB 推送身份与主机只读拉取身份分开 |
| 腾讯云 | 已授权实例和地域、TAT Agent 可用；管理员配置身份与日常 Invoke/Describe 身份分开 |
| 主机 | 每台主机的 SSH host/port/user、私密 identity_file 和已核验 known_hosts_file；项目独立数据库、网络、域名与拉取凭据 |
| 生产授权 | 本机 Ed25519 私钥及匹配公钥；发布授权 annotations 的本机 PAT 限定目标仓库并具备 `repo-release:rw`，与 TAT 云凭据分开 |
| 应用 | 真实迁移命令或明确无迁移、每服务身份探针、必要业务验收和其他持久数据范围 |

重装后核对 TAT Agent 实际在线；免密登录开关开启不代表 Agent 已安装。缺失时使用已授权管理员通道或[腾讯云安装入口](https://cloud.tencent.com/document/product/1340/51945)补装；控制台一键安装会重启实例，须在已有重启授权范围内执行。

新服务器先盘点预装服务和端口。AI 用 `scripts/setup-host.py` 串联已有 bootstrap、installer 和原生 Caddy 入口，分别安装 test/production 子包；默认只预览，不连接 SSH。私密 target JSON 恰好包含上表五个 SSH 字段，文件 0600；运行用户须有无交互 sudo 或使用 root。StrictHostKeyChecking/BatchMode 固定开启，root 先核验捕获代码摘要再执行，秘密通过 SSH stdin 传输。

```sh
python3 "$SKILL_DIR/scripts/setup-host.py" \
  --bundle-dir "$ENV_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --target "$PRIVATE_DIR/ssh-target.json" --bootstrap-spec "$PRIVATE_DIR/bootstrap-spec.json" \
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json" \
  --caddy-baseline-sha256 "$INVENTORIED_CADDYFILE_SHA256"
# 预览通过后，在已有安装授权内加 --apply；每个环境使用自己的包、spec 和目标。
```

已有 Caddy 必须给已审 baseline，保留不升级；缺失 Caddy 时，可在受审 spec 的 `docker_packages.caddy` 固定实际 APT 版本，由 driver 首次安装并记录默认 baseline，此时可省略 baseline 参数。匹配的已安装版本重复调用不会重装，漂移停止。setup 的 ready 只表示配置完成，仍需实际发布、HTTPS 和业务验收。 APT 安装遇到 dpkg 锁最多等待 120 秒；失败返回固定的 `SETUP_BOOTSTRAP_APT_*` 等阶段码，不输出命令或秘密。该等待不覆盖 `apt-get update` 的 lists 锁；按阶段码只读核对系统包管理任务，结束后用相同输入续接，不删除锁或停止系统更新。其他共享拓扑按[共享 Caddy 契约](shared-caddy-v1/contract.md)接入。

若首装已留下安装回执、仅管理员 helper 的兼容问题使最后步骤失败，修复后可给新包的 `--lock-sha256`，并显式补上原回执的 `--installed-lock-sha256` 和已核验的 Caddy baseline 继续。工具只允许同版本、同文件清单内的四个管理员 helper 与包摘要变化，逐字核对已安装运行文件，保留原安装回执；这不适用于控制器、策略、CI 或业务升级。新的 setup 回执分别记录此次包摘要和实际安装摘要。

运行秘密通过已有管理员安全通道写入受保护文件，能在主机生成的值就在主机生成。TAT 正文、普通仓库和聊天不承载秘密；不新增凭据网页或传输服务。首次空库与接管现有数据必须显式区分，不能因为找不到历史回执就假定是空项目。

### 首次安装运行依赖

`setup-host` 使用 `host/bootstrap-host.py`：按[输入示例](bootstrap-inputs.md#bootstrap-spec)填写与该环境 policy 摘要绑定的 `bootstrap-spec.json`，固定 PostgreSQL 16 / Redis 7 的 TCR 摘要及盘点得到的 APT 版本，`generate_env` 声明在主机生成的随机值。它安装缺失的 Docker/Compose，建立独立网络、数据库/用户和可选 Redis；秘密留在主机，已有资源必须属于同一安装记录。Redis 密码通过容器内 0600 配置及健康检查环境变量传入，不进入进程参数；容器环境仍含秘密，盘点只能输出筛选后的字段。此入口不用于活动部署升级或凭据轮换。也可通过已授权管理员通道单独预览此固定入口：

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

安装器校验依赖、完整工件、权限和数据库起点，再安装固定程序与显式空库记录；不会创建数据库、重装公共组件或接管已有应用。重复调用不会覆盖运行中的项目配置，内容漂移停止。迁移后的失败保留事务现场，不能自动改回旧镜像假装恢复。安装器没有版本升级入口，不能用首次安装接管已部署版本。

### 原生 Caddy 的首次域名接入

若盘点确认 Ubuntu 24.04 使用系统服务 Caddy、现有配置没有 import 或环境替换，可在项目安装后使用包内固定入口。它从已安装策略读取 HTTPS 域名和回环端口，保留原配置，追加本项目的独立配置文件；现有域名冲突或运行配置漂移时停止。其他共享入口按共享 Caddy 契约处理。

```sh
sudo python3 "$HOST_BUNDLE_DIR/host/configure-native-caddy.py" \
  --project "$PROJECT_ID" --environment "$ENVIRONMENT" --policy-sha256 "$REVIEWED_POLICY_SHA256" \
  --baseline-sha256 "$INVENTORIED_CADDYFILE_SHA256"
# 预览符合已授权范围后加 --apply；只在首次接入执行，普通发布不调用。
```

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

工具先核对目标地域的实际 CVM/Lighthouse 实例运行状态与 Linux TAT Agent 在线，再 Describe 命令：同版本同内容复用，不一致停止；不存在才 Create，再回读内容和全部相关元数据。初始化身份需有对应实例及 Agent 的只读查询权限。创建结果不确定时不重试写入；下一次先查询。输出文件不覆盖已有文件，重查时使用新的证据文件名。`target_verified` 仅指云实例和 Agent；绑定中的三项摘要仍是**预期工件**，命令配置成功不等于主机已安装或部署成功。
模板显式约束唯一参数 `release_request_b64url=INVALID` 及空描述；按[官方 CreateCommand 接口](https://cloud.tencent.com/document/api/1340/52684)的互斥要求，创建只发送 `DefaultParameterConfs`。真实回读可能将旧字段 `DefaultParameters` 留为空字符串：配置器接受它与精确匹配的唯一 conf，或与 conf 一致的规范旧字段；发布执行器也兼容只有规范旧字段的历史命令。额外参数、冲突默认值或描述变化仍拒绝。

## 4．人只完成必须的控制台步骤

AI 用[仓库配置器](api-onboarding.md#2自动准备-cnb-仓库和构建设置)创建或复用密钥仓库并回读类型，随后按 `secrets.tcr_import`、`secrets.tat_import` 和生产的 `production.tat_import` 准备 Secret 文件、对应仓库/ref/event 范围及校验步骤：

- TCR 文件提供 `TCR_USERNAME`、`TCR_PASSWORD`。
- TAT 文件提供 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`、`CNB_TAT_BINDING_JSON`，后者来自上一步受保护绑定。
- 已验收的临时云凭据路径还必须提供 `TENCENTCLOUD_TOKEN`，有效期覆盖本次操作；本机初始化会话不作为 CI 长期身份。
- 候选 Tag 使用该仓库受支持的 `CNB_TOKEN`，可选 `CNB_TOKEN_USER_NAME`；不把管理员云凭据用于 Git 推送。

[CNB Secret](https://docs.cnb.cool/zh/repo/secret.html)要求在 Web 编辑，不能用 Git 本地推送替代。用户完成实名、验证码及这类没有可用 API 的配置，AI 负责材料和验收。这里不依赖 AI 操作浏览器；普通终端、Git、HTTP/API 能完成其余已支持步骤。

## 5．发布、续接和验收

主机安装及权限核验通过、生成配置通过[完整 CNB 格式检查](bootstrap-inputs.md)后，按项目授权推送测试分支。CNB 自动执行检查→构建/TCR→TAT→运行与公网核验→候选 Tag→annotations 回读，最后才设 ready。只修失败阶段的实际问题；不手工创建候选绕过流水线，不把 TAT SUCCESS 单独当成验收。

核验部署、候选创建和最终 ready 回读这些必需阶段均实际成功，再核对 Tag 和主机回执。`breakIfModify` 提前结束旧构建时，总状态可能仍为 success，而后续发布步骤是 skipped；这种构建不算部署成功。

业务验收使用项目已有测试与实际接口，覆盖登录、业务写入、文件和结果回读等适用路径；记录请求对应的发布身份及真实后端，mock 结果与真实外部服务分开写明。恢复要求非空的业务表应由这些已授权业务操作产生数据。把项目命令与证据位置写入项目部署文档，不另建通用测试平台。

依赖使用锁文件、配置的国内 npm 源和已有缓存；不会在发布前清理全局镜像缓存。首次依赖/镜像下载与后续缓存命中的时间分开记录；缓存不能替代同提交检查或镜像 digest。

若需要优化 CI 耗时，先用阶段耗时定位瓶颈，并结合实际任务图和执行日志确认是否重复调度。合并兼容任务图时，保留完整检查与失败门禁，显式声明生成物的生产者→消费者依赖，避免并发清理、读写同一产物。优化前后以同等环境、输入和缓存条件下的实际日志执行次数与阶段计时验收；缓存命中、任务去重收益和整条流水线耗时分别记录。

若瓶颈在镜像构建或导出，先查看实际层占用和包管理器缓存目录。依赖层包含锁文件、工作区清单、安装配置、补丁和安装脚本实际需要的文件，其他源码和动态发布身份在各自首次需要的位置引入；用重复构建、仅身份/源码变化和清单变化验证缓存命中与失效。下载缓存可使用与实际目录一致的构建缓存挂载，临时文件在生成它们的同一层清理；最终镜像须在没有这些挂载的新容器中通过运行与身份检查。[Docker 缓存指南](https://docs.docker.com/build/cache/optimize/)中的构建缓存不代表临时 CI 机器之间会自动共享，跨轮复用必须以平台实际命中记录为准。

后续会话只读项目的 `docs/DEPLOYMENT.md`、`docs/PROJECT_STATUS.md`，再按当前阶段读取固定工件和最新证据。状态分别记录首装、新项目开通、测试、候选、生产、恢复、升级和中断；未运行的项写“未验证”，不引用来源项目的历史成功充当本项目成功。

本包版本与工件摘要见 [bundle.json](../assets/cnb-tcr-tat/bundle.json)；当前项目按自己的生成锁和实际回执验收。历史成功不替代新项目或新工件的验收，文档更新也不要求重发已经验收的应用。

## 6．生产发布同一候选

AI 将已测试候选提交纳入配置的 `production_branch`（通常 main），保留原候选 Tag 与 digest。在 Tag 页面触发 `web_trigger_production_readiness`，流水线核验分支祖先、清单和固定 TAT 就绪回执。取得明确生产意图后，AI 在本机运行生产子包的 `admin/sign-production-approval.mjs`，用 `--readiness-invocation-id` 独立回读 TAT，带 `--authorize-production-apply` 签发绑定 prepared 的限时授权。

候选和就绪文件的取得方式、依赖与完整 CLI 见[本机签名与发布](bootstrap-inputs.md#production)。这两个入口使用 `--key=value`；签名授权或发布执行开关放在命令末尾。

随后本机运行 `admin/publish-production-approval.mjs`，先预览，再用 `--apply` 和私密环境中的项目 PAT（`CNB_TOKEN`，含 `repo-release:rw`）发布并逐项回读授权，最后才标记 signed。CNB owner 在同一 Tag 批准发布，`tag_deploy.production` 校验签名后调用固定生产入口，使用候选的同一组镜像。原生审批不会替代或生成本机 Ed25519 签名，CI 不接触私钥；已有具体授权仍有效时不要求用户重复确认。

## 7．导出、下载与隔离恢复

已安装 `recovery` 策略时，AI 在授权的短暂停写窗口调用固定 `host/recover-project.py export`，传入项目、环境及 core/policy/recovery-policy 三摘要和唯一 export-id；先预览，`--apply` 才暂停应用、导出数据库与声明目录并恢复源服务。通过已授权 SSH/SFTP 下载私密导出包及回执，核对 archive/manifest 摘要；没有另一个 download 子命令。

完整 export、回执路径读取与下载命令见[离机恢复](bootstrap-inputs.md#recovery)。下载由管理员读取受保护文件，不放宽源端备份权限。

```sh
python3 "$ENV_BUNDLE_DIR/host/recover-project.py" restore-local \
  --archive "$PRIVATE_ARCHIVE" --archive-sha256 "$ARCHIVE_SHA256" \
  --manifest-sha256 "$MANIFEST_SHA256" --destination "$NEW_PRIVATE_RESTORE_DIR"
# 预览后按授权加 --apply；本机须已拉取导出记录中同摘要的 PostgreSQL 镜像。
```

恢复使用与源端不同的本机 Docker daemon、独立卷、无网络/无端口容器，核对全部表、序列和备份目录内容；成功停止隔离容器并保留卷及回执。只有实际恢复对账通过才记录恢复成功；这不是整机或未声明数据的恢复证明。
