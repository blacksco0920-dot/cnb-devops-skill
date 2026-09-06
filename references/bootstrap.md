# 使用可复用发布包

AI 接入兼容项目时先运行生成器，不重新编写发布控制器。用户只需提供业务选择、完成必须本人操作的步骤；本页的命令和配置由 AI 处理。

当前交付范围：**测试发布和自动候选的本地可复用包**，以及固定 TAT 命令的配置工具。新包尚无云端验收，生产入口保持阻断。支持 Ubuntu 24.04、Docker Compose、已有 PostgreSQL 容器、同仓同提交的应用与发布程序；外部共享网络及 HTTPS 路由需先接通。不兼容时列出具体差异，沿用项目已验收的路径。

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

生成的 `deploy/vendor/cnb-devops/` 包含相同的 CI/主机核心、依赖锁、项目策略、Compose、TAT 命令及工件摘要。`.cnb.yml` 加入本项目的测试与候选阶段，保留无关任务；已有同名任务或被手改的核心会明确阻断。已有项目文档保留，AI 补充本次实际结果。普通配置更新重新预览/应用即可；公共核心升级需检查版本差异，不追随远程 main 自动更新。

构建用 `GIT_SHA`、`BUILD_ID` 两个 Docker build args。每个服务必须暴露精确的发布身份：`schema=cnb-release-identity/v1`、`service`、`git_sha`、`build_id`，可以用随包的 `ci/release-identity.mjs` 生成静态 JSON；动态 API 按配置提供同样数据。`unknown/development` 仅供本地开发，不能通过部署验收。身份文件如何随应用提供是必要的业务适配，不改发布核心。

## 2．一次核对账号和主机

AI 先形成一批具体材料，避免逐个猜测、重复申请：

| 位置 | 材料与核验 |
| --- | --- |
| CNB 业务仓库 | 测试分支、候选 Tag 写入权限；按需接入已有 GitHub 同步工作流 |
| TCR | 各服务镜像仓库；CNB 推送身份与主机只读拉取身份分开 |
| 腾讯云 | 已授权实例和地域、TAT Agent 可用；管理员配置身份与日常 Invoke/Describe 身份分开 |
| 主机 | Docker/Compose、运行用户、项目独立数据库与用户、网络、HTTPS 路由、受保护运行配置及镜像拉取凭据 |
| 应用 | 真实迁移命令或明确无迁移、每服务身份探针、必要业务验收和其他持久数据范围 |

新服务器先盘点预装服务和端口。包内主机安装入口只承担已声明的项目安装边界；它不能替代 Docker、数据库、域名或共享 Caddy 的验收。已有共享主机按[共享 Caddy 契约](shared-caddy-v1/contract.md)接入；日常发布不得改公共入口或删除其他项目资源。

运行秘密通过已有管理员安全通道写入受保护文件，能在主机生成的值就在主机生成。TAT 正文、普通仓库和聊天不承载秘密；不新增凭据网页或传输服务。首次空库与接管现有数据必须显式区分，不能因为找不到历史回执就假定是空项目。

### 安装本项目的固定发布入口

在主机条件已满足、项目数据库确认为空的测试环境，AI 通过已授权管理员通道传入生成的 vendor 目录及私密运行配置。先预览，再按范围安装；工件清单摘要从本机审阅结果单独核对。

```sh
python3 "$HOST_BUNDLE_DIR/host/install-project.py" \
  --bundle-dir "$HOST_BUNDLE_DIR" --runtime-env "$PRIVATE_RUNTIME_ENV"
sudo python3 "$HOST_BUNDLE_DIR/host/install-project.py" \
  --bundle-dir "$HOST_BUNDLE_DIR" --runtime-env "$PRIVATE_RUNTIME_ENV" \
  --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" --apply
```

安装器校验依赖、完整工件、权限和数据库起点，再安装固定程序与显式空库记录；不会创建数据库、重装公共组件或接管已有应用。重复调用不会覆盖运行中的项目配置，内容漂移停止。迁移后的失败保留事务现场，不能自动改回旧镜像假装恢复。以上新增安装路径仅有本地模拟验证，干净云主机实测仍未完成。

## 3．配置固定 TAT 命令

将生成的 `tat-spec.template.json` 复制到本机任务私密目录，AI 从已授权盘点结果填写 `target.region` 和 `target.instance_id`。模板故意没有真实云目标；不能直接拿空模板创建命令。其正文、程序/策略/Compose 摘要已生成，避免人工拼接。

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

## 4．人只完成必须的控制台步骤

AI 按 `secrets.tcr_import`、`secrets.tat_import` 准备 CNB Secret 文件结构、引用范围及校验步骤：

- TCR 文件提供 `TCR_USERNAME`、`TCR_PASSWORD`。
- TAT 文件提供 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`、`CNB_TAT_BINDING_JSON`，后者来自上一步受保护绑定。
- 候选 Tag 使用该仓库受支持的 `CNB_TOKEN`，可选 `CNB_TOKEN_USER_NAME`；不把管理员云凭据用于 Git 推送。

[CNB Secret](https://docs.cnb.cool/zh/repo/secret.html)要求在 Web 编辑，不能用 Git 本地推送替代。用户完成实名、验证码及这类没有可用 API 的配置，AI 负责材料和验收。这里不依赖 AI 操作浏览器；普通终端、Git、HTTP/API 能完成其余已支持步骤。

## 5．发布、续接和验收

主机安装及权限核验通过后，按项目授权推送测试分支。CNB 自动执行检查→构建/TCR→TAT→运行与公网核验→候选 Tag→annotations 回读，最后才设 ready。只修失败阶段的实际问题；不手工创建候选绕过流水线，不把 TAT SUCCESS 单独当成验收。

依赖使用锁文件、配置的国内 npm 源和已有缓存；不会在发布前清理全局镜像缓存。首次依赖/镜像下载与后续缓存命中的时间分开记录；缓存不能替代同提交检查或镜像 digest。

后续会话只读项目的 `docs/DEPLOYMENT.md`、`docs/PROJECT_STATUS.md`，再按当前阶段读取固定工件和最新证据。状态分别记录首装、新项目开通、测试、候选、生产、恢复、升级和中断；未运行的项写“未验证”，不引用来源项目的历史成功充当本项目成功。

本包的版本、来源、缺口和实际验证范围以 [bundle.json](../assets/cnb-tcr-tat/bundle.json)为准。来源应用代码的外部分发许可尚未记录；当前提取用于本地验证，正式开源发布前需完成代码归属核对。
