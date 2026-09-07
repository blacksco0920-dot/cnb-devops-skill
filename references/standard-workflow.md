# 标准工作流：CNB → TCR → TAT

首次接入和新增项目先读本页。目标是复用已验证的阶段和工件，只适配业务差异；日常构建、部署和 Tag 生成由流水线执行。接入说明和当前进度分别落到业务仓库的 `docs/DEPLOYMENT.md`、`docs/PROJECT_STATUS.md`，不另建流程平台。

## 本版范围与证据

0.2 包已完成 FinAgent 首轮真实重装、测试与候选、同镜像生产、业务与离机恢复，耗时及限制见[完整演练](../docs/history/2026-09-07-complete-rehearsal.md)。首轮含修复，快速稳定复用与第二项目云端接入仍待验证。日常接入只需要 Skill 与项目差异，不读取 ecat 或旧私密脚本。

## 一次性接入

1. **读项目并列差异。** 从已有配置确定服务清单、Dockerfile/构建上下文、验证命令、运行端口、数据存储、源码同步路径；再确定测试/受控分支、候选前缀、TCR 镜像命名和目标环境。人只补账号、域名、本人验证和生产意图；可从项目或已有授权查到的信息不重复询问。
2. **先复用再适配。** 先运行包内生成器；已有项目则核对下表对应工件、版本、依赖和验收记录。列出“直接复用／参数适配／缺失”及原因；同一阶段已有合用实现就不重写。目标、路径和允许镜像仓库仍由项目批准的固定配置约束，不能变成任意流水线输入。
3. **接通基础条件。** AI 从一份配置 prepare 双环境，用私密 SSH 目标和已审摘要运行 `scripts/setup-host.py`，再配置各环境固定 TAT、TCR 推拉权限和 Secret。生产配置只含批准公钥，私钥留本机；本机授权发布 PAT 需目标仓库的 `repo-release:rw`。新主机先盘点预装服务，已有共享主机按[接入分类](project-adoption.md#host-and-account-classification)处理。
4. **完成必须的人为操作。** 按[人员交接](human-handoffs.md)给出实际页面、已备材料、一个动作和完成标志。本人登录/实名、没有可用 API 的 Secret 控制台配置、项目规定的审批由人完成；不要让人写命令、设计权限或整理技术回执。已完成的操作不重复要求。
5. **先通测试路径。** 用 Git、受支持的 API/CLI 发起已授权构建并核验结果。普通终端可完成的动作不依赖 Computer Use；浏览器不可控时保留同一流程，仅将必要控制台操作交给人，不为切换工具重建凭据或控制程序。

| 包内入口 | 复用内容 | 新项目需要适配 |
| --- | --- | --- |
| `scripts/prepare-project.py`、`scripts/setup-host.py` | 双环境生成、SSH 串联固定首装入口 | 项目配置、私密目标、APT/镜像摘要和 Caddy 基线 |
| `ci/run-tat-release.mjs`、`host/tat-deploy-test.py` | 固定命令回读、发布事务及运行/公网核验 | 服务、迁移、探针、目标绑定与环境隔离 |
| `ci/candidate_manifest.py`、`ci/publish-candidate-tag.sh` | 完整镜像清单、不可变候选及 annotations 回读 | 项目仓库、候选前缀及受控分支 |
| `admin/sign-production-approval.mjs`、`admin/publish-production-approval.mjs` | 本机独立核验就绪、签名及发布授权 | 生产意图、私密签名密钥与限定仓库的本机 PAT |
| `ci/run-production-deploy.mjs`、`host/production-release.py` | 生产回执核验、固定公钥验签并复用部署核心 | 已批准候选、prepared 与各环境固定工件摘要 |
| `host/recover-project.py` | 导出及不同 Docker daemon 上的隔离恢复 | 数据目录分类、非空表要求、导出包与回执摘要 |

表中 `scripts/` 属于 Skill，`ci/admin/host` 随包生成。AI 在已有授权范围内操作代码、命令和回执，不要求人手写配置；不复制来源项目的凭据、目标 ID 或当前发布状态。

## 接通后由流水线执行

| 阶段 | 输入与执行者 | 产物及完成条件 |
| --- | --- | --- |
| 1．检查 | 测试分支 push；CNB 运行项目验证 | 该完整提交的真实检查结果；失败即停止后续构建/发布 |
| 2．构建与推送 | CNB 构建每个应用服务一次并推送 TCR | 同一构建的完整 `repository@sha256:digest` 映射；数据库/缓存镜像另由 bootstrap spec 固定 |
| 3．测试部署 | CNB 调用已配置的固定 TAT 命令 | 回读 invocation、服务器实际镜像和健康状态；不是只看调用返回成功 |
| 4．测试验收 | 已配置的运行、公开访问与业务探针；AI 核对证据 | 构建、运行、公网证据分别通过；mock、数据和恢复范围如实记录 |
| 5．候选 | CNB 在上述成功后生成 `<项目候选前缀>-<构建ID>` | 创建不可变 Tag，绑定清单与完整镜像集，annotations 回读后最后设 ready |
| 6．生产门禁 | main（或配置的生产分支）纳入候选提交；Tag 就绪→本机 sign/publish→CNB owner 批准 | 签名绑定候选、prepared 和时限；原生 owner 批准不会生成 Ed25519 签名，CI 无私钥 |
| 7．生产执行与验收 | 已授权的部署事件再次检查门禁，再调用固定生产命令 | 使用测试过的同一组 digest；核对实际运行、公开业务及所需备份恢复证据 |
| 8．恢复验收 | 授权短暂停写 export，SSH/SFTP 下载，再运行 restore-local | 不同本机 Docker daemon、无网络/无端口；数据库及声明备份目录对账，保存真实恢复回执 |

生成器按测试分支接 push，候选 Tag 下使用 `web_trigger_production_readiness` 和 `tag_deploy.production`。候选创建是成功流水线的一步；本机 publisher 只发布已签的生产授权，不代替流水线创建候选。具体命令与私密输入见[接入步骤](bootstrap.md)。

门禁细节按需读[CNB 部署页面](cnb-deployment-ui.md)、[发布安全](release-safety.md)。现有 [production-gates 示例](cnb-deployment-ui/examples/candidate-production-gates.yml)是契约示例，内含阻断占位，不能拿它充当已适配的生产执行器。

## 下一次发布与故障续接

- 日常发布复用已接通的事件、脚本、身份和固定命令；AI 主要处理项目变更、发起已授权动作、核对结果和定位异常。
- 下一会话只先读两个项目文档与当前阶段所需的回执。成功步骤不重做；配置或证据确实失效时只重验受影响部分。恢复阻断按发布安全规则处理，不能跳过。
- 失败停在实际边界，先修最小问题。例如 TCR 已推送而主机拉取失败，应检查主机网络和拉取权限，不重新构建应用。
- 生产复用包内签名与主机验证，不另建控制仓库或服务。兼容性不足时只说明具体缺口，不把新框架混入普通接入。
- 当前状态记录阶段耗时、人工介入、直接复用与新增工件，工具可提供时记录 token 用量。缺失数据标未采集，不估造；本地检查数量不代替云端成功或效率证据。
