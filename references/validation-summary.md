# 公开验证摘要 / Public validation summary

截至 2026-09-11，本文提取已有记录的能力、证据级别和限制。本次发行没有重新执行历史云端演练；安装和使用不依赖私有开发记录。结果只适用于当时的提交、候选、已接受安装和已声明数据，不能替新生成工件补签验收。早期演练的精确身份和摘要保留在[运行包清单](../assets/cnb-tcr-tat/bundle.json)。

This summarizes recorded validation as of 2026-09-11, not a new cloud rehearsal. Evidence applies only to its original commits, candidates, accepted installations, and declared data. The public Skill is independently usable; private development records are not prerequisites. Historical identities remain in the bundle manifest.

## 适用范围与共同限制

固定路线支持 PostgreSQL 16、可选 Redis 7、Ubuntu 24.04 / Linux amd64 和 Docker Compose。无数据库或其他数据库不支持当前首装路线。完整管理端需要类 Unix 环境、Node.js 22、Python 3.12+、Git/SSH；恢复需本地 Unix socket Docker。实操主要来自 macOS/Codex；原生 Windows 不支持完整入口，Linux 桌面、WSL、远程开发及其他 AI 工具的端到端首接尚未验证。

全新账号完整接入、外部新手独立完成和首次接入总耗时仍待验证，不承诺固定分钟数或 token。共享主机只验证同一所有者的声明范围和观测时点，不证明持续负载或跨信任租户隔离。生产仍须使用测试候选的同一镜像并通过项目治理、签名和批准；活动控制器升级有独立流程。恢复仅覆盖声明并实际对账的数据，不自动包含整机、运行秘密、集群角色或外部存储。

<a id="complete-rehearsal"></a>
## 双环境完整演练 — 2026-09-07

第一个已适配项目完成三轮真实双主机重装、测试部署、不可变候选、批准后同镜像生产、每环境 18 项合成业务检查，以及 PostgreSQL 和声明 uploads 的离机恢复。第 3 轮首次无需 Skill 修改或失败重试，在 30 分钟目标内完成；完整固定身份、安装锁、回执摘要和原始计时见清单的 `validation.cloud_evidence`，只对应那一轮已接受安装。

应用此前已完成容器化、迁移、探针和验收脚本适配，账号权限、仓库、TCR、固定命令、Secret、域名及可复用凭据/缓存已经准备。前两轮有修复，第 4 轮在云端接受重装前取消，尚无连续两轮快速成功证据。该计时不是陌生项目或全新账号首接承诺。

恢复在不同 Docker daemon 核对全部 12 张表、schema、序列和 uploads，源服务保持，隔离目标无网络/端口并在验收后停止。业务含真实 PaddleOCR，字段提取为 MockExtractor；未验证真实 MiniMax、完整 H5 UI、租户隔离或生产负载。Redis、可重建 OCR 缓存、整机、运行秘密和集群角色不在本轮恢复范围。第二项目和活动包升级不属于该轮证据。

<a id="later-releases"></a>
## 后续发布、共享主机与续接

| 日期 / 范围 | 已记录的结果 | 验收边界 |
| --- | --- | --- |
| 09-08，第一个项目复用既有 API 资源 | 重新构建、测试、同候选生产、双环境离机恢复通过 | 未验证全新账号、活动包升级或整体提速 |
| 09-09，固定生产与恢复续接入口 | 同镜像生产、双环境业务及 PostgreSQL/uploads 恢复通过；重复续接未重新导出或恢复 | 活动主机仍为原包；无真实 MiniMax、整机恢复或全流程提速结论 |
| 09-09 至 11，第二项目共享主机 | 双环境独立首装、限定的失败测试控制器升级与修复、普通测试更新、同候选生产、业务/页面、时点共存及双环境 PostgreSQL/uploads 恢复 | 同一所有者；不外推任意活动包升级、生产后续更新或持续负载；恢复不含 Redis、运行秘密及整机 |
| 09-11，发布后收尾与新会话接管 | 固定历史生产回查、声明式共存和本地状态同步；新会话从项目索引找到回执并只读接管 | 引用原业务/恢复结果，没有重做验收；不证明持续健康或陌生项目首接 |
| 09-11，项目 CI 与镜像优化 | 保留完整检查时任务执行由 23 次降为 15 次；本机缓存命中/失效及独立镜像运行、真实测试部署和候选通过 | 去重那轮未证明云端提速；后续相邻构建耗时下降的运行/缓存条件未严格控制；没有重做生产、完整在线业务或恢复 |

<a id="unfamiliar-project"></a>
## 陌生项目独立测试接入 — 2026-09-11

第三项目在既有共享主机完成业务适配、新 CNB 私有/Secret 仓库和云配置、独立测试首装、首轮候选、真实 HTTP 业务、登录入口页面、COS 测试前缀读写及 PostgreSQL 离机恢复。用户在官方 Web 保存 Secret，流水线引用成功；两个未授权分支分别引用两文件均被 `allow_branches` 拒绝，脚本未执行。

独立会话做适配和生成，协调会话准备资源、审查及验收，复用既有登录与管理员连接；不是全新账号、空白主机或无人协助测试。流水线用时约 3.11 分钟，前置适配、资源准备、审查和等待另计，不能作为首次接入总耗时。业务/共存/恢复在候选生成后独立完成。本机 annotations GET 缺权被拒绝，候选经 Git annotated Tag 核验，ready 依据 CI 固定 gate 的真实回读，不冒称本机 API 通过。

本轮仅测试环境；短信为模拟码，AI 为规则兜底，浏览器限登录入口。COS 凭据未证明只能访问测试前缀，对象版本、备份恢复未验证。数据库恢复不含 COS、运行秘密或整机。

<a id="tcr-closeout"></a>
## TCR 初始化与测试收尾 — 2026-09-11

新固定入口对第三项目的既有精确 TCR 私有仓库、专用身份、组/策略及密钥文件绑定完成真实只读回查；测试入口核验原固定命令、精确 TAT 任务、已保存候选/Tag 和部署回执。状态收尾复用已绑定业务、页面、共存和恢复证据，重复执行离线复用、状态字节不变，保留原观测时间。

此次没有创建资源、轮转、Registry 登录/推拉、重新部署或重做验收。新 TCR 入口只支持 Personal / ap-guangzhou，从零创建和掉电恢复尚未实测，整体提速未计量。历史回查不证明当前远端 Tag/annotations 或此刻运行状态；TAT 发布身份密钥签发仍由 AI 按[接入契约](api-onboarding.md)调用 API。

<a id="api-and-oidc"></a>
<a id="api-onboarding"></a>
## 官方登录与 API — 2026-09-07

固定 CNB CLI 1.15.18 和 tccli 3.1.162.1 在既有账号/资源上通过两项官方登录、腾讯云完整临时三元组、CNB 已有元数据、TAT 固定命令创建/回读/复用及 CAM 专用用户/精确策略配置。人完成官方页面授权；未签发长期密钥、Invoke 或部署，配置回执明确 deployment_ready 为 false。

默认 CNB CLI 登录即使组织为 Owner，新建仓库仍被 `403/10023` 拒绝，缺 `group-resource:rw`，该固定 CLI 无 `login --scope`。Secret 元数据通过父组织完整列表核对，单仓库 Token GET 被拒绝。登录、角色和 scope 分别核验，不以重复登录修复相同缺权；操作入口见 [CNB OpenAPI](cnb-openapi.md) 和[账号接入](api-onboarding.md)。

<a id="pat-followup"></a>
### PAT 续验 — 2026-09-08

显式私密 `--token-file` 沿用原 spec/journal，成功创建私有及 Secret 验证仓库、读写构建开关并重复 unchanged，仓库 ID 不变。实际经历两次令牌创建/导入和两张非秘密截图，不能宣传一次操作。凭据按指定组织/短期要求交接，但未取得创建后排他范围和有效期的独立回读；API 成功不能替代它。

本轮未写 Secret 内容、推代码、构建、TAT 或生产，不证明全新账号完整接入。执行耗时不含令牌创建导入、前置读取和排障。重复执行无云端写入的判断来自回执及执行器计数，未独立抓包；本地 journal 仍可更新。

<a id="oidc"></a>
### OIDC 的研究边界

09-07 查阅官方文档、Swagger、CLI 和源码，未切换真实流水线。[官方 CNB OIDC 插件](https://cnb.cool/cnb/plugins/market/-/git/raw/main/plugins/tencentcom/tencentcloud-oidc-auth/README.en.md)说明通过流水线身份取得 id_token，再由腾讯云 [AssumeRoleWithWebIdentity](https://cloud.tencent.com/document/product/1312/73070) 换取临时凭据。当前 runner/signer 支持完整 STS 三元组，**OIDC 仍非默认且未完成云端验收**。采用前须按官方当前契约逐项核验：

- CNB 实例启用联邦及事件支持，插件版本/镜像摘要固定。
- 精确限制 issuer、audience 和 `{slug}:{branch或Tag}:{event}` subject，使用环境专用角色，不能只信任公共 issuer/audience。
- 分别验证测试 push、生产就绪 web_trigger、同候选 tag_deploy 的凭据传递、过期和失败行为。
- 保留镜像拉取身份、业务密钥、本机生产签名私钥及原候选/审批约束；OIDC 不自动替代它们。

<a id="local-checks"></a>
## 本地检查与证据级别

内部回归覆盖生成、文件摘要、交易/失败门禁、候选/TAT 绑定、恢复及状态续接；部分 Docker、PostgreSQL 和云 API 使用模拟，不等于真实部署或业务验收。公开包可运行 `python3 scripts/verify-skill-package.py .`，仅用 Python 标准库、无需 Git 历史或私有文件核验发行完整性，不执行云端部署。

独立会话本地评估修正了不适用项目过度准备、生成归属、顺序补生产和 Secret 根级变量交接。复测通过 PostgreSQL 样例生成/复跑、及时停止无数据库路线，以及用户在普通编辑器复制保存假值材料。它是离线评估；第三项目后来的真实 Secret/部署证据单列于上文，不据此宣称外部新手或其他工具首接通过。

来源代码分发权与技术验收分别确认。所有者于 2026-09-11 确认提取部署代码可随 Skill 按 MIT 公开，见[代码来源与授权](../assets/cnb-tcr-tat/dependencies/SOURCES.md)；[第三方许可证](../assets/cnb-tcr-tat/dependencies/THIRD_PARTY.md)保留。历史来源名称和摘要用于追溯，不要求取得源业务项目才能使用 Skill。
