# 公开 API 与低操作成本接入研究

2026-09-07。仅核验公开文档、Swagger、官方 CLI/插件源码与本包实现；没有登录业务账号、创建资源或切换发布鉴权。本记录用于后续实施，不作为新流程已上线的证据。

结论：仓库创建、构建开关和 TAT 脚本管理可以通过公开 API 自动执行；CNB Secret 文件编辑仍需保留官方支持的 Web 路径。官方 CLI 登录及 OIDC 提供了进一步减少人工凭据操作的途径。用户只应处理账号授权、无法推断的资源/业务选择和正式发布决定，技术配置由 AI 完成。

## 已核实的能力与边界

| 操作 | 官方接口或入口 | 对接入的影响 |
| --- | --- | --- |
| 创建 CNB 密钥仓库 | `POST /{slug}/-/repos`，`visibility: "secret"`，`group-resource:rw` | AI 创建并回读仓库类型；不能遗漏 visibility 而使用公开仓库默认值 |
| 创建组织、配置构建 | `POST /groups`；`GET/PUT /{repo}/-/settings/cloud-native-build` | 已授权时可由 AI 读取现状并配置所需部分；对应 `group-manage:rw`、`repo-manage:r/rw`，仍受账号角色约束 |
| 写入 Secret 文件 | 官方手册要求受审计的 Web 编辑；当前公开 Swagger 未提供完整写入契约 | AI 准备内容与精确页面，人员完成必要保存；不能承诺公开 API 已替代该步骤 |
| 管理 TAT 脚本 | `CreateCommand`、`DescribeCommands`、`ModifyCommand`、`DeleteCommand` | 创建、核对、维护和退役均有 API；不需要用户手写脚本或逐项配置控制台 |
| 执行并检查 TAT | `InvokeCommand`、`DescribeInvocations`、`DescribeInvocationTasks` | 调用和实际完成分别验证；本包已有实现，继续复用 |
| 查询 TAT 就绪 | `DescribeAutomationAgentStatus`，配合 CVM/Lighthouse 实例查询 | 自动识别 Agent 是否在线。离线 Agent 无法执行安装自己的命令，缺失时需已有管理员通道 |
| 初始化专用云身份 | CAM `AddUser`、`CreatePolicy`、`AttachUserPolicy`、`CreateAccessKey` | 最初取得有权限的管理员登录后，可自动准备限定用途的身份及策略；不会从无权限账号自动获得授权 |

CNB 依据为[公开 Swagger](https://api.cnb.cool/swagger.json)和[密钥仓库手册](https://docs.cnb.cool/zh/repo/secret.html)。本次 Swagger 摘要为 `aeabebcca0d030179c8ddf2ca6164d65fea7372773e2fe03990b62e0e0220f5a`。通用 blob 创建并不等于完整 Secret 文件写入；单次 `build/start` 的 `env` 也不是持久密钥存储。前端内部提交和 PAT 创建接口未列入公开契约，不作为通用 Skill 的默认依赖。

TAT 官方说明：[API 概述](https://cloud.tencent.com/document/product/1340/52695)、[修改命令](https://cloud.tencent.com/document/api/1340/52677)、[权限粒度](https://cloud.tencent.com/document/product/598/70026)、[Agent 安装](https://cloud.tencent.com/document/product/1340/51945)。调用要求实例运行且 Agent 在线；CVM 与 Lighthouse 不混入同一次执行请求。未在已核公开目录找到通用的 Agent 安装 Action，控制台一键安装不能直接视为公开 API。

CAM 对应入口：[AddUser](https://cloud.tencent.com/document/api/598/34595)、[CreatePolicy](https://cloud.tencent.com/document/api/598/34578)、[AttachUserPolicy](https://cloud.tencent.com/document/api/598/34579)、[CreateAccessKey](https://cloud.tencent.com/document/api/598/82370)。密钥直接进入受保护存储，不输出到会话；已有合用身份与授权应复用。

## 减少手工创建和复制令牌

- **CNB：**官方 CLI 的 `cnb login` 使用 OAuth2 设备授权。AI 启动命令，用户在官方页面完成登录和授权；日常 OpenAPI 操作可交给 CLI。本次检查官方 npm 包 `@cnbcool/cnb-cli` 的 `1.15.18` 版本，它保存登录凭据并支持刷新。实际权限仍需回读，不能假定一次登录获得任意组织或操作权限。[官方 CLI 文档](https://docs.cnb.cool/zh/develops/cnb-cli.html)
- **腾讯云：**`tccli auth login` 支持浏览器授权和独立 profile。官方源码包含 OAuth 登录、临时云凭据及刷新处理，期限以服务返回为准；无需把手工复制长期 SecretKey 作为唯一初始方案。[官方用法](https://cloud.tencent.com/document/product/440/111345)、[官方实现](https://github.com/TencentCloud/tencentcloud-cli/blob/master/tccli/oauth.py)

复用官方登录入口，无需自行建设登录网页或托管用户密钥。选定发行版本后仍需验证凭据落盘、权限和错误输出；关闭 debug，不将完整 profile 或刷新令牌交给流水线。所查 TCCLI master 存在关闭 TLS 校验的调用，接入前须核对所选发行版，不能照抄其内部 HTTP 请求。

官方 CLI 有登录能力，不等于现有部署脚本自动兼容其凭据文件。本机身份初始化、CI 日常身份与生产签名私钥分别处理；不因登录成功而跳过项目的正式发布批准。

## 进一步减少长期云密钥：OIDC

CNB 官方插件市场提供 `tencentcom/tencentcloud-oidc-auth`。其公开说明给出：流水线用 `CNB_TOKEN` 调用 `POST /{repo}/-/id_token`，再通过腾讯云 `AssumeRoleWithWebIdentity` 换取临时凭据。该入口在本次通用 Swagger 中未列出，但有官方插件的专项文档，不能与未经说明的网页内部接口混为一谈。[官方插件说明](https://cnb.cool/cnb/plugins/market/-/git/raw/main/plugins/tencentcom/tencentcloud-oidc-auth/README.en.md)、[腾讯云 STS 接口](https://cloud.tencent.com/document/product/1312/73070)

这可以减少 CNB 中长期保存腾讯云 SecretId/SecretKey 的需要。接入应由 AI 配置身份提供商、环境专用角色和权限，信任条件绑定实际仓库、分支或候选 Tag、事件；流水线只得到该环境所需的临时权限。生产仍使用已测试候选及既有审批和验签流程。

需要先验收的具体条件：

- CNB 实例已启用 OIDC 联邦；官方插件限制发令牌的事件。本项目的测试 push、生产就绪 web_trigger 与生产 tag_deploy 要分别核对实际声明。
- 精确限制 issuer、audience 和 subject；subject 按 `{slug}:{branch或Tag}:{event}` 匹配，不能只信任公共 issuer/audience。
- 固定插件版本/镜像摘要，确认临时凭据的传递、过期刷新及失败行为；当前 runner 和 signer 未传递 STS Token，需要适配并验证。
- OIDC 替代云端访问凭据，不自动替代镜像拉取身份、业务外部服务密钥或本机生产签名私钥，也不证明所有 Secret 文件都能删除。

## 建议的最小实施顺序

1. **接入官方登录与已有公开 API。** AI 安装/校验 CLI，复用登录；自动创建或发现组织、业务/密钥仓库、构建设置、专用云身份与固定 TAT。先读现状，成功步骤和有效权限不重复建立。
2. **补齐 TAT 维护及就绪检查。** 复用现有 `configure-tat.mjs` 的创建/回读和既有发布 runner；发布命令优先按版本新建并更新已审绑定，修改或退役时核对原摘要、依赖和实际主机。已在线 TAT 可用于授权范围内的管理员盘点和首装通道准备，减少用户手工配置 SSH；这种管理员操作不扩展日常发布权限。API 能修改命令不代表随意修改后就能继续发布。
3. **验证 OIDC 接入。** 先跑最小临时凭据与固定命令检查，再覆盖测试、生产就绪和同候选发布。验收通过后再把它作为新项目默认；保留现有已验证部署的路径。
4. **压缩确实无法代办的动作。** 每次给用户一个清楚的页面和动作：登录/本人验证、确认资源用途、必要的 Secret 保存或正式发布批准。不要求填写 JSON/YAML、理解权限术语或整理技术回执。

验收应记录实际需要用户操作的次数、原因和等待时间；不承诺所有账号永久只授权一次。用普通终端即可执行的步骤不依赖浏览器自动化；中断后从实际失败步骤继续，不重复全套接入。
