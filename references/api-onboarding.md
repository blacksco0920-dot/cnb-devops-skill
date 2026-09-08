# 用官方登录和 API 接通账号

供 AI 在首次接入、增加项目或登录过期时使用；业务适配、主机安装及发布仍走[标准工作流](standard-workflow.md)。先读项目的部署与状态记录，复用有效登录、资源和阶段回执。这里的命令、JSON、权限和私密文件全部由 AI 处理，用户不需要理解或填写。

## 1．准备工具，复用登录

使用项目已有私密目录 `PRIVATE_DIR`（0700）和独立工具目录 `TOOLS_DIR`，实际路径由 AI 选择并记录，不进普通仓库。Node.js 22、Python 3.12+；复用已安装且版本匹配的工具，不每次重装。初次安装：

```sh
umask 077
npm install --prefix "$TOOLS_DIR/cnb" --ignore-scripts --save-exact @cnbcool/cnb-cli@1.15.18
CNB_BIN="$TOOLS_DIR/cnb/node_modules/.bin/cnb"
python3 -m venv "$TOOLS_DIR/tencent"
SESSION_PYTHON="$TOOLS_DIR/tencent/bin/python"
# 仅使用官方 OAuth 模块，无需为登录下载全套云服务 SDK。
"$SESSION_PYTHON" -m pip install requests==2.32.5 six==1.17.0
"$SESSION_PYTHON" -m pip install --no-deps tccli==3.1.162.1
```

已有 CNB 登录可用时直接做资源预览；已有获准且适用的私密初始化令牌时，直接使用[令牌入口](#cnb-bootstrap-token)，无需再做 CNB OAuth 登录。确实需要登录时，AI 启动以下命令，让人只在命令提供的**官方页面**完成本人登录授权。腾讯云使用项目专用 profile，不能覆盖 default；不要另开凭据收集网页或让用户把令牌发到聊天。

```sh
"$CNB_BIN" login --host cnb.cool
"$SESSION_PYTHON" "$SKILL_DIR/scripts/tencent-session.py" \
  --profile "$PROJECT_BOOTSTRAP_PROFILE" --login
```

腾讯云入口复用固定版本的官方登录及刷新模块：恢复 HTTPS 证书校验、关闭 OAuth HTTP 重定向、将官方回调限制到本机，并只输出登录页面和结果。登录最长等待十分钟；本人验证未完成时续接登录，不重建资源。普通浏览器即可，不依赖 AI 操控浏览器。无本机浏览器的远程终端仍需已有受保护凭据或组织支持的登录方式，本入口不让用户把官方手动模式返回的完整授权内容贴进聊天。

AI 检查官方存储目录与文件权限（目录 0700、凭据 0600），关闭调试输出，不读取到会话或复制完整 profile。OAuth 登录不是任意资源的管理员授权，后续 API 仍核验实际账号权限。

执行本次云配置前，导出短期三元组；`--refresh` 让官方模块按本次所需有效期刷新。文件名使用本次新名称，保留既有凭据直到其消费者已切换；输出不覆盖现存文件。

```sh
"$SESSION_PYTHON" "$SKILL_DIR/scripts/tencent-session.py" \
  --profile "$PROJECT_BOOTSTRAP_PROFILE" --refresh \
  --min-validity-seconds 900 --output "$PRIVATE_DIR/bootstrap-credentials.json"
```

只有 `secretId/secretKey/token` 写入 0600 文件；刷新令牌留在官方本机存储。状态记录导出的到期时间与用途。该临时身份用于本机初始化，不能原样放入流水线当作长期运行身份。预估操作超过十五分钟时提高最短有效期；权限有效期不足就先续接登录。

## 2．自动准备 CNB 仓库和构建设置

**先区分登录与写权限。** 2026-09-07 实测，官方 CLI `1.15.18` 默认 `cnb_cli` 登录可读取本次组织和已有仓库，但创建返回 `403/10023`，缺少 `group-resource:rw`。该版本没有 `login --scope`；重复登录、刷新或账号已经是 Owner 都不能据此获得缺失权限。创建和构建设置写入不能仅凭登录成功判为可用。

AI 从已选组织与项目配置生成如下非秘密 spec，业务仓库明确 `private`、密钥仓库明确 `secret`。首次准备可暂不开启自动触发，Secret 与主机就绪后再将所需开关设为 true；保留其他开关现状。

```json
{
  "schema_version": 1,
  "repositories": [
    {"slug": "example/app", "visibility": "private", "build_settings": {"auto_trigger": false}},
    {"slug": "example/app-secrets", "visibility": "secret"}
  ]
}
```

```sh
node "$SKILL_DIR/scripts/configure-cnb.mjs" \
  --spec "$PRIVATE_DIR/cnb-spec.json" --cnb-bin "$CNB_BIN" \
  --state "$PRIVATE_DIR/cnb-state.json"
# 已授权且预览符合本项目范围时，用相同输入加 --apply。
```

预览只读；应用前核对所有目标，再在权限允许时创建缺失仓库或更新明确请求的设置并回读。已有正确资源复用；类型、归属或权限不符即停止。Secret 的单仓库详情接口拒绝 Token 访问，配置器改用父组织仓库列表完整分页核对路径、类型和 ID，并明确记录父组织 Owner/Master 权限依据；不把列表返回的 `access: Unknown` 伪装成仓库角色。

持久状态在创建前落盘，不确定结果先回查，不重复 POST。明确的平台拒绝且重新确认不存在时，配置器才解除本次 pending；超时、5xx 或回查失败仍保留。始终使用同一 `cnb-state.json`；`CREATE_RECONCILIATION_REQUIRED` 需要核对云端结果，不能删状态重试。进程中断遗留 `.lock` 时，AI 先确认原进程已结束，再清理锁，保留状态文件。

执行器默认核对官方登录的主机与凭据文件权限，使用 CLI 自己的刷新；显式 `--token-file` 则只使用该文件的值，不要求 OAuth profile。两种方式都固定访问官方 API，清除意外继承的 CI/其他助手 token；不因失败自动更换身份。组织须已经存在；公开 `POST /groups` 可创建组织，但需要另行核对该操作权限，本配置器不创建组织。

出现 `CNB_SCOPE_REQUIRED` 时，记录 `required_scopes` 与失败步骤，停止相同权限下的写重试。在已有授权内复用或准备下述初始化令牌，然后使用同一 spec 和状态文件重新预览；不要删 journal、反复登录或让用户学习 scope。没有可用初始化令牌且用户不准备新令牌时，才集中交接必要的官方网页创建/设置。Secret 内容仍仅走官方 Web 保存。

<a id="cnb-bootstrap-token"></a>
### 初始化令牌：一次交接，继续自动配置

个人访问令牌可用于公开 API；CNB [官方 Terraform 工具](https://cnb.cool/cnb/sdk/terraform-cnb)也采用该方式创建仓库。这是默认 OAuth 缺权时的显式后备入口，不是新增一套部署流程。

AI 先检查现有批准的凭据和有效期。确需新增时，在[官方令牌页](https://cnb.cool/profile/token)准备名称、较短有效期及下表选项，给用户具体操作；不套用包含删除等额外权限的通用预设。已选组织下的完整仓库配置需要：

| 操作 | 所需权限 |
| --- | --- |
| 查询组织与仓库、创建私有/Secret 仓库 | `group-resource:rw` |
| 回读普通仓库信息 | `repo-basic-info:r` |
| 读取并修改构建设置 | `repo-manage:rw`；不操作构建设置时省略 |

资源范围必须覆盖已选组织的创建动作和新仓库回读。公开资料未确认“指定尚不存在的仓库”或“指定组织自动包含未来仓库”的限制方式，不能承诺已做到；AI 核对官方页面实际可选范围，若超出已有授权则先准备清楚实际范围再交接。凭据仅用于本机初始化，不放进流水线充当日常身份。AI 私下记录实际范围、到期时间及用途；文件保存成功不能证明这些信息。

用户在官方页面创建后，通过本机安全入口导入一次。AI 在用户可交互的终端准备以下命令，用户只粘贴令牌并回车；输入不回显、不会进入命令历史或聊天。已有安全存储可直接提供符合要求的文件，不重复导入。

```sh
python3 "$SKILL_DIR/scripts/save-cnb-token.py" \
  --output "$PRIVATE_DIR/cnb-bootstrap.token"

node "$SKILL_DIR/scripts/configure-cnb.mjs" \
  --spec "$PRIVATE_DIR/cnb-spec.json" --cnb-bin "$CNB_BIN" \
  --state "$PRIVATE_DIR/cnb-state.json" \
  --token-file "$PRIVATE_DIR/cnb-bootstrap.token"
# 预览符合既有授权时，同样的命令加 --apply；不要丢弃状态文件。
```

保存器只接收交互终端的隐藏输入，不接受值参数、管道或环境变量；无可交互终端时使用宿主已有的受保护凭据导入通道，两者都不可用就集中交接必要的官方网页创建/设置，不改成聊天粘贴或要求用户自行寻找工具。父目录须为本人所有的 0700 目录，文件为 0600 的单链接普通文件，不能是符号链接。格式为单行原始令牌，可带一个末尾换行；不需要用户写 JSON。输出不覆盖已有文件；轮换用新路径，确认消费者切换后处理旧凭据。

配置器只向本次 CLI 子进程注入文件值，保留原 OAuth 存储；所选文件无效、过期或缺权时只报告当前失败，不回退到另一身份。原始令牌不包含本入口可核验的授权/到期证明，实际权限仍由 CNB 判断。范围或到期信息缺失时记为 unknown，先做同身份只读预览，只补影响当前操作的非秘密授权事实或必要官方操作；预览成功不证明写权限或有效期，不因此重登。服务端已确认拒绝的创建与结果未知的创建继续按同一 journal 规则处理。

当前公开接口没有已核实的个人令牌自动签发或网页预填契约，不承诺免除这次人工创建与安全导入。[统一申请 OAuth 应用](https://docs.cnb.cool/zh/oauth/developer.html)可作为维护者后续方向，不能让每个使用者自行申请。此入口须经真实 PAT 创建与回读验收，才能记录云端通过。

## 3．接通固定 TAT 与专用云身份

先按[主机首装](bootstrap.md#2一次核对账号和主机)完成盘点和安装。AI 从生成的每环境 `tat-spec.template.json` 填入已选实例与地域，使用上述临时身份运行[固定 TAT 配置](bootstrap.md#3配置固定-tat-命令)，传入 `--credentials "$PRIVATE_DIR/bootstrap-credentials.json"`。

配置器先核对对应地域的实际 CVM/Lighthouse 实例、RUNNING 状态和 Linux TAT Agent 在线，再创建或复用命令。缺失、离线或权限不足会给出明确阶段码，不产生成功绑定。在线检查只证明云实例与 Agent 可用；主机工件、实际发布和公网业务仍分别验收。

发布程序维护沿用版本化入口：同版本同内容复用，内容漂移停止；新版本新建命令并审阅新绑定。普通发布身份只允许固定命令作用于固定实例。`ModifyCommand`、`DeleteCommand` 虽有公开 API，也不能静默修改活动绑定；旧命令退役需确认所有消费者与定时调用已经解绑，本轮不自动退役。

新建日常发布身份时，AI 用 `scripts/configure-cam.mjs` 从已核对的 TAT 绑定准备专用用户和策略。其 spec 字段为：

| 字段 | AI 填写依据 |
| --- | --- |
| `schema_version`、`project`、`environment` | 版本 1、当前项目 ID 与 test/production 环境 |
| `account_id` | 主账号 ID 字符串；执行时与 STS `GetCallerIdentity` 回读核对 |
| `user_name`、`policy_name` | 本项目专用名称，均以 `<project>-<environment>-` 开头，总长不超过 64 |
| `target.region`、`target.instance_id`、`target.command_ids` | 当前环境绑定，单实例、一至两个固定命令；不允许任意命令或实例通配 |

```sh
node "$SKILL_DIR/scripts/configure-cam.mjs" --spec "$PRIVATE_DIR/cam-spec.json"
# 在已有专用身份配置授权内执行；完整结果留在私密目录。
node "$SKILL_DIR/scripts/configure-cam.mjs" --spec "$PRIVATE_DIR/cam-spec.json" \
  --apply --credentials "$PRIVATE_DIR/bootstrap-credentials.json" \
  --sdk-root "$PROJECT_DIR/deploy/vendor/cnb-devops/dependencies" \
  > "$PRIVATE_DIR/cam-identity.json"
```

它仅创建无控制台登录的专用用户、固定 Invoke/Describe 策略及关联，并回读账号、策略、组权限和已有密钥；不接管不符的同名身份，也不修改已有密钥。`verified` 仅指身份/权限，`credential_status: not_created` 和 `deployment_ready: false` 明示后续工作。初始管理员需有本次 CAM 创建、关联及查询权限；现成且已验收的发布身份直接复用其回执和凭据，不因该脚本拒绝已有密钥而重建。

本轮没有自动签发长期 AccessKey 的执行器。采用专用直接身份时，**后续仍由 AI** 在已授权安全通道调用官方 [CreateAccessKey](https://cloud.tencent.com/document/api/598/82370)，显式设置 `CreateAccessKey.TargetUin = cam-identity.user_uin`，不得省略而为当前管理员创建密钥；返回的 `AccessKeyId/SecretAccessKey` 直接保存为私密 `secretId/secretKey`，不让用户抄密钥。写前持久记录该签发动作；未知结果先 [ListAccessKeys](https://cloud.tencent.com/document/api/598/45156) 核对并进入恢复处理，不能因暂时查不到密钥就重发。成功后核验实际固定命令权限，再交给对应 Secret 消费者。管理员 OAuth 会话与日常发布身份不能混用。

## 4．把剩下的动作一次准备好

AI 汇总所需 Secret 文件、变量名、允许引用的仓库/ref/event、准确页面和安全存储位置。按[Secret 保存交接](human-handoffs.md#cnb-secret-repository-operation)让人完成官方 Web 保存，再做无害引用验证；人不手写 YAML、不设计权限、不整理回执。仅把已确认无法通过当前授权通道完成的 CNB 创建/设置合并到这次交接；TAT 脚本与专用身份权限由 AI 配置。

仅凭生成文件或 API 成功不能报告流水线完成。当前进度记录：已发现/创建的资源及私密回执位置、Secret 是否已保存和验收、目标就绪状态、凭据到期时间、下一步；用户动作次数与实际等待时间分开记录。之后只继续失败或未完成阶段。

## 临时凭据与 OIDC 的当前范围

测试发布、生产执行及本机签名核验共用的 TAT 客户端已支持完整 `SecretId/SecretKey/Token`。环境变量可用 `TENCENTCLOUD_TOKEN` 或 `TENCENTCLOUD_SECURITY_TOKEN`；同时提供时必须相同，空值或冲突会拒绝执行。短期凭据的有效期应覆盖整个操作窗口。

这只是临时凭据兼容，**尚未把 OIDC 设为新项目默认**。正式接入还需固定官方插件版本/镜像摘要，核验账号已启用联邦，建立环境专用角色和精确 subject 信任，并分别验收测试 push、生产就绪及同候选生产部署。参见[已核实的 OIDC 条件](../docs/history/2026-09-07-api-onboarding.md#进一步减少长期云密钥oidc)。现有 Secret、审批、镜像拉取身份和生产签名私钥的职责保持独立。

接口依据：[CNB 官方 CLI](https://docs.cnb.cool/zh/develops/cnb-cli.html)、[CNB Swagger](https://api.cnb.cool/swagger.json)、[腾讯云 CLI 登录](https://cloud.tencent.com/document/product/440/111345)、[官方 OAuth 实现](https://github.com/TencentCloud/tencentcloud-cli/blob/master/tccli/oauth.py)。[本轮真实 API 验证](../docs/history/2026-09-07-api-live-validation.md)覆盖登录及部分配置，不替代完整的新账号接入和部署验收。
