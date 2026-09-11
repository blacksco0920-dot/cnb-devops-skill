# 发布后核验与收尾

用户完成原生批准后，AI 使用本文的固定入口取得结果，并更新项目原有状态文档。用户无需填写 JSON、阅读脚本或重新提供已经保存的配置。

三个入口分别回答：发布当时是否正确完成、共享主机在观测时是否符合预期、项目当前还缺哪些验收。业务和页面检查仍由应用自己的验收程序负责。

## 1. 核验已经发生的生产发布

沿用[发布会话](bootstrap-inputs.md)的同一份 spec、目录、候选及凭据。先从实际生产流水线结果取得 TAT `invocation_id`，不能用就绪检查的执行 ID 或测试构建 ID 代替。

```sh
node scripts/release-session.mjs verify --spec "$RELEASE_SPEC" --invocation-id "$PRODUCTION_INVOCATION"
node scripts/release-session.mjs verify --spec "$RELEASE_SPEC" --invocation-id "$PRODUCTION_INVOCATION" --apply
node scripts/release-session.mjs status --spec "$RELEASE_SPEC"
```

默认预览离线；`verify --apply` 只读 TAT Describe、CNB annotations，并保存本地证据，不触发发布。它交叉核验实际目标、固定命令、完整请求、候选镜像、签名、执行起止时间和生产回执。证据缺失、截断、失败或绑定不符都会停止。

结果写入会话目录的 `deployment-verification/receipt.json`，schema 为 `cnb-deployment-verification/v1`，同目录保存七份有摘要绑定的原文。第一次完成后，重复核验保留原回执；`status` 离线重验已保存证据，返回 `verified / next_action: none`。

**已经完成的执行，按实际执行窗口判断当时授权是否有效。** 今天授权过期不应让 AI 重新申请批准或重新部署；新的 `sign`、`publish` 仍须通过当前有效期门禁。若还没有完成证据，不能仅凭用户说“已批准”就宣称发布成功。

这份回执证明历史发布，不证明主机此刻仍运行该版本。当前运行情况由下一步观测补充。

## 2. 声明共享主机的共存检查

```sh
python3 scripts/verify-coexistence.py --spec "$COEXISTENCE_SPEC"
python3 scripts/verify-coexistence.py --spec "$COEXISTENCE_SPEC" --apply
```

AI 从已验收安装、固定主机策略、候选和变更前盘点生成私密 spec。自己的应用容器允许替换；邻居容器、本项目数据库/Redis、共享入口及控制文件必须保持声明的基线。不要把变更后的盘点冒充变更前基线，也不要为了检查通过而更新预期值。

spec 文件路径必须为绝对路径，顶层 `schema` 为 `cnb-coexistence-spec/v1`。下表字段全部必需，除后述可选 `observation` 外不接受额外字段。`{path, sha256}` 均指绝对路径及文件原字节 SHA256，不能对原文重新序列化后计算引用摘要。新建私密目录权限 0700、输入文件 0600；已有策略、SSH 密钥和 known-hosts 文件沿用入口允许的受保护权限，不为适配而改写。

| 字段 | AI 取值来源 |
| --- | --- |
| `project`、`environment` | 本次待核验的主机策略身份；生产使用 production |
| `application_commit`、`build_id` | 已核验候选的原始提交与构建身份 |
| `target` | 已登记目标文件的 `{path, sha256}` 引用；文件内容恰为 `host`、`port`、`user`、`identity_file`、`known_hosts_file`，后两项为已有文件的绝对路径 |
| `policy`、`candidate`、`baseline` | 固定主机策略、完整候选、归一化基线，各自使用路径和摘要引用 |
| `evidence_dir` | 仓库外尚不存在的私密证据目录，其父目录须已存在且为 0700；每次观测用新目录 |
| `services` | 按角色声明容器及资源、网络、端口、挂载、健康和重启约束；包括本项目数据库/Redis |
| `protected_containers`、`protected_files` | 需保持不变的容器名和控制文件绝对路径；与基线集合一致 |
| `identity_probes` | 本项目及每个相邻站点的版本端点，绑定各自预期提交/构建 |
| `availability_probes` | 覆盖策略全部 availability_probes 的 HTTPS 健康或页面地址，至少一个 |
| `caddy_helper_sha256` | 本 Skill 的 `assets/cnb-tcr-tat/host/configure-native-caddy.py` 摘要 |

生产可直接引用 `cnb-candidate/v1`、`environment: test` 的已验收候选；不要修改候选环境、构建号或原文。候选 `services` 必须与当前策略的应用角色集合完全一致，各值为对应仓库的 `repository@sha256:<digest>`。回执另外记录 `candidate_environment`，与本次观测的 `environment` 区分。

`services` 包含策略的全部应用角色及声明的本项目基础设施，容器名不得重复。策略已有的资源上限、网络、挂载和 loopback_port 必须一致；其余预期由已验收安装声明确定。应用容器不得同时出现在 `protected_containers` 中，声明的非应用容器必须列入保护集合。采集只查询声明的容器，不自动发现未声明邻居；构造保护列表时应从已验收盘点完整选入本轮保护范围。`services` 的每个值形如以下示例；实际端口、路径、资源和角色由项目适配结果决定，不能照抄示例：

```json
{
  "container": "example-production-api",
  "resource_limits": {"memory_bytes": 268435456, "cpu_millis": 500},
  "networks": ["example-production"],
  "network_mode": "example-production",
  "port_bindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
  "mounts": [{"type": "bind", "name": null, "source": "/opt/apps/example-production/uploads", "destination": "/app/uploads", "rw": true}],
  "health": "healthy",
  "max_restart_count": 0
}
```

每个身份探针必须包含 `project`、`service`、`url`、`api_envelope`、`application_commit`、`build_id`。本项目的 service/url/api_envelope 与主机策略完全一致；相邻项目使用其已验收版本，不能套用本项目构建号。探针需覆盖基线 Caddy 站点中的每个项目，同一 project/service 不得重复。

所有公网探针只接受默认 HTTPS/443，不接受 URL 用户名、密码、query 或 fragment，不跟随重定向；健康和页面地址必须直接返回 200。身份端点还须返回 `cnb-release-identity/v1` 的精确身份对象；`api_envelope: true` 时从已约定的成功 API envelope 中提取 `data.release`，不能为通过检查任意改写响应规则。

基线顶层恰为 `schema: cnb-coexistence-baseline/v1`、`source_target_sha256`、按名称索引的 `containers`、按路径索引的 `files` 和 `caddy`；只允许再加可选的 `original_source`。`source_target_sha256` 必须等于 spec 的 target 文件摘要，容器和文件键集合分别与两个 protected 列表完全一致。

入口不会自动转换旧盘点。AI 从已有受限字段盘点投影出新的私密基线文件，转换时加入 `original_source: {path, sha256}`，保留原文件及其原字节摘要。程序会重验该原文摘要，但不会自动证明投影与旧格式等价；AI 必须核对字段映射，并保留归一化来源记录。不得把旧盘点的整份对象、统计值、响应原文或秘密字段直接塞入基线：

- 容器保留 `name/id/image/image_reference/started_at/restart_count/status/health`、`memory_bytes/nano_cpus/cpu_period/cpu_quota/network_mode`、`port_bindings/mounts`，不带额外字段。`name` 去除 Docker 的前导 `/` 后须等于容器键。旧格式的 `image_id` 映射为 `image`，旧格式的镜像引用 `image` 映射为 `image_reference`，不能交换二者。
- 挂载统一为上例的 `type/name/source/destination/rw`：旧 Docker 字段 `Type/Name/Source/Destination/RW` 分别映射，未提供卷名时 `name` 为 null；丢弃 Mode/Propagation 等未纳入契约的字段。`port_bindings` 使用 Docker 的端口键及 HostIp/HostPort，未发布端口用 `{}`。网络对象只投影为网络名称列表。旧基线未采集 `networks/oom_killed` 时可省略，不能编造；省略 networks 时只能声称保护已记录的 network_mode，不能声称完整附加网络集合未变。新观测必须采集两者，并要求当前容器无 OOM。
- 文件保留 `sha256/uid/gid/mode`，后三项使用整数；属主和组均须为 root。路径限定为 `/opt/cnb-devops/<project>/<test|production>/v1/<允许的控制文件名>`，文件名由固定程序的 CONTROL_NAMES 定义，不采集运行秘密。本项目的 host-policy.json 必须在保护列表中，摘要与 spec.policy 一致。
- `caddy` 使用 `cnb-native-caddy-inventory/v1`、status verified 的固定 helper 结果，恰含 schema/status/main_sha256/base_sha256/running_sha256/sites。sites 保留 project/environment/path/site_sha256/policy_sha256/domains/loopback_ports。基线必须已经包含本项目同环境站点，且其 policy_sha256 与 spec.policy 一致；本次比较要求整个站点集合及三项配置摘要不变。首装追加站点先完成[共享入口验收](native-caddy-shared.md)，再将该已验收安装作为应用发布基线。

具体字段校验在 [固定程序](../scripts/verify-coexistence.py)，不同项目和服务数量的离线输入在 [行为用例](../tests/test_verify_coexistence.py)。AI 仅在适配字段时按需读取，不需要从历史项目复制脚本。

默认预览只读本地输入，不创建输出目录，也不确认 SSH、健康或运行状态。真实 `--apply` 使用严格 known-hosts 的非交互 SSH，以 root 或 `sudo -n` 运行固定只读采集；共享入口沿用 Ubuntu 24.04 原生 systemd Caddy 的受限 inventory，不适用于任意代理或 Docker 网关。入口不重启容器、不修改入口。

成功采集后输出 `host-observation.json` 和 schema 为 `cnb-coexistence-verification/v1` 的 `coexistence.receipt.json`；只有全部声明检查为 true 时 status 才为 verified。回执记录实际检查、发布身份、输入及观测摘要、证据引用、collection_started_at 和 observed_at；不要固定检查总数作为通过门槛。采集或输入失败可能仅返回脱敏错误，不保证生成回执。

已有 evidence_dir 会在预览和 apply 阶段都拒绝，不能覆盖或删除历史目录后重跑。需要新观测时另存 spec 并指定新目录；只复用旧回执时须称为历史证据。`observation_source: live` 的成功回执才是真实观测，预览中同名字段只表示计划采用的采集方式。可选 `observation: {path, sha256}` 必须引用符合 `cnb-coexistence-observation/v1` 的受限字段输入，仅用于离线 fixture；即便 status verified，它仍标为 fixture、保留输入 observed_at 且 collection_started_at 为 null，不能算线上验收。单次观测不代表持续负载或跨信任租户隔离测试。

## 3. 从回执更新原有项目状态

```sh
python3 scripts/reconcile-project-state.py --spec "$CLOSEOUT_SPEC"
python3 scripts/reconcile-project-state.py --spec "$CLOSEOUT_SPEC" --apply
```

AI 生成 `cnb-project-closeout/v1` spec，所有字段均必需；无可用可选项时使用空对象或空数组：

```json
{
  "schema": "cnb-project-closeout/v1",
  "project": "example",
  "environment": "production",
  "project_dir": "/absolute/project",
  "state_file": "/absolute/private/state.json",
  "status_document": "/absolute/project/PROJECT_STATE.md",
  "output_dir": "/absolute/private/closeout-run",
  "deployment": {"path": "/absolute/private/release-session/deployment-verification/receipt.json", "sha256": "<sha256>"},
  "required_checks": ["business", "ui", "coexistence", "recovery"],
  "checks": {},
  "resource_refs": {}
}
```

`status_document` 必须指向项目原来的状态文档。`required_checks` 由项目本轮验收范围确定，不能为消除待办而删减；`checks` 填入现有回执的 `{path, sha256}`：

| 检查名 | 接纳条件 |
| --- | --- |
| `business` / `ui` | 项目验收回执，状态 passed/verified；同环境、提交和构建；非空检查全部通过。兼容旧回执无 project 字段并显式记录这一限制 |
| `coexistence` | 本文固定入口的真实观测；同身份、候选原文和策略摘要；观测不早于发布完成；证据摘要一致 |
| `recovery` | `rehearse-recovery.py` 的成功 result 与同目录 `restore/restore-receipt.json`；源保持不变、不同 Docker daemon、全表/schema/序列/文件核验；明确 PostgreSQL、业务挂载及未覆盖范围 |

已有绑定的业务、页面和恢复回执可复用，本入口不会再次运行业务程序或导出数据。提供的回执不合格则停止；声明必需的回执缺失则记录 `deployment_verified` 和具体待办，全部已声明检查通过才记录 `declared_acceptance_verified`。

`resource_refs` 可登记 `tat_binding`、`cam_identity`、`release_credential_receipt`、`accepted_installation` 的路径和摘要。只登记脱敏资源回执，不能把密钥文件作为回执。资源引用与 `current` 是接管索引，不是发布授权；后续操作仍需重验各自固定门禁。本入口核对已通过发布验证器的完整回执及原文绑定，不独立替代其签名和 TAT 验证。

默认预览只读本地文件。`--apply` 更新原私密状态的 `environments.<environment>.current`，同步有限当前别名，并更新原 Markdown 的 `cnb-devops:current:<environment>` 受管块。其他环境、人工正文、用户授权及未拥有字段保留；完整旧状态、旧文档、目标内容和结果回执保存在事务目录。

同输入重跑不改写已经完成的状态和文档；两文件写入中断可核对续接。若第三方改过输入、状态或文档，停止检查差异，保留旧事务；确需更新时使用新的事务目录，不删除证据来绕过冲突。历史字段只供追溯，接管以该环境 `current` 为准。

目前固定发布回查产出生产回执；共存程序可检查测试和生产。不要伪造发布回执，把测试部署硬塞入生产收尾流程。
