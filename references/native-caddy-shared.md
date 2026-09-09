# 在同一组服务器上追加项目

供 AI 处理已授权的多项目共存接入。用户只需确定新增项目和域名；AI 盘点、备份验证、分配资源并执行接入。测试和生产仍分别运行在各自服务器上，先验收测试，再进入原有生产审批。

## 适用条件

同一所有者的 Ubuntu 24.04 主机，入口为原生 systemd Caddy；已有站点必须是 Skill 生成的精确 import，且与已安装 policy、实际运行配置一致。本入口保留已有配置字节和活动控制器，只追加新项目的固定路由。未知配置、任意 import、通配符、运行漂移或未解决的管理员事务会停止接入；这些情况转到[共享入口契约](shared-caddy-v1/contract.md)。

每项目独立账号、网络、数据库、目录、镜像仓库和回环端口。Docker 组成员具有主机级能力，因此这是同一所有者的运维共存，不能用于不可信租户隔离。先检查剩余 CPU、内存、磁盘及现有负载，再配置资源上限并实测，不以“端口未占用”代替容量判断。

## 接入顺序

1. **盘点并保存旧项目基线。** 使用当前已审 `configure-native-caddy.py --inventory` 得到完整站点、域名、端口和摘要；另核对容器身份、业务访问和管理员写入者。不要用容器 Caddy 的盘点器生成原生证据。
2. **验证入口可恢复。** 使用下述固定采集/恢复入口，实际恢复主配置、站点片段和证书。应用数据库与 uploads 的恢复另外验收，二者互不替代。
3. **准备共享维护输入。** AI 记录用户已有的追加项目授权、适用凭据检查及真实恢复回执；只处理确有暴露、失效或范围变化的凭据。协调已有管理员写入者，不能因新锁存在就假设旧程序已停止写入。
4. **生成并安装新项目。** 正常生成双环境包；每环境的 `setup-host` 加 `--native-caddy-shared-dir`，已有 Caddy 的 baseline 取 inventory 的 `base_sha256`。它先检查共享条件，再创建项目资源；路由写入有持久事务及全配置回读。
5. **沿用标准发布。** 新项目构建、固定 TAT、候选及生产审批不变。验证新项目业务/恢复，同时对照旧项目基线；再更新一次新项目，检查共存。普通发布始终不写 Caddy。

若项目通过同一域名提供 Web、`/api` 和移动网页，在 `host.native_caddy_gateway` 指定实际负责内部转发的服务名。该服务必须有独立回环端口，Caddy 只代理到它；每个构建服务仍需自己的真实发布身份探针。生产 host 独立声明同一选项和端口。

## 固定入口与私密输入

以下材料由 AI 填写和操作，不交给用户编写。均保存在本次私密目录（0700），文件为 0600。

`scripts/rehearse-native-caddy.py capture --spec <capture.json>` 先离线预览，已有授权时加 `--apply` 只读采集源机。spec 包含：

| 字段 | 内容 |
| --- | --- |
| `schema` | `cnb-native-caddy-recovery-spec/v1` |
| `target` | 已验收的严格 SSH 目标 JSON 绝对路径，格式见[首装输入](bootstrap-inputs.md) |
| `helper`、`helper_sha256` | 当前已审原生 helper 路径与其原始字节摘要 |
| `evidence_dir` | 本次独立私密证据目录 |

采集会对源前后配置、成员、内容和元数据进行比对。保持这五个字段不变，另建 restore spec，加入 `caddy_image` 与 `node_image` 两个本机已拉取的 `repository@sha256:digest`。Caddy 必须与源机版本一致；运行 `restore --spec <restore.json>` 预览后加 `--apply`。恢复容器无外部网络、无发布端口，回读 Caddy 完整配置及各域名证书；缺少业务上游时允许 502，不代表业务恢复成功。同一 spec 重复运行验证并复用已有证据，不重新采集。

共享维护目录包含五个固定文件，`setup-host` 会校验其关联和摘要：

| 文件 | 必须证明的内容 |
| --- | --- |
| `inventory.json` | 上述原生 inventory，canonical JSON 加 LF 后计算 SHA256 |
| `gateway-recovery-receipt.json` | 固定入口实际生成的 verified 回执；目标及 inventory 匹配，源未变、配置恢复、TLS 恢复和隔离均通过 |
| `maintenance-authorization.json` | `schema=cnb-native-caddy-maintenance-authorization/v1`、`status=authorized`；绑定 project、environment、`source_target_sha256`、`inventory_sha256`；scope 恰为 `preserve-existing`、`add-project-static-routes`；`authorization_source` 引用已有实际授权 |
| `credential-review-receipt.json` | `schema=cnb-native-caddy-credential-review/v1`、`status=reviewed`；同目标与 inventory，非空 `evidence` 记录实际检查，`unresolved` 为空才可继续 |
| `native-caddy-shared-input.json` | 恰好 `schema=cnb-native-caddy-shared-input/v1`、`inventory_sha256` 及上述三回执的原始字节 SHA256：`gateway_recovery_receipt_sha256`、`maintenance_authorization_sha256`、`credential_review_receipt_sha256` |

`source_target_sha256` 为目标 JSON 原始字节摘要。摘要只用于绑定文件，不能把未检查的内容变成证明；不得手填成功状态来绕过失败。只有最后一个不含秘密的五字段输入随 setup 传到主机。

## 中断后继续

管理员 helper 同时持有旧版固定锁与持久事务锁。未完成事务保留在 `/var/lib/cnb-devops/native-caddy/active-transaction.json`，并阻断后续维护。核对对应 journal 后，以同一已审 helper 执行 `--recover <transaction_id>`；只接受记录中的已知前后状态，出现第三方漂移即停止。成功后重新运行原 setup 输入；新增其他项目时重新盘点，不能沿用旧 inventory。

入口恢复、setup ready、新项目测试共存和生产共存是不同结果，按各自实际证据记录。目前能力处于预览验证阶段，不能据本地检查承诺新项目接入时限。
