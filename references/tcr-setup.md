# TCR 个人版初始化

供 AI 在首次准备镜像仓库、推送身份和主机拉取身份时读取。用户提供项目与账号授权；仓库、权限、密码、JSON 和回执均由 AI 准备。已有接受的配置先复用，不为使用新入口而重建或轮转。

当前入口仅覆盖 **TCR Personal / ap-guangzhou / ccr.ccs.tencentyun.com**。其他版本或地址不套用本契约；这不是要求迁移已有 Registry。

## 新项目

AI 从应用服务、基础镜像和已授权租期填写非秘密 spec。仓库 name 是完整 `namespace/repository`，逐项列出，不用通配。两个身份使用项目专用名称；示例时间须替换为本次已接受的有效期，不能把演练租期作为所有项目默认。

```json
{
  "schema_version": 1,
  "project": "example",
  "environment": "test",
  "account_id": "10001",
  "edition": "Personal",
  "region": "ap-guangzhou",
  "registry": "ccr.ccs.tencentyun.com",
  "namespace": "example-test",
  "repositories": [
    {"name": "example-test/api", "description": "example test API"},
    {"name": "example-test/postgres", "description": "example test PostgreSQL"}
  ],
  "lease": {"expires_at": "<本次授权的 UTC 到期时间>"},
  "identities": {
    "build-push": {
      "user_name": "example-test-build-push",
      "policy_name": "example-test-build-push-repositories",
      "initialization_policy_name": "example-test-build-push-initialize-once"
    },
    "host-pull": {
      "user_name": "example-test-host-pull",
      "policy_name": "example-test-host-pull-repositories",
      "initialization_policy_name": "example-test-host-pull-initialize-once"
    }
  }
}
```

```sh
node "$SKILL_DIR/scripts/configure-tcr.mjs" --spec "$PRIVATE_DIR/tcr-spec.json"
node "$SKILL_DIR/scripts/configure-tcr.mjs" --spec "$PRIVATE_DIR/tcr-spec.json" \
  --state-dir "$PRIVATE_DIR/tcr-state" --apply \
  --credentials "$PRIVATE_DIR/bootstrap-credentials.json" \
  --credentials-expires-at "$BOOTSTRAP_EXPIRES_AT" \
  --sdk-root "$PROJECT_DIR/deploy/vendor/cnb-devops/dependencies"
```

默认离线预览，不查询账号、不创建文件。apply 使用有效的本机管理员身份，先完整核验目标，再创建缺失的私有仓库、无控制台 CAM 子身份与精确权限；输出不代表应用已部署。依赖沿用固定 `tencentcloud-sdk-nodejs-common@4.1.220`，无需安装全套腾讯云 SDK。

AI 先建立 0700 的 state-dir。`--credentials-expires-at` 使用官方登录导出的 UTC 到期时间（以 Z 结尾）；带 token 的临时凭据必须提供，不能自行延长。SDK 目录必须已有锁文件与安装完成的依赖；生成固定包不等于已经安装依赖。可以复用版本符合的已有目录。

build-push 只获得声明仓库的 `PullRepositoryPersonal/PushRepositoryPersonal`；host-pull 只有 `PullRepositoryPersonal`。官方 Personal 资源为 `qcs::tcr:::repo/<namespace>/<repository>`，空地域覆盖所有地域，空账号指策略创建者所属主账号；不得把这种表达称为地域隔离。

初始化 API key 明确属于新子身份，不能省略 TargetUin 给管理员签发。随机16位 Registry 密码先保存在私密文件，再以子身份调用一次 `CreateUserPersonal`（不传 Region）；临时初始化策略仅授权该动作，成功后解绑并回读。主账号尚未开通 Personal 时，由 AI 给出准确官方操作，不自动设置主账号密码。

state-dir 使用0700，状态和凭据0600。状态只保存目标、进度及非秘密引用；密码、API key 与 Docker auth 不进入 stdout、聊天或普通仓库。Registry 用户名为经核验的子用户 UIN，密码与 API SecretKey 不混用。CI 只接收 build-push Registry 凭据，服务器只接收 host-pull Registry 凭据；初始化 API key 留本机。

## 中断与已有资源

写调用前记录 intent；未知结果先回读同一资源，不能删除状态或重复创建。AccessKey 创建响应丢失且本机没有 Secret 时，报告凭据恢复所缺信息，绝不补建、重置或自动撤销。Registry 初始化结果未知时保留原密码和原尝试，不能用新密码重试。配置冲突、权限查询不完整、额外权限或账号不符时保持现状并报告具体阶段。

显式 `--verify-existing` 使用 spec 的 `existing` 信息和现有私密凭据，仅只读核验，不接管同名资源。AI 从原配置回执取确切 UIN、policy ID、创建时间/描述及凭据文件引用；Personal 命名空间和仓库使用账号/地域/Registry/完整名称及创建元数据，没有可填写的 Enterprise NamespaceId/RepoId。

原 spec 增加 `existing`，字段如下；全部来自原始回执，不能用本次时间或推测值补齐：

| 字段 | 内容 |
| --- | --- |
| `namespace_creation_time` | 原命名空间 CreationTime |
| `repositories` | 与顶层相同顺序的 `[{"name":"namespace/repository","creation_time":"..."}]` |
| `identities` | 恰含 build-push、host-pull，各自填写下列全部字段 |
| 身份字段 | `user_uin`、`user_uid`、`policy_id` 为真实正整数；`user_remark`、`policy_description`、`policy_add_time`、`policy_update_time`、`key_create_time`、`key_description` 与原 API 元数据一致 |
| 凭据引用 | `api_credentials_file`、`registry_credentials_file` 为各角色现有私密文件绝对路径 |

创建及策略时间保留 API 的 `YYYY-MM-DD HH:mm:ss`（UTC+8），不转为当前时间。API 文件为 `{"secretId":"...","secretKey":"..."}`；Registry 文件为 `{"registry":"...","username":"<子用户 UIN>","password":"...","role":"build-push 或 host-pull","policy_expires_at":"..."}`，本入口生成的密码为16位字母数字。已有凭据不符合本契约时继续沿原配置核验，不为适配而重置密码。

```sh
node "$SKILL_DIR/scripts/configure-tcr.mjs" --spec "$PRIVATE_DIR/tcr-existing.json" \
  --verify-existing --credentials "$PRIVATE_DIR/bootstrap-credentials.json" \
  --credentials-expires-at "$BOOTSTRAP_EXPIRES_AT" --sdk-root "$TENCENT_SDK_DIR"
```

此模式不写文件。AI 可将脱敏 stdout 保存为配置回执；回执中的路径仅为引用，不含密钥值。

现有资源模式核验 STS 账号和子身份、CAM 用户/组/有效策略/key 与文件绑定、私有仓库及元数据。凭据文件存在不证明密码能登录，初始化响应成功也不等于镜像推拉成功。输出分别记录配置、初始化、登录及推拉状态；未执行的项保留 `not_checked`，由后续真实 CI 和主机按 digest 拉取补验。

完成后将非秘密回执、凭据用途、有效期、保管位置和轮换复核时间写入项目原有索引；不重复申请已经有效的授权。需要 Secret 保存时沿[统一交接](human-handoffs.md#cnb-secret-repository-operation)准备完整文件。

CNB SaaS 出口地址会动态变化，不建立永久 CNB IP 白名单或因此削弱认证；需要固定网络边界时采用 TAT 或受控代理，见 [CNB FAQ](https://docs.cnb.cool/zh/faq.html)。

## 官方接口依据

- [Personal 子用户权限和精确资源表达](https://intl.cloud.tencent.com/zh/document/product/1051/39862)。
- [CreateUserPersonal](https://cloud.tencent.com/document/product/1141/41596)、[CreateRepositoryPersonal](https://cloud.tencent.com/document/product/1141/41597)、[Personal 数据结构](https://cloud.tencent.com/document/product/1141/41603)。
- [CreateAccessKey](https://cloud.tencent.com/document/api/598/82370)、[ListAccessKeys](https://cloud.tencent.com/document/api/598/45156)：一次性 Secret 响应与后续 key 清单职责不同。
