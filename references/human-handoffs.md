# Human Handoffs

Last verified: 2026-09-07

本页供 AI 在当前任务需要补充信息、本人操作或审批时按需读取。角色表示责任归属；个人用户可按项目政策兼任多个角色。技术材料、命令与回执由 AI 在已有授权范围内准备、执行和核验，用户只补无法发现的选择、本人验证和必要审批。

## 按实际任务选择阅读范围

- **标准包首次接入简单主机**：先走[标准工作流](standard-workflow.md)与[首装入口](bootstrap.md)，从下表填充要求，再按当前缺口定位负责人。
- **继续发布或增加独立项目**：先读项目部署/状态索引及仍有效的回执，复用已接受的事实、配置和授权；每个项目分别核对目标与权限范围。
- **接管现有主机、控制器兼容或共享路由问题**：按实际条件读目标主机负责人或共享 Caddy 管理员章节；跨账号委托仅在组织政策要求时读取。维护、备份恢复、凭据轮换和审批门禁按对应合同保留。

<a id="standard-artifacts"></a>
## 标准产物如何满足要求

| 当前要求 | AI 优先读取的标准产物 | 如何使用 |
| --- | --- | --- |
| 拓扑、路径、账号与权限合同 | `deploy/project.yml`、各环境 `host-policy.json`、Compose、锁定版本的 installer | 提取已有路径、对象类型、UID/GID、mode 和执行约束；安装/兼容检查提供实际结果，仅对未覆盖的实际要求补充合同字段 |
| 构建、固定命令与发布证据 | `artifact-lock.json`、CI/TAT 配置、binding、安装与发布回执 | 核对版本、目标绑定、权限范围和实际构建/运行/公网结果；不复制其他项目的目标或凭据 |
| 数据与恢复 | `recovery-policy.json`、导出及离机恢复回执 | 对照实际持久数据核对范围，以真实恢复及对账结果验收 |
| 秘密配置 | 变量名清单、私密存储位置及有效 secret receipt | 核对用途、有效期和实际消费边界；值留在批准的私密存储 |

这些产物用于填充现有要求；生成或安装成功不能替代实际需要的兼容检查、发布、恢复或审批验收。缺失、失效或不适配的部分仍阻断对应动作。

## 把当前动作交给人

AI 先用已有事实准备可审阅的材料，完成当前授权内可执行的检查，再给人一个必要动作：明确页面、动作、范围和完成标志。账号或目标绑定缺失时，只请求能继续准备的最小前提；不让人编写技术回执，也不让人把敏感内容发到聊天。AI 核验实际结果后更新项目索引；未确认的草稿保持 pending，不编造授权、绑定或成功状态。

先区分阻塞来自 Skill 能力、AI 尚未完成的技术工作，还是确需用户提供的信息。能力不兼容时，直接说清当前支持范围和本次结果；状态记录由 AI 留好，不让人收集暂时无法使用的参数。新增项目缺少 provisioning、binding 或 secret receipt 时，由 AI 在授权范围内发现、生成或验证；“补齐接入记录”不是给小白的动作。

例如，项目无数据库时可交付“这个项目不需要数据库，当前发布包要求 PostgreSQL，尚不能直接接入。已检查现有代码并保存进度；不需要你填写配置。”确实缺域名时只问“测试环境准备用哪个域名？暂无域名也可以直接说明。”页面保存时提供准确入口和已准备材料的安全位置，说清“粘贴已备内容并保存”，随后由 AI 回读核验。不要把内部待办表作为用户必须完成的清单。

账号初始化优先走[官方登录与 API 入口](api-onboarding.md)。AI 自动配置固定 TAT 与云身份权限；CNB 默认 CLI 创建缺权时，按[初始化令牌入口](api-onboarding.md#cnb-bootstrap-token)复用已有凭据，或准备一次官方创建与本机隐藏输入交接，再继续同一配置器。只有没有可用令牌通道时才逐项交接网页创建/设置；必要的 Secret 保存仍集中准备，不让用户学习 API 或反复登录。

区分 AI 权限确认、云控制台登录/验证码/本人验证，以及候选 Tag 部署页审批。AI 权限问题直接说明操作和回复方式；问题卡片不可见时用普通文字重述，不重启接入，已有明确且有效的授权不重复询问。候选审批必须指出具体 Tag 和页面；项目要求的机器授权记录由 AI 先准备并核验，按钮可见不代表执行条件已满足。

## 按问题找负责人

先按当前阻塞项定位角色；共用交付格式见[交付物与回执](#shared-artifacts)。

| 当前问题 | 负责人及操作 |
| --- | --- |
| 现有主机或控制器路径不兼容 | [目标主机负责人](#target-host-owneroperator) |
| 多项目共用 Caddy、接管或主机维护 | [共享 Caddy 主机管理员](#shared-caddy-host-administrator) |
| 应用拓扑、源码接入或控制器合同 | [应用负责人](#application-owner) |
| CNB 流水线或 TCR 推拉权限 | [CNB 与 TCR 管理员](#cnb-and-tcr-administrator) |
| 客户腾讯云账号、TAT 命令或执行权限 | [客户腾讯云管理员](#customer-tencent-cloud-administrator) |
| DNS、证书或备案阻塞 | [DNS 与 ICP 管理员](#dns-and-icp-administrator) |
| 数据迁移、备份或恢复验收 | [数据负责人](#data-owner) |
| 候选已就绪，需生产审批 | [生产审批人](#production-approver) |
| Secret 配置、授权或凭据轮换 | [Secret 仓库维护者](#cnb-secret-repository-operation) |

## Shared artifacts

### handoff manifest

A `handoff manifest` contains only non-secret project and environment fields,
the responsible role, completion state, and validation result. It never
contains a RoleArn, external ID, UIN, instance ID, target region, IP address,
credential, or formal domain-control artifact. Those values go directly to the
approved secret or control system.

A `versioned production handoff` is one such manifest. It binds an accepted
schema/version, exact candidate, environment, policy, execution-adapter kind
and version, responsible role, and validation result. It begins pending and
contains no target or credential values.

### secret receipt

A `secret receipt` records the variable name, storage location, responsible
role, creation date, expiry or rotation date, and validation state. It never
records the value. A valid receipt prevents the next AI or operator from asking
for an already configured secret again.

Classify each secret by where it is consumed: build secrets authorize source or
registry build work; pipeline secrets authorize the CNB execution boundary; and
runtime secrets are entered only at the target-host boundary. Keep the inventory
value-free in `.env.example` and, when CNB Secret data is used,
`.cnb/secret.example.yml`; each configured value has a `secret receipt` rather
than a chat transcript or complete environment file.

Record the actual expiry with a timezone and every consuming location. Before
an operation, check that the credential and any time-limited access policy cover
its execution window. For renewal, update the approved consumers, validate the
new credential at each required boundary, and record retirement of the old one.
Do not treat a receipt's existence as proof that a short-lived credential remains
usable; keep the responsible owner and next renewal action in the project index.

### Private file transfer

When downloading a credential or backup, verify the actual destination file,
ordinary-file type, restricted permissions, size, and source/destination checksum.
A console's transfer-success message or a download-event timeout does not settle
whether the file arrived. Locate the expected artifact before retrying; if absent,
record transfer as incomplete. Move any download staging copy into the approved
private store promptly, then record metadata only. Do not ask a human to paste
file contents into chat or recreate a credential merely to repair a transfer.

### release evidence

`release evidence` is the non-secret chain:

```text
full Git SHA → CNB build identity → complete TCR digest map
→ TAT invocation/result → actual target runtime digest map → HTTPS result
```

Each handoff is either accepted, rejected with one precise correction, or still
blocked. Do not silently convert missing information into a default.

### readiness receipt

A `readiness receipt` records one candidate identity, manifest hash, policy and
verifier versions, completion time, expiry, and passed/blocked result. It is
non-secret and never grants approval. A passed receipt is valid for at most 24
hours and is revalidated when production execution begins.

### compatibility receipt

A value-free `compatibility receipt` binds an opaque target-scope commitment
and control-record ID, exact deployment controller, exact path-contract digest,
verifier, issue and expiry times, and per-check pass/block status. The approved
control record holds the actual target host set, paths, and expected metadata;
the receipt contains no credential, raw target IDs or paths, metadata value, or
file content.

A passed receipt applies only to that target scope, controller, contract, and
validity period. Target-set, metadata, ACL, mount, required-capability,
controller, or contract drift invalidates it; any maintenance invalidates it as
well. Immediately before release execution, recheck freshness, scope, and drift
against the approved control record and fail closed on uncertainty.

## Target-host owner/operator

### When

For existing-host adoption, changed controller/path requirements, before and
after host maintenance, or when project policy requires independent compatibility
acceptance. Simple first installation uses the standard artifact mapping above.
Name this accountable role in the handoff manifest; ordinary release authority
does not imply host-maintenance authority.

### Deliver

- The approved control record containing the real target scope and controller
  path contract. Expose only its opaque control-record ID and target-scope
  commitment outside that control boundary.
- A full read-only compatibility preflight using the exact incoming controller,
  plus a value-free `compatibility receipt` bound to the exact path-contract
  digest and finite validity period.
- If metadata maintenance is required, its separate authorization, executor,
  narrow numeric UID/GID or mode scope, completion evidence, and the fresh
  post-maintenance receipt. An ACL change requires its own reviewed fd-safe
  procedure and authority.

### Acceptance

The receipt is passed, unexpired, in scope, and unchanged by target, metadata,
ACL, mount, capability, controller, contract, or maintenance drift. Release
execution independently rechecks freshness, scope, and drift before mutation.

### Never deliver

Credentials, raw target IDs or paths, file contents, a blanket root authority,
or permission for an ordinary release to repair metadata or ACLs.

## Shared Caddy host administrator

### When

Before the first managed release on a multi-project host, when separately
bootstrapping the host, installing/recovering the controlled helper pair, or
provisioning project locks, and for hostname deletion, ownership transfer,
legacy takeover, or recovery-marker repair.

### Deliver

- Inventory and owner mapping, external restore-verified snapshot receipts,
  and value-free credential-rotation receipts, accepted under the
  [host inventory gates](shared-caddy-v1/host-handoff.md#inventory-snapshot-and-credential-gates).
- Approved helper and host inputs from the [host input contract](shared-caddy-v1/host-handoff.md#inputs),
  with one separately authorized maintenance action. Ordinary staging or
  production release approval does not authorize baseline, ownership, or helper
  changes. Follow the fixed [baseline import/recovery order](shared-caddy-v1/host-handoff.md#baseline-import-and-recovery)
  before provisioning.
- A value-free [host acceptance record](shared-caddy-v1/host-handoff.md#acceptance-record).

### Acceptance

Accept the dedicated host handoff's gates and acceptance record before a live
application release. Pending restore/rotation evidence, unaccepted maintenance,
or any recovery marker keeps release blocked. Route ownership, helper and
provenance checks remain governed by that handoff; application release authority
cannot substitute for host maintenance authority.

### Never deliver

An arbitrary helper path or command, a wildcard sudo rule, permission for a
normal release to rewrite the root config or another project, a volume prune or
bind-source deletion, or a claim that taking the new lock stopped an
uncooperative legacy writer.

## Application owner

### When

Before a repository is first connected, whenever its deployable topology or
deployment-controller path contract changes, before the first managed release
to an existing host, and before a candidate is approved.

### Deliver

- Authoritative source repository, governed source/release branches, and actual
  synchronization paths; mark external synchronization `not-applicable` for
  CNB-native source.
- Docker build contexts, target architectures, complete service roles and
  count, ports, health endpoints, dependency order, migrations, and persistent
  volumes.
- The governed branch, candidate prefix, and whether application/controller
  commits must be identical because they share a repository.
- The per-environment controller path contract, populated from the
  [standard artifacts](#standard-artifacts): path/object roles, no-symlink,
  numeric UID/GID, exact mode/ACL, parent traversal, mount/capacity,
  lock/transaction/recovery and atomic operation requirements. Keep target-specific
  values in the approved control system; extend only requirements the selected
  artifacts do not cover.
- For existing-host adoption or a controller change requiring compatibility
  checks, an accepted value-free `compatibility receipt` before ordinary release.
- Environment variable names, classification, and owning role; no values.
- Independently selected CNB page operator, readiness operator, production
  approver, and change/rollback owner; do not assume roles are upward-inclusive.
- The selected project-owned execution adapter, adapter owner, and default
  disabled status until its handoff is accepted.

### Source setup and acceptance

Select the branch matching the observed authoritative source and governed
synchronization path. Do not add a synchronization system to satisfy a handoff.

#### CNB-native source

When CNB is authoritative and there is no external synchronization path, record
synchronization as `not-applicable`. Do not request a GitHub repository, Actions
setup, or `CNB_PUSH_TOKEN`. Record the governed CNB branch's full SHA and accept
source/build evidence only when the repository's real clean build succeeds.

#### GitHub-to-CNB synchronization

Only for an observed governed GitHub-to-CNB synchronization path:

1. In GitHub, open the repository, then **Settings → Secrets and variables →
   Actions**. Create or confirm the per-repository `CNB_PUSH_TOKEN`. If its
   `secret receipt` is already accepted, do not request or replace it.
2. In CNB, create the token with access limited to the target repository and
   the minimum code-write scope needed by synchronization.
3. Configure synchronization only for governed branches. Do not use a
   destructive `--mirror` flow that could delete CNB candidate tags.
4. Record the GitHub and CNB full commit IDs after synchronization. Accept this
   path only when both governed branch records show the same full SHA and the
   real clean build succeeds. Retain the accepted `CNB_PUSH_TOKEN` secret receipt
   without exposing or requesting its value again.

### Common controller handoff

AI indexes the existing contract artifacts and their verified results for the
named target-host owner/operator. Existing-host adoption or controller changes
requiring compatibility checks still need the exact-controller read-only
preflight and value-free `compatibility receipt` before acceptance.

Official guidance:

- <https://docs.github.com/en/actions/concepts/security/secrets>
- <https://docs.cnb.cool/zh/guide/access-token.html>
- <https://docs.cnb.cool/zh/guide/first-repo.html>
- <https://docs.cnb.cool/zh/build/deploy.html>

### Acceptance

For the initial source handoff, apply the matching source acceptance branch
above: require the authoritative full SHA, a real clean build, the complete
service map, and the owner/contract facts listed under Deliver. Candidate naming,
UI roles, and execution-adapter ownership are explicit rather than inherited
from another project. Runtime/public evidence from a deployment that has not
occurred is not an initial source-handoff prerequisite.

At candidate and deployment acceptance, require separate build/runtime/public
evidence for the exact complete service digest map under
[release safety](release-safety.md). Source acceptance alone does not establish
a candidate or deployment. Before the first managed release, an existing host
also has an accepted
`compatibility receipt` for the exact controller and path contract; a blocked
receipt is resolved only through separately authorized maintenance, never by
the ordinary release.

### Never deliver

Token values, complete environment files, mutable image tags as release
evidence, or permission to delete unrelated CNB refs.

## CNB and TCR administrator

### When

When a project first receives build/push access, when a new customer server
needs pull access, or when a Registry credential is rotated.

### Deliver

- TCR Personal namespace/repository identities and the exact Registry endpoint
  used by each credential.
- One dedicated programmatic build-push CAM identity, never a main-account
  credential, and one dedicated pull-only CAM subuser for each customer/project
  repository set.
- A policy record, rotation date, isolation test result, and `secret receipt`
  for each credential.

TCR Personal is the selected free path within its service limits and has no SLA.
TCR Enterprise service accounts are an optional paid upgrade, not the assumed
free mechanism.

### Exact setup steps

1. Confirm the build-push credential belongs to a dedicated programmatic CAM
   identity with only the required repository push/read scope. Then, in
   **CAM → Users**, create a different dedicated programmatic subuser for one
   customer/project repository set's pull access.
2. In **CAM → Policies**, grant the host only `tcr:PullRepositoryPersonal` on
   each exact repository. Use the Personal edition form below; list multiple
   repositories individually, without namespace or descendant wildcards.
   For CI, add only `tcr:PushRepositoryPersonal` to its approved repository set.
   Replace the expiry placeholder with the approved lease's UTC deadline:

   ```json
   {
     "version": "2.0",
     "statement": [{
       "effect": "allow",
       "action": ["tcr:PullRepositoryPersonal"],
       "resource": [
         "qcs::tcr:::repo/<NAMESPACE>/<REPOSITORY>"
       ],
       "condition": {
         "date_less_than": {
           "qcs:current_time": "<APPROVED_EXPIRY_IN_UTC>"
         }
       }
     }]
   }
   ```

   Tencent's Personal resource guide allows these empty fields: region covers
   all regions and account resolves to the policy creator's parent account.
   This documented format still names the exact repository; successful policy
   creation alone does not prove that Registry authorization matches it.
   Verified on 2026-09-06: private digest manifest reads succeeded with this
   exact-repository form using the existing credential. This proves those
   manifest reads, not every image-layer download or a denied write attempt.
3. Only for first-time Registry initialization, temporarily grant
   `tcr:CreateUserPersonal` on resource `*`, within the approved lease.
   Do not also grant `tcr:ModifyUserPasswordPersonal`.
4. Use the official SDK/CLI under that subuser's own API identity to call
   `CreateUserPersonal` once, with `Password` and no `Region`. Console login
   for the subuser is not required. Generate a private random 16-character
   password, persist it in a protected attempt file before the request, and
   retain the attempt if the response is uncertain. An existing initialized
   user or uncertain response requires review, never an automatic retry with a
   new password or an unapproved reset. Remove the initialization grant after
   success and verify that its association is gone.
5. Use that initialized identity's actual UIN as the Docker username, confirmed
   from CAM; do not substitute its display name, UserId, or parent account UIN.
   Keep the private Registry password distinct from its API SecretId/SecretKey.
6. Enter the build-push Registry credential in the project's CNB Secret file.
   Enter only the pull-only Docker credential on the target host using the
   approved runtime-secret mechanism; do not transfer the initialization API
   key to the host. Record only `secret receipt`s.
7. Read back the effective policy and associations, then verify an actual
   private `repository@sha256:digest` with an isolated Docker configuration.
   A successful login proves authentication, not repository pull permission.
   Check that the host's effective grants contain no push/write authority;
   this policy evidence is separate from the real digest-read result. Do not
   require a real push attempt or access to another project's repository as a
   negative test. Any additional denial probe needs an approved, non-mutating
   scope and must be reported only as evidence for that specific request.

Official guidance:

- <https://cloud.tencent.com/document/product/1141/40540>
- <https://cloud.tencent.com/document/product/1141/41409>
- <https://cloud.tencent.com/document/product/1141/41415>
- <https://cloud.tencent.com/document/product/1141/41596>
- <https://cloud.tencent.com/document/product/1141/41412>
- <https://intl.cloud.tencent.com/zh/document/product/1051/39862>
- <https://cloud.tencent.com/document/product/598/10608>

CNB SaaS egress addresses change dynamically. Do not create a permanent CNB IP
allowlist or weaken authentication; use TAT or a controlled proxy when a stable
network boundary is required: <https://docs.cnb.cool/zh/faq.html>.

### Acceptance

Record policy/association readback, actual private digest pull, and absence of
host write grants as separate evidence. Initialization-only permission is
removed, and both secret receipts name an owner, the approved expiry, and next
rotation date. A policy correction remains unverified until its actual Registry
read succeeds; policy inspection is not a claim that a push was attempted and
denied.

### Never deliver

Registry passwords, API keys, a shared all-project pull identity, a broad
`tcr:*` long-lived policy, or Enterprise-only service-account instructions
presented as the free Personal path.

## Customer Tencent Cloud administrator

### When

Before a customer-owned mainland-China server can be considered production
ready, and whenever its role, instance, region, or maintenance window changes.

### Deliver

- Main-account UIN, target region, TAT-supported target product and instance ID,
  OS/architecture, outbound connectivity, TAT agent state, and maintenance
  window directly into the approved control locations—not into chat or the
  `handoff manifest`.
- A dedicated direct CAM identity for fixed readiness/apply commands, accepted
  against the [TAT execution contract](release-safety.md#credentials-and-execution).
  CNB receives no arbitrary script text or caller-selected targets.
- A `secret receipt` for the required variable names, approved storage
  locations, owner, and validation state—never their values.
- If organizational delegation requires it, a customer-controlled
  `cross-account role` and STS receipt may be supplied as an optional pattern.

### Exact console steps

1. In **CAM → Users**, create a dedicated direct programmatic identity for this
   project's readiness and apply Saved Commands. Attach only the least-privilege
   policy for those pre-created command and target resources; do not grant a
   generic remote-command policy or console access.
2. In TAT, pre-create one fixed readiness Saved Command and one fixed apply
   Saved Command. Test readiness without mutation; keep apply unavailable until
   the immutable candidate, fresh readiness, and independent approval exist.
3. If the organization needs delegation, open **CAM → Roles → New role**, choose
   **Tencent Cloud account**, narrow trust to the dedicated programmatic
   identity, and enable external-ID validation. This cross-account role/STS path
   is optional; never trust a human administrator's general identity or every
   identity in the account.
4. Attach a custom least-privilege policy for the fixed-command adapter. It
   reads back the selected Saved Command with `tat:DescribeCommands`, invokes
   that fixed `CommandId` with `tat:InvokeCommand`, polls with
   `tat:DescribeInvocations`, and, when instance output is requested, calls
   `tat:DescribeInvocationTasks`. Scope those calls to the approved CommandId
   and exact target InstanceIds from the approved project-owned adapter/control
   record. A CVM ID beginning `ins-` uses a `qcs::cvm:...:instance/...` resource;
   a Lighthouse ID beginning `lhins-` uses a
   `qcs::lighthouse:...:instance/...`. Do not interchange them or permit
   arbitrary script text or caller-selected targets from CNB.
5. In the corresponding CVM or Lighthouse console, confirm the TAT agent is
   online. TAT is the remote execution boundary; production deployment does
   not require exposing port 22.
6. In CNB Web, enter only the approved variable values directly into the
   project's Secret boundary. Report only variable names and `secret receipt`s;
   validate the fixed command inputs against the
   [execution contract](release-safety.md#credentials-and-execution).
   The dedicated direct CAM identity credential is a pipeline secret in that
   approved boundary with a value-free rotation receipt; it does not require an
   STS temporary credential triple.
7. When the optional role path is used, grant the dedicated operator identity
   `AssumeRole` only for that role. A
   reviewed client must exchange it for temporary SecretId, SecretKey, and
   Token. Record the returned credential expiration in a value-free receipt.
   Choose the shortest `DurationSeconds` that still covers the declared
   worst-case remote timeout, all control-plane work, and an explicit safety
   margin. Immediately before approval, refresh the complete triple whenever
   its remaining lifetime no longer covers that bound, then execute a harmless
   TAT preflight before any release.

The full temporary credential triple is required only when the optional role
path is used. It invokes the same fixed Saved Commands and must pass the same
DescribeCommands/InvokeCommand readback and harmless TAT preflight. Production
remains blocked until that temporary-credential path is accepted; never fall
back to a non-dedicated customer key.

Official guidance:

- <https://cloud.tencent.com/document/product/598/19381>
- <https://cloud.tencent.com/document/api/598/35840>
- <https://cloud.tencent.com/document/product/598/13895>
- <https://cloud.tencent.com/document/product/1340/56294>
- <https://cloud.tencent.com/document/product/1340/50821>
- <https://cnb.cool/cnb/plugins/tencentcom/tcloud-cmd/-/blob/main/README.en.md>

### Acceptance

The dedicated direct identity is limited to the project's fixed readiness/apply
commands, TAT is online, the policy is least privilege, and value-free receipts
exist. If the optional role path is selected, its trust is narrow, external-ID
checking is enabled, and the current temporary credential receipt shows enough
remaining lifetime. Until the selected execution path passes its harmless TAT
preflight, acceptance is explicitly **blocked for production**.

### Never deliver

The customer's main-account password or API key, a non-dedicated customer key,
a direct-identity credential outside its approved Secret boundary,
RoleArn/external ID/UIN/instance/region values in chat or the ordinary manifest,
or a request to expose SSH for the pipeline.

## DNS and ICP administrator

### When

Before a mainland-China public hostname is cut over, and whenever its address,
certificate path, or filing/access-registration state changes.

### Deliver

- FQDN, DNS zone/provider, intended A/AAAA/CNAME value, TTL, old value,
  rollback value, cutover window, and owner in the approved DNS change record.
- ICP filing and required access-registration state for the actual service and
  provider. The `handoff manifest` records only the status and record owner.

### Exact console steps

1. Open the authoritative DNS provider and create a reviewed change containing
   the old, new, and rollback records plus TTL.
2. Complete the applicable mainland-China ICP filing and access-registration
   process before treating the hostname as production ready.
3. Apply the DNS change only in the approved window. Do not pass DNS account
   credentials to the application or pipeline.
4. After propagation, verify authoritative DNS, TCP 80/443, certificate chain,
   and the application's HTTPS behavior independently.

Official guidance:

- <https://cloud.tencent.com/document/product/302/3449>
- <https://cloud.tencent.com/document/product/243/37403>
- <https://caddyserver.com/docs/automatic-https>

### Acceptance

Authoritative DNS returns the approved value, 80/443 reach the intended host,
the certificate is valid for the FQDN, and public application checks pass. If
DNS or filing is pending, report public evidence as pending rather than
rebuilding the application.

### Never deliver

DNS account credentials, registrar recovery factors, domain-control proof in
the ordinary manifest, or an instruction to bypass filing requirements.

## Data owner

### When

Before first production use, every data migration, and every release whose
application rollback may be incompatible with stored data.

### Deliver

- One explicit mode: `none`, `empty`, or `migrate`.
- Database engine/version, encoding, extensions, schema state, migration order,
  persistent volumes, and external stores.
- The data and backup portions of the controller path contract, including
  object kind, numeric UID/GID, exact mode and ACL requirements, retention,
  parent traversal, capacity, and atomic-write expectations; no data values or
  dump contents.
- For existing-host adoption or changed controller/path requirements, the data
  owner's acceptance of the value-free `compatibility receipt` before backup or
  migration may start; also require it when project policy calls for it.
- Encrypted backup location and checksum, restore steps, freeze window, RPO,
  RTO, retention, reconciliation checks, and named recovery owner.

### AI execution and owner decisions

For observed `none/empty` first deployment, record the actual data state and
applicable initialization checks; do not infer emptiness from missing receipts.
An empty starting snapshot is not business recovery. Initialize within the
approved scope, then create representative business data and complete any
required recovery acceptance. The migration-window restore gate below applies
to existing data; shared-host takeover retains its pre-mutation restore gates.
See [backup and restore acceptance](release-safety.md#backup-and-restore-acceptance).

1. AI prepares the actual data/backup scope, destination, retention and RPO/RTO
   requirements from project artifacts. The owner confirms undiscoverable choices
   and the short write pause needed for export; reuse valid existing authorization.
2. AI runs the [standard export, protected download and isolated restore](bootstrap-inputs.md#recovery)
   on the authorized targets, retaining checksums and real receipts. Data outside
   that preset uses its approved recovery procedure; it must remain accounted for.
3. AI verifies integrity, business reconciliation, source resumption and measured
   recovery time. Use the standard program's actual table/sequence/file comparison
   and bound receipt assertions; record business results and mock limitations.
4. For existing-data migration, the owner reviews the scope and results and approves the window
   only after the rehearsal meets RPO/RTO. Database recovery remains a separate
   decision from image rollback.
5. Where compatibility checks apply, a blocked or stale receipt stops the action;
   metadata repair remains separately authorized target-host maintenance.

Official guidance:

- <https://www.postgresql.org/docs/current/backup.html>
- <https://www.postgresql.org/docs/current/app-pgdump.html>
- <https://cloud.tencent.com/document/product/362/8191>
- <https://cloud.tencent.com/document/product/362/5756>

### Acceptance

Mode, backup checksum, successful restore rehearsal, business reconciliation,
retention, recovery owner, and any required exact-controller
`compatibility receipt` are recorded. The release evidence states whether the prior application
can safely use the post-migration data.

### Never deliver

Database passwords, decrypted backups, complete production dumps, or a promise
that rolling back an image will roll back a database or persistent volume.

## Production approver

### When

After all staging evidence passes and immediately before one immutable
candidate may be promoted. Customer-account production also requires an accepted
customer-administrator handoff and a successful harmless preflight through the
selected fixed TAT execution path; without them, do not enter approval.

### Deliver

- Candidate manifest, staging acceptance, change summary, complete service
  digest map, migration/backup decision, maintenance window, recovery owner,
  and exact approval target.
- For customer-account production, the accepted fixed-command preflight
  evidence; when the optional role path is selected, include its value-free STS
  temporary-credential receipt.
- An approval or rejection naming one candidate identity; merge approval is not
  production approval.
- A passed candidate-bound `readiness receipt` no older than the configured
  lifetime (never more than 24 hours), plus the accepted versioned production
  handoff and enabled adapter receipt.

### Exact console steps

1. Confirm every environment-level blocker is clear. For customer-account
   production, explicitly verify the selected fixed Saved Command and harmless
   preflight. When the optional role path is used, also verify its exact pinned
   runtime and full temporary credential triple; an unverified two-field
   configuration is not sufficient.
2. Open the selected candidate's **Tag details page** and its deployment page
   generated by `.cnb/tag_deploy.yml`; do not use a branch page as the approval
   target.
3. Run the separate readiness control. Compare its receipt with the selected
   Tag, full commit, controller commit, build identity, manifest hash,
   service set, and every digest with the candidate manifest.
4. Review staging runtime/public evidence, accepted handoff/adapter receipts,
   recovery state, readiness age, and the data owner's decision.
5. Approve only that immutable candidate. **Approval and execution are separate**:
   approval makes the deployment action eligible but does not invoke the
   production adapter. A different candidate or changed
   digest requires a new review.
6. Execute only through the configured deployment control, which re-runs the
   dynamic gate before loading credentials or calling the adapter.
7. After execution, require the actual production digest map and public result
   before accepting the release record.
8. If execution enters `recovery-required`, complete recovery review, generate
   a fresh readiness receipt, and obtain **new approval** before retrying—even
   when every candidate digest is unchanged.

Official guidance: <https://docs.cnb.cool/zh/build/deploy.html>.

### Acceptance

The named candidate has explicit approval, production uses the same complete
digest map, and the final `release evidence` is recorded atomically. Missing
evidence, changed service membership, or a recovery-required state blocks
approval. Customer-account production also remains blocked until its selected
fixed-command execution path and harmless preflight are accepted; an optional
STS path has the additional temporary-credential receipt requirement.

### Never deliver

A blanket or standing approval, approval for a branch or mutable tag, permission
to rebuild in production, or an instruction to normalize a partial failure as
success.

## CNB Secret repository operation

AI handles configuration preparation and verification within the approved scope.
Repository creation uses an available authorized channel; the default CLI login
has a known scope limit. The Secret maintainer completes the audited Web save;
browser automation is optional, not a prerequisite.

1. AI selects an existing **Secret repository**, or creates it through an
   authorized [public API](cnb-openapi.md#secret-repositories). If the current
   login lacks scope, use the [private initialization token](api-onboarding.md#cnb-bootstrap-token)
   and retain the same creation journal. Only when that channel is unavailable,
   prepare the exact name, type and organization for official Web creation,
   combined with the following save handoff.
   Verify metadata through the organization listing and prepare exact file links.
2. AI classifies the consuming job and prepares the narrow repository/event/branch
   rules. Script/commands tasks omit `allow_images`; plugin tasks constrain the
   pinned image and use the applicable variable-loading mechanism. Validate the
   complete file against the [consumer's format](cnb-openapi.md#secret-repositories)
   before handing it over.
3. AI makes the complete material available through an approved private channel
   the person can actually open. For a local file, provide a direct file entry
   and an ordinary editor fallback; a directory or shell variable is insufficient.
   State whether the editor has actually been opened. This is a prepared-file
   handoff, distinct from importing a newly created PAT through hidden input;
   it needs no interactive terminal or browser automation.
4. Give one current action with a completion signal: open the prepared source,
   copy all content, paste into the exact verified CNB file editor and save,
   then report that the page shows success. AI supplies the repository, branch,
   filename, actual edit/create entry and required save fields; the person does
   not write YAML, select permissions or prepare a receipt. If the target has
   not been verified, record that gap rather than offer an inferred URL as an
   actionable page. For an offline exercise, state its local action and completion
   separately from any future online step. Sensitive values stay in the approved
   private handoff and editor, never chat or ordinary artifacts.
5. Record user-reported save separately from verified consumption. AI performs
   an authorized harmless validation, verifies permitted references
   and the relevant out-of-scope rejection, then records variable names and a
   value-free `secret receipt`. A prepared file or reported save does not complete
   reference validation; unperformed checks remain pending.

Secret repositories cannot be cloned or pushed from a local checkout. Do not
substitute an undocumented browser-internal endpoint for the audited flow. If a
value appears in chat, logs or ordinary artifacts, never echo it; the authorized
owner rotates it at the source before replacement.

Official guidance:

- <https://docs.cnb.cool/zh/repo/secret.html>
- <https://docs.cnb.cool/zh/build/file-reference.html>
