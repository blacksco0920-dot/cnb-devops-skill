# 首装、生产与恢复的执行输入

配合 [bootstrap](bootstrap.md) 使用。以下是 AI 的技术参考；从项目差异和批准记录填值，不复用来源项目的目标、凭据或当前发布状态。命令以 Bash/zsh 为例；执行前关闭 `set -x`，私密目录为未被版本控制的受保护目录且权限 `0700`（可使用项目 `.git` 下的任务目录），秘密不放进命令文字或输出。

<a id="production-key"></a>
## 生成配置前：生产密钥

仅配置测试环境可跳过本节。完整双环境配置需要项目专用 Ed25519 公钥：已有匹配密钥对且授权仍有效时复用；新项目由 AI 在批准的本机私密目录生成。先确认目录不被版本控制、权限为 `0700`，关闭命令追踪。以下命令只适用于两个目标文件均不存在时；不覆盖或轮换现有密钥。

```sh
set -euo pipefail
umask 077
PRIVATE_DIR="<本项目已批准的本机私密目录>"
test -d "$PRIVATE_DIR"
test ! -e "$PRIVATE_DIR/production-approval.pem"
test ! -e "$PRIVATE_DIR/production-approval.pub"
openssl genpkey -algorithm ED25519 -out "$PRIVATE_DIR/production-approval.pem"
openssl pkey -in "$PRIVATE_DIR/production-approval.pem" -pubout \
  -out "$PRIVATE_DIR/production-approval.pub"
```

AI 读取 `.pub` 文件，将完整 SPKI PEM 公钥填入 `production.approval_public_key`；私钥只交给后面的本机签名入口，不进入聊天、项目、CNB 或主机。记录密钥文件位置与公钥对应关系，然后运行[项目生成](bootstrap.md)。公钥与本机私钥不匹配时停止，不替换已安装的信任配置。

## 生成后：环境与私密文件

先完成 `prepare-project.py --diff/--apply`。测试包与生产包都有独立的 `artifact-lock.json`、`host-policy.json`、`ci-config.json`、`tat-spec.template.json`；不要混用摘要。

```sh
set -euo pipefail
SKILL_DIR="<本次加载的 Skill 绝对路径>"
PROJECT_DIR="<业务仓库绝对路径>"
BUNDLE_DIR="$PROJECT_DIR/deploy/vendor/cnb-devops"
ENVIRONMENT=test                 # 另一台改为 production
ENV_BUNDLE_DIR="$BUNDLE_DIR"     # production 使用 "$BUNDLE_DIR/production"
PRIVATE_DIR="<本环境已批准的私密目录>"
TARGET="$PRIVATE_DIR/ssh-target.json"

sha256_file() {
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}
REVIEWED_ARTIFACT_LOCK_SHA256="$(sha256_file "$ENV_BUNDLE_DIR/artifact-lock.json")"
POLICY_SHA256="$(sha256_file "$ENV_BUNDLE_DIR/host-policy.json")"
```

摘要计算只标识本地字节；先审阅生成差异与工件锁，再将这两个值固定到本次安装记录。后续修改包必须重新审阅，不能把远端回报的摘要当作批准输入。`setup-host` 会验证锁中的每个文件。

| 私密输入 | 精确格式或键名 |
| --- | --- |
| `ssh-target.json`，`0600` | 恰好 `host`、整数 `port`、`user`、绝对路径 `identity_file`、绝对路径 `known_hosts_file`；`user` 为 root 或 policy 的 `release_user` |
| SSH 私钥、known_hosts | 私钥 `0400/0600`；known_hosts `0400/0600/0644`。重装后通过可信控制台/既有管理员通道核验新 host key，再更新；`ssh-keyscan` 的未经核验输出不是证明 |
| `bootstrap-spec.json`，`0600` | 下节五个必需字段及按需选项；不含数据库密码 |
| `runtime-import.env`，`0600`，可选 | 首装外部业务值，每行 `KEY=value`；不含自动生成键、镜像键或重复键；通过 `setup-host --runtime-import` 传输 |
| `docker-config.json`，`0600` | 仅 `auths`，每个所需 registry 仅 `auth`；只读拉取身份 |
| TAT spec / binding | 由本环境 `tat-spec.template.json` 填 `target.region`、`target.instance_id`；binding 保存为 `0600` |
| TAT 管理员凭据 | `configure-tat --credentials` 接受 `0600` JSON：`secretId`、`secretKey`，可选 `token`；或环境变量 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`、可选 `TENCENTCLOUD_TOKEN` |
| 日常 TAT / 本机 signer | 默认使用专用直接 CAM 身份的 `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY`；已验收的临时身份必须同时加载 `TENCENTCLOUD_TOKEN`，有效期覆盖完整操作。客户端已支持三元组，OIDC 的真实流水线验收仍独立进行 |
| CNB Secret | TCR 文件：`TCR_USERNAME`、`TCR_PASSWORD`；每环境 TAT 文件：所选身份的云凭据及 `CNB_TAT_BINDING_JSON`；临时身份不能遗漏 Token |
| 本机生产授权 | Ed25519 私钥文件 `0600`，匹配生成的 `approval-ed25519.pub`；publisher 环境 `CNB_TOKEN` 限定本仓库且有 `repo-release:rw`；不把私钥送入 CI/主机 |

路径各级须为当前用户或 root 所有、无符号链接、不可由组/其他人写入。保留现有合用的私密文件，示例写入均不覆盖。

## 首次推送前检查 CNB 格式

在生成后的项目根目录校验完整流水线及部署页面；两项均通过后再推送。下面使用已有 PyYAML/jsonschema，按官方 `$schema` 选择 Draft，记录本次 schema 摘要。`tag_deploy.production` 是完整事件键，不能拆成嵌套的环境映射。

```sh
cd "$PROJECT_DIR"
python3 - <<'PY'
import hashlib, json, urllib.request
from pathlib import Path
import yaml
from jsonschema.validators import validator_for

for file, schema_name in [
    ('.cnb.yml', 'conf-schema-zh.json'),
    ('.cnb/tag_deploy.yml', 'tag-deploy-schema-zh.json'),
]:
    with urllib.request.urlopen('https://docs.cnb.cool/' + schema_name, timeout=20) as response:
        raw = response.read()
    schema = json.loads(raw)
    model = yaml.safe_load(Path(file).read_text(encoding='utf-8'))
    errors = list(validator_for(schema)(schema).iter_errors(model))
    if errors:
        raise SystemExit(f'FAIL {file}: {errors[0].json_path} ({errors[0].validator})')
    print(f'PASS {file} schema_sha256={hashlib.sha256(raw).hexdigest()}')
PY
```

## SSH 与 APT 盘点

从 target 取值到本地变量，不打印目标。后面导出/下载复用同一 SSH 数组。

```sh
target_value() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$TARGET" "$1"
}
SSH_OPTS=(-F /dev/null -p "$(target_value port)" -i "$(target_value identity_file)"
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes
  -o IdentityAgent=none -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
  -o GlobalKnownHostsFile=/dev/null -o "UserKnownHostsFile=$(target_value known_hosts_file)"
  -o ConnectTimeout=15 -o ConnectionAttempts=1)
SSH_TARGET="$(target_value user)@$(target_value host)"
SSH_ROOT=()
if [ "$(target_value user)" != root ]; then SSH_ROOT=(sudo -n); fi
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'sh -s' > "$PRIVATE_DIR/host-inventory.txt" <<'REMOTE'
cat /etc/os-release
dpkg --print-architecture
apt-cache policy docker.io docker-compose-v2 curl ca-certificates caddy
if [ "$(id -u)" = 0 ]; then ss -lntup; else sudo -n ss -lntup; fi
if test -f /etc/caddy/Caddyfile; then
  if [ "$(id -u)" = 0 ]; then sha256sum /etc/caddy/Caddyfile; else sudo -n sha256sum /etc/caddy/Caddyfile; fi
fi
REMOTE
```

核对 Ubuntu `24.04`、CPU 平台、端口与服务归属；从每台主机现有 APT 源的 `Candidate` 选实际版本。索引缺失/过期时，在已授权安装范围内运行 `sudo -n apt-get update` 后重取；不改 APT 源，不从另一机器猜版本。已有 Caddy 必须审阅配置和运行归属后取 baseline；无 Caddy 也无遗留 Caddyfile 时固定 `docker_packages.caddy`，由 setup 首装。上面的盘点不替代共享入口分类。

盘点容器只输出名称、镜像、状态、端口及必要资源指标；启动命令也可能含密码。不要把完整 `docker ps --no-trunc --format '{{json .}}'`、`docker inspect`、环境文件或未筛选的原始盘点文件输出到会话。私密目录仅保护文件访问，不会自动遮盖工具输出。

<a id="bootstrap-spec"></a>
## bootstrap-spec

以下 JSON 展示完整结构，尖括号必须换成已审结果；不存在 Redis 配置时删除 `images.redis`。镜像必须是目标可拉取且平台匹配的 TCR digest，PostgreSQL 主版本 16、Redis 主版本 7；不能填可变 tag。`ca-certificates` 为可选允许键，其余示例键覆盖纯净主机需安装的包。

```json
{
  "schema": "cnb-first-host/v1",
  "policy_sha256": "<host-policy.json 原始字节 SHA256>",
  "images": {
    "postgres": "ccr.ccs.tencentyun.com/<namespace>/<postgres-repo>@sha256:<64位digest>",
    "redis": "ccr.ccs.tencentyun.com/<namespace>/<redis-repo>@sha256:<64位digest>"
  },
  "docker_packages": {
    "docker.io": "<本机 APT Candidate>",
    "docker-compose-v2": "<本机 APT Candidate>",
    "curl": "<本机 APT Candidate>",
    "caddy": "<本机 APT Candidate>"
  },
  "generate_env": ["AUTH_TOKEN_SECRET"]
}
```

`generate_env` 只放项目 `host.required_env` 中可随机生成的键；数据库/Redis URL 自动产生，不放入此数组。该首装 preset 要求唯一网络 `<project>-<environment>`，数据库 host/container 为同前缀加 `-postgres`、端口 5432、admin 为 postgres、应用用户不为 postgres；可选 Redis 同前缀加 `-redis`、端口 6379、DB 0。现有项目不符合时先核实拓扑差异，不把其当空项目接管。

若 `required_env` 仅含 `DATABASE_URL`、`REDIS_URL`、`AUTH_TOKEN_SECRET`，此 preset 均可在主机生成。外部 API 密钥不可随机代造：AI 从本项目已有私密配置准备 `runtime-import.env`，在 setup 预览和应用时都加 `--runtime-import "$PRIVATE_DIR/runtime-import.env"`。两端先验证格式和必填键，再通过 SSH 标准输入传输；主机临时文件使用 root 所有的 0600 权限并在调用后删除。回执只记摘要。重复安装只接受已安装的相同业务值；该入口不用于更新活动环境变量。实际使用 mock 时如实记录。

按实际容量，可为 `project.yml` 的每个 `services.<name>.resource_limits` 配置整数 `memory_bytes` 和 `cpu_millis`；bootstrap spec 的可选 `resource_limits` 同样按 `postgres`/`redis` 逐项填写。Compose 和运行回读会核验上限，但上限不证明主机容量充足，仍需业务负载验收。需要 pgvector 的新库可声明 `postgres_extensions: ["vector"]`，同时固定含该扩展的 PostgreSQL 16 镜像；管理员预装扩展，应用角色保持普通权限。

### 生成限定范围的 Docker config

在已经安全加载**只读拉取**身份的环境执行；这里的 `TCR_USERNAME/TCR_PASSWORD` 不得取 CI 推送身份。脚本不登录、不卡控制台，只生成本地输入；真实拉取由 bootstrap 验证。多 registry 应分别加载对应身份生成各自 `auth`，保持键集合与 policy 服务及 bootstrap 镜像用到的 registry 完全相等。不能有 `credsStore`、`credHelpers` 或多余 registry。

本机验证推送身份时，也使用其独立的私密文件配置。仅给 `docker login` 换 `--config` 目录不保证账号隔离：Docker Desktop 可能自动启用系统钥匙串，同一 registry 的后一次登录会覆盖前一次。核对实际配置里的账号与用途；用各自目录执行真实 push/pull，不以登录成功代替权限验证。

```sh
umask 077
python3 - "$ENV_BUNDLE_DIR/host-policy.json" "$PRIVATE_DIR/bootstrap-spec.json" \
  "$PRIVATE_DIR/docker-config.json" <<'PY'
import base64, json, os, sys
policy, spec = (json.load(open(p)) for p in sys.argv[1:3])
registries = {s['image_repository'].split('/')[0] for s in policy['services'].values()}
registries |= {image.split('/')[0] for image in spec['images'].values()}
assert len(registries) == 1, 'Multiple registries require distinct reviewed credentials'
raw = (os.environ['TCR_USERNAME'] + ':' + os.environ['TCR_PASSWORD']).encode('ascii')
assert all(32 < c < 127 for c in raw) and all(raw.split(b':', 1))
auth = base64.b64encode(raw).decode('ascii')
with open(sys.argv[3], 'x') as output:
    json.dump({'auths': {next(iter(registries)): {'auth': auth}}}, output)
PY
```

## 双环境 setup 与固定 TAT

每环境独立执行，`--apply` 之前先跑不含该开关的离线预览；它同时验证完整 spec 和 Docker config。纯净无 Caddy 的路径如下；已有 Caddy 时在两次调用都加 `--caddy-baseline-sha256 "$INVENTORIED_CADDYFILE_SHA256"`。

```sh
python3 "$SKILL_DIR/scripts/setup-host.py" \
  --bundle-dir "$ENV_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --target "$TARGET" --bootstrap-spec "$PRIVATE_DIR/bootstrap-spec.json" \
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json" \
  --installation-output "$PRIVATE_DIR/accepted-installation.json"
python3 "$SKILL_DIR/scripts/setup-host.py" \
  --bundle-dir "$ENV_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --target "$TARGET" --bootstrap-spec "$PRIVATE_DIR/bootstrap-spec.json" \
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json" \
  --installation-output "$PRIVATE_DIR/accepted-installation.json" --apply \
  > "$PRIVATE_DIR/setup-result.json"
```

`--installation-output` 的父目录必须已存在且仅管理员可访问。预览只核验路径，不联网或写文件；apply 在主机 setup 已验证成功后，经同一严格 SSH 读回并核对已安装 policy、controller 和 artifact lock，再把原始 `installation.json` 原样保存为本机 `0600` 文件。已有相同有效原文只读复用，冲突或不完整文件停止且不覆盖。结果中的 `installation_path` 和 `installation_sha256` 是恢复入口所需原文的位置与摘要；失败码以 `SETUP_READY_INSTALLATION_` 开头表示主机 setup 已成功、仅证据交接未完成，应使用相同输入续接，不能重装。

本地结果的 `receipt_path` 指向主机 `/var/lib/cnb-devops/<project>/<environment>/setup/<输入摘要>/setup-receipt.json`，同结果的 `caddy_baseline_sha256` 供成功首装的续接核对。runtime 位于该环境 `bootstrap/runtime.env`，保持 root-only；安装目录从 `host-policy.json.install_dir` 读取。重装清空主机后重新首装，不搬回旧 installation/setup 回执。

把本环境 `tat-spec.template.json` 复制到私密目录，**仅填写批准的两个 target 字段**；其余正文/摘要/元数据原样保持。按既有权限核验固定命令：

```sh
npm ci --ignore-scripts --prefix "$ENV_BUNDLE_DIR/dependencies"
node "$SKILL_DIR/scripts/configure-tat.mjs" --spec "$PRIVATE_DIR/tat-spec.json"
node "$SKILL_DIR/scripts/configure-tat.mjs" \
  --spec "$PRIVATE_DIR/tat-spec.json" --apply \
  --credentials "$PRIVATE_DIR/tat-admin-credentials.json" \
  --sdk-root "$ENV_BUNDLE_DIR/dependencies" \
  --output "$PRIVATE_DIR/tat-binding-new.json" > "$PRIVATE_DIR/tat-configure-result.json"
```

同版本同正文/元数据先 Describe 后复用；只有不存在才 Create，漂移停止，不确定写入先查询。重装后实例 ID 不变也要核对实际 target；变更目标需重新批准绑定。回读不改既有命令，输出文件使用新名称。把核验后的 binding 作为该环境 CNB Secret 的 `CNB_TAT_BINDING_JSON`，不能把 setup ready 或配置命令成功当成发布证明。

<a id="production"></a>
## 本机生产准备与授权续接

使用 `scripts/release-session.mjs`，不再临时编写候选下载、凭据加载或签名拼接程序。它调用候选提交中的标准 gate/signer/publisher；不合并 main、不点击 CNB 原生按钮、不执行生产部署。首次使用运行 `node "$SKILL_DIR/scripts/release-session.mjs" --help` 查看完整参数。

AI 从本项目已审配置和私密凭据记录生成 `0600` 的 spec，并先建 `0700` 的 `session_dir`。路径均为绝对路径；`bundle_dir` 为测试生成包根目录，生产子包固定为其 `production/`。两份 lock 摘要来自已审生成记录；凭据沿用本项目已经批准的用途和范围，不要求用户再填写这些技术字段。

```json
{
  "schema": "cnb-release-session/v1",
  "project_dir": "<本项目目录>",
  "bundle_dir": "<本项目的deploy/vendor/cnb-devops目录>",
  "bundle_lock_sha256": "<已审测试artifact-lock.json原始摘要>",
  "production_lock_sha256": "<已审生产artifact-lock.json原始摘要>",
  "session_dir": "<本候选本次授权的私密目录>",
  "candidate_tag": "<本轮流水线的精确候选Tag>",
  "application_commit": "<本轮完整提交>",
  "production_binding": "<已核验生产tat-binding.json路径>",
  "approval_private_key": "<本机Ed25519私钥路径>",
  "cnb_token_file": "<本机项目专用PAT文件路径>",
  "tat_credentials_file": "<本机专用生产TAT凭据JSON路径>"
}
```

PAT 为纯令牌文件，可含一个末尾换行，需项目的 Git 读取、候选 annotations 读取和 `repo-release:rw`。TAT 凭据沿用配置器的 `secretId` / `secretKey` / 可选 `token` JSON 契约，必须是已批准的生产发布身份；本机初始化管理员会话不能直接替代它。凭据文件保持 `0600`，不要把值写入 spec、命令参数或聊天。

测试构建 ID 和精确提交已知时即可准备；候选是否实际存在和通过仍由稍后的 gate 验证。不要等用户触发就绪后才安装依赖。

```sh
node "$SKILL_DIR/scripts/release-session.mjs" prepare --spec "$PRIVATE_DIR/release-session.json"
node "$SKILL_DIR/scripts/release-session.mjs" prepare --spec "$PRIVATE_DIR/release-session.json" --apply
```

`prepare` 检查本机工具、固定包和生产子包依赖，缺失时按锁文件安装到 `production/dependencies`，不能只安装测试包依赖。准备不会读取私钥或令牌正文，也不证明生产已就绪。

按项目规则让受控分支纳入同一候选提交，在该 Tag 触发原生就绪检查，待真实流水线通过后，按顺序执行：

```sh
node "$SKILL_DIR/scripts/release-session.mjs" candidate --spec "$PRIVATE_DIR/release-session.json" --apply
node "$SKILL_DIR/scripts/release-session.mjs" sign --spec "$PRIVATE_DIR/release-session.json" --apply --authorize-production-apply
node "$SKILL_DIR/scripts/release-session.mjs" publish --spec "$PRIVATE_DIR/release-session.json"
node "$SKILL_DIR/scripts/release-session.mjs" publish --spec "$PRIVATE_DIR/release-session.json" --apply
```

`candidate` 读取 annotations，并用标准 Git gate 验证受控分支、annotated Tag、完整提交和候选；不依赖 Tag 详情 API。保留 `candidate.json`、`readiness.json` 的原始字节。`sign` 必须有已明确的生产意图，按 invocation 独立回读 TAT；`publish` 使用限定仓库的 PAT，预览后写入并逐项回读授权，最后才标 signed。两阶段隔离凭据，CI 和主机不接触签名私钥。

随后由 CNB owner 在同一 Tag 完成原生批准，`tag_deploy.production` 仍会独立校验签名并发布测试过的相同 digest。已有授权不重复询问；原生批准不代替本机签名。实际部署结束后再核对完整镜像、HTTPS/发布身份与项目业务。

中断或换会话时先执行：

```sh
node "$SKILL_DIR/scripts/release-session.mjs" status --spec "$PRIVATE_DIR/release-session.json"
```

状态只说明本机执行到哪里，不作为云端成功或授权来源。保持同一 spec 和候选，按返回阶段续接；已有签名必须重新通过有效期、候选和 prepared 绑定校验，发布程序支持对同一已签内容回读复用。签名仅本机落盘：准备错误且尚无签名文件时，可修正输入条件后重新核验再签；已有不完整或非法签名则保留并阻断，不覆盖。不得删状态或证据来规避未知结果。签名最长一小时且不超过 prepared 到期；到期时 `status` 返回 blocked 和 `refresh_readiness_new_session`，按原门禁取得新就绪及授权，并保留旧会话记录。

<a id="recovery"></a>
## 固定导出、下载与离机恢复

使用 `scripts/rehearse-recovery.py` 串联原 `host/recover-project.py`。本入口负责固定 SSH 采集和阶段续接，原恢复器继续负责停写、源恢复、不同本机 daemon 上的隔离恢复，以及全部表/序列/声明目录对账。AI 不再临时编写主机采集或下载程序。

先完成项目实际业务验收及声明的非空表数据。AI 从已核验的部署记录取得以下输入：

- `ENV_BUNDLE_DIR`：本环境生成包；测试为根包、生产为 `production/` 子包。
- `REVIEWED_ARTIFACT_LOCK_SHA256`：本环境当前已审生成锁摘要。
- `TARGET`：沿用首装的 `0600` SSH 目标文件与严格主机密钥配置。
- `ACCEPTED_INSTALLATION`：首装 `setup-result.json.installation_path` 指向的原始主机 `installation.json`，保持 `0600` 并核对 `installation_sha256`；不是让用户编写一个新验收证明。当前生成锁与实际安装锁可以不同，但固定运行文件必须匹配已审包；差异不能被解释成升级授权。
- `GIT_SHA` / `BUILD_ID`：本环境当前实际发布的完整提交和业务构建 ID。生产仍使用测试构建 ID，不使用生产流水线 ID。
- `EXPORT_ID` / `EVIDENCE_DIR`：本次唯一导出 ID 和 `0700` 私密证据目录；后续续接保持相同值。

构建运行时可先准备这些路径、依赖和恢复参数。完整参数见 `python3 "$SKILL_DIR/scripts/rehearse-recovery.py" --help`；预览不连接主机或读取云端状态。

```sh
RECOVERY_ARGS=(
  --bundle-dir "$ENV_BUNDLE_DIR"
  --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256"
  --target "$TARGET"
  --accepted-installation "$ACCEPTED_INSTALLATION"
  --git-sha "$GIT_SHA" --build-id "$BUILD_ID"
  --export-id "$EXPORT_ID" --evidence-dir "$EVIDENCE_DIR"
)
python3 "$SKILL_DIR/scripts/rehearse-recovery.py" "${RECOVERY_ARGS[@]}"
# 业务验收通过，且已有导出短暂停写授权后：
python3 "$SKILL_DIR/scripts/rehearse-recovery.py" "${RECOVERY_ARGS[@]}" --apply
```

本机需 Python 3.11+、Docker 和本地 Unix socket daemon。执行器在停写前检查运行文件、精确发布身份、本机 daemon 与 PostgreSQL 镜像；缺少私有镜像时可加 `--pull-docker-config "$PRIVATE_DIR/docker-config.json"`，用独立认证目录拉取该摘要，不改个人 Docker 登录配置。恢复本身不联网、不发布端口。

入口按依赖顺序执行源前态、标准 export preview/apply、源恢复确认、固定文件下载、摘要与清单校验、标准 restore-local preview/apply 和后态核验。下载仅限 `journal.json`、`export-receipt.json`、`source-resumed.json` 和 `export.tar`，用 journal 独立核对源恢复回执。固定远端路径来自已审 policy；源文件仍为 root-only。每阶段保存开始/结束时间、结果与证据摘要，stdout 只给结果及断点，不输出备份或原始秘密。

失败后保留证据目录，用**同一条命令**续接可验证的已完成阶段。成功导出不重复执行；导出结果不明先核实远端记录；源服务恢复未确认则停在该边界。必要的 `resume-source` 是原恢复器的独立显式动作，使用同一 project/environment、core/policy/recovery-policy 三摘要和 export-id，先预览再按既有授权执行。`--controller-sha256` 始终为 `host/tat-deploy-test.py` 的摘要，生产也不改成 `production-release.py`。

本地恢复已开始却没有完整成功回执时，保留容器/卷和现场，不能清空目录后盲目重试。标准恢复回执必须为 `status=verified`、`external_restore_verified=true`，且 schema、全表、序列和备份目录均对账通过；源端导出回执不代表离机恢复成功。最终核对源容器/公网前后态一致、恢复容器停止、无网络/端口，再将私密证据位置、摘要、范围和下一动作写入项目状态。

恢复范围不包含 Redis、未声明数据、整机、运行秘密或生产原地回退。记录整个操作窗口与各阶段时间，不把成功批次时间替代含准备/失败的总耗时，也不重复累计并行阶段。
