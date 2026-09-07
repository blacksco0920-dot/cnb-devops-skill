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
| `bootstrap-spec.json`，`0600` | 下节完整五字段结构；不含数据库密码 |
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

若 `required_env` 仅含 `DATABASE_URL`、`REDIS_URL`、`AUTH_TOKEN_SECRET`，此 preset 均可在主机生成。外部 API 密钥不可随机代造：当前 `setup-host` 没有 runtime-import 参数；需要此类必需值的项目按 `bootstrap-host.py --runtime-import <主机root所有0600文件>` 的已有管理员入口导入，再使用固定 installer/Caddy 入口。实际使用 mock 时在业务回执中如实写明。

### 生成限定范围的 Docker config

在已经安全加载**只读拉取**身份的环境执行；这里的 `TCR_USERNAME/TCR_PASSWORD` 不得取 CI 推送身份。脚本不登录、不卡控制台，只生成本地输入；真实拉取由 bootstrap 验证。多 registry 应分别加载对应身份生成各自 `auth`，保持键集合与 policy 服务及 bootstrap 镜像用到的 registry 完全相等。不能有 `credsStore`、`credHelpers` 或多余 registry。

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
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json"
python3 "$SKILL_DIR/scripts/setup-host.py" \
  --bundle-dir "$ENV_BUNDLE_DIR" --lock-sha256 "$REVIEWED_ARTIFACT_LOCK_SHA256" \
  --target "$TARGET" --bootstrap-spec "$PRIVATE_DIR/bootstrap-spec.json" \
  --tcr-docker-config "$PRIVATE_DIR/docker-config.json" --apply \
  > "$PRIVATE_DIR/setup-result.json"
```

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
## 本机签名与发布

使用已测试候选提交中的同一份生成包；本机 Node.js 22、Python 3.11+、Git 可用。候选已纳入 `production_branch`，在该 Tag 页面触发 `web_trigger_production_readiness`，等待它成功。此后本机从原 Tag 与 annotations 取材料；下面的下载仅 GET，签名仍会独立回读 TAT。环境中的 `CNB_TOKEN` 通过已有私密加载通道提供，不写到 curl 参数里。

```sh
CANDIDATE_TAG="<本次流水线生成的不可变候选Tag>"
EVIDENCE_DIR="<未被版本控制、本候选本次审批的新私密目录>"
mkdir -m 700 "$EVIDENCE_DIR"
node --input-type=module - "$BUNDLE_DIR/ci-config.json" "$CANDIDATE_TAG" "$EVIDENCE_DIR" <<'JS'
import fs from 'node:fs';
import path from 'node:path';
const [configFile, tag, output] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
const response = await fetch(`https://api.cnb.cool/${config.cnb_repository}/-/git/tag-annotations/${encodeURIComponent(tag)}`, {
  headers: {Authorization: `Bearer ${process.env.CNB_TOKEN}`, Accept: 'application/vnd.cnb.api+json'},
  redirect: 'error', signal: AbortSignal.timeout(15000)
});
if (!response.ok) throw Error(`Annotation GET failed: HTTP ${response.status}`);
const items = await response.json(), annotations = Object.create(null);
if (!Array.isArray(items)) throw Error('Annotation array required');
for (const item of items) {
  if (typeof item.key !== 'string' || typeof item.value !== 'string' || Object.hasOwn(annotations, item.key))
    throw Error('Invalid or duplicate annotation');
  annotations[item.key] = item.value;
}
if (annotations.production_readiness_status !== 'passed') throw Error('Readiness has not passed');
const encoded = annotations.production_readiness_b64url;
if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw Error('Readiness transport invalid');
const readiness = Buffer.from(encoded, 'base64url');
if (readiness.toString('base64url') !== encoded) throw Error('Noncanonical readiness transport');
fs.writeFileSync(path.join(output, 'annotations.json'), JSON.stringify(annotations), {mode: 0o600, flag: 'wx'});
fs.writeFileSync(path.join(output, 'readiness.json'), readiness, {mode: 0o600, flag: 'wx'});
JS
json_value() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
CANDIDATE_COMMIT="$(json_value "$EVIDENCE_DIR/annotations.json" candidate_commit)"
READINESS_INVOCATION_ID="$(json_value "$EVIDENCE_DIR/annotations.json" production_readiness_invocation_id)"
PRODUCTION_BRANCH="$(json_value "$BUNDLE_DIR/production/ci-config.json" production_branch)"
cd "$PROJECT_DIR"
python3 "$BUNDLE_DIR/ci/candidate_gate.py" production \
  --config "$BUNDLE_DIR/ci-config.json" --tag "$CANDIDATE_TAG" \
  --commit "$CANDIDATE_COMMIT" --branch "$PRODUCTION_BRANCH" \
  --annotations "$EVIDENCE_DIR/annotations.json" --output-dir "$EVIDENCE_DIR" --phase readiness
```

标准 gate 使用 `CNB_TOKEN`（可选 `CNB_TOKEN_USER_NAME`）fetch 并核对治理分支、Tag 类型、完整提交、ready annotations，写出 Tag message 的原始 `candidate.json`。这里 `--phase readiness` 只表示导出候选，不重复触发远端 readiness。`--phase apply` 会要求已存在的 approval，因此不能用于签名前下载。不要重新序列化 `candidate.json`、`readiness.json` 或稍后的 `approval.json`。

按已明确的生产意图签发当前候选的限时授权；本机环境先安全加载专用直接 CAM 的两项 TAT 键。若使用已验收的短期身份，须同时加载 `TENCENTCLOUD_TOKEN` 并核对剩余有效期，不能把本机初始化管理员会话直接当成发布身份。signer 没有离线签名模式或 `--readiness` 参数，指定 invocation 后直接独立回读；输出私钥匹配检查后的 `0600` 授权文件，已有文件时停止。

```sh
PRODUCTION_BINDING="<已核验的生产tat-binding.json绝对路径>"
APPROVAL_PRIVATE_KEY="<已批准的Ed25519私钥绝对路径>"
npm ci --ignore-scripts --prefix "$BUNDLE_DIR/production/dependencies"
node "$BUNDLE_DIR/production/admin/sign-production-approval.mjs" \
  --config="$BUNDLE_DIR/production/ci-config.json" \
  --candidate-config="$BUNDLE_DIR/ci-config.json" \
  --binding="$PRODUCTION_BINDING" --manifest="$EVIDENCE_DIR/candidate.json" \
  --readiness-invocation-id="$READINESS_INVOCATION_ID" \
  --private-key="$APPROVAL_PRIVATE_KEY" --output="$EVIDENCE_DIR/approval.json" \
  --authorize-production-apply > "$EVIDENCE_DIR/sign-result.json"

PUBLISH_ARGS=(--config="$BUNDLE_DIR/production/ci-config.json"
  --candidate-config="$BUNDLE_DIR/ci-config.json"
  --manifest="$EVIDENCE_DIR/candidate.json" --readiness="$EVIDENCE_DIR/readiness.json"
  --approval="$EVIDENCE_DIR/approval.json" --readiness-invocation-id="$READINESS_INVOCATION_ID")
node "$BUNDLE_DIR/production/admin/publish-production-approval.mjs" "${PUBLISH_ARGS[@]}"
# preview 成功后，按已有生产授权发布；--apply 保持在末尾。
node "$BUNDLE_DIR/production/admin/publish-production-approval.mjs" "${PUBLISH_ARGS[@]}" --apply \
  > "$EVIDENCE_DIR/publication-result.json"
```

publisher 使用本机项目 PAT 的 `CNB_TOKEN`，不加载签名私钥；先写 pending，再写签名正文和摘要，逐项回读后才标 signed。生产 owner 在**同一 Tag**按项目配置批准，再触发 `tag_deploy.production`；该事件重新检查门禁并执行相同 digest 的生产部署。签名最长一小时且不超过 prepared 到期时间；过期、候选变化、恢复阻断后的重试按既定策略刷新 readiness 与审批。完成后分别记录实际 digest、HTTPS/发布身份和项目业务验收。

<a id="recovery"></a>
## 导出、下载与离机恢复

先用项目实际接口完成业务验收和声明的非空表数据；回执写明 mock/真实服务、上传文件和结果回读范围。重新选择要导出的 `ENVIRONMENT`、`ENV_BUNDLE_DIR`、`PRIVATE_DIR`、`TARGET` 并重建上文 SSH 数组。下面的 source 命令在对应主机运行，`export` 和 `resume-source` 均默认预览；导出 `--apply` 使用已授权短暂停写窗口。

恢复前以**已接受的实际安装记录**为准：从该记录取得安装锁摘要，核对主机 `installation.json.lock_sha256` 与已安装 `artifact-lock.json` 原始摘要；逐项核对核心、policy、Compose、固定 TAT、恢复入口及恢复策略的已审字节和权限。经过文档支持的管理员 helper 兼容续接或仅 CI/包元数据更新后，当前生成锁可以不同于保留的安装锁；只要实际运行边界仍匹配已接受记录，就保留原锁和回执继续。不能直接要求两份整包锁相等，也不能据此覆盖安装记录或略过运行文件核验。

```sh
json_value() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
PROJECT_ID="$(json_value "$ENV_BUNDLE_DIR/host-policy.json" project)"
INSTALL_DIR="$(json_value "$ENV_BUNDLE_DIR/host-policy.json" install_dir)"
POLICY_SHA256="$(sha256_file "$ENV_BUNDLE_DIR/host-policy.json")"
CORE_SHA256="$(sha256_file "$ENV_BUNDLE_DIR/host/tat-deploy-test.py")"
RECOVERY_POLICY_SHA256="$(sha256_file "$ENV_BUNDLE_DIR/recovery-policy.json")"
EXPORT_ID="recovery-$(date -u +%Y%m%dT%H%M%S | tr 'T' 't')"
EXPORT_ARGS=(--project "$PROJECT_ID" --environment "$ENVIRONMENT"
  --policy-sha256 "$POLICY_SHA256" --controller-sha256 "$CORE_SHA256"
  --recovery-policy-sha256 "$RECOVERY_POLICY_SHA256" --export-id "$EXPORT_ID")
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "${SSH_ROOT[@]}" \
  python3 "$INSTALL_DIR/recover-project.py" export "${EXPORT_ARGS[@]}"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "${SSH_ROOT[@]}" \
  python3 "$INSTALL_DIR/recover-project.py" export "${EXPORT_ARGS[@]}" --apply \
  > "$PRIVATE_DIR/export-result-$EXPORT_ID.json"
```

安装的程序为 `<host-policy.install_dir>/recover-project.py`，安装目录通常 `/opt/cnb-devops/<project>/<environment>/v1`。`--controller-sha256` 总是核心 `host/tat-deploy-test.py` 的摘要，**生产也不是 `production-release.py` 的摘要**。export-id 为小写字母开头、不超过 48 位的小写字母/数字/连字符，成功后不可复用。任何命令非零立即停下并保留现场；源容器未恢复时，用相同 `EXPORT_ARGS` 将 `export` 改成 `resume-source`，预览后按原授权加 `--apply` 恢复精确原容器，核对业务再继续。

导出目录由标准入口固定为 `/var/lib/cnb-devops/<project>/<environment>/exports/<export-id>`。使用同一已核验 SSH 通道以管理员读取 root-only 文件到新本地目录，不改源端权限：

```sh
REMOTE_EXPORT_DIR="/var/lib/cnb-devops/$PROJECT_ID/$ENVIRONMENT/exports/$EXPORT_ID"
DOWNLOAD_DIR="$PRIVATE_DIR/download-$EXPORT_ID"
mkdir -m 700 "$DOWNLOAD_DIR"
umask 077
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "${SSH_ROOT[@]}" \
  cat "$REMOTE_EXPORT_DIR/export-receipt.json" > "$DOWNLOAD_DIR/export-receipt.json"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "${SSH_ROOT[@]}" \
  cat "$REMOTE_EXPORT_DIR/source-resumed.json" > "$DOWNLOAD_DIR/source-resumed.json"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "${SSH_ROOT[@]}" \
  cat "$REMOTE_EXPORT_DIR/export.tar" > "$DOWNLOAD_DIR/export.tar"
ARCHIVE_SHA256="$(json_value "$DOWNLOAD_DIR/export-receipt.json" archive_sha256)"
MANIFEST_SHA256="$(json_value "$DOWNLOAD_DIR/export-receipt.json" manifest_sha256)"
test "$(sha256_file "$DOWNLOAD_DIR/export.tar")" = "$ARCHIVE_SHA256"
POSTGRES_IMAGE="$(python3 - "$DOWNLOAD_DIR/export.tar" "$MANIFEST_SHA256" <<'PY'
import hashlib, json, sys, tarfile
with tarfile.open(sys.argv[1], 'r:') as archive:
    raw = archive.extractfile('manifest.json').read()
assert hashlib.sha256(raw).hexdigest() == sys.argv[2], 'Manifest checksum mismatch'
print(json.loads(raw)['postgres']['image'])
PY
)"
```

在与源端不同的本机 Docker daemon 上恢复；Python 3.11+，当前 Docker context 必须是本地 Unix socket。提前把上面导出记录指定的 `linux/amd64` PostgreSQL 16 镜像拉到此 daemon；恢复命令本身不联网、不拉镜像。下面把已有的只读 Docker 输入复制到独立拉取目录，不更改个人 Docker 登录配置：

```sh
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG
LOCAL_CONTEXT="$(docker context show)"
LOCAL_ENDPOINT="$(docker context inspect "$LOCAL_CONTEXT" --format '{{.Endpoints.docker.Host}}')"
case "$LOCAL_ENDPOINT" in unix:///*) ;; *) exit 1 ;; esac
PULL_AUTH_DIR="$DOWNLOAD_DIR/pull-auth"
mkdir -m 700 "$PULL_AUTH_DIR"
install -m 600 "$PRIVATE_DIR/docker-config.json" "$PULL_AUTH_DIR/config.json"
docker --host "$LOCAL_ENDPOINT" --config "$PULL_AUTH_DIR" \
  pull --platform linux/amd64 "$POSTGRES_IMAGE"
RESTORE_DIR="$PRIVATE_DIR/restore-$EXPORT_ID"  # 必须尚不存在，父目录已存在
python3 "$ENV_BUNDLE_DIR/host/recover-project.py" restore-local \
  --archive "$DOWNLOAD_DIR/export.tar" --archive-sha256 "$ARCHIVE_SHA256" \
  --manifest-sha256 "$MANIFEST_SHA256" --destination "$RESTORE_DIR"
python3 "$ENV_BUNDLE_DIR/host/recover-project.py" restore-local \
  --archive "$DOWNLOAD_DIR/export.tar" --archive-sha256 "$ARCHIVE_SHA256" \
  --manifest-sha256 "$MANIFEST_SHA256" --destination "$RESTORE_DIR" --apply \
  > "$DOWNLOAD_DIR/restore-result.json"
```

`$RESTORE_DIR/restore-receipt.json` 的 `status=verified`、`external_restore_verified=true` 才是离机恢复成功；源端 `export-receipt.json` 明确仍为 false。回执包含数据库 schema/全部表行/序列和声明备份目录的对账；本地独立容器无网络、无端口，结束后停止并保留卷。该范围不包含 Redis、未声明数据、主机全盘、原 runtime 秘密或集群角色。保留 `source-resumed.json`、导出/恢复回执及它们的 SHA256，在项目状态文档中只登记位置、范围和结果。
