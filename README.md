# cnb-devops-skill

面向国内独立开发者和小团队的 CNB DevOps Codex Skill。它把 CNB OpenAPI、GitHub 同步、TCR、SSH、Docker Compose 与 Caddy 部署整理成一套可重复、可诊断、默认安全的工作流。

```text
GitHub / 本地 Git
       ↓
CNB 云原生构建
       ↓
TCR 不可变镜像摘要
       ↓
测试环境验证
       ↓ 同一提交、同一镜像
生产审批与发布
       ↓
Caddy 自动 HTTPS
```

## 适合谁

- 使用 Codex、CNB 和腾讯云轻量服务器的个人开发者
- 想把多个项目统一为同一套自动部署规范的小团队
- 不想手写 CNB API 请求，又希望保留生产安全边界的 Vibe Coding 用户

## 能做什么

- 查询 CNB 用户、仓库、默认分支、构建设置和构建记录
- 幂等创建普通仓库，默认私有
- 开启云原生构建自动触发
- 手动触发测试构建并等待结果
- 以完整 Git SHA 触发生产晋级
- 定位 CNB、Docker、TCR、SSH、Compose、Caddy、DNS 和 HTTPS 故障
- 指导测试环境先验收、生产复用同一不可变镜像摘要

## 安装

直接安装到 Codex Skills 目录：

```bash
git clone https://github.com/blacksco0920-dot/cnb-devops-skill.git \
  ~/.codex/skills/cnb-devops-skill
```

开发本仓库时可使用软链接安装：

```bash
./scripts/install-local.sh
```

重新打开 Codex 后，直接说“检查这个项目的 CNB 自动部署”即可触发技能。

## 准备 CNB Token

在 CNB Web 创建访问令牌，再只在当前终端或系统密钥管理器中提供：

```bash
export CNB_TOKEN='你的令牌'
python3 scripts/cnb.py me
```

按任务授予最小权限：

| 权限 | 用途 |
| --- | --- |
| `repo-manage:r` | 查询构建设置 |
| `repo-manage:rw` | 开启自动触发 |
| `repo-cnb-trigger:rw` | 手动触发构建或生产晋级 |
| `group-resource:rw` | 创建普通仓库 |

脚本不会保存或主动打印令牌。API 错误即使回显令牌，也会在输出前脱敏。

## 三步上手

### 1. 准备构建仓库

```bash
python3 scripts/cnb.py ensure-repo <组织> <仓库名>
python3 scripts/cnb.py enable-auto <组织/仓库名>
```

仓库默认私有。只有明确需要开源时才使用：

```bash
python3 scripts/cnb.py ensure-repo <组织> <仓库名> --public
```

新建空仓库时，先推送 `main`，再推送功能分支和标签。CNB 可能把第一个收到的分支设为默认分支：

```bash
git push cnb main
python3 scripts/cnb.py head <组织/仓库名>
```

预期输出中的 `name` 为 `main`。Git remote 中不要包含 Token，认证继续使用临时 HTTP Header 或系统凭据。若历史仓库默认分支已经设错，先在 CNB Web 的“仓库设置 -> 基础设置”中切换为 `main`，确认后再删除旧分支；当前受支持的 OpenAPI 只提供默认分支读取接口。

### 2. 构建并验证测试环境

```bash
python3 scripts/cnb.py trigger <组织/仓库名> \
  --branch main \
  --event api_trigger_staging

python3 scripts/cnb.py builds <组织/仓库名> --compact
python3 scripts/cnb.py wait <组织/仓库名> <构建号>
```

### 3. 晋级已验证提交到生产

```bash
python3 scripts/cnb.py promote <组织/仓库名> \
  --branch main \
  --sha <40或64位完整提交SHA>
```

`promote` 不接受短 SHA。生产流水线应拉取测试环境已经验证的镜像摘要，不应重新构建一次“看起来相同”的镜像。

如果现有 Token 没有 `repo-cnb-trigger:rw`，同仓库可以配置一个专用 `production` 分支：分支 `push` 只执行 `cnb:apply`，对当前提交同步触发 `api_trigger_production`。这样仍有明确审批动作，也不需要把 `main` 改成自动部署生产。跨仓库触发仍需 Token 权限。

## CNB 密钥仓库说明

CNB Secret 类型仓库目前只能在 CNB Web 创建和编辑，不能通过 Git clone/push 修改，也没有受支持的 OpenAPI 文件写入能力。因此推荐流程是：

1. 工具生成只有字段名和中文注释的 `secret.example.yml`。
2. 用户在 CNB Web 创建 Secret 仓库并一次性填写。
3. `.cnb.yml` 只引用 Secret 仓库，不保存真实值。

不要把密钥临时提交到普通仓库，也不要用浏览器自动化绕过这个产品边界。

## 安全默认值

- 普通仓库默认私有，公开必须显式 `--public`
- 仓库名、Git 引用、事件名和提交 SHA 均在请求前校验
- 每个项目使用独立 Ed25519 流水线身份
- 首次确认 SSH 主机指纹，后续固定 `known_hosts`
- 禁止盲目信任 `ssh-keyscan`
- 测试与生产使用同一提交、同一镜像摘要
- 生产需要审批，回滚只切换发布文件，不自动回滚数据库
- 统一使用 Caddy 管理 80/443 和 HTTPS

## 失败时怎么看

把部署链路拆成三层：

| 层级 | 成功标准 |
| --- | --- |
| 构建 | 测试通过，镜像已推送并获得 digest |
| 运行 | 服务器拉取成功，容器 healthy，迁移成功 |
| 公网 | Caddy 可达，DNS 正确，443 和 HTTPS 正常 |

CNB 构建成功不代表域名一定可访问；DNS 或证书失败也不应触发重复构建。详细排查见 [`references/deployment-playbook.md`](references/deployment-playbook.md)。

## 命令一览

```bash
python3 scripts/cnb.py --help
python3 scripts/cnb.py me
python3 scripts/cnb.py repos <owner>
python3 scripts/cnb.py create-repo <owner> <repo>
python3 scripts/cnb.py ensure-repo <owner> <repo>
python3 scripts/cnb.py head <owner/repo>
python3 scripts/cnb.py settings <owner/repo>
python3 scripts/cnb.py enable-auto <owner/repo>
python3 scripts/cnb.py trigger <owner/repo> [选项]
python3 scripts/cnb.py promote <owner/repo> --sha <完整SHA>
python3 scripts/cnb.py builds <owner/repo> --compact
python3 scripts/cnb.py status <owner/repo> <构建号> --compact
python3 scripts/cnb.py wait <owner/repo> <构建号>
python3 scripts/cnb.py runner-log <owner/repo> <流水线ID>
```

## 开发与测试

项目仅依赖 Python 标准库：

```bash
python3 -m unittest discover -s tests -v
python3 /path/to/skill-creator/scripts/quick_validate.py .
```

## 开源协议

[MIT](LICENSE)
