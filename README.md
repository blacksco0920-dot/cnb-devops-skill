# cnb-devops-skill

一个面向国内独立开发者的 Codex Skill，用来快速接入 CNB 云原生构建和轻量 Docker Compose 自动部署。

它适合这样的流程：

```text
GitHub push main
-> 同步到 CNB
-> CNB 云原生构建
-> 推送镜像到 TCR
-> SSH 到服务器
-> Docker Compose 拉镜像并重启
-> Caddy / Nginx 统一反向代理
```

## 它能做什么

- 查询 CNB 用户和仓库
- 创建 CNB 仓库
- 查询/开启云原生构建自动触发
- 手动触发 CNB 构建
- 查询构建状态
- 帮 Codex 排查 CNB、TCR、SSH、Docker Compose 部署链路
- 沉淀适合个人开发者和小团队的部署操作指引

## 安装

推荐直接安装到 Codex Skills 目录：

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/blacksco0920-dot/cnb-devops-skill.git ~/.codex/skills/cnb-devops-skill
```

如果你是本地开发这个仓库，也可以运行：

```bash
./scripts/install-local.sh
```

安装后，新开一个 Codex 会话，提到 CNB、cnb.cool、云原生构建、自动部署等任务时，Codex 会自动加载这个 Skill。

## 初始化

创建一个 CNB 访问令牌，然后在终端设置：

```bash
export CNB_TOKEN='你的 CNB Token'
```

建议 token 至少包含这些权限：

```text
repo-manage:r      查询仓库/构建设置
repo-manage:rw     更新构建设置
repo-cnb-trigger:rw 手动触发构建
group-resource:rw  创建仓库
```

验证 token：

```bash
python scripts/cnb.py me
```

## 快速开始

查看某个组织或用户下的仓库：

```bash
python scripts/cnb.py repos blacksco0920
```

创建仓库：

```bash
python scripts/cnb.py create-repo blacksco0920 FinAgentCrm
```

开启云原生构建自动触发：

```bash
python scripts/cnb.py enable-auto blacksco0920/FinAgentCrm
```

手动触发 main 分支构建：

```bash
python scripts/cnb.py trigger blacksco0920/FinAgentCrm --branch main
```

查看构建状态：

```bash
python scripts/cnb.py status blacksco0920/FinAgentCrm <构建号sn>
```

## 给小白的理解方式

你可以把它理解成一个“CNB 自动部署遥控器”。

你不需要记住 API 地址、URL 编码、Header、JSON 格式。只需要告诉 Codex：

```text
帮我检查 FinAgentCrm 的 CNB 自动部署为什么没跑
```

Codex 就会按 Skill 里的流程去检查：

```text
仓库是否存在
自动触发是否开启
构建是否能触发
镜像是否能拉取
服务器 /opt/server-ops 是否存在
Docker Compose 是否正常
```

## 常见问题

### 1. 为什么手动触发构建返回 403？

通常是 token 缺少：

```text
repo-cnb-trigger:rw
```

重新生成 token 或补权限即可。

### 2. 为什么服务器 docker pull 返回 unauthorized？

这不是 CNB token 的问题，而是服务器没有登录 TCR 镜像仓库。需要在服务器上执行类似：

```bash
docker login ccr.ccs.tencentyun.com
```

并使用腾讯云/TCR 的用户名和密码或访问凭据。

### 3. 这个 Skill 会保存我的 token 吗？

不会。脚本只从环境变量 `CNB_TOKEN` 读取 token，不会写入文件，也不会主动打印 token。

## 目录结构

```text
cnb-devops-skill/
├── SKILL.md
├── README.md
├── scripts/
│   ├── cnb.py
│   └── install-local.sh
└── references/
    └── endpoints.md
```

## 开源协议

MIT
