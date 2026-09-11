# 共存检查的离线输入示例

[共存输入示例程序](examples/coexistence-inputs.py)展示完整的 spec、target、policy、candidate、baseline 和 observation 结构，以及文件原字节的摘要绑定。它自带合成数据，只用 Python 标准库和公开 Skill 文件，无需私有开发仓库。字段约束以[发布后核验与收尾](post-release-closeout.md)及[固定验证程序](../scripts/verify-coexistence.py)为准。

从 Skill 根目录运行以下命令。输出目录必须尚不存在、父目录已存在；程序创建 0700 目录和 0600 文件。命令先解析临时目录的真实绝对路径，避免 macOS 的 `/tmp` 或 `/var` 符号链接被输入保护拒绝。示例中的 `.invalid` 地址、身份文件、提交、镜像、时间及基线全部为合成值，不得用于云端部署或作为真实验收证据。

```sh
EXAMPLE_PARENT="$(python3 -c 'import tempfile; from pathlib import Path; print(Path(tempfile.mkdtemp(prefix="cnb-coexistence-")).resolve())')"
python3 references/examples/coexistence-inputs.py --output "$EXAMPLE_PARENT/one" --roles api
python3 scripts/verify-coexistence.py --spec "$EXAMPLE_PARENT/one/spec.json"
python3 scripts/verify-coexistence.py --spec "$EXAMPLE_PARENT/one/spec.json" --apply

python3 references/examples/coexistence-inputs.py --output "$EXAMPLE_PARENT/four" --roles api web worker admin
python3 scripts/verify-coexistence.py --spec "$EXAMPLE_PARENT/four/spec.json"
python3 scripts/verify-coexistence.py --spec "$EXAMPLE_PARENT/four/spec.json" --apply
```

两个例子都使用 `renamed` 项目的 production 观测和一个 `neighbor` 站点，但应用角色数量不同。输入明确包含 `observation`，因此这些 `--apply` 只读取本地合成观测并保存本地回执，不连接 SSH 或公网。成功回执的 `observation_source` 为 `fixture`、`collection_started_at` 为 null，不能算线上验收。证据目录存在时再次执行会拒绝；保留结果，另选新目录制作下一个示例。

| 输入组成 | 示例表达的约束 |
| --- | --- |
| `services` | 所选应用角色加上数据库角色 `store`，分别声明资源、网络、端口、挂载和健康预期 |
| `policy.services` / `candidate.services` | 只包含应用角色，集合一致；候选逐角色绑定精确镜像 digest |
| `protected_containers` / `baseline.containers` | 邻居数据库和本项目数据库受保护，容器身份、启动时间、镜像及声明配置保持基线 |
| `protected_files` / `baseline.files` | 两项目的 host-policy.json，含 SHA-256、root 属主/组及整数文件模式 |
| `identity_probes` | 本项目每个角色使用新提交/构建；邻居继续使用自己的已接受旧版本 |
| `caddy` | 本项目站点已经过安装验收，站点集合与配置摘要在应用发布前后保持一致 |
| `observation` | 只含契约允许的受限字段，排除环境变量、原始命令和秘密响应 |

本项目应用容器可以随候选更换；保护集合内的容器不能这样更换。示例采用最小合成策略来展示比较器字段，不是完整生成主机策略。真实输入应引用已生成并验收的完整策略、候选原文和变更前盘点，计算它们实际字节的 SHA-256，填入本次授权目标和已有受保护 SSH 文件，省略合成 `observation`，再按固定入口预览和只读采集。不要把示例值、变更后状态或旧验收结果改名为新基线。
