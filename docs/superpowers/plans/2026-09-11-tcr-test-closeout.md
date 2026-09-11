# TCR 初始化与测试收尾 Implementation Plan

> **For agentic workers:** Use subagent-driven-development to implement the independent tasks, then review their integration.

**Goal:** 固化陌生项目实测中的 TCR 初始化及测试验收收尾。

**Architecture:** 两个独立管理端入口组合现有固定程序；状态收尾按测试/生产回执分派，保持生产约束。

**Tech Stack:** Node.js、Python 标准库、固定腾讯云 common SDK；现有私密文件和 SHA256 契约。

## Global Constraints

- 设计见 `docs/superpowers/specs/2026-09-11-tcr-test-closeout-design.md`。
- 工作区 `.worktrees/tcr-test-closeout`，基线 `5f75301`；不修改已安装 bundle，不做线上创建、轮转或重部署。
- 所有凭据值留私密文件；新业务入口有离线预览、实际结果回读及重复执行边界。
- 保持当前用户授权，不增加重复确认；只报告真实验证范围。

## Task 1: TCR initializer

Files: `scripts/configure-tcr.mjs`、必要的专用小模块、`tests/configure-tcr.test.mjs`。

- [x] 先写失败案例：新建与回读、相同状态零写续接、未知 key 响应不重复创建、越权/现有资源冲突、显式导入只读、离线路径与脱敏。
- [x] 实现固定 Personal 资源、两角色身份、私密凭据、写前 journal；导出可注入官方客户端的入口，CLI 使用固定 SDK。
- [x] 运行 `node --test tests/configure-tcr.test.mjs`；覆盖 CLI 与文件系统而非仅断言请求次数。
- [x] 审查后以已有 wxseo 显式资源进行只读核验，保留限制及结果。

## Task 2: Test verification and closeout

Files: `scripts/verify-test-deployment.mjs`、`scripts/reconcile-project-state.py`、对应 Node/Python tests。

- [x] 先写失败案例：精确候选/Tag/TAT、错实例/参数/镜像/摘要/时间、截断、多任务、离线零写、幂等重验。
- [x] 组合固定 candidate 与 TAT verifier，输出独立测试回执及原文；status 不声称当前 annotations 已核验。
- [x] 扩展 reconcile schema/environment 分派；测试生产不能交叉冒用，验收缺项、另一环境/人工文档及事务续接保持。
- [x] 运行新增 Node tests 和 `python3 -B -m unittest discover -s tests -p test_reconcile_project_state.py`。
- [x] 对真实 wxseo 执行只读测试核验，以原始业务证据的明确投影接通现有状态文档；不重新发布。

## Task 3: Routing, review and integration

Files: `SKILL.md`、相关 API/收尾按需文档、已有验证索引与本轮记录。

- [x] 文档只提供 AI 能直接执行的完整契约；公开介绍明确支持范围，用户只承担必要账号操作。
- [x] 审阅两项实现、拒绝路径、真实回执和文档一致性；修复有证据的问题。
- [x] 运行受影响的集成回归、技能/包完整性检查和改动文档链接检查；不重新跑已完成的应用业务或恢复。
- [x] 将审核通过的改动集成本地仓库，记录本轮准确范围和未验证的新建云路径。

## 验证结果

- 两项实现经独立审查；已修复审查和真实只读验证发现的问题。
- 受影响 Node 回归 124 通过；Python 收尾 26 通过；技能包 32 通过；入口校验、运行包摘要和改动文档链接均通过。
- 新测试入口用真实 TAT 只读回查通过；两项固定收尾重复执行复用原回执；既有 TCR 精确资源回读通过。
- 真实范围、证据摘要及未验证项见[本轮记录](../../history/2026-09-11-tcr-test-closeout.md)。本轮没有新建云资源或重新部署。
