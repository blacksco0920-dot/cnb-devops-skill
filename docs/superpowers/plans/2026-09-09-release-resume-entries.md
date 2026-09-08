# Release Resume Entries Implementation Plan

> **For agentic workers:** Use subagent-driven-development for the independent production and recovery entries; root reviews their integration and evidence.

**Goal:** 固定本机生产授权与离机恢复的重复编排，让下一会话从可验证断点继续。

**Architecture:** 两个薄层脚本调用现有生成包；各自维护私密阶段记录。项目文档只索引状态与下一动作。保留现有 CI、签名、主机事务和恢复对账协议。

**Tech Stack:** 现有 Node.js 22、Python 3.11+ 标准库、Git、SSH、Docker 和包内锁定 TAT SDK。

## Global Constraints

不新增云资源、不升级活动包、不运行真实生产发布。先默认预览，变更使用显式执行参数；授权不从本机状态推导。状态绑定输入与原始证据，失败不吞并、秘密不输出；未知写入先核实再续接。

## 实施与验证

- [x] **生产入口**：新增 `scripts/release-session.mjs` 与 `tests/test_release_session.mjs`。先用缺入口/错误依赖目录、已有候选目录和过期签名等场景观察失败；实现 prepare/candidate/sign/publish/status，调用标准 gate/signer/publisher，验证候选与证据不变、缺权/过期停止、已发布回读可复用。
- [x] **恢复入口**：新增 `scripts/rehearse-recovery.py` 与 `tests/test_rehearse_recovery.py`。先验证导出中断/下载失败/不可信回执阻断；实现固定预检、SSH、export、下载、restore 与阶段摘要，测试恢复语义由真实包内验证器负责，传输才使用合成替身。
- [x] **接入文档**：更新 `SKILL.md`、`references/standard-workflow.md`、`references/bootstrap-inputs.md` 和 `references/project-adoption.md`。AI 优先使用固定入口，构建等待期提前准备独立工作；较低层接口只作为按需排障参考。README 仅说明用户无需重复配置、失败可续接及云端验证边界。
- [x] **独立审阅与验收**：对新入口运行安全/中断场景与本机 CLI 验证，检查受影响测试、链接和包完整性；审阅可用性和秘密边界。记录实际命令结果后提交、快进本机主分支使现有 Skill 链接生效。云端耗时改善留待下一轮同范围实测。

设计依据见 [设计记录](../specs/2026-09-09-release-resume-entries-design.md)，真实失败依据见 [复测记录](../../history/2026-09-08-api-release-rehearsal.md)。


## 验证结果

2026-09-09，本轮只更新 Skill 本机执行器和指引，生成包/主机程序/云资源未修改。

- 新生产入口：`node --test tests/test_release_session.mjs`，11 项通过。真实调用标准 Git gate、签名与授权验证、publisher；网络、TAT 和测试内依赖安装使用隔离替身。覆盖依赖漏装、下载错误、无产物签名重试、损坏签名保留、到期阻断、锁恢复及发布响应丢失后的回读续接。安装路径烟测另发现 Node 入口通过 Skill 符号链接调用会静默跳过，已修正真实路径判断；真实符号链接 CLI 和模块静默导入回归通过。
- 新恢复入口：`python3 -m unittest discover -s tests -p 'test_rehearse_recovery.py' -q`，21 项通过。标准归档/数据对账代码实际执行，SSH/Docker 边界使用合成替身；覆盖导出仅一次、下载续接、源未恢复、摘要/身份漂移、损坏回执、失败现场和最终隔离状态核验。这不是一次真实数据库或云端恢复实测。
- 独立示例项目：由真实生成器生成两环境包；CLI 生产 prepare 预览发现缺依赖，实际按锁文件 npm ci 成功，重复 prepare 与 status 续接通过；测试和生产恢复 CLI 离线预览均通过，证据目录未写入。
- 既有业务项目的 `preview.1` 包：新生产入口离线 prepare 通过，识别已有生产依赖；未读取私钥/令牌正文、未生成会话状态或调用云端。这是本机兼容性检查，不是活动运行包升级或生产发布。
- 包检查：32 项 Skill 包/链接检查通过，`scripts/check-bundle.py`、`quick_validate.py`、语法与 `git diff --check` 通过；首装 SSH 9 项既有检查通过。
- 独立代码审阅：两个入口均无待处理的 P1/P2；恢复最终隔离回读的增量另行复核通过。另一名无历史上下文的执行者从 SKILL 和按需引用识别了正确入口、准备时机与续接边界，未要求临时脚本或来源项目资料；这是一次只读使用检查，不是多模型质量或云端效率测量。

本轮没有重发已验收应用。下一轮仍需在相同范围实测整轮墙钟、人工等待和排障，才能判断提效；不将本机检查或局部脚本执行时间当作部署耗时改善。
