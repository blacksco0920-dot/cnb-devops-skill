# TCR 初始化与测试收尾

用户在陌生项目实测完成后明确要求按建议推进，目标是减少下一项目首次接入的临时编排。两项独立交付共享现有私密输入、固定程序与可回读证据，按当前授权连续实现。

## 1. TCR 初始化

新增 `scripts/configure-tcr.mjs`，仅支持本轮有实际证据的 TCR Personal、ap-guangzhou、ccr.ccs.tencentyun.com。默认离线预览；`--apply` 完整预检后执行；显式已有资源模式仅只读核验。输出身份、资源、初始化/登录状态，不把初始化当成镜像推拉成功。

AI 填写项目、账号、命名空间、私有仓库、两名角色及既有授权的策略有效期；不让用户填写 JSON。固定 build-push 只允许声明仓库的 push/pull，host-pull 只允许 pull。CAM 身份无控制台、无组、无额外策略。API key 与 Registry 密码只保存在受保护文件，不进入参数/日志/状态正文。

以固定 common SDK 及官方 Personal API 实现；不改变 `configure-cam.mjs` 的 TAT 专用语义。初始化密码生成后先落盘，使用明确子身份初始化，再解除临时初始化策略。主账号未初始化时明确交接，不自动设置主账号密码。不能声称空地域/账号的 Personal 资源 ARN 限定到了该地域；准确记录官方资源语义。

状态固定 spec/目标摘要，写前记 intent，响应与最终配置回读后确认。未知结果仅按确切资源回读续接；密钥响应丢失且无私密原文时停止，不补建/重设/自动撤销。已有资源须显式指定 CAM UIN/policy IDs、Personal 复合身份及预期创建/描述等元数据、现有私密凭据引用，再完整只读核验；名字相同不构成接管。Personal 不虚构 NamespaceId/RepoId。

文件权限、链接拒绝、互斥、原子写及错误脱敏沿用现有入口。精确输入契约和官方来源随实现写入按需参考文档。

## 2. 测试执行核验与收尾

新增薄入口 `scripts/verify-test-deployment.mjs --spec <absolute> [--apply]`。默认离线预览/已有回执重验；apply 仅 DescribeCommands/DescribeInvocationTasks 及本地证据写入，绝不 Invoke，不进入生产就绪或签名上下文。

spec 绑定 project_dir、bundle_dir/lock、output_dir、完整提交、candidate_tag、invocation_id、candidate/tag_object/binding 的原文引用及私密 TAT 凭据路径。tag_object 为已保存 annotated Tag 原文，头部 object/type/tag 和 message 原字节精确匹配；不声称重新读取了当前远端 ref。

固定包锁先核验，再复用 candidate_manifest、release-request 与 `verifyTatInvocation`。验证精确目标、命令正文和参数、SUCCESS/exit0/未截断、输出回执原字节摘要、镜像、控制器以及候选 runtime/public 的 invocation 绑定。执行开始≤结束≤候选创建≤核验时间；不要求创建时间等于执行结束。

产出独立 `cnb-test-deployment-verification/v1`，只表示历史测试执行、候选原文和保存的 annotated Tag 通过；current annotations 明确 not_checked，不因缺 repo-release:r 另加登录授权。已有记录需逐字节/摘要重验，幂等且不得换 invocation 覆盖旧结果。

`reconcile-project-state.py` 按 schema/environment 分派测试与生产完整性校验，其余业务、页面、共存、恢复和原子更新复用现有逻辑。生产要求保持不变，不接受伪造生产回执。缺验收项保留具体待办，其他环境与人工内容保留。旧应用业务结果仅在核对原始内部身份后做明确带来源摘要的投影，不放宽通用身份校验。

## 验证与边界

先验证可观察行为的失败案例，再实现：离线零网络零写、精确绑定、未知写入续接、私密文件安全、越权/冲突/截断拒绝、幂等、测试/生产分离和原文事务保护。随后只读核验既有 TCR 资源，并用刚完成的真实测试证据运行新测试回查及状态收尾；不创建或轮转线上凭据，不重部署。

两个入口分别交付和审查。沿用已有入口的薄组合优于扩大生产 release-session 或继续文档手工编排。本轮不改运行包、生产流程、TCR Enterprise 或 COS 恢复，不作未经测量的提速承诺。
