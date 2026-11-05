# 2026年11月5日复验证据索引

完整说明见[业务契约与告警复核报告](../航天样例业务契约与告警复核_20261105.md)。

|文件|用途|
|---|---|
|summary.json|本轮统计与边界|
|seeded_defects.csv、json|32项预置缺陷与静态、契约检出的逐项映射|
|remote_specific_probes.csv、json|远端3项已知漏报的当前告警位置|
|review29.csv、json|29条告警的逐项源码审查|
|project_comparison.csv、json|13次扫描的原始与去重告警数|
|scan_receipts.json|扫描退出码、CodeChecker及Z3状态、输入源码哈希|
|contract_pairs.json|随仓库提供的6对业务缺陷与参考版本执行回执|
|contract_receipts.json|完整工程中的6对业务契约执行回执|
|runtime/|对应回执的编译日志和实际运行输出|
|remote_expected_rules.csv、json|108个工程—规则组合的出现情况|
|resolved_false_positives.csv、json|359条确认误报的消除情况|
|test_verification.json|761项完整测试、98项定向测试及真实CLI结果|
|detector_hashes.json、fixture_hashes.json|扫描时检测器源码与发布样例的哈希|
|source_reasoning_checks.json|数值范围核对及条件化的递增交错示例|

回执中的`${WORKSPACE}`代表本轮本地工作区。编译命令和路径用于记录原执行上下文；在其他机器上重放时，使用[业务契约样例README](../../examples/business_contracts/README.md)中的命令生成本机路径。

`FAIL`表示缺陷样例触发了业务断言；`PASS`表示该契约已执行的断言通过。4个本地参考工程的整次扫描退出码为2，原因是可选Z3检查不支持，不能解释成整个工程验证通过。7条硬件条件告警仍保持待板级核验。
