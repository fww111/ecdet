# 航天样例统一验收集合

`manifest.json`登记8个完整工程、44项缺陷实例及3组禁止回归的误报。4个本地工程共32项预置缺陷；远端4个工程另登记12项经源码核对的缺陷，包括队友报告中的9项独立根因和此前确认的3项漏报。同类问题出现在不同工程时分别计数。远端工程还有未纳入这44项的告警，需按告警级审查表解释。

`examples/spacecraft/`来自上游提交`61c9820a18416ccafd1a0073d60bd62a3fc848f2`；`examples/spacecraft_local/`来自2026年11月4日模拟样例。C源码、头文件和SVD保持原始缺陷版本，每个工程的`defects.json`保存缺陷编号、位置、类别和预期证据。`source_sha256`记录导入时的原始字节哈希；`normalized_source_sha256`仅将CRLF转换为LF后计算，用于跨平台校验清单。扫描前校验规范化哈希，扫描后比较本次运行前后的原始字节哈希，分别检查样例漂移和扫描过程中输入变化。

静态分析按38项缺陷根因匹配，其中37项要求内置引擎命中，1项除零由CodeChecker匹配；其余6项需要显式业务契约。规则出现次数、告警条数和缺陷实例数分开统计。AOCS、EPS的固定格式串FIO30-C以及TTC普通RAM的VOLATILE-RMW误报改为阴性断言；对应检查器的真阳性由独立回归用例覆盖。

```powershell
python -m pytest tests/test_spacecraft_suite.py -q
python scripts/prepare_spacecraft_suite.py --compiler gcc
python -m ecdet scan examples/spacecraft/aocs --no-build -o ecdet_reports/spacecraft-aocs
python -m ecdet scan examples/spacecraft/eps --no-build --contracts examples/business_contracts/contracts/eps/contracts.json -o ecdet_reports/spacecraft-eps
python examples/business_contracts/verify_pairs.py --output ecdet_reports/spacecraft-contracts --compiler gcc
python scripts/prepare_spacecraft_controls.py --output ecdet_reports/spacecraft-controls --compiler gcc
python scripts/verify_spacecraft_suite.py --output ecdet_reports/spacecraft-suite --compiler gcc --constraints
```

缺陷门禁要求逐项证据命中，误报门禁要求指定错误告警消失。规范提示保留原标准类别和严重级别，独立列入报告；不会通过将所有规范规则改为Advisory来改变精确率分母。业务契约及源码审查不能替代真实硬件调度验证。

`verify_spacecraft_suite.py`按预期引擎、规则、文件、行号或契约编号匹配44项证据，并检查3组误报阴性断言。通过该门禁表示登记集合验收通过，不表示每个分析器都完成了有效分析。各工程回执中的`subanalyses`分别保留Z3、业务契约和ESBMC状态；UNSUPPORTED、ERROR、TIMEOUT等仍需在汇总报告中单独说明。3组阴性断言也不等于全部历史误报实例均已重查。

`reference_changes.json`保存4个本地工程的32项修复补丁及EPS占空比修复。`prepare_spacecraft_controls.py`将它们应用到输出目录中的完整工程副本，生成5个参考工程和本机编译数据库，保留原始样例。输出目录已存在同名工程时停止，防止覆盖此前证据。
