# LLM端点受控验收

本例包含4个中性命名函数，分别用于数组访问和字符串拷贝的正反例。候选只来自本目录的`samples.c`，预期结果保存在`cases.json`中，仅用于调用后的比对，不写入提示词。

从项目设置库读取用户配置：

```powershell
python scripts/validate_llm_endpoint.py --settings-db path/to/ecdet_web.db --output-dir ecdet_reports/llm_controlled
```

也可使用`--base-url`和`--model`指定端点与模型。密钥仅从`ECODET_LLM_API_KEY`环境变量或设置库读取，脚本没有密钥命令行参数。设置库以只读方式打开；未明确配置端点和模型时，不自动调用默认地址或切换Mock。

| 状态 | 含义 |
| --- | --- |
| NOT_CONFIGURED | 缺少明确的端点或模型配置，没有发送请求，退出码2 |
| ERROR | 配置无效，或所有调用都未得到合格结构化结论，退出码1 |
| COMPLETED | 已完成受控调用与统计，退出码0；分别查看正确建议、错误建议和需复核数量 |

COMPLETED表示验收流程完成，不等于模型质量达到某个门槛。结果分别记录实际调用次数、结构化响应场景数、引用校验、预期比对、需复核和耗时，不能将调用失败后得到的需复核计作正确建议。

默认最多8次请求，单次超时30秒。每个候选通过TriageRunner和统一调用预算，SARIF保留`validation-candidate`引擎与`Suspected`状态，模型建议不升级为工具证实的缺陷。输出为`validation.json`和`results.sarif`，其中端点已脱敏，密钥不写入结果。

测试中的假客户端明确标记为fake，CLI不提供自动Mock模式。4个受控场景用于检查端点、结构化研判和证据流程，不能据此报告项目级准确率。
