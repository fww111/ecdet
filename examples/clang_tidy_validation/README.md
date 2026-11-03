# clang-tidy真实接入验收样例

本例用于固定的空指针解引用正反例验收。`null_bad.c`包含确定的空指针解引用，`null_good.c`先检查指针再访问。

```powershell
python scripts/validate_clang_tidy.py --binary path/to/clang-tidy --output-dir ecdet_reports/clang_tidy_live
```

脚本执行真实工具，保存版本、命令、标准输出、标准错误和耗时。固定检查为`clang-analyzer-core.NullDereference`，随后经现有适配器转换为Alert并写入SARIF。正例应检出1条目标告警，反例应检出0条目标告警；编译失败或工具缺失不能算验收通过。

该样例证明固定场景的真实工具接入和报告转换，不代表项目级检出率，也不证明所有clang-tidy检查或嵌入式工具链均已适配。
