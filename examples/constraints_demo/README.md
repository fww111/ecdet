# Z3局部数组边界验证样例

`bounds.c`包含5个受限C子集函数，验证器直接从源码提取分支、整数类型和数组访问。

| 函数 | 预期结果 | 原因 |
| --- | --- | --- |
| `missing_lower_guard` | SAT | 只检查小于8，负数也能到达访问 |
| `guarded_index` | UNSAT | 当前访问的局部模型同时排除了负数和上界 |
| `promoted_byte` | SAT | 8位无符号参数先提升为32位有符号整数，255加1得到256 |
| `unsigned_wrap` | UNSAT | 32位无符号最大值加1按模运算得到0 |
| `signed_overflow` | UNSUPPORTED | 到达当前表达式需要发生有符号溢出，不输出安全结论 |

运行真实验收：

```powershell
python scripts/validate_constraints.py --output-dir ecdet_reports/constraints_validation
```

脚本保存源码哈希、SMT约束、输入类型、SAT候选输入、资源受限的UNKNOWN记录及SARIF。独立C程序验证候选输入的分支与下标计算，不执行越界内存读取。

模型使用8位字节、16位short、32位int和二进制补码整数。UNSAT只对应记录的局部数组访问与支持的语义；循环、调用、指针、除法、移位、类型覆盖和其他不支持结构保留显式状态。候选告警保持Suspected，原有告警不被删除或升级。
