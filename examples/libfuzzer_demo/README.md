# libFuzzer字节接口测试示例

`packet_bad.c`和`packet_fixed.c`提供同名的`parse_packet(const uint8_t *, size_t)`接口。前者从输入取得下标后写入4字节数组，后者先检查数组边界。`harness.c`由`generate_byte_harness('parse_packet')`模板生成，将变异输入交给目标函数。

```powershell
python scripts/validate_libfuzzer.py --clang path/to/clang.exe --output-dir ecdet_reports/fuzz_validation
python -m ecdet fuzz examples/libfuzzer_demo --harness harness.c --source packet_bad.c --clang path/to/clang.exe --runs 5000 --timeout 20 --max-len 64
```

后端同时启用覆盖率插桩、AddressSanitizer和UndefinedBehaviorSanitizer。保存语料、错误输入、覆盖计数、工具版本和源码哈希；错误输入须在同一可执行文件下独立重放成功后才生成Detected告警。没有精确栈帧时，报告明确使用驱动入口位置。错误版和修复版的输出目录应分别设置。

`--corpus`可重复指定语料文件或目录，相对路径以工程根目录为基准。输出语料会在后续运行中复用。`--runs`限制执行次数，`--timeout`限制模糊测试时间并设置外层终止保护，编译与重放分别有超时。完成预算且没有发现错误表示本次未触发问题。

官方资料：[LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)、[AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)。
