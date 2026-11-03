# Renode固件执行示例

本例使用自包含的STM32F4最小平台描述，在Cortex-M4 CPU、内存、NVIC和USART2模型上执行裸机固件。固件启动后通过UART输出`ECDET_BOOT_OK`；接收字节`s`后输出`ECDET_STATUS_OK`。定义`INJECT_FAILURE`时，该命令改为输出`ECDET_SELFTEST_FAIL`。

真实验收入口：

```powershell
python scripts/validate_renode.py --renode path/to/renode.exe --clang path/to/clang.exe --output-dir ecdet_reports/renode
```

Clang必须支持`--target=arm-none-eabi`并具有LLD链接器。脚本使用项目中的链接脚本构建两个ELF，在真实Renode进程中运行，注入UART输入，保存UART输出、执行脚本、工具版本、固件和源码哈希及SARIF。工具分别通过参数配置；常规运行还可以使用`ECDET_RENODE`设置仿真器路径。

验收预期为正常固件PASS、故障固件FAIL，且故障固件产生1条`ECDET-RENODE-ORACLE`事件。判据只匹配UART文件，进程日志或脚本中的文本不作为固件输出。加载错误、缺少UART输出、脚本未完成和运行超时分别记录为ERROR或TIMEOUT，不产生缺陷告警。

本例验证STM32F4最小外设模型上的UART输入输出。仿真结果与固件和平台描述版本绑定；其他外设、中断场景和真实硬件运行需要各自的测试。

官方资料：[Renode安装包](https://github.com/renode/renode/releases/tag/v1.17.0)、[UART文件后端](https://renode.readthedocs.io/en/latest/host-integration/uart.html)、[平台描述格式](https://renode.readthedocs.io/en/latest/advanced/platform_description_format.html)。
