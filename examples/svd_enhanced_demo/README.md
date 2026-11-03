# 寄存器增强检测演示

本例使用受控SVD和C源码，验证寄存器数组、分组偏移、外设继承以及写1清零检查。

安装并扫描：

```bash
python -m pip install -e ".[hardware]"
python -m ecdet scan examples/svd_enhanced_demo --no-build -o ecdet_reports/svd_enhanced
```

芯片描述包含两个外设，每个外设展开4个寄存器，合计8个。`CTRL`的两个状态位具有写1清零语义，`DATA0`、`DATA1`和`CH_STATUS`为只读寄存器。

| 函数 | 预期硬件规则结果 |
| --- | --- |
| `clear_ready_bad` | 对写1清零寄存器执行读改写，触发`ECDET-MMIO-W1C` |
| `clear_ready_good` | 直接写入待清除位，不触发写1清零规则 |
| `clear_ready_direct_bad` | 在继承外设的绝对地址上读改写，触发`ECDET-MMIO-W1C` |
| `array_readonly_bad` | 写入数组第二个只读寄存器，触发`ECDET-MMIO-ACCESS` |
| `cluster_readonly_bad` | 写入分组内只读寄存器，触发`ECDET-MMIO-ACCESS` |
| `inherited_readonly_bad` | 写入继承外设中的只读寄存器，触发`ECDET-MMIO-ACCESS` |

扫描还会执行其他启用的代码规则。上述3处只读寄存器写入属于error级告警，因此扫描退出码应为1。SARIF和HTML报告记录源码位置、寄存器地址和硬件语义证据。

该例用于宿主机静态扫描，不应下载到真实硬件运行。
