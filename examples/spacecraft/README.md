# 航天器嵌入式软件样例集

本目录包含 4 个航天器分系统的嵌入式 C 工程样例，用于验证 ECDET 在真实航天软件形态下的
规则覆盖能力。样例带有**人为注入的缺陷**（内存安全、MISRA C:2012、CERT C、中断并发、
MMIO 访问语义、星上安全等），**仅用于检测工具测试，不可作为飞行软件基线**。

每个样例均为独立的 CMake 工程，包含与工程配套的 `SPC3000.svd`，扫描时会自动加载
寄存器权限模型。

| 样例 | 分系统 | 主要场景 | 代码规模 |
| --- | --- | --- | --- |
| `aocs` | 姿轨控计算机（AOCS/GNC） | IMU 采样中断、四元数姿态确定、飞轮 PID、J2 轨道递推、FDDI/看门狗 | 约 900 行 C |
| `obdh` | 星务管理单元（OBDH） | CCSDS 遥测组帧、遥控解析分发、遥测采集、环形缓冲、载荷路由与鉴权 | 约 900 行 C |
| `eps` | 电源控制单元（EPS/PCU） | MPPT 扰动观察、电池 SOC、母线保护与卸载、加热器 PWM、ADC 中断 | 约 740 行 C |
| `ttc` | 测控应答机（TT&C） | 遥控帧解码、RS(255,223) 纠错、测距解算、注入鉴权、DMA 收发 | 约 830 行 C |

## 扫描命令

```powershell
ecdet scan examples/spacecraft/aocs --no-build
ecdet scan examples/spacecraft/obdh  --no-build
ecdet scan examples/spacecraft/eps   --no-build
ecdet scan examples/spacecraft/ttc   --no-build
```

去掉 `--no-build` 时，ECDET 会调用 CMake 生成编译数据库后再执行 CodeChecker 与内置规则。

## 缺陷覆盖（节选）

| 类别 | 规则示例 | 主要落点 |
| --- | --- | --- |
| 缓冲区与数组 | `CERT C STR31-C`、`CERT C ARR30-C`、`MISRA 18.8` | 遥测帧头、SOC 表、操作码表、FEC 动态数组 |
| 类型与常量 | `MISRA 10.3`、`ECDET-CWE-197`、`MISRA 12.2`、`13.6` | 标定增益、移位计数、`sizeof(i++)` |
| 中断并发 | `ECDET-ISR-RACE`、`ECDET-VOLATILE`、`ECDET-HW-VOLATILE-RMW`、`ECDET-HW-CRITICAL-PAIR`、`ECDET-ISR-BLOCK`、`ECDET-HW-ISR-HEAP` | IMU/ADC/定时/DMA 中断与任务共享状态 |
| 硬件语义 | `ECDET-MMIO-ACCESS`、`ECDET-HW-BITFIELD`、`MISRA 6.1` | 只读/只写寄存器、位域越界、`uint8_t` 位域 |
| 星上安全 | `CERT C MSC30-C`、`CERT C FIO30-C`、`ECDET-CWE-1284`、`MISRA 21.7` | `rand()` 会话标识、非字面量格式串、无界 `%s`、`atoi()` |
| 控制流与资源 | `MISRA 15.1/15.2/15.5/16.4`、`MISRA 21.3`、`CERT C MEM34-C` | 回跳 `goto`、单入单出、`switch` 缺省分支、堆分配与非法释放 |

## 说明

- 各样例中的 `SPC3000.svd` 是简化的星载 SoC 寄存器模型，仅覆盖样例实际使用的
  外设，寄存器偏移与 `include/*.h` 中的结构体一一对应。
- 缺陷分布刻意分散：`aocs` 侧重姿态控制与中断并发，`obdh` 侧重包处理与内存安全，
  `eps` 侧重 MMIO/位域与电源保护，`ttc` 侧重遥控解码与星上安全。
- `tests/test_spacecraft_examples.py` 对每个样例的关键规则命中做回归断言，
  避免后续规则调整导致样例失去覆盖价值。
