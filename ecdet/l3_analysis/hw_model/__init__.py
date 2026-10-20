"""L3 硬件语义与并发建模（方案 3.3.2，对应 P2）。

将寄存器语义、ISR 入口与 RTOS API 语义显式注入分析上下文，
使 MMIO 误访问、ISR 竞争、ISR 阻塞调用等嵌入式特有缺陷
从"不可判定"变为"可规则化检查"。
"""

from ecdet.l3_analysis.hw_model.context import HwContext, build_hw_context
from ecdet.l3_analysis.hw_model.svd import Register, RegisterMap, parse_svd

__all__ = ["HwContext", "build_hw_context", "Register", "RegisterMap", "parse_svd"]
