"""L3 动态分析引擎（方案 3.3.5，对应 P7）。

执行载体三级吞吐-保真梯度：宿主机原生执行（嵌入式 Linux 目标档，
本包 HostCarrier）→ Unicorn CPU 级仿真 → Renode 外设级仿真
（检测到安装即接入）。harness 生成-编译-修正闭环 + oracle 三类
（崩溃退出码 / UB stderr / 看门狗超时），输出真触发 PoC 证据，
进入 L5 可证明性分级的 Detected 级。
"""

from ecdet.l3_analysis.dynamic.engine import DynamicEngine, DynamicFinding

__all__ = ["DynamicEngine", "DynamicFinding"]
