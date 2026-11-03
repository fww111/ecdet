"""L3 动态分析引擎（方案 3.3.5，对应 P7）。

源码函数测试使用DynamicEngine；字节接口覆盖率测试使用LibFuzzerEngine；
ELF固件仿真使用RenodeRunner。Unicorn当前只提供探测接口。
各执行路径保留实际载体、输入与状态，运行证据按各自判据写入报告。
"""

from ecdet.l3_analysis.dynamic.engine import DynamicEngine, DynamicFinding

__all__ = ["DynamicEngine", "DynamicFinding"]
