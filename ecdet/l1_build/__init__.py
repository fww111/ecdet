"""L1 编译环境复现层 —— 解决 P1。

技术路线（方案 3.3.1）：
  1. CMake 工程 → cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON 原生导出；
  2. Make 工程 → Bear 构建拦截产出编译数据库；
  3. Keil(.uvprojx) / IAR(.ewp) 闭源 IDE 工程 → 自研 XML 解析器，
     将包含路径、宏定义、目标核翻译为等价 clang 交叉驱动命令行；
  4. 无构建系统 → 源码目录直接扫描合成编译命令（零人工干预兜底）。
"""

from ecdet.l1_build.reconstructor import (
    BuildReconResult,
    CompileCommand,
    reconstruct,
)

__all__ = ["BuildReconResult", "CompileCommand", "reconstruct"]
