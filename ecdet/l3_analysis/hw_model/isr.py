"""ISR 入口识别（方案 3.3.2：三路合一）。

MVP 实现两路半：
  1. 命名约定：*_IRQHandler / *_Handler / *_ISR / *_isr（CMSIS 风格向量表名）；
  2. 中断属性：__attribute__((interrupt...)) / #pragma vector 标注；
  3. 向量表归属：const 指针数组初始化列表中与已定义函数同名的符号
     （启动文件 vectors[] 形态）。
NVIC 优先级偏序推导留待接链接脚本后补齐。
"""

from __future__ import annotations

import re

from ecdet.l3_analysis.builtin_rules.checks import ProjectContext
from ecdet.l3_analysis.builtin_rules.cstruct import parse_array_decls

ISR_NAME_RE = re.compile(r"(_IRQHandler|_Handler|_ISR|_isr|_irq)$")
INTERRUPT_ATTR_RE = re.compile(
    r"__attribute__\s*\(\s*\([^)]*\binterrupt\b[^)]*\)\s*\)|#pragma\s+vector")
_VECTOR_FUNC_RE = re.compile(r"^[A-Za-z_]\w*$")


def collect_isr_names(ctx: ProjectContext) -> set[str]:
    """从工程事实中识别 ISR 函数名集合。"""
    isrs: set[str] = set()
    for f in ctx.facts:
        # 1) 已定义函数的命名约定
        for func in f.functions:
            if ISR_NAME_RE.search(func.name):
                isrs.add(func.name)
                continue
            # 2) 中断属性：签名前 2 行含 interrupt 属性 / #pragma vector
            context_src = "\n".join(
                f.lex.source_lines[max(0, func.def_line - 2):func.def_line])
            if INTERRUPT_ATTR_RE.search(context_src):
                isrs.add(func.name)
        # 3) 向量表：const 指针数组的初始化列表中的裸函数名
        _scan_vector_tables(f, isrs)
    return isrs


def _scan_vector_tables(f, isrs: set[str]) -> None:
    """识别启动文件形态的向量表：[] = { A, B, C }; 中标识符名字段。"""
    defined = {func.name for func in f.functions}
    lines = f.lex.clean_lines
    i = 0
    while i < len(lines):
        line = lines[i]
        # 数组声明行（如 `const void *vectors[] =` 或 `void (* const vectors[])(void) =`）
        if re.search(r"\w+\s*\[\s*\]\s*=\s*\{?\s*$", line.strip()) or \
                re.search(r"\w+\s*\[\s*\]\s*=\s*\{", line.strip()):
            j = i
            depth = 0
            while j < len(lines):
                for tok in re.findall(r"[A-Za-z_]\w*|[,{};]", lines[j]):
                    if tok == "{":
                        depth += 1
                    elif tok == "}":
                        depth -= 1
                        if depth <= 0:
                            return
                    elif tok.endswith(("Handler", "IRQHandler", "_isr", "_ISR")) \
                            and _VECTOR_FUNC_RE.match(tok):
                        isrs.add(tok)
                    elif tok in defined:
                        # 向量表中的裸符号若与已定义函数同名，视为 ISR
                        isrs.add(tok)
                if ";" in lines[j] and depth == 0:
                    return
                j += 1
            return
        i += 1
