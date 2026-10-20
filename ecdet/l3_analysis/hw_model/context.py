"""硬件语义上下文组装 —— 注入点（方案 3.3.2 annotate(IR, ...) 对应物）。

将 SVD 寄存器语义库、ISR 集合、数值宏表汇入单一 HwContext，
供 MMIO/竞争/阻塞 API 检查消费。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l3_analysis.builtin_rules.checks import ProjectContext
from ecdet.l3_analysis.hw_model.isr import collect_isr_names
from ecdet.l3_analysis.hw_model.rtos_api import (
    BLOCKING_APIS,
    CRITICAL_ENTER_MACROS,
    CRITICAL_EXIT_MACROS,
)
from ecdet.l3_analysis.hw_model.svd import RegisterMap, parse_svd

_CAST_PTR_RE = re.compile(r"\(\s*[\w\s]+\s*\*\s*\)\s*(.+?)\s*$")
_EXPR_TOKEN_RE = re.compile(
    r"0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*|[+\-*/%<>&|()~]+")
_SVD_ERRORS = (ET.ParseError, OSError, ValueError)


@dataclass
class HwContext:
    regmap: RegisterMap | None          # 无 SVD 时为 None（MMIO 检查跳过）
    isr_names: set[str] = field(default_factory=set)
    macros: dict[str, int] = field(default_factory=dict)          # 已折叠数值宏
    macro_bodies: dict[str, str] = field(default_factory=dict)    # 原始宏体
    blocking_apis: dict = field(default_factory=lambda: BLOCKING_APIS)
    critical_enter: set = field(default_factory=lambda: CRITICAL_ENTER_MACROS)
    critical_exit: set = field(default_factory=lambda: CRITICAL_EXIT_MACROS)


def build_hw_context(ctx: ProjectContext,
                     svd_path: Path | None = None) -> HwContext:
    regmap = None
    if svd_path and Path(svd_path).exists():
        try:
            regmap = parse_svd(svd_path)
        except _SVD_ERRORS:
            regmap = None
    hw = HwContext(regmap=regmap, isr_names=collect_isr_names(ctx))

    # 全工程数值宏表（含跨文件 BASE 宏），顺序：文件序 → 行序
    for f in ctx.facts:
        for p in f.lex.pp_lines:
            if p.directive != "define" or p.is_function_like or not p.macro_name:
                continue
            hw.macro_bodies.setdefault(p.macro_name, p.body.strip())
    for name in list(hw.macro_bodies):
        val = fold_expr(hw.macro_bodies[name], hw.macro_bodies)
        if val is not None:
            hw.macros[name] = val
    return hw


def fold_expr(expr: str, bodies: dict[str, str],
              depth: int = 0) -> int | None:
    """折叠常量表达式：数字字面量 + 已定义宏（递归展开）+ 基础算术/位运算。"""
    if depth > 8:
        return None
    tokens = _EXPR_TOKEN_RE.findall(expr)
    if not tokens:
        return None
    parts: list[str] = []
    for tok in tokens:
        hex_m = re.fullmatch(r"0[xX]([0-9a-fA-F]+)[uUlL]*", tok)
        if hex_m:
            parts.append(str(int(hex_m.group(1), 16)))
        elif re.fullmatch(r"\d+[uUlL]*", tok):
            parts.append(re.sub(r"[uUlL]+$", "", tok))
        elif re.fullmatch(r"[A-Za-z_]\w*", tok):
            if tok not in bodies:
                return None
            sub = fold_expr(bodies[tok], bodies, depth + 1)
            if sub is None:
                return None
            parts.append(str(sub))
        else:
            parts.append("//" if tok == "/" else tok)
    joined = " ".join(parts)
    # 剥离整型 cast：(unsigned int) / (uint32_t) 等
    joined = re.sub(
        r"\(\s*(?:unsigned\s+|signed\s+|long\s+|short\s+)*"
        r"(?:void|char|int|_Bool|\w*_t)\s*\)", " ", joined)
    if not re.fullmatch(r"[0-9 ()+\-*/%<>&|~]*", joined.replace(" ", "")):
        return None
    try:
        return eval(joined, {"__builtins__": {}}, {})   # 仅白名单字符可达此处
    except Exception:  # noqa: BLE001 —— 表达式不完整（如未闭合括号）
        return None


def resolve_base_address(name: str, hw: HwContext, depth: int = 0) -> int | None:
    """解析外设基址宏：直接数值宏或 ((TYPE *) EXPR) 形态的指针 cast 宏。"""
    if depth > 8:
        return None
    if name in hw.macros:
        return hw.macros[name]
    body = hw.macro_bodies.get(name)
    if body is None:
        return None
    inner = body.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1].strip()
    m = _CAST_PTR_RE.match(inner)
    if m:
        return fold_expr(m.group(1), hw.macro_bodies, depth + 1)
    return fold_expr(inner, hw.macro_bodies, depth + 1)
