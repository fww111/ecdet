"""上下文裁剪器（方案 3.3.5 之 1）。

以告警函数为核心，纳入：
  - 告警所在函数全文；
  - 深度 ≤ 2 的被调函数闭包（同工程内可解析者）；
  - 函数体引用到的本文件宏定义；
按字符预算截取（token 近似：C/C++ 源码约 4 字符/token）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext


@dataclass
class ContextSlice:
    path: str
    alert_line: int
    func_name: str = ""
    func_start: int = 0
    func_end: int = 0
    function_text: str = ""
    extras: list[str] = field(default_factory=list)     # 宏/被调函数片段
    truncated: bool = False

    @property
    def n_chars(self) -> int:
        return len(self.function_text) + sum(len(e) for e in self.extras)

    def render(self) -> str:
        parts = []
        if self.function_text:
            parts.append(
                f"## 告警所在函数 {self.func_name}"
                f"（{self.path} 第 {self.func_start}-{self.func_end} 行）\n"
                f"{self.function_text}")
        parts.extend(self.extras)
        return "\n\n".join(parts)


def _find_function(ctx: ProjectContext, path: str, line: int):
    for f in ctx.facts:
        norm = f.path.replace("\\", "/")
        if norm != path.replace("\\", "/"):
            continue
        for func in f.functions:
            if func.def_line <= line <= func.body_close_line:
                return f, func
        return f, None                     # 文件在但行不在函数内
    return None, None


def slice_context(alert: Alert, ctx: ProjectContext,
                  budget_chars: int = 8000) -> ContextSlice:
    path = alert.location.path.replace("\\", "/")
    line = alert.location.line
    slice_ = ContextSlice(path=path, alert_line=line)

    f, func = _find_function(ctx, path, line)
    if f is None:
        slice_.extras.append(f"（源文件 {path} 不在工程事实中，无法切片）")
        slice_.truncated = True
        return slice_

    src = f.lex.source_lines
    if func is None:
        # 非函数位置（全局变量/宏行）：取告警行上下 ±10 行
        lo, hi = max(1, line - 10), min(len(src), line + 10)
        slice_.function_text = "\n".join(src[lo - 1:hi])
        slice_.func_start, slice_.func_end = lo, hi
        return slice_

    slice_.func_name = func.name
    slice_.func_start = func.def_line
    slice_.func_end = func.body_close_line
    slice_.function_text = "\n".join(src[func.def_line - 1:func.body_close_line])
    used = len(slice_.function_text)

    # 本文件宏定义（函数体引用到的）
    func_idents = {t.value for t in func.tokens if t.kind == "ident"}
    for p in f.lex.pp_lines:
        if p.directive != "define" or not p.macro_name:
            continue
        if p.macro_name in func_idents:
            block = f"#define {p.macro_name} {p.body}".strip()
            if used + len(block) > budget_chars:
                slice_.truncated = True
                break
            slice_.extras.append(block)
            used += len(block)

    # 被调函数闭包（深度 ≤ 2，同工程内）
    callee_index: dict[str, tuple] = {}
    for f2 in ctx.facts:
        for fn2 in f2.functions:
            callee_index.setdefault(fn2.name, (f2, fn2))
    seen = {func.name}
    frontier = [name for name, _ in func.calls_in_body() if name not in seen]
    for depth in (1, 2):
        nxt: list[str] = []
        for name in frontier:
            if name in seen:
                continue
            seen.add(name)
            hit = callee_index.get(name)
            if hit is None:
                continue
            f2, fn2 = hit
            text = "\n".join(
                f2.lex.source_lines[fn2.def_line - 1:fn2.body_close_line])
            block = f"## 被调函数 {name}（{f2.path}:{fn2.def_line}，深度 {depth}）\n{text}"
            if used + len(block) > budget_chars:
                slice_.truncated = True
                return slice_
            slice_.extras.append(block)
            used += len(block)
            if depth < 2:
                nxt.extend(c for c, _ in fn2.calls_in_body() if c not in seen)
        frontier = nxt
    return slice_
