"""Source-bounded context slices with file-scoped call resolution."""
from __future__ import annotations

import re
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
    extras: list[str] = field(default_factory=list)
    truncated: bool = False
    provided_ranges: list[dict] = field(default_factory=list)
    unresolved_calls: list[dict] = field(default_factory=list)
    syntax_backends: list[dict] = field(default_factory=list)

    @property
    def n_chars(self) -> int:
        return len(self.function_text) + sum(len(item) for item in self.extras)

    def render(self) -> str:
        parts = []
        if self.function_text:
            own = next((r for r in self.provided_ranges if r["path"] == self.path), None)
            start, end = (own["start_line"], own["end_line"]) if own else (self.func_start, self.func_end)
            parts.append(f"## 告警代码 {self.func_name}（{self.path} 第{start}-{end}行）\n{self.function_text}")
        parts.extend(self.extras)
        if self.truncated:
            parts.append("上下文已截断；只能引用实际提供的源码行。")
        if self.unresolved_calls:
            parts.append("未解析调用：" + ", ".join(item["name"] for item in self.unresolved_calls))
        own_backend = next((item for item in self.syntax_backends
                            if item["path"].replace("\\", "/") == self.path), None)
        if own_backend:
            origin = "Tree-sitter语法结构" if own_backend["selected"] == "tree-sitter" else "基础结构恢复"
            parts.append(f"结构来源：{origin}（{own_backend['status']}）；预处理分支未求值。")
        return "\n\n".join(parts)


def _functions(facts):
    index = getattr(facts, "syntax", None)
    return index.functions if index is not None and index.status == "PASS" else facts.functions


def _is_ast(function) -> bool:
    return hasattr(function, "start_byte")


def _start(function) -> int:
    return function.start_line if _is_ast(function) else function.def_line


def _end(function) -> int:
    return function.end_line if _is_ast(function) else function.body_close_line


def _function_key(owner, function):
    return owner.path, function.start_byte if _is_ast(function) else function.def_line


def _source(owner) -> str:
    return getattr(owner, "source", "") or "\n".join(owner.lex.source_lines)


def _text(owner, function) -> str:
    if _is_ast(function):
        return _source(owner).encode("utf-8")[function.start_byte:function.end_byte].decode("utf-8")
    return "\n".join(owner.lex.source_lines[function.def_line - 1:function.body_close_line])


def _syntax_metadata(owner) -> dict:
    index = getattr(owner, "syntax", None)
    if index is None:
        return {"path": owner.path, "backend": "builtin", "selected": "builtin",
                "status": "UNAVAILABLE", "diagnostics": ["No structural index attached"]}
    keys = {"kind", "message", "start_line", "end_line", "start_col", "end_col"}
    diagnostics = [{key: value for key, value in item.items() if key in keys}
                   if isinstance(item, dict) else str(item) for item in index.diagnostics]
    return {"path": owner.path, "backend": index.backend, "status": index.status,
            "selected": "tree-sitter" if index.status == "PASS" else "builtin",
            "diagnostics": diagnostics}


def _calls(owner, function):
    if _is_ast(function):
        return [(call.name or call.expression,
                 "conditional call" if getattr(call, "conditional", False)
                 else "" if call.kind == "direct" else f"{call.kind} call")
                for call in function.calls]
    macros = {macro.macro_name for macro in owner.lex.pp_lines}
    return [(name, "macro call" if name in macros else "indirect call" if name in function.params else "")
            for name, _ in function.calls_in_body()]


def _find_function(ctx: ProjectContext, path: str, line: int, col: int = 1):
    for facts in ctx.facts:
        if facts.path.replace("\\", "/") != path.replace("\\", "/"):
            continue
        matches = [fn for fn in _functions(facts) if _start(fn) <= line <= _end(fn)]
        if len(matches) == 1:
            only = matches[0]
            if not _is_ast(only):
                return facts, only
            inside = ((line > only.start_line or col >= only.start_col)
                      and (line < only.end_line or col < only.end_col))
            # Legacy line-only alerts commonly use col=1 on indented lines.
            # Tolerate leading whitespace, never other declarations or code.
            whitespace_prefix = (line == only.start_line and col == 1
                                 and not facts.lex.source_lines[line - 1][:only.start_col - 1].strip())
            return facts, only if inside or whitespace_prefix else None
        for function in matches:
            if (_is_ast(function)
                    and (line > function.start_line or col >= function.start_col)
                    and (line < function.end_line or col < function.end_col)):
                return facts, function
        return facts, None
    return None, None


def _partial_line(owner, start_line: int, end_line: int, start_col: int, end_col: int) -> bool:
    lines = owner.lex.source_lines
    return bool(lines[start_line - 1][:start_col - 1].strip()
                or lines[end_line - 1][end_col - 1:].strip())


def _ast_window(owner, function, focus: int, budget: int):
    exact = _text(owner, function)
    raw_lines = exact.splitlines(keepends=True)
    if len(exact) <= budget:
        shown, low, high = exact, 1, len(raw_lines)
    else:
        lines = exact.splitlines()
        shown, low, high = _source_window(lines, 1, len(lines),
                                          focus - function.start_line + 1, budget)
    start_line, end_line = function.start_line + low - 1, function.start_line + high - 1
    start_col = function.start_col if low == 1 else 1
    end_col = function.end_col if high == len(raw_lines) else len(owner.lex.source_lines[end_line - 1]) + 1
    start_byte = function.start_byte + len("".join(raw_lines[:low - 1]).encode("utf-8"))
    end_byte = function.start_byte + len("".join(raw_lines[:high]).rstrip("\r\n").encode("utf-8"))
    partial = bool(shown) and _partial_line(owner, start_line, end_line, start_col, end_col)
    span = {"path": owner.path.replace("\\", "/"), "start_line": start_line, "end_line": end_line,
            "start_col": start_col, "end_col": end_col, "start_byte": start_byte, "end_byte": end_byte,
            "partial_line": partial, "conditional": getattr(function, "conditional", False)}
    return shown, span, (low != 1 or high != len(raw_lines) or partial)


def _source_window(lines: list[str], start: int, end: int, focus: int,
                   budget: int) -> tuple[str, int, int]:
    text = "\n".join(lines[start - 1:end])
    if len(text) <= budget:
        return text, start, end
    lo = hi = min(max(focus, start), end)
    if len(lines[lo - 1]) > budget:
        return "", lo, lo - 1
    # Expand complete lines around the alert; never invent citation positions.
    while True:
        changed = False
        if lo > start and len("\n".join(lines[lo - 2:hi])) <= budget:
            lo -= 1
            changed = True
        if hi < end and len("\n".join(lines[lo - 1:hi + 1])) <= budget:
            hi += 1
            changed = True
        if not changed:
            return "\n".join(lines[lo - 1:hi]), lo, hi


def slice_context(alert: Alert, ctx: ProjectContext, budget_chars: int = 8000) -> ContextSlice:
    path, line = alert.location.path.replace("\\", "/"), alert.location.line
    result = ContextSlice(path=path, alert_line=line)
    result.syntax_backends = [_syntax_metadata(owner) for owner in ctx.facts]
    facts, function = _find_function(ctx, path, line, alert.location.col)
    if facts is None or not 1 <= line <= facts.lex.n_lines:
        result.truncated = True
        result.extras.append(f"（源文件{path}或告警位置不在工程事实中，无法切片）")
        result.unresolved_calls.append({"name": "<context>", "path": path, "reason": "source unavailable"})
        return result
    source = facts.lex.source_lines
    if function is None and sum(_start(fn) <= line <= _end(fn) for fn in _functions(facts)) > 1:
        result.truncated = True
        result.unresolved_calls.append({"name": "<function>", "path": path, "reason": "ambiguous function position"})
        return result
    if function is None:
        start, end = max(1, line - 10), min(len(source), line + 10)
    else:
        result.func_name = function.name
        start, end = _start(function), _end(function)
    result.func_start, result.func_end = start, end
    if function is not None and _is_ast(function):
        result.function_text, span, result.truncated = _ast_window(facts, function, line, max(0, budget_chars))
        if result.function_text:
            result.provided_ranges.append(span)
        if getattr(function, "conditional", False):
            result.truncated = True
            result.unresolved_calls.append({"name": function.name, "path": path, "reason": "conditional definition"})
    else:
        result.function_text, shown_start, shown_end = _source_window(source, start, end, line, max(0, budget_chars))
        result.truncated = (shown_start, shown_end) != (start, end)
        if result.function_text:
            result.provided_ranges.append({"path": path, "start_line": shown_start, "end_line": shown_end})
    if function is None:
        return result

    def append_macros(owner, fn):
        from ecdet.l3_analysis.builtin_rules.ctokens import lex_c
        tokens = lex_c(_text(owner, fn)).tokens if _is_ast(fn) else fn.tokens
        identifiers = {token.value for token in tokens if token.kind == "ident"}
        for macro in owner.lex.pp_lines:
            if macro.directive != "define" or not macro.macro_name or macro.macro_name not in identifiers:
                continue
            block = f"#define {macro.macro_name} {macro.body}".strip()
            if block in result.extras:
                continue
            if result.n_chars + len(block) > budget_chars:
                result.truncated = True
                continue
            result.extras.append(block)

    append_macros(facts, function)
    by_name: dict[str, list[tuple]] = {}
    for owner in ctx.facts:
        for fn in _functions(owner):
            by_name.setdefault(fn.name, []).append((owner, fn))
    seen = {_function_key(facts, function)}
    frontier = [(facts, name, reason, 1) for name, reason in _calls(facts, function)]
    while frontier:
        owner, name, reason, depth = frontier.pop(0)
        if reason:
            result.unresolved_calls.append({"name": name, "path": owner.path, "reason": reason})
            continue
        candidates = by_name.get(name, [])
        conditional = [(f, fn) for f, fn in candidates if getattr(fn, "conditional", False)]
        candidates = [(f, fn) for f, fn in candidates if not getattr(fn, "conditional", False)]
        local = [(f, fn) for f, fn in candidates if f.path == owner.path]
        global_ = [(f, fn) for f, fn in candidates
                   if not (fn.is_static if _is_ast(fn) else re.search(r"\bstatic\b", fn.signature))]
        choices = local or global_
        if len(choices) != 1:
            if not any(p.macro_name == name for p in owner.lex.pp_lines):
                result.unresolved_calls.append({"name": name, "path": owner.path,
                                                "reason": "ambiguous" if choices else
                                                "conditional definition" if conditional else "definition unavailable"})
            continue
        callee_file, callee = choices[0]
        key = _function_key(callee_file, callee)
        if key in seen:
            continue
        seen.add(key)
        text = _text(callee_file, callee)
        block = f"## 被调函数 {name}（{callee_file.path}:{callee.def_line}，深度{depth}）\n{text}"
        if result.n_chars + len(block) > budget_chars:
            result.truncated = True
            result.unresolved_calls.append({"name": name, "path": owner.path, "reason": "context budget"})
            continue
        result.extras.append(block)
        if _is_ast(callee):
            _, callee_span, _ = _ast_window(callee_file, callee, _start(callee), len(text))
            result.provided_ranges.append(callee_span)
        else:
            result.provided_ranges.append({"path": callee_file.path.replace("\\", "/"),
                                           "start_line": callee.def_line, "end_line": callee.body_close_line})
        append_macros(callee_file, callee)
        if depth < 2:
            frontier.extend((callee_file, child, why, depth + 1) for child, why in _calls(callee_file, callee))
        elif _calls(callee_file, callee):
            result.unresolved_calls.extend({"name": child, "path": callee_file.path, "reason": "depth limit"}
                                           for child, _ in _calls(callee_file, callee))
    return result
