"""证据行号程序化核对器（方案 3.3.5 之 3：幻觉抑制与证据回链）。

LLM 引用的行号必须：
  1. 落在告警函数行区间内（无函数上下文时退化为文件范围）；
  2. 对应行为真实代码 —— 以词法净化行判空（注释/字符串内容已被遮蔽为空白），
     避免以 `*` 开头的解引用语句被误判为注释延续行；
  3. 包含告警行本身（研判必须指向告警位置）。
未通过核对的 TRUE_POSITIVE 一律降级 NEEDS_REVIEW。
"""

from __future__ import annotations

from ecdet.l3_analysis.builtin_rules.ctokens import LexResult


def verify_cited_lines(cited: list[int], lex: LexResult,
                       func_start: int, func_end: int,
                       alert_line: int,
                       has_function: bool = True) -> tuple[bool, list[int]]:
    """返回 (是否通过, 通过核对的行号列表)。

    has_function=False 时（告警位于全局声明等非函数位置），
    区间约束退化为整个文件。
    """
    if not cited:
        return False, []
    if has_function:
        lo, hi = func_start, func_end
    else:
        lo, hi = 1, lex.n_lines
    ok: list[int] = []
    for ln in cited:
        if not isinstance(ln, int) or not (lo <= ln <= hi):
            continue
        if not lex.line_text(ln).strip():       # 净化行空 = 纯注释/字符串
            continue
        ok.append(ln)
    contains_alert = alert_line in ok
    return (len(ok) > 0 and contains_alert), ok
