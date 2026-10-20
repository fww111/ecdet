"""抽象解释（MVP：函数内常量传播）—— P4 可证明性分级机制（方案 3.3.4）。

值域分析以"常量点区间"为基底（区间域的最简形态）：
  - 对函数做线性扫描，折叠 `var = <常量表达式>` 的赋值；
  - 遇到无法折叠的赋值或自增/复合赋值即置 TOP（放弃该变量信息）——保守可靠；
  - 以证明结论消费：数组下标经折叠证明越界 → CERT C ARR30-C 告警升级为
    Proven（数学证明级），证明在界内 → 不告警（误报抑制）。

局限（诚实声明）：无 CFG 分支合并、无循环不动点迭代、指针/别名未建模，
仅在单赋值直线上可靠；Proven 结论仅限能完整折叠的确定下标。
"""

from __future__ import annotations

import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import FileFacts
from ecdet.l3_analysis.builtin_rules.cstruct import FunctionInfo
from ecdet.l3_analysis.builtin_rules.ctokens import CToken

_TYPE_IDENTS = {"void", "char", "short", "int", "long", "float", "double",
                "signed", "unsigned", "_Bool",
                "int8_t", "int16_t", "int32_t", "int64_t",
                "uint8_t", "uint16_t", "uint32_t", "uint64_t"}
_FOLDABLE_OPS = {"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "(", ")"}
_COMPOUND_ASSIGNS = {"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
_EXPR_CHARS_OK = re.compile(r"[0-9a-fA-FxX ()+\-*/%<>&|~]*")


def _fold_tokens(tokens: list[CToken], consts: dict[str, int]) -> int | None:
    """将 token 序列折叠为整型常量；含未知符号/不支持的语法返回 None。"""
    parts: list[str] = []
    for t in tokens:
        if t.kind == "number":
            s = t.value.rstrip("uUlL")
            if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
                parts.append(str(int(s, 16)))
            elif s.isdigit():
                parts.append(s)
            else:
                return None
        elif t.kind == "ident":
            if t.value in consts:
                parts.append(str(consts[t.value]))
            else:
                return None
        elif t.kind == "keyword" or (t.kind == "punct" and t.value in _FOLDABLE_OPS):
            parts.append(t.value)
        elif t.kind == "punct" and t.value == "~":
            parts.append(t.value)
        else:
            return None
    if not parts:
        return None
    joined = " ".join(parts)
    # 剥离整型 cast：(uint32_t) / (unsigned int) 等
    joined = re.sub(
        r"\(\s*(?:unsigned\s+|signed\s+|long\s+|short\s+)*\s*"
        r"(?:void|char|int|_Bool|\w*_t)\s*\)", " ", joined)
    if not _EXPR_CHARS_OK.fullmatch(joined.replace(" ", "")):
        return None
    joined = joined.replace("/", "//")     # C 整除语义（正数域近似）
    try:
        return eval(joined, {"__builtins__": {}}, {})   # 仅白名单字符可达
    except Exception:  # noqa: BLE001
        return None


def propagate_constants(func: FunctionInfo) -> dict[str, int]:
    """函数内线性常量传播。返回 变量 → 常量值（未知变量不在表中）。"""
    consts: dict[str, int] = {}
    toks = func.tokens
    i = 0
    n = len(toks)
    while i < n:
        t = toks[i]
        if t.kind != "ident" or t.value in _TYPE_IDENTS:
            i += 1
            continue
        nxt = toks[i + 1].value if i + 1 < n else ""
        # var = expr ;
        if nxt == "=":
            j = i + 2
            depth = 0
            expr: list[CToken] = []
            while j < n:
                v = toks[j].value
                if v in "([{":
                    depth += 1
                elif v in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif v == ";" and depth == 0:
                    break
                expr.append(toks[j])
                j += 1
            val = _fold_tokens(expr, consts)
            if val is not None:
                consts[t.value] = val
            else:
                consts.pop(t.value, None)     # 赋值不确定 → TOP
            i = j + 1
            continue
        # var++ / var-- / var op= … → 值不再可靠
        if nxt in ("++", "--") or nxt in _COMPOUND_ASSIGNS:
            consts.pop(t.value, None)
        i += 1
    return consts


def proven_index_check(facts: list[FileFacts]) -> list[Alert]:
    """CERT C ARR30-C 的 Proven 级补充检查：

    常量折叠可证明越界的变量下标 → PROVEN 告警；
    证明在界内的变量下标 → 不告警（相对数据流保守告警是误报抑制）。
    字面量下标仍由 check_array_index 负责，此处跳过避免重复。
    """
    out: list[Alert] = []
    type_words = set(_TYPE_IDENTS)
    for f in facts:
        sizes = {a.name: a.size for a in f.arrays if a.size >= 0}
        if not sizes:
            continue
        for func in f.functions:
            consts = propagate_constants(func)
            toks = func.tokens
            for i, t in enumerate(toks):
                if t.kind != "ident" or t.value not in sizes:
                    continue
                # 声明形态排除（与 check_array_index 同口径）
                if i > 0 and (toks[i - 1].value in type_words
                              or toks[i - 1].value.endswith("_t")):
                    continue
                if i + 3 >= len(toks):
                    continue
                if toks[i + 1].value != "[" or toks[i + 3].value != "]":
                    continue
                inner = toks[i + 2]
                if inner.kind == "number":
                    continue        # 字面量下标由 DETECTED 规则负责
                if inner.kind != "ident":
                    continue
                val = consts.get(inner.value)
                if val is None:
                    continue        # 无法证明，不猜
                size = sizes[t.value]
                if val < 0 or val >= size:
                    out.append(Alert(
                        rule_id="CERT C ARR30-C",
                        engine="builtin-absint",
                        severity=Severity.ERROR,
                        message=(f"抽象解释证明：数组 {t.value}[{size}] 的下标 "
                                 f"{inner.value} 折叠为 {val}，越界访问必然发生"),
                        location=Location(path=f.path, line=t.line),
                        cwe="CWE-787",
                        provenance=Provenance.PROVEN,
                        evidence=[Evidence(
                            kind="code",
                            message=f"常量传播：{inner.value} = {val}，"
                                    f"合法范围 [0, {size})",
                            location=Location(path=f.path, line=t.line))],
                    ))
    return out
