"""2026-11 规则缺口核验批次 —— 确认缺失且 token 级可判定的规则实现。

本模块只承载《规则核验与去重对照表_20261103.xlsx》中标记为"缺失"
且不依赖 SVD/位域布局/整工程类型系统的候选规则；判定口径均写入
各检查函数 docstring，避免被误当作完整 MISRA/CERT 实现。

已知边界（与主引擎一致）：
  - 无宏展开与条件编译求值；
  - 类型表来自逐行声明扫描（函数局部覆盖全局），不建模作用域嵌套；
  - 指针分析仅覆盖"声明 + 直接强制转换/返回"形态，不做别名传播。
"""

from __future__ import annotations

import re

from ecdet.l2_ir.model import Alert, Severity, Provenance
from ecdet.l3_analysis.builtin_rules.checks import (
    FileFacts,
    ProjectContext,
    _alert,
    _evidence,
    _match_forward,
    _SIDE_EFFECT_OPS,
)
from ecdet.l3_analysis.builtin_rules.ctokens import lex_c
from ecdet.l3_analysis.builtin_rules.ectypes import (
    INT32,
    INT64,
    EssentialType,
    build_type_table,
    resolve_type,
    usual_arith,
)

_TYPE_KEYWORDS = {"void", "char", "short", "int", "long", "float", "double",
                  "signed", "unsigned", "_Bool", "struct", "union", "enum"}
_QUALIFIERS = {"const", "volatile", "restrict"}
_STORAGE = {"static", "extern", "register", "inline", "typedef", "auto"}
_STRUCTURAL = {"(", ")", "[", "]", "{", "}"}

_INT_LITERAL_RE = re.compile(
    r"^(?P<body>0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)(?P<suffix>[uUlL]*)$")

_DECL_PTR_RE = re.compile(
    r"(?:^|[;{}])\s*(?:(?:static|extern|register)\s+)*"
    r"(?P<pre>(?:(?:const|volatile)\s+)*)"
    r"(?P<base>((?:unsigned|signed|struct|union|enum)\s+)?"
    r"(?:void|char|short|int|long|float|double|_Bool|BOOL|"
    r"u?int(?:8|16|32|64)_t|[uUsS](?:8|16|32)(?:_t)?|"
    r"UINT8|UINT16|UINT32|INT8|INT16|INT32|"
    r"[A-Za-z_]\w*_t|[A-Za-z_]\w*_TypeDef))"
    r"\s*(?P<stars>\*+)\s*(?P<post>(?:(?:const|volatile)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?=[=;,)])"
)

_LOCAL_DECL_RE = re.compile(
    r"(?:^|[;{}(,])\s*(?P<storage>(?:(?:static|const|volatile|register|extern)\s+)*)"
    r"(?P<type>(?:(?:unsigned|signed)\s+)?"
    r"(?:void|char|short(?:\s+int)?|int|long(?:\s+long)?(?:\s+int)?|float|double|_Bool"
    r"|u?int(?:8|16|32|64)_t|BOOL|[A-Za-z_]\w*_t|[A-Za-z_]\w*_TypeDef))"
    r"\s*(?:\*+\s*)?(?P<name>[A-Za-z_]\w*)\s*(?=[=;,\[(])"
)

_BITFIELD_RE = re.compile(
    r"\b(?P<type>(?:(?:unsigned|signed)\s+)?"
    r"(?:char|short(?:\s+int)?|int|long(?:\s+long)?|_Bool|BOOL|"
    r"u?int(?:8|16|32|64)_t|[uU](?:8|16|32)))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<width>\d+)\s*;"
)

_SECRET_RE = re.compile(
    r"(?i)\b(?P<name>password|passwd|pwd|secret|token|"
    r"api[_-]?key|private[_-]?key|access[_-]?key)\b"
    r"\s*(?:\[\s*\])?\s*(?:=\s*|\s+)"
    r"(?P<value>\"[^\"]{4,}\")"
)

_MEMCPY_SRC_RE = re.compile(
    r"\b(?:memcpy|memmove)\s*\(\s*[A-Za-z_]\w*\s*,\s*"
    r"(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<size>[0-9]+)\s*\)"
)

_ELEMENT_BYTES = {
    "char": 1, "int8_t": 1, "uint8_t": 1, "u8": 1, "U8": 1, "s8": 1, "S8": 1,
    "short": 2, "int16_t": 2, "uint16_t": 2, "u16": 2, "U16": 2,
    "s16": 2, "S16": 2,
    "int": 4, "unsigned": 4, "long": 4, "float": 4, "int32_t": 4,
    "uint32_t": 4, "u32": 4, "U32": 4, "s32": 4, "S32": 4,
    "double": 8, "int64_t": 8, "uint64_t": 8, "long long": 8,
}


def _num(text: str) -> int | None:
    m = _INT_LITERAL_RE.match(text.strip())
    if not m:
        return None
    body = m.group("body")
    try:
        if body.lower().startswith("0x"):
            return int(body, 16)
        if len(body) > 1 and body.startswith("0"):
            return int(body, 8)
        return int(body, 10)
    except ValueError:
        return None


def _literal_c_type(text: str) -> EssentialType | None:
    """C 整型字面量的实际类型（ILP32：int/long 均为 32 位）。"""
    value = _num(text)
    if value is None:
        return None
    suffix = _INT_LITERAL_RE.match(text.strip()).group("suffix").lower()
    unsigned = "u" in suffix
    if "ll" in suffix:
        return EssentialType(5, not unsigned)
    if "l" in suffix:
        return EssentialType(3, not unsigned)
    if unsigned:
        return EssentialType(3, False) if value <= 0xFFFFFFFF else EssentialType(5, False)
    if value <= (1 << 31) - 1:
        return INT32
    if value <= (1 << 63) - 1:
        return INT64
    return INT64


def _pick_rule(active: set[str], candidates: list[str]) -> str | None:
    return next((r for r in candidates if r in active), None)


def _check_chain(bits: int, signed: bool, value: int) -> bool:
    if signed:
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        return not (lo <= value <= hi)
    return not (0 <= value <= (1 << bits) - 1)


def _numeric_macros(f: FileFacts) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in f.lex.pp_lines:
        if p.directive == "define" and p.macro_name and not p.is_function_like:
            v = _num(p.body.strip())
            if v is not None:
                out[p.macro_name] = v
    return out


def _norm_base(text: str) -> str:
    words = [w for w in re.split(r"[\s*]+", text.strip())
             if w and w not in _QUALIFIERS and w not in _STORAGE]
    if not words:
        return ""
    text = " ".join(words)
    alias = {
        "uint8_t": "unsigned char", "int8_t": "signed char",
        "uint16_t": "unsigned short", "int16_t": "signed short",
        "uint32_t": "unsigned int", "int32_t": "signed int",
        "uint64_t": "unsigned long long", "int64_t": "signed long long",
        "UINT8": "unsigned char", "INT8": "signed char",
        "UINT16": "unsigned short", "INT16": "signed short",
        "UINT32": "unsigned int", "INT32": "signed int",
        "u8": "unsigned char", "s8": "signed char",
        "u16": "unsigned short", "s16": "signed short",
        "u32": "unsigned int", "s32": "signed int",
    }.get(text, text)
    return alias


def _pointer_vars(f: FileFacts) -> dict[str, tuple[str, set[str]]]:
    """变量名 → (指针基类型, 指向类型限定符)。"""
    out: dict[str, tuple[str, set[str]]] = {}

    def add(name: str, type_text: str) -> None:
        if "*" not in type_text:
            return
        quals = {w for w in re.findall(r"[A-Za-z_]\w*", type_text)
                 if w in _QUALIFIERS}
        base = _norm_base(type_text)
        if base:
            out[name] = (base, quals)

    for func in f.functions:
        for pname, ptype in zip(func.params, func.param_types):
            add(pname, ptype)
    for idx, line in enumerate(f.lex.clean_lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        for m in _DECL_PTR_RE.finditer(text):
            # 保留声明中的星号，避免局部/全局指针被 add() 丢弃
            type_text = f"{m.group('pre')} {m.group('base')} {m.group('stars')}"
            add(m.group("name"), type_text)
    return out


def _local_names(f: FileFacts, func) -> set[str]:
    names: set[str] = set()
    for line in range(func.body_open_line, func.body_close_line + 1):
        if not (1 <= line <= len(f.lex.clean_lines)):
            continue
        text = f.lex.clean_lines[line - 1]
        for m in _LOCAL_DECL_RE.finditer(text):
            if m.group("type") in ("void", "float", "double"):
                continue
            storage = m.group("storage") or ""
            if "static" in storage or "extern" in storage:
                continue      # 静态/外部存储期对象，函数返回后地址仍有效
            names.add(m.group("name"))
    return names


def _cast_sites(func) -> list[tuple[int, list, int, str, set[str]]]:
    """扫描函数体内 `(type*)expr` 形态的强制转换。

    返回 (操作数索引, 目标类型 token, 是否指针, 目标基类型, 目标限定符)。
    """
    toks = func.tokens
    out = []
    for i, t in enumerate(toks):
        if t.kind != "punct" or t.value != "(":
            continue
        close = _match_forward(toks, i, "(", ")")
        if close <= i + 1:
            continue
        inner = toks[i + 1:close]
        if any(tk.value in _STRUCTURAL - {"(", ")"} for tk in inner):
            continue
        words = [tk.value for tk in inner]
        typeish = [w for w in words if w in _TYPE_KEYWORDS or w in _QUALIFIERS
                   or w.endswith(("_t", "_TypeDef", "_T")) or w in
                   ("BOOL", "UINT8", "UINT16", "UINT32", "INT8", "INT16", "INT32")]
        if not typeish or len(typeish) != sum(1 for w in words if w != "*"):
            continue
        is_ptr = "*" in words
        base = _norm_base(" ".join(w for w in words if w not in _QUALIFIERS and w != "*"))
        quals = {w for w in words if w in _QUALIFIERS}
        if not base and not is_ptr:
            continue
        operand = close + 1
        if operand >= len(toks) or toks[operand].kind not in ("ident", "number", "string"):
            continue
        out.append((operand, inner, is_ptr, base, quals))
    return out


_BITFIELD_ALLOWED = {"_Bool", "int", "signed int", "unsigned int", "unsigned",
                     "signed", "uint32_t", "int32_t", "UINT32", "INT32"}


def check_bitfield_type(f: FileFacts, ctx: ProjectContext,
                        active: set[str]) -> list[Alert]:
    """MISRA 6.1：位域类型应为 _Bool / signed int / unsigned int（或 32 位 typedef）。"""
    out: list[Alert] = []
    for idx, line in enumerate(f.lex.clean_lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        for m in _BITFIELD_RE.finditer(text):
            ftype = " ".join(m.group("type").split())
            if ftype in _BITFIELD_ALLOWED:
                continue
            out.append(_alert(
                "MISRA C:2012 6.1", Severity.WARNING,
                f"位域 {m.group('name')} 使用类型 {ftype}，不属于允许的 "
                "_Bool/signed int/unsigned int",
                f.path, idx, "CWE-197",
                [_evidence(f.path, idx, "code",
                           f"{ftype} {m.group('name')} : {m.group('width')}")],
                provenance=Provenance.SUSPECTED,
            ))
    return out


def check_pointer_cast(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 11.3/11.4/11.8 + CERT INT36-C：指针转换族。

    仅对"操作数是已声明标识符/整数字面量"的转换判定；函数调用结果、
    宏表达式不参与，避免把正常类型擦除误判。
    """
    out: list[Alert] = []
    ptrs = _pointer_vars(f)
    ints = build_type_table(f.lex, f.func_lines, functions=f.functions)
    for func in f.functions:
        toks = func.tokens
        for operand, inner, target_ptr, target_base, target_quals in _cast_sites(func):
            if not target_ptr and target_base == "void":
                continue      # (void)expr 仅为丢弃结果，非指针/整数转换
            tok = toks[operand]
            src_base = src_quals = None
            if tok.kind == "ident" and tok.value in ptrs:
                src_base, src_quals = ptrs[tok.value]
            src_int = tok.kind == "ident" and tok.value in ints

            if src_quals and target_ptr and (src_quals - target_quals):
                rid = _pick_rule(active, ["MISRA C:2012 11.8"])
                if rid:
                    lost = "、".join(sorted(src_quals - target_quals))
                    out.append(_alert(
                        rid, Severity.WARNING,
                        f"强制转换移除了 {tok.value} 指向类型的 {lost} 限定",
                        f.path, tok.line, "CWE-704",
                        [_evidence(f.path, tok.line, "code",
                                   f"源声明含 {lost}，目标类型未保留")],
                        provenance=Provenance.SUSPECTED,
                    ))
                    continue

            ptr_to_int = target_ptr is False and src_base is not None
            int_to_ptr = target_ptr and (src_int or tok.kind == "number")
            if ptr_to_int or int_to_ptr:
                rid = _pick_rule(active, ["MISRA C:2012 11.4", "CERT C INT36-C"])
                if rid:
                    if int_to_ptr:
                        msg = f"整数 {tok.value} 被转换为指针，地址可移植性与对齐均无保证"
                    else:
                        msg = f"指针 {tok.value} 被转换为整数，指针宽度与整型宽度不保证一致"
                    out.append(_alert(
                        rid, Severity.WARNING, msg, f.path, tok.line, "CWE-704",
                        [_evidence(f.path, tok.line, "code",
                                   f"目标类型：{' '.join(t.value for t in inner)}")],
                    ))
                    continue

            if target_ptr and src_base and src_base != "void" and target_base != "void" \
                    and src_base != target_base:
                rid = _pick_rule(active, ["MISRA C:2012 11.3"])
                if rid:
                    out.append(_alert(
                        rid, Severity.NOTE,
                        f"指针 {tok.value} 从 {src_base}* 转换为 {target_base}*，"
                        "指向类型不同",
                        f.path, tok.line, "CWE-704",
                        [_evidence(f.path, tok.line, "code",
                                   f"{src_base}* → {target_base}*")],
                        provenance=Provenance.SUSPECTED,
                    ))
    return out


def _eval_const_expr(toks: list, i: int) -> tuple[int, object] | None:
    """递归下降求值常量算术表达式（+-*/% 与括号，支持一元正负号）。

    返回 (end_idx, err)；err 为 None 或 (op_token, op_sym, result_value, et)。
    按 C 运算符优先级（*/% 高于 +-）求值，每个二元运算后以 usual_arith 结果
    类型检查是否溢出/回绕，取首次溢出。
    """
    n = len(toks)
    pos = [i]
    err = [None]

    def cur():
        return toks[pos[0]] if pos[0] < n else None

    def parse_factor():
        t = cur()
        if t is None:
            return None
        if t.kind == "punct" and t.value in ("-", "+"):
            sign = -1 if t.value == "-" else 1
            pos[0] += 1
            sub = parse_factor()
            if sub is None:
                return None
            return (sign * sub[0], sub[1])
        if t.kind == "number":
            et = _literal_c_type(t.value)
            v = _num(t.value)
            if et is None or v is None:
                return None
            pos[0] += 1
            return (v, et)
        if t.kind == "punct" and t.value == "(":
            pos[0] += 1
            sub = parse_expr()
            if sub is None:
                return None
            if cur() is None or cur().value != ")":
                return None
            pos[0] += 1
            return sub
        return None

    def parse_term():
        left = parse_factor()
        if left is None:
            return None
        lv, le = left
        while cur() is not None and cur().kind == "punct" and cur().value in ("*", "/", "%"):
            op = cur()
            pos[0] += 1
            right = parse_factor()
            if right is None:
                return None
            rv, re_ = right
            et = usual_arith(le, re_)
            if op.value == "*":
                result = lv * rv
            else:
                if rv == 0:
                    return None  # 除零交给对应检查器，不让规则求值器异常退出。
                # C 整数除法向零截断，不能使用 Python 对负数向下取整的 //。
                quotient = (abs(lv) // abs(rv)) * (-1 if (lv < 0) != (rv < 0) else 1)
                result = quotient if op.value == "/" else lv - quotient * rv
            if err[0] is None and _check_chain(et.bits, et.signed, result):
                err[0] = (op, op.value, result, et)
            lv, le = result, et
        return (lv, le)

    def parse_expr():
        left = parse_term()
        if left is None:
            return None
        lv, le = left
        while cur() is not None and cur().kind == "punct" and cur().value in ("+", "-"):
            op = cur()
            pos[0] += 1
            right = parse_term()
            if right is None:
                return None
            rv, re_ = right
            et = usual_arith(le, re_)
            result = lv + rv if op.value == "+" else lv - rv
            if err[0] is None and _check_chain(et.bits, et.signed, result):
                err[0] = (op, op.value, result, et)
            lv, le = result, et
        return (lv, le)

    value = parse_expr()
    if value is None:
        return None
    return pos[0], err[0]


def check_constant_overflow(f: FileFacts, ctx: ProjectContext,
                            active: set[str]) -> list[Alert]:
    """ECDET-CWE-190 + CERT INT30-C/INT32-C：常量算术溢出/回绕。

    只对"完全由整型字面量 + - * / % ( ) 构成"的表达式按优先级求值并检测
    溢出；跨宏/变量的表达式留给 Clang 常量传播，避免误报。
    """
    out: list[Alert] = []
    toks = f.lex.tokens
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        is_num = t.kind == "number"
        is_unary = (t.kind == "punct" and t.value in ("-", "+") and i + 1 < n
                    and (toks[i + 1].kind == "number"
                         or (toks[i + 1].kind == "punct" and toks[i + 1].value == "(")))
        if not is_num and not is_unary:
            i += 1
            continue
        r = _eval_const_expr(toks, i)
        if r is None:
            i += 1
            continue
        end, err = r
        if err is not None:
            op_tok, op_sym, result, et = err
            candidates = (["CERT C INT32-C", "ECDET-CWE-190"] if et.signed
                          else ["CERT C INT30-C", "ECDET-CWE-190"])
            rid = _pick_rule(active, candidates)
            if rid:
                kind = "有符号溢出" if et.signed else "无符号回绕"
                out.append(_alert(
                    rid, Severity.WARNING,
                    f"常量表达式经 {op_sym} 运算后结果为 {result}，"
                    f"超出 {et.label()} 范围，发生{kind}",
                    f.path, op_tok.line, "CWE-190",
                    [_evidence(f.path, op_tok.line, "code",
                               f"结果 {result} 超出 {et.label()} 范围")],
                ))
        i = end if end > i else i + 1
    return out


def check_shift_count(f: FileFacts, ctx: ProjectContext,
                      active: set[str]) -> list[Alert]:
    """MISRA 12.2 + CERT INT34-C：移位计数越界/为负。"""
    out: list[Alert] = []
    types = build_type_table(f.lex, f.func_lines, functions=f.functions)
    macros = _numeric_macros(f)
    rid = _pick_rule(active, ["MISRA C:2012 12.2", "CERT C INT34-C"])
    if not rid:
        return out
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.value not in ("<<", ">>"):
                continue
            if i == 0 or i + 1 >= len(toks):
                continue
            left = toks[i - 1]
            if left.kind == "ident" and left.value in types:
                width = types[left.value].bits
            elif left.kind == "number":
                et = _literal_c_type(left.value)
                width = et.bits if et else 32
            else:
                continue
            right = toks[i + 1]
            negative = False
            if right.value == "-" and i + 2 < len(toks) and toks[i + 2].kind == "number":
                negative, right = True, toks[i + 2]
            if right.kind == "number":
                count = _num(right.value)
            elif right.kind == "ident" and right.value in macros:
                count = macros[right.value]
            else:
                continue
            if count is None:
                continue
            if negative or count < 0 or count >= width:
                out.append(_alert(
                    rid, Severity.WARNING,
                    f"移位计数 {('-' if negative else '')}{count} 超出左操作数位宽 "
                    f"{width} 的有效范围 0..{width - 1}",
                    f.path, t.line, "CWE-682",
                    [_evidence(f.path, t.line, "code",
                               f"左操作数 {left.value}（{width} 位）")],
                ))
    return out


def check_sizeof_side_effect(f: FileFacts, ctx: ProjectContext,
                             active: set[str]) -> list[Alert]:
    """MISRA 13.6：sizeof 操作数含副作用。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value != "sizeof":
                continue
            if i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            close = _match_forward(toks, i + 1, "(", ")")
            if close == -1:
                continue
            for j in range(i + 2, close):
                tk = toks[j]
                if tk.kind == "punct" and tk.value in _SIDE_EFFECT_OPS:
                    out.append(_alert(
                        "MISRA C:2012 13.6", Severity.WARNING,
                        f"sizeof 操作数包含副作用运算符 {tk.value}",
                        f.path, tk.line, "CWE-758",
                        [_evidence(f.path, tk.line, "code", "sizeof 操作数")],
                    ))
                    break
                if tk.kind == "ident" and j + 1 < close and toks[j + 1].value == "(":
                    out.append(_alert(
                        "MISRA C:2012 13.6", Severity.WARNING,
                        f"sizeof 操作数包含函数调用 {tk.value}()",
                        f.path, tk.line, "CWE-758",
                        [_evidence(f.path, tk.line, "code", "sizeof 操作数")],
                    ))
                    break
    return out


def check_invariant_condition(f: FileFacts, ctx: ProjectContext,
                              active: set[str]) -> list[Alert]:
    """MISRA 14.3：if/while/for 条件为常量不变量。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value in ("do", "switch"):
                continue
            if t.value not in ("if", "while", "for"):
                continue
            if i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            close = _match_forward(toks, i + 1, "(", ")")
            if close == -1:
                continue
            inner = toks[i + 2:close]
            if t.value == "for":
                parts, cur, depth = [], [], 0
                for tk in inner:
                    if tk.kind == "punct" and tk.value in "([":
                        depth += 1
                    elif tk.kind == "punct" and tk.value in ")]":
                        depth -= 1
                    if tk.value == ";" and depth == 0:
                        parts.append(cur)
                        cur = []
                    else:
                        cur.append(tk)
                parts.append(cur)
                cond = parts[1] if len(parts) > 1 else []
            else:
                cond = inner
            cond = [tk for tk in cond if tk.kind != "punct" or tk.value in ("-", "+")]
            if len(cond) == 1 and cond[0].kind == "number":
                out.append(_alert(
                    "MISRA C:2012 14.3", Severity.NOTE,
                    f"{t.value} 的条件表达式为常量 {cond[0].value}（不变量）",
                    f.path, t.line,
                    evidence=[_evidence(f.path, t.line, "code", "常量控制表达式")],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


def check_unreachable(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 2.1（保守口径）：同一块内 return 之后仍有语句。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        depth = 0
        for i, t in enumerate(toks):
            if t.value == "{":
                depth += 1
            elif t.value == "}":
                depth = max(0, depth - 1)
            if t.kind != "keyword" or t.value != "return":
                continue
            prev = toks[i - 1].value if i > 0 else ""
            if i > 0 and prev not in ("{", ";", ":"):
                continue      # if/for/while 的单语句 return 不是无条件
            j, d = i + 1, 0
            while j < len(toks):
                tk = toks[j]
                if tk.kind == "punct":
                    if tk.value in "([{":
                        d += 1
                    elif tk.value in ")]}":
                        d = max(0, d - 1)
                    elif tk.value == ";" and d == 0:
                        break
                j += 1
            if j + 1 >= len(toks):
                continue
            nxt = toks[j + 1]
            if nxt.value in ("}", "case", "default", "else"):
                continue
            if nxt.kind == "ident" and j + 2 < len(toks) and toks[j + 2].value == ":":
                continue      # goto 标签处视为可达
            out.append(_alert(
                "MISRA C:2012 2.1", Severity.NOTE,
                f"return 语句之后的代码不可达（首个不可达 token：{nxt.value}）",
                f.path, nxt.line,
                evidence=[_evidence(f.path, nxt.line, "code", "return 后语句")],
                provenance=Provenance.SUSPECTED,
            ))
    return out


def check_switch_termination(f: FileFacts, ctx: ProjectContext,
                             active: set[str]) -> list[Alert]:
    """MISRA 16.3：switch 子句缺少无条件 break/return。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value != "switch":
                continue
            j = i + 1
            while j < len(toks) and toks[j].value != "(":
                j += 1
            if j >= len(toks):
                continue
            close = _match_forward(toks, j, "(", ")")
            if close == -1 or close + 1 >= len(toks) or toks[close + 1].value != "{":
                continue
            end = _match_forward(toks, close + 1, "{", "}")
            if end == -1:
                continue
            labels = []
            depth = 0
            for k in range(close + 2, end):
                tk = toks[k]
                if tk.kind == "punct":
                    if tk.value in "([{":
                        depth += 1
                    elif tk.value in ")]}":
                        depth = max(0, depth - 1)
                elif depth == 0 and tk.kind == "keyword" and tk.value in ("case", "default"):
                    labels.append(k)
            for idx, start in enumerate(labels):
                stop = labels[idx + 1] if idx + 1 < len(labels) else end
                has_stmt = False
                depth = 0
                stmt_start = start + 1
                last_kw = None
                k = start + 1
                while k < stop:
                    tk = toks[k]
                    if tk.kind == "punct":
                        if tk.value in "([{":
                            depth += 1
                        elif tk.value in ")]}":
                            depth = max(0, depth - 1)
                        elif tk.value == ";" and depth == 0:
                            first = toks[stmt_start] if stmt_start < k else None
                            if first is not None and first.kind == "keyword" \
                                    and first.value in ("break", "return",
                                                        "continue", "goto"):
                                last_kw = first
                            stmt_start = k + 1
                        elif tk.value == ":" and depth == 0:
                            stmt_start = k + 1
                    elif tk.kind != "punct" and not (
                            tk.kind == "keyword" and tk.value in ("case", "default")):
                        has_stmt = True
                    k += 1
                if not has_stmt:
                    continue      # 空子句（标签分组）不单独判定
                if last_kw is None:
                    prev = toks[start - 1].value if start > 0 else ""
                    out.append(_alert(
                        "MISRA C:2012 16.3", Severity.WARNING,
                        f"switch 子句（{prev}）未以无条件 break/return 终止，存在贯穿风险",
                        f.path, toks[start].line, "CWE-484",
                        [_evidence(f.path, toks[start].line, "code", "case/default 子句")],
                        provenance=Provenance.SUSPECTED,
                    ))
    return out


def check_local_addr_escape(f: FileFacts, ctx: ProjectContext,
                            active: set[str]) -> list[Alert]:
    """MISRA 18.6（保守口径）：return &局部对象。"""
    out: list[Alert] = []
    for func in f.functions:
        locals_ = _local_names(f, func)
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value != "return":
                continue
            if i + 2 >= len(toks) or toks[i + 1].value != "&" \
                    or toks[i + 2].kind != "ident":
                continue
            name = toks[i + 2].value
            if name not in locals_:
                continue
            out.append(_alert(
                "MISRA C:2012 18.6", Severity.WARNING,
                f"返回局部对象 {name} 的地址，函数退出后指针悬空",
                f.path, t.line, "CWE-562",
                [_evidence(f.path, t.line, "code", f"return &{name}")],
            ))
    return out


def check_vla(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 18.8：可变长度数组声明。"""
    out: list[Alert] = []
    types = build_type_table(f.lex, f.func_lines, functions=f.functions)
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != "[":
                continue
            prev = toks[i - 1] if i > 0 else None
            typeish = prev and (
                (prev.kind == "keyword" and prev.value in _TYPE_KEYWORDS)
                or (prev.kind == "ident" and (
                    prev.value.endswith("_t") or prev.value in ("BOOL", "UINT32", "INT32")))
                or prev.value == "*")
            if not typeish:
                continue
            close = _match_forward(toks, i + 1, "[", "]")
            if close <= i + 2:
                continue
            dim = toks[i + 2:close]
            if any(tk.value == "sizeof" for tk in dim):
                continue
            if all(tk.kind == "number" or tk.value in ("+", "-", "*", "/", "%", "(")
                   or (tk.kind == "ident" and tk.value.isupper()) for tk in dim):
                continue
            out.append(_alert(
                "MISRA C:2012 18.8", Severity.WARNING,
                f"数组 {t.value} 使用可变长度维度，栈分配大小不可静态确定",
                f.path, t.line, "CWE-770",
                [_evidence(f.path, t.line, "code",
                           "维度含运行时标识符："
                           + " ".join(tk.value for tk in dim))],
            ))
    return out


def check_pp_condition(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 20.8（保守口径）：纯数字 #if/#elif 求值不在 {0,1}。"""
    out: list[Alert] = []
    for p in f.lex.pp_lines:
        if p.directive not in ("if", "elif"):
            continue
        parts = p.text.split(None, 1)
        expr = parts[1].strip() if len(parts) > 1 else ""
        probe = re.sub(r"0[xX][0-9a-fA-F]+", "0", expr)
        if not expr or re.search(r"[A-Za-z_!&|]", probe):
            continue      # 含宏/逻辑运算的表达式不在此简化模型内求值
        if not re.fullmatch(r"[0-9a-fA-FxX()+\-*/%<>=^~ \t]+", expr):
            continue
        try:
            value = eval(expr, {"__builtins__": {}}, {})  # noqa: S307 —— 字符白名单已限
        except Exception:   # noqa: BLE001 —— 不完整表达式
            continue
        if value not in (0, 1, True, False):
            out.append(_alert(
                "MISRA C:2012 20.8", Severity.NOTE,
                f"#if 控制表达式求值为 {value}，不是 0 或 1",
                f.path, p.line,
                evidence=[_evidence(f.path, p.line, "code", p.text)],
                provenance=Provenance.SUSPECTED,
            ))
    return out


def check_pp_stringize(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 20.10：# 字符串化 / ## 拼接运算符。"""
    out: list[Alert] = []
    for p in f.lex.pp_lines:
        if p.directive != "define":
            continue
        if "#" not in p.body:
            continue
        out.append(_alert(
            "MISRA C:2012 20.10", Severity.WARNING,
            "宏体使用了 # 或 ## 预处理运算符",
            f.path, p.line, "CWE-758",
            [_evidence(f.path, p.line, "code", f"#define {p.macro_name} {p.body}")],
        ))
    return out


def _array_element_bytes(a) -> int | None:
    """数组元素字节数；struct/union/指针/未知类型返回 None（保守跳过）。"""
    if "*" in a.type_text:
        return None
    et = resolve_type(a.type_text)
    if et is None:
        return None
    return et.bits // 8


def check_copy_source_bounds(f: FileFacts, ctx: ProjectContext,
                             active: set[str]) -> list[Alert]:
    """MISRA 21.17：memcpy/memmove 字节长度超过源数组字节容量（越界读）。"""
    out: list[Alert] = []
    capacities: dict[str, int] = {}
    for a in f.arrays:
        if a.size <= 0:
            continue
        element_bytes = _array_element_bytes(a)
        if element_bytes is None:
            continue      # 未知元素类型保守跳过，避免把元素数误当字节数
        capacities[a.name] = a.size * element_bytes
    for idx, line in enumerate(f.lex.clean_lines, start=1):
        if line.strip().startswith("#"):
            continue
        for m in _MEMCPY_SRC_RE.finditer(line):
            src, n = m.group("src"), int(m.group("size"))
            cap = capacities.get(src)
            if cap is None or n <= cap:
                continue
            out.append(_alert(
                "MISRA C:2012 21.17", Severity.ERROR,
                f"从数组 {src}（字节容量 {cap}）拷贝 {n} 字节，越界读取",
                f.path, idx, "CWE-125",
                [_evidence(f.path, idx, "code",
                           f"源数组 {src} 字节容量 {cap}，拷贝长度 {n}")],
            ))
    return out


def check_assignment_in_condition(f: FileFacts, ctx: ProjectContext,
                                  active: set[str]) -> list[Alert]:
    """CERT EXP45-C：if/while/for 条件中含赋值。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value not in ("if", "while", "for"):
                continue
            if i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            close = _match_forward(toks, i + 1, "(", ")")
            if close == -1:
                continue
            inner = toks[i + 2:close]
            if t.value == "for":
                depth, segs, cur = 0, [], []
                for tk in inner:
                    if tk.kind == "punct" and tk.value in "([":
                        depth += 1
                    elif tk.kind == "punct" and tk.value in ")]":
                        depth -= 1
                    if tk.value == ";" and depth == 0:
                        segs.append(cur)
                        cur = []
                    else:
                        cur.append(tk)
                inner = segs[1] if len(segs) > 1 else []
            hit = next((tk for tk in inner if tk.value == "="), None)
            if hit is None:
                continue
            out.append(_alert(
                "CERT C EXP45-C", Severity.WARNING,
                f"{t.value} 控制表达式包含赋值运算（可能误写 = 为 ==）",
                f.path, hit.line, "CWE-480",
                [_evidence(f.path, hit.line, "code", "控制表达式中的 =")],
            ))
    return out


def check_free_non_dynamic(f: FileFacts, ctx: ProjectContext,
                           active: set[str]) -> list[Alert]:
    """CERT MEM34-C：free 释放非动态对象（取地址/数组/字面量）。"""
    out: list[Alert] = []
    array_names = {a.name for a in f.arrays}
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "ident" or t.value != "free" \
                    or i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            j = i + 2
            if j >= len(toks):
                continue
            if toks[j].value == "&" and j + 1 < len(toks):
                target = toks[j + 1].value
                reason = "取地址的对象"
            elif toks[j].kind == "ident" and toks[j].value in array_names:
                target = toks[j].value
                reason = "数组"
            elif toks[j].kind == "string":
                target, reason = "字符串字面量", "字符串字面量"
            else:
                continue
            out.append(_alert(
                "CERT C MEM34-C", Severity.ERROR,
                f"free 释放{reason} {target}，该内存并非堆分配",
                f.path, toks[j].line, "CWE-590",
                [_evidence(f.path, toks[j].line, "code", "free 实参")],
            ))
    return out


def check_hardcoded_secret(f: FileFacts, ctx: ProjectContext,
                           active: set[str]) -> list[Alert]:
    """CERT MSC41-C：疑似硬编码口令/密钥（关键字启发式，suspected）。"""
    out: list[Alert] = []
    for idx, line in enumerate(f.lex.source_lines, start=1):
        clean = f.lex.clean_lines[idx - 1] if idx <= len(f.lex.clean_lines) else ""
        m = _SECRET_RE.search(line)
        if not m:
            continue
        if m.group("name").lower() not in clean.lower():
            continue      # 关键字仅出现在注释/字符串中
        out.append(_alert(
            "CERT C MSC41-C", Severity.WARNING,
            f"标识符 {m.group('name')} 直接赋值/定义为字符串常量，疑似硬编码敏感信息",
            f.path, idx, "CWE-798",
            [_evidence(f.path, idx, "code", "敏感信息以明文常量存储")],
            provenance=Provenance.SUSPECTED,
        ))
    return out


def check_large_stack_array(f: FileFacts, ctx: ProjectContext,
                            active: set[str]) -> list[Alert]:
    """ECDET-CWE-785：函数内数组占用栈空间 ≥ 1 KiB。"""
    out: list[Alert] = []
    for arr in f.arrays:
        if arr.is_global or arr.size <= 0:
            continue
        words = set(re.findall(r"[A-Za-z_]\w*", arr.type_text))
        elem = 4
        for name, size in _ELEMENT_BYTES.items():
            if name in arr.type_text.split():
                elem = size
                break
        if "*" in arr.type_text:
            elem = 4
        if arr.size * elem < 1024:
            continue
        out.append(_alert(
            "ECDET-CWE-785", Severity.WARNING,
            f"局部数组 {arr.name} 占用约 {arr.size * elem} 字节栈空间，"
            "存在栈溢出风险",
            f.path, arr.line, "CWE-785",
            [_evidence(f.path, arr.line, "code",
                       f"{arr.type_text} {arr.name}[{arr.size}]")],
        ))
    return out


def check_pp_operator(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    return check_pp_stringize(f, ctx, active)


def check_goto_later(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 15.2：goto 只能跳到同一函数内之后定义的标签。"""
    out: list[Alert] = []
    for func in f.functions:
        toks = func.tokens
        labels: dict[str, int] = {}
        for i, t in enumerate(toks):
            if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != ":":
                continue
            prev = toks[i - 1].value if i > 0 else ""
            if i == 0 or prev in ("{", "}", ";", ":"):
                labels.setdefault(t.value, i)
        for i, t in enumerate(toks):
            if t.kind != "keyword" or t.value != "goto" or i + 1 >= len(toks):
                continue
            target = toks[i + 1]
            if target.kind != "ident":
                continue
            label_idx = labels.get(target.value)
            if label_idx is None or label_idx >= i:
                continue
            out.append(_alert(
                "MISRA C:2012 15.2", Severity.WARNING,
                f"goto 跳转到此前定义的标签 {target.value}（应仅允许前向跳转）",
                f.path, t.line, "CWE-670",
                [_evidence(f.path, t.line, "code", f"goto {target.value}")],
                provenance=Provenance.SUSPECTED,
            ))
    return out


def _split_args(toks: list, start: int, end: int) -> list[list]:
    args, cur, depth = [], [], 0
    for k in range(start, end):
        tk = toks[k]
        if tk.kind == "punct" and tk.value in "([{":
            depth += 1
        elif tk.kind == "punct" and tk.value in ")]}":
            depth -= 1
        if tk.value == "," and depth == 0:
            args.append(cur)
            cur = []
        else:
            cur.append(tk)
    args.append(cur)
    return args


def _has_side_effect(tokens: list) -> bool:
    for i, tk in enumerate(tokens):
        if tk.kind == "punct" and tk.value in _SIDE_EFFECT_OPS:
            return True
        if tk.kind == "ident" and i + 1 < len(tokens) and tokens[i + 1].value == "(":
            return True
    return False


def check_macro_side_effect(f: FileFacts, ctx: ProjectContext,
                            active: set[str]) -> list[Alert]:
    """CERT PRE31-C：宏参数含副作用且参数在宏体中被多次求值。"""
    out: list[Alert] = []
    macros: dict[str, tuple[list[str], list]] = {}
    for p in f.lex.pp_lines:
        if p.directive == "define" and p.is_function_like and p.macro_name:
            macros[p.macro_name] = (p.params, lex_c(p.body).tokens)
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "ident" or t.value not in macros \
                    or i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            close = _match_forward(toks, i + 1, "(", ")")
            if close == -1:
                continue
            params, body = macros[t.value]
            args = _split_args(toks, i + 2, close)
            for name, arg in zip(params, args):
                count = sum(1 for tk in body if tk.kind == "ident" and tk.value == name)
                if count >= 2 and _has_side_effect(arg):
                    out.append(_alert(
                        "CERT C PRE31-C", Severity.WARNING,
                        f"宏 {t.value}({name}) 的实参含副作用，且 {name} 在宏体中被"
                        f"求值 {count} 次，行为不确定",
                        f.path, t.line, "CWE-480",
                        [_evidence(f.path, t.line, "code",
                                   f"{t.value}({name}=...) 宏参数多次求值")],
                    ))
                    break
    return out


def check_external_object_once(ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 8.5：外部对象/函数在多个 .c 文件中重复定义。"""
    out: list[Alert] = []
    obj_defs: dict[str, list[tuple[str, int]]] = {}
    fn_defs: dict[str, list[tuple[str, int]]] = {}
    for f in ctx.facts:
        if not f.path.endswith((".c", ".cc", ".cpp")):
            continue
        for name, line, is_static in f.global_vars:
            if not is_static:
                obj_defs.setdefault(name, []).append((f.path, line))
        for func in f.functions:
            if "static" not in func.signature:
                fn_defs.setdefault(func.name, []).append((f.path, func.def_line))
    for name, sites in obj_defs.items():
        files = {p for p, _ in sites}
        if len(files) > 1:
            for path, line in sites:
                out.append(_alert(
                    "MISRA C:2012 8.5", Severity.WARNING,
                    f"外部对象 {name} 在 {len(files)} 个文件中重复定义，链接域冲突",
                    path, line,
                    evidence=[_evidence(path, line, "code",
                                        "；".join(f"{p}:{ln}" for p, ln in sites))],
                    provenance=Provenance.SUSPECTED,
                ))
    for name, sites in fn_defs.items():
        files = {p for p, _ in sites}
        if name != "main" and len(files) > 1:
            for path, line in sites:
                out.append(_alert(
                    "MISRA C:2012 8.5", Severity.WARNING,
                    f"外部函数 {name} 在 {len(files)} 个文件中重复定义",
                    path, line,
                    evidence=[_evidence(path, line, "code",
                                        "；".join(f"{p}:{ln}" for p, ln in sites))],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


FILE_RULES_EXTRA = {
    "MISRA C:2012 6.1": check_bitfield_type,
    "MISRA C:2012 11.3": check_pointer_cast,
    "MISRA C:2012 11.4": check_pointer_cast,
    "MISRA C:2012 11.8": check_pointer_cast,
    "CERT C INT36-C": check_pointer_cast,
    "ECDET-CWE-190": check_constant_overflow,
    "CERT C INT30-C": check_constant_overflow,
    "CERT C INT32-C": check_constant_overflow,
    "MISRA C:2012 12.2": check_shift_count,
    "CERT C INT34-C": check_shift_count,
    "MISRA C:2012 13.6": check_sizeof_side_effect,
    "MISRA C:2012 14.3": check_invariant_condition,
    "MISRA C:2012 2.1": check_unreachable,
    "MISRA C:2012 16.3": check_switch_termination,
    "MISRA C:2012 18.6": check_local_addr_escape,
    "MISRA C:2012 18.8": check_vla,
    "MISRA C:2012 20.8": check_pp_condition,
    "MISRA C:2012 20.10": check_pp_stringize,
    "MISRA C:2012 21.17": check_copy_source_bounds,
    "CERT C EXP45-C": check_assignment_in_condition,
    "CERT C MEM34-C": check_free_non_dynamic,
    "CERT C MSC41-C": check_hardcoded_secret,
    "ECDET-CWE-785": check_large_stack_array,
}

PROJECT_RULES_EXTRA = {
    "MISRA C:2012 8.5": check_external_object_once,
}
