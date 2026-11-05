"""硬件语义规则检查 —— P2 机制落地（方案 3.3.2 解决机理）。

寄存器访问、ISR 抢占与 RTOS 阻塞语义显式注入后，以下缺陷可规则化检查：
  ECDET-MMIO-ACCESS  写只读寄存器 / 读只写寄存器（PERIPH->REG 与直接地址解引用）
  ECDET-MMIO-W1C     对写1清零寄存器进行读改写，可能清除其他已置位状态
  ECDET-ISR-RACE     ISR 与任务上下文共享全局变量且访问侧无临界区保护
  ECDET-VOLATILE     ISR 共享变量未声明 volatile
  ECDET-ISR-BLOCK    ISR 中调用阻塞 / 非 FromISR 安全的 RTOS API
"""

from __future__ import annotations

import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext, _evidence
from ecdet.l3_analysis.builtin_rules.ectypes import resolve_type
from ecdet.l3_analysis.hw_model.context import HwContext, resolve_base_address

# 直址解引用：*(volatile uint32_t *)0x40021000 = x
_MMIO_LIT_WRITE_RE = re.compile(
    r"\*\s*\(\s*[^)]*\*\s*\)\s*\(?\s*(0[xX][0-9a-fA-F]+)\s*\)?\s*"
    r"(?:\)\s*)?(=|\+=|-=|\|=|&=|\^=|<<=|>>=|\+\+|--)")
_MMIO_LIT_ANY_RE = re.compile(
    r"\*\s*\(\s*[^)]*\*\s*\)\s*\(?\s*(0[xX][0-9a-fA-F]+)")
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
_POSTFIX_INC = {"++", "--"}


def _alert(rule_id: str, sev: Severity, msg: str, path: str, line: int,
           cwe: str | None = None, evidence: list | None = None,
           provenance: Provenance = Provenance.DETECTED) -> Alert:
    return Alert(rule_id=rule_id, engine="builtin-hw", severity=sev,
                 message=msg, location=Location(path=path, line=line),
                 cwe=cwe, provenance=provenance, evidence=evidence or [])


def check_mmio_access(ctx: ProjectContext, hw: HwContext,
                      active: set[str]) -> list[Alert]:
    """ECDET-MMIO-ACCESS：按 SVD 访问权限核对 MMIO 访问（无 SVD 跳过）。"""
    if hw.regmap is None or "ECDET-MMIO-ACCESS" not in active:
        return []
    out: list[Alert] = []
    for f in ctx.facts:
        toks = f.lex.tokens
        # 形态 1：PERIPH->REG（基址经 #define 解析）
        for i, t in enumerate(toks):
            if t.kind != "ident" or i + 2 >= len(toks):
                continue
            if toks[i + 1].value != "->" or toks[i + 2].kind != "ident":
                continue
            periph_name, reg_name = t.value, toks[i + 2].value
            base = resolve_base_address(periph_name, hw)
            if base is None or base not in hw.regmap.periph_by_base:
                continue
            reg = hw.regmap.resolve(hw.regmap.periph_by_base[base], reg_name)
            if reg is None:
                continue
            nxt = toks[i + 3].value if i + 3 < len(toks) else ";"
            prv = toks[i - 1].value if i > 0 else ""
            is_write = nxt in _ASSIGN_OPS or prv in _POSTFIX_INC
            is_read = not is_write or nxt in ("|=", "&=", "+=", "-=", "^=")
            out.extend(_check_reg_access(reg, is_write, is_read, f.path, t.line))
        # 形态 2：直接地址解引用
        for idx, line in enumerate(f.lex.clean_lines, start=1):
            m_any = _MMIO_LIT_ANY_RE.search(line)
            if not m_any:
                continue
            addr = int(m_any.group(1), 16)
            reg = hw.regmap.lookup(addr)
            if reg is None:
                continue
            is_write = bool(_MMIO_LIT_WRITE_RE.search(line))
            out.extend(_check_reg_access(reg, is_write, not is_write,
                                         f.path, idx))
    return out


def _check_reg_access(reg, is_write: bool, is_read: bool,
                      path: str, line: int) -> list[Alert]:
    out: list[Alert] = []
    label = f"{reg.peripheral}.{reg.name}（{reg.access}）"
    if is_write and not reg.writable:
        out.append(_alert(
            "ECDET-MMIO-ACCESS", Severity.ERROR,
            f"向只读寄存器 {label} 写入（0x{reg.abs_addr:08X}），写入被硬件忽略",
            path, line, None,
            [_evidence(path, line, "api",
                       f"寄存器 {label} @ 0x{reg.abs_addr:08X}，SVD access={reg.access}")],
        ))
    elif is_read and not reg.readable:
        out.append(_alert(
            "ECDET-MMIO-ACCESS", Severity.WARNING,
            f"读取只写寄存器 {label}（0x{reg.abs_addr:08X}），读到值未定义",
            path, line, None,
            [_evidence(path, line, "api",
                       f"寄存器 {label} @ 0x{reg.abs_addr:08X}，SVD access={reg.access}")],
        ))
    return out


def _paren_pairs(tokens) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for i, token in enumerate(tokens):
        if token.value == "(":
            stack.append(i)
        elif token.value == ")" and stack:
            start = stack.pop()
            pairs[start] = i
            pairs[i] = start
    return pairs


def _w1c_references(tokens, hw: HwContext, pairs: dict[int, int]):
    """Resolve explicit register references, without guessing pointer aliases."""
    for i, token in enumerate(tokens):
        end = i + 1
        reg = None
        if (token.kind == "ident" and i + 2 < len(tokens)
                and tokens[i + 1].value == "->" and tokens[i + 2].kind == "ident"):
            base = resolve_base_address(token.value, hw)
            peripheral = hw.regmap.periph_by_base.get(base)
            if peripheral:
                reg = hw.regmap.resolve(peripheral, tokens[i + 2].value)
            end = i + 3
        elif token.value == "*" and i + 1 in pairs:
            cast_end = pairs[i + 1]
            cast = tokens[i + 2:cast_end]
            if (cast_end <= i + 2 or not any(t.value == "*" for t in cast)
                    or not all(t.kind in {"ident", "keyword"} or t.value == "*" for t in cast)):
                continue
            start = cast_end + 1
            end = start + 1
            while start < len(tokens) and tokens[start].value == "(" and start in pairs:
                end = pairs[start] + 1
                start += 1
            if start >= len(tokens) or tokens[start].kind != "number":
                continue
            # Only a literal address, optionally wrapped in parentheses.
            if any(t.value != ")" for t in tokens[start + 1:end]):
                continue
            try:
                address = int(re.sub(r"[uUlL]+$", "", tokens[start].value), 0)
            except ValueError:
                continue
            reg = hw.regmap.lookup(address)
            if reg is not None and reg.abs_addr != address:
                reg = None  # Byte offsets have different access semantics.
        if reg is None:
            continue
        start = i
        while (start > 0 and tokens[start - 1].value == "(" and pairs.get(start - 1) == end
               and not (start > 1 and tokens[start - 2].kind in {"ident", "keyword"})):
            start -= 1
            end += 1
        yield start, end, reg


def _w1c_is_evaluated(tokens, start: int, pairs: dict[int, int]) -> bool:
    if start and tokens[start - 1].value in {"sizeof", "_Alignof"}:
        return False
    for opening, closing in pairs.items():
        if opening < start <= closing and opening > 0:
            if tokens[opening - 1].value in {"sizeof", "_Alignof"}:
                return False
    return True


def _w1c_is_read(tokens, start: int, end: int, pairs: dict[int, int]) -> bool:
    if not _w1c_is_evaluated(tokens, start, pairs):
        return False
    if start and tokens[start - 1].value == "&":
        before = start - 2
        unary = before < 0 or tokens[before].value not in {")", "]"} and tokens[before].kind not in {"ident", "number"}
        if before in pairs and tokens[before].value == ")":
            cast = tokens[pairs[before] + 1:before]
            # A parenthesized value such as (FLAG_A) is the left operand of
            # binary &, whereas (unsigned int)&REG takes the register address.
            type_text = " ".join(t.value for t in cast if t.value not in {"const", "volatile"})
            known_type = resolve_type(type_text) is not None or any(
                t.value in {"void", "float", "double", "_Bool", "struct", "union", "enum"}
                for t in cast)
            unary = known_type and all(t.kind in {"ident", "keyword"} or t.value == "*" for t in cast)
        if unary:
            return False
    return not (end < len(tokens) and tokens[end].value == "=")


def _w1c_rhs_end(tokens, start: int) -> int:
    depth = 0
    for i in range(start, len(tokens)):
        value = tokens[i].value
        if value in {";", "}"} or (depth == 0 and value in {",", ")", "]"}):
            return i
        if value in {"(", "["}:
            depth += 1
        elif value in {")", "]"}:
            depth -= 1
    return len(tokens)


def check_mmio_w1c(ctx: ProjectContext, hw: HwContext,
                   active: set[str]) -> list[Alert]:
    """Warn on explicit read-modify-write of known write-one-to-clear bits."""
    if hw.regmap is None or "ECDET-MMIO-W1C" not in active:
        return []
    out: list[Alert] = []
    for facts in ctx.facts:
        tokens = facts.lex.tokens
        pairs = _paren_pairs(tokens)
        references = list(_w1c_references(tokens, hw, pairs))
        for start, end, reg in references:
            mask = reg.one_to_clear_mask
            if not mask or not _w1c_is_evaluated(tokens, start, pairs):
                continue
            after = tokens[end].value if end < len(tokens) else ""
            before = tokens[start - 1].value if start else ""
            operation = after
            rmw = after in (_ASSIGN_OPS - {"="}) | _POSTFIX_INC or before in _POSTFIX_INC
            if before in _POSTFIX_INC:
                operation = before
            if after == "=":
                rhs_end = _w1c_rhs_end(tokens, end + 1)
                rmw = any(end < other_start < rhs_end and other_reg.abs_addr == reg.abs_addr
                          and _w1c_is_read(tokens, other_start, other_end, pairs)
                          for other_start, other_end, other_reg in references)
                operation = "= with register readback"
            if not rmw:
                continue
            line = tokens[start].line
            label = f"{reg.peripheral}.{reg.name}"
            field_names = ",".join(item.name for item in getattr(reg, "fields", ())
                                   if item.modified_write_values == "oneToClear" and item.writable)
            out.append(_alert(
                "ECDET-MMIO-W1C", Severity.WARNING,
                f"对写1清零寄存器 {label} 进行读改写，可能清除其他已置位状态；请按字段写入语义核对写入掩码",
                facts.path, line,
                evidence=[_evidence(
                    facts.path, line, "api",
                    f"寄存器 {label} @ 0x{reg.abs_addr:08X}，SVD oneToClear 掩码=0x{mask:08X}，"
                    f"字段={field_names or 'register-level'}，操作={operation}",
                )],
            ))
    return out


def check_isr_race(ctx: ProjectContext, hw: HwContext,
                   active: set[str]) -> list[Alert]:
    """ECDET-ISR-RACE + ECDET-VOLATILE：共享变量分析。

    保护判定按行区间：任务函数中对共享变量的引用行若落在
    临界区 [enter, exit] 区间内则视为受保护，区间外视为无保护。
    """
    out: list[Alert] = []
    want_race = "ECDET-ISR-RACE" in active
    want_volatile = "ECDET-VOLATILE" in active
    if not (want_race or want_volatile):
        return out

    # 全局变量登记：名 → (file, decl_line, is_volatile)
    globals_info: dict[str, tuple[str, int, bool]] = {}
    for f in ctx.facts:
        for gname, gline, _static in f.global_vars:
            decl = f.lex.source_lines[gline - 1] if gline - 1 < len(f.lex.source_lines) else ""
            globals_info.setdefault(gname, (f.path, gline, "volatile" in decl))

    isr_refs: dict[str, set[str]] = {}
    task_refs: dict[str, set[tuple[str, str]]] = {}   # name -> {(file, func)}
    for f in ctx.facts:
        for func in f.functions:
            is_isr = func.name in hw.isr_names
            refs = {t.value for t in func.tokens if t.kind == "ident"}
            for g in refs & globals_info.keys():
                if is_isr:
                    isr_refs.setdefault(g, set()).add(func.name)
                else:
                    task_refs.setdefault(g, set()).add((f.path, func.name))

    shared = set(isr_refs) & set(task_refs)
    for g in sorted(shared):
        gpath, gline, is_volatile = globals_info[g]
        if want_volatile and not is_volatile:
            out.append(_alert(
                "ECDET-VOLATILE", Severity.WARNING,
                f"ISR 共享变量 {g} 未声明 volatile，编译器优化可能破坏跨上下文可见性",
                gpath, gline, "CWE-362",
                [_evidence(gpath, gline, "code", f"ISR 写：{sorted(isr_refs[g])}；"
                           f"任务访问：{sorted(fn for _, fn in task_refs[g])}")],
            ))
        if want_race:
            # 逐函数找出落在临界区区间之外的引用行；告警定位于首个无保护访问行
            unprotected: list[str] = []
            first_site: tuple[str, int] | None = None
            for f2 in ctx.facts:
                for func in f2.functions:
                    if (f2.path, func.name) not in task_refs[g]:
                        continue
                    bad_lines = _unprotected_ref_lines(func, g, hw)
                    if bad_lines:
                        unprotected.append(f"{f2.path}:{func.name}"
                                           f"(L{',L'.join(map(str, sorted(bad_lines)))})")
                        if first_site is None:
                            first_site = (f2.path, min(bad_lines))
            if unprotected and first_site is not None:
                out.append(_alert(
                    "ECDET-ISR-RACE", Severity.WARNING,
                    f"全局变量 {g} 被 ISR（{sorted(isr_refs[g])[0]}）与任务上下文共享，"
                    f"且存在临界区区间之外的访问；需核对访问原子性、中断优先级与启动时序",
                    first_site[0], first_site[1], "CWE-362",
                    [_evidence(gpath, gline, "code",
                               f"声明于 {gpath}:{gline}；无保护访问："
                               f"{', '.join(unprotected)}；共享访问事实不等于已复现竞争")],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


def _critical_intervals(func, hw: HwContext) -> list[tuple[int, int]]:
    """从函数 token 流提取临界区行区间 [enter_line, exit_line]。"""
    toks = func.tokens
    events: list[tuple[int, int, bool]] = []
    braces = 0
    for i, t in enumerate(toks):
        if t.value == '{':
            braces += 1
        elif t.value == '}':
            braces = max(0, braces - 1)
        if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != "(":
            continue
        if t.value in hw.critical_enter:
            unconditional = braces == 0 and (i == 0 or toks[i-1].value in {';', '}'})
            events.append((t.line, 1, unconditional))
        elif t.value in hw.critical_exit:
            events.append((t.line, -1, True))
    intervals: list[tuple[int, int]] = []
    depth = 0
    start = 0
    start_unconditional = False
    for line, delta, unconditional in events:
        if delta == 1:
            if depth == 0:
                start = line
                start_unconditional = unconditional
            depth += 1
        else:
            if depth > 0:
                depth -= 1
                if depth == 0:
                    intervals.append((start, line))
    if depth > 0 and start_unconditional:
        intervals.append((start, func.body_close_line))
    return intervals


def _unprotected_ref_lines(func, var: str, hw: HwContext) -> list[int]:
    """返回函数内对 var 的引用中，落在全部临界区区间之外的行号。"""
    intervals = _critical_intervals(func, hw)

    def protected(line: int) -> bool:
        return any(lo <= line <= hi for lo, hi in intervals)

    return [t.line for t in func.tokens
            if t.kind == "ident" and t.value == var and not protected(t.line)]


def check_isr_blocking(ctx: ProjectContext, hw: HwContext,
                       active: set[str]) -> list[Alert]:
    """ECDET-ISR-BLOCK（含缺口清单别名 ECDET-HW-FROMISR）。

    除阻塞 API 外，只要该 API 存在 FromISR 变体（如 xSemaphoreGive），
    在 ISR 中直接调用非 FromISR 版本同样不安全，一并报告。
    """
    if "ECDET-ISR-BLOCK" not in active:
        return []
    out: list[Alert] = []
    for f in ctx.facts:
        for func in f.functions:
            if func.name not in hw.isr_names:
                continue
            for callee, line in func.calls_in_body():
                api = hw.blocking_apis.get(callee)
                if api is None:
                    continue
                if not api.is_blocking and api.isr_safe_variant is None:
                    continue
                kind = "阻塞" if api.is_blocking else "非 FromISR 版本"
                hint = f"，应改用 {api.isr_safe_variant}" if api.isr_safe_variant \
                    else "，ISR 上下文应轮询或置标志由任务处理"
                out.append(_alert(
                    "ECDET-ISR-BLOCK", Severity.ERROR,
                    f"ISR {func.name} 中调用{kind} API {callee}(){hint}",
                    f.path, line, "CWE-676",
                    [_evidence(f.path, line, "api",
                               f"{callee} 为{kind}调用（RTOS 语义标注表）")],
                ))
    return out


def check_critical_pair(ctx: ProjectContext, hw: HwContext,
                        active: set[str]) -> list[Alert]:
    """ECDET-HW-CRITICAL-PAIR：临界区进入/退出未配对。"""
    if "ECDET-HW-CRITICAL-PAIR" not in active:
        return []
    out: list[Alert] = []
    for f in ctx.facts:
        for func in f.functions:
            stack: list[int] = []
            for t in func.tokens:
                if t.kind != "ident":
                    continue
                if t.value in hw.critical_enter:
                    stack.append(t.line)
                elif t.value in hw.critical_exit:
                    if not stack:
                        out.append(_alert(
                            "ECDET-HW-CRITICAL-PAIR", Severity.ERROR,
                            f"函数 {func.name} 中退出临界区但此前没有进入操作",
                            f.path, t.line, "CWE-667",
                            [_evidence(f.path, t.line, "api", "多余的退出临界区调用")],
                        ))
                    else:
                        stack.pop()
            for line in stack:
                out.append(_alert(
                    "ECDET-HW-CRITICAL-PAIR", Severity.ERROR,
                    f"函数 {func.name} 进入临界区后未退出，中断可能长期被关闭",
                    f.path, line, "CWE-667",
                    [_evidence(f.path, line, "api", "缺失配对的退出临界区调用")],
                ))
    return out


# ISR 中非 async-safe 的库函数（堆、stdio、字符串分词、进程/环境等）
_ASYNC_UNSAFE = {
    "malloc", "calloc", "realloc", "free",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf",
    "vsnprintf", "puts", "putchar", "scanf", "sscanf", "fopen", "fclose",
    "fread", "fwrite", "fflush", "setbuf", "setvbuf",
    "strtok", "strerror", "getenv", "setlocale", "system",
    "exit", "abort", "atexit", "_Exit", "quick_exit",
    "qsort", "bsearch", "rand", "srand", "time", "localtime", "gmtime",
}


def check_isr_async_unsafe(ctx: ProjectContext, hw: HwContext,
                           active: set[str]) -> list[Alert]:
    """ECDET-HW-ISR-HEAP：ISR 中调用非 async-safe 函数。"""
    if "ECDET-HW-ISR-HEAP" not in active:
        return []
    out: list[Alert] = []
    for f in ctx.facts:
        for func in f.functions:
            if func.name not in hw.isr_names:
                continue
            for callee, line in func.calls_in_body():
                if callee not in _ASYNC_UNSAFE:
                    continue
                out.append(_alert(
                    "ECDET-HW-ISR-HEAP", Severity.ERROR,
                    f"ISR {func.name} 中调用非 async-safe 函数 {callee}()",
                    f.path, line, "CWE-676",
                    [_evidence(f.path, line, "api",
                               f"{callee}() 不保证中断上下文可重入/安全")],
                ))
    return out


_COMPOUND_OPS = {"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}


def _is_rmw(toks, i: int, name: str) -> bool:
    nxt = toks[i + 1].value if i + 1 < len(toks) else ""
    prv = toks[i - 1].value if i > 0 else ""
    if nxt in ("++", "--") or prv in ("++", "--") or nxt in _COMPOUND_OPS:
        return True
    if nxt == "=":
        for k in range(i + 2, min(i + 6, len(toks))):
            if toks[k].kind == "ident" and toks[k].value == name:
                return True
    return False


def check_volatile_rmw(ctx: ProjectContext, hw: HwContext,
                       active: set[str]) -> list[Alert]:
    """ECDET-HW-VOLATILE-RMW：共享 volatile 变量的非原子读改写。"""
    if "ECDET-HW-VOLATILE-RMW" not in active:
        return []
    globals_info: dict[str, tuple[str, int, bool]] = {}
    for f in ctx.facts:
        for gname, gline, _static in f.global_vars:
            decl = f.lex.source_lines[gline - 1] if gline - 1 < len(f.lex.source_lines) else ""
            globals_info.setdefault(gname, (f.path, gline, "volatile" in decl))
    isr_refs: dict[str, set[str]] = {}
    task_refs: dict[str, set[tuple[str, str]]] = {}
    for f in ctx.facts:
        for func in f.functions:
            if func.name == "main":
                continue
            refs = {t.value for t in func.tokens if t.kind == "ident"}
            for g in refs & globals_info.keys():
                if func.name in hw.isr_names:
                    isr_refs.setdefault(g, set()).add(func.name)
                else:
                    task_refs.setdefault(g, set()).add((f.path, func.name))
    out: list[Alert] = []
    for g in sorted(set(isr_refs) & set(task_refs)):
        gpath, gline, is_volatile = globals_info[g]
        if not is_volatile:
            continue
        for f in ctx.facts:
            for func in f.functions:
                if (f.path, func.name) not in task_refs[g]:
                    continue
                intervals = _critical_intervals(func, hw)
                for i, t in enumerate(func.tokens):
                    if t.kind != "ident" or t.value != g or not _is_rmw(func.tokens, i, g):
                        continue
                    if any(lo <= t.line <= hi for lo, hi in intervals):
                        continue
                    out.append(_alert(
                        "ECDET-HW-VOLATILE-RMW", Severity.WARNING,
                        f"volatile 共享变量 {g} 在临界区外执行读改写（自增/复合赋值），"
                        "操作本身非原子",
                        f.path, t.line, "CWE-362",
                        [_evidence(gpath, gline, "code",
                                   f"ISR 写：{sorted(isr_refs[g])}；任务 RMW 未受保护")],
                    ))
                    break
    return out


def _int_value(text: str) -> int | None:
    try:
        base = 16 if text.lower().startswith("0x") else 8 if text.startswith("0") \
            and len(text) > 1 and text.isdigit() else 10
        return int(text.rstrip("uUlL"), base)
    except ValueError:
        return None


def _match_brace(tokens: list, open_idx: int) -> int:
    """返回与 open_idx 处括号配对的闭括号下标（支持 () [] {}）。"""
    pairs = {"(": ")", "[": "]", "{": "}"}
    if open_idx >= len(tokens) or tokens[open_idx].kind != "punct":
        return -1
    open_v = tokens[open_idx].value
    closer = pairs.get(open_v)
    if closer is None:
        return -1
    depth = 0
    for j in range(open_idx, len(tokens)):
        tk = tokens[j]
        if tk.kind != "punct":
            continue
        if tk.value == open_v:
            depth += 1
        elif tk.value == closer:
            depth -= 1
            if depth == 0:
                return j
    return -1


def _bitfield_signed(type_text: str) -> bool:
    t = type_text.lstrip()
    return not (t.startswith("unsigned") or t.startswith("u")
                or t.startswith("UINT"))


def _extract_bitfield(toks: list, start: int, end: int,
                      fields: dict) -> None:
    """从一条声明 token 段提取 `NAME : WIDTH` 位域成员。"""
    for idx in range(start, end - 1):
        if (toks[idx].kind == "ident" and toks[idx + 1].kind == "punct"
                and toks[idx + 1].value == ":" and toks[idx + 2].kind == "number"):
            width = _int_value(toks[idx + 2].value)
            if width is None or width <= 0:
                continue
            type_words = [tt.value for tt in toks[start:idx]
                          if tt.value not in ("struct", "union", "enum")
                          and tt.kind in ("keyword", "ident")]
            type_text = " ".join(type_words)
            fields[toks[idx].value] = (width, _bitfield_signed(type_text),
                                       type_text)


def _parse_struct_bitfields(toks: list, start: int, end: int) -> dict:
    """解析结构体 body token 区间 [start, end] 内的位域成员。"""
    fields: dict = {}
    seg_start = start
    k = start
    while k <= end:
        tk = toks[k]
        if tk.kind == "punct" and tk.value == ";":
            _extract_bitfield(toks, seg_start, k, fields)
            seg_start = k + 1
        elif tk.kind == "punct" and tk.value == "{":
            inner = _match_brace(toks, k)
            if inner != -1:
                k = inner
                seg_start = k + 1
        k += 1
    return fields


def _collect_struct_defs(toks: list, bitfields: dict, type_names: set) -> None:
    """收集 `struct TAG { ... }` 定义（含 typedef 别名）到位域表。"""
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        if t.kind != "keyword" or t.value != "struct":
            i += 1
            continue
        j = i + 1
        tag = None
        if j < n and toks[j].kind == "ident":
            tag = toks[j].value
            j += 1
        if j >= n or toks[j].kind != "punct" or toks[j].value != "{":
            i = j if j < n else i + 1   # 前向声明/变量声明，交变量收集处理
            continue
        close = _match_brace(toks, j)
        if close == -1:
            i = j + 1
            continue
        fields = _parse_struct_bitfields(toks, j + 1, close)
        names = []
        if tag:
            names.append(tag)
        k = close + 1
        while k < n and toks[k].value != ";":
            if toks[k].kind == "ident":
                names.append(toks[k].value)
            k += 1
        for nm in names:
            type_names.add(nm)
            slot = bitfields.setdefault(nm, {})
            for member, val in fields.items():
                slot.setdefault(member, val)
        i = k + 1


def _collect_struct_vars(toks: list, type_names: set, var_tags: dict) -> None:
    """收集 `struct TAG var` / `TAG var` 变量声明 → 变量名 → 结构体类型名。"""
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        tag = None
        j = i
        if t.kind == "keyword" and t.value == "struct":
            j = i + 1
            if j < n and toks[j].kind == "ident":
                tag = toks[j].value
                j += 1
            if j < n and toks[j].kind == "punct" and toks[j].value == "{":
                i = j
                continue
        elif t.kind == "ident" and t.value in type_names:
            tag = t.value
            j = i + 1
            if j < n and toks[j].kind == "punct" and toks[j].value == "{":
                i = j
                continue
        else:
            i += 1
            continue
        if tag is None:
            i += 1
            continue
        while j < n and toks[j].kind == "punct" and toks[j].value == "*":
            j += 1
        k = j
        while k < n:
            tk = toks[k]
            if tk.kind == "ident":
                var_tags[tk.value] = tag
            elif tk.kind == "punct" and tk.value in (";", "="):
                break
            k += 1
        i = k + 1


def _struct_bitfield_model(facts: list) -> tuple[dict, dict]:
    """返回 (bitfields, var_tags)：位域表与变量→结构体类型映射。"""
    bitfields: dict = {}
    type_names: set = set()
    for f in facts:
        _collect_struct_defs(f.lex.tokens, bitfields, type_names)
    var_tags: dict = {}
    for f in facts:
        _collect_struct_vars(f.lex.tokens, type_names, var_tags)
    return bitfields, var_tags


def check_bitfield_overflow(ctx: ProjectContext, hw: HwContext,
                            active: set[str]) -> list[Alert]:
    """ECDET-HW-BITFIELD：位域成员常量赋值超出声明位宽。

    仅识别 `obj.member = 常量` / `obj->member = 常量`，并按 obj 的实际
    结构体类型解析 member 位宽；同名普通变量或不同结构体同名字段不会误报。
    """
    if "ECDET-HW-BITFIELD" not in active:
        return []
    bitfields, var_tags = _struct_bitfield_model(ctx.facts)
    out: list[Alert] = []
    for f in ctx.facts:
        for func in f.functions:
            toks = func.tokens
            for i, t in enumerate(toks):
                if t.kind != "ident" or i + 4 >= len(toks):
                    continue
                if toks[i + 1].kind != "punct" or toks[i + 1].value not in (".", "->"):
                    continue
                if toks[i + 2].kind != "ident":
                    continue
                if toks[i + 3].value != "=" or toks[i + 4].kind != "number":
                    continue
                tag = var_tags.get(t.value)
                if tag is None:
                    continue
                spec = bitfields.get(tag, {}).get(toks[i + 2].value)
                if spec is None:
                    continue
                width, signed, ftype = spec
                value = _int_value(toks[i + 4].value)
                if value is None:
                    continue
                lo, hi = (-(1 << (width - 1)), (1 << (width - 1)) - 1) if signed \
                    else (0, (1 << width) - 1)
                if lo <= value <= hi:
                    continue
                out.append(_alert(
                    "ECDET-HW-BITFIELD", Severity.WARNING,
                    f"位域 {t.value}.{toks[i + 2].value}（{ftype}:{width}）被赋常量 "
                    f"{value}，超出可表示范围 {lo}..{hi}，高位被截断",
                    f.path, toks[i + 4].line, "CWE-197",
                    [_evidence(f.path, toks[i + 4].line, "code",
                               f"{t.value}.{toks[i + 2].value} = {toks[i + 4].value}，"
                               f"位宽 {width}")],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


HW_RULES = {
    "ECDET-MMIO-ACCESS": check_mmio_access,
    "ECDET-MMIO-W1C": check_mmio_w1c,
    "ECDET-ISR-RACE": check_isr_race,
    "ECDET-VOLATILE": check_isr_race,
    "ECDET-ISR-BLOCK": check_isr_blocking,
    "ECDET-HW-CRITICAL-PAIR": check_critical_pair,
    "ECDET-HW-ISR-HEAP": check_isr_async_unsafe,
    "ECDET-HW-VOLATILE-RMW": check_volatile_rmw,
    "ECDET-HW-BITFIELD": check_bitfield_overflow,
}
