"""硬件语义规则检查 —— P2 机制落地（方案 3.3.2 解决机理）。

寄存器访问、ISR 抢占与 RTOS 阻塞语义显式注入后，以下缺陷可规则化检查：
  ECDET-MMIO-ACCESS  写只读寄存器 / 读只写寄存器（PERIPH->REG 与直接地址解引用）
  ECDET-ISR-RACE     ISR 与任务上下文共享全局变量且访问侧无临界区保护
  ECDET-VOLATILE     ISR 共享变量未声明 volatile
  ECDET-ISR-BLOCK    ISR 中调用阻塞 / 非 FromISR 安全的 RTOS API
"""

from __future__ import annotations

import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext, _evidence
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
            if func.name == "main":
                continue      # main 中的访问视为调度前初始化（MVP 口径）
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
            # 逐函数找出落在临界区区间之外的引用行
            unprotected: list[str] = []
            for f2 in ctx.facts:
                for func in f2.functions:
                    if (f2.path, func.name) not in task_refs[g]:
                        continue
                    bad_lines = _unprotected_ref_lines(func, g, hw)
                    if bad_lines:
                        unprotected.append(f"{f2.path}:{func.name}"
                                           f"(L{',L'.join(map(str, sorted(bad_lines)))})")
            if unprotected:
                out.append(_alert(
                    "ECDET-ISR-RACE", Severity.WARNING,
                    f"全局变量 {g} 被 ISR（{sorted(isr_refs[g])[0]}）与任务上下文共享，"
                    f"且存在临界区区间之外的访问，存在竞争",
                    gpath, gline, "CWE-362",
                    [_evidence(gpath, gline, "code",
                               f"无保护访问：{', '.join(unprotected)}；"
                               "需以临界区或互斥量覆盖全部访问")],
                ))
    return out


def _critical_intervals(func, hw: HwContext) -> list[tuple[int, int]]:
    """从函数 token 流提取临界区行区间 [enter_line, exit_line]。"""
    toks = func.tokens
    events: list[tuple[int, int]] = []
    for i, t in enumerate(toks):
        if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != "(":
            continue
        if t.value in hw.critical_enter:
            events.append((t.line, 1))
        elif t.value in hw.critical_exit:
            events.append((t.line, -1))
    events.sort()
    intervals: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for line, delta in events:
        if delta == 1:
            if depth == 0:
                start = line
            depth += 1
        else:
            if depth > 0:
                depth -= 1
                if depth == 0:
                    intervals.append((start, line))
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
    """ECDET-ISR-BLOCK：ISR 中调用阻塞 / 非 FromISR 安全 API。"""
    if "ECDET-ISR-BLOCK" not in active:
        return []
    out: list[Alert] = []
    for f in ctx.facts:
        for func in f.functions:
            if func.name not in hw.isr_names:
                continue
            for callee, line in func.calls_in_body():
                api = hw.blocking_apis.get(callee)
                if api is None or not api.is_blocking:
                    continue
                hint = f"，应改用 {api.isr_safe_variant}" if api.isr_safe_variant \
                    else "，ISR 上下文应轮询或置标志由任务处理"
                out.append(_alert(
                    "ECDET-ISR-BLOCK", Severity.ERROR,
                    f"ISR {func.name} 中调用阻塞 API {callee}(){hint}",
                    f.path, line, "CWE-676",
                    [_evidence(f.path, line, "api",
                               f"{callee} 为阻塞调用（RTOS 语义标注表）")],
                ))
    return out


HW_RULES = {
    "ECDET-MMIO-ACCESS": check_mmio_access,
    "ECDET-ISR-RACE": check_isr_race,
    "ECDET-VOLATILE": check_isr_race,
    "ECDET-ISR-BLOCK": check_isr_blocking,
}
