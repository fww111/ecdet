"""内置规则检查实现 —— 阶段一 MVP 全部 24 条规则。

设计要点：
  - 全部基于 L2 词法结果（净化文本 + token 流），零外部依赖；
  - 每条告警携带证据链（Evidence），满足可追溯要求（方案 3.3.7）；
  - 需要字符串字面量内容的规则（STR31 等）读原始行 source_lines，
    其余一律读净化文本，避免注释/字符串误匹配。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.cstruct import (
    ArrayDecl,
    FunctionInfo,
    SwitchInfo,
    parse_array_decls,
    parse_functions,
    parse_switches,
)
from ecdet.l3_analysis.builtin_rules.ctokens import CToken, LexResult, PPLine, lex_c
from ecdet.l3_analysis.builtin_rules.ectypes import (
    EssentialType,
    build_type_table,
    integer_promote,
    literal_type,
    usual_arith,
)

# ---------------------------------------------------------------------------
# 分析事实对象
# ---------------------------------------------------------------------------


@dataclass
class FileFacts:
    """单个翻译单元（.c）或头文件（.h）的结构化事实。"""

    path: str
    lex: LexResult
    functions: list[FunctionInfo] = field(default_factory=list)
    arrays: list[ArrayDecl] = field(default_factory=list)
    func_lines: set[int] = field(default_factory=set)
    global_vars: list[tuple[str, int, bool]] = field(default_factory=list)  # (名, 行, 是否static)
    switches: list[tuple[FunctionInfo, list[SwitchInfo]]] = field(default_factory=list)
    declared_funcs: set[str] = field(default_factory=set)   # 头文件原型名集合


@dataclass
class ProjectContext:
    facts: list[FileFacts]
    enabled_rules: set[str] = field(default_factory=set)
    # 工程内全部声明（函数定义名 + 头文件原型名），供 17.3 判定
    project_decls: set[str] = field(default_factory=set)


def build_file_facts(path: str, source: str) -> FileFacts:
    lex = lex_c(source, path)
    funcs = parse_functions(lex)
    func_lines = set()
    for f in funcs:
        func_lines.update(range(f.def_line, f.body_close_line + 1))
    arrays = parse_array_decls(lex, func_lines)
    gvars = _parse_global_vars(lex, func_lines)
    switches = [(f, parse_switches(f)) for f in funcs]
    return FileFacts(
        path=path,
        lex=lex,
        functions=funcs,
        arrays=arrays,
        func_lines=func_lines,
        global_vars=gvars,
        switches=switches,
    )


_GVAR_RE = re.compile(
    r"^\s*(static\s+)?(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+\w+\s+)*"
    r"(?:void|char|short|int|long|float|double|_Bool|u?int(?:8|16|32|64)_t|BOOL|"
    r"[uUsS](?:8|16|32)(?:_t)?|UINT8|UINT16|UINT32|INT8|INT16|INT32)\s*\**\s*"
    r"([A-Za-z_]\w*)\s*[;=]"
)


def _parse_global_vars(lex: LexResult, func_lines: set[int]) -> list[tuple[str, int, bool]]:
    out: list[tuple[str, int, bool]] = []
    for idx, text in enumerate(lex.clean_lines, start=1):
        s = text.strip()
        if not s or s.startswith("#") or idx in func_lines:
            continue
        if "(" in s:      # 排除函数原型
            continue
        m = _GVAR_RE.match(s)
        if m:
            out.append((m.group(2), idx, bool(m.group(1))))
    return out


# ---------------------------------------------------------------------------
# 公共工具
# ---------------------------------------------------------------------------

ENGINE = "builtin"


def _alert(rule_id: str, sev: Severity, msg: str, path: str, line: int,
           cwe: str | None = None, evidence: list[Evidence] | None = None,
           provenance: Provenance = Provenance.DETECTED) -> Alert:
    return Alert(
        rule_id=rule_id,
        engine=ENGINE,
        severity=sev,
        message=msg,
        location=Location(path=path, line=line, col=1),
        cwe=cwe,
        provenance=provenance,
        evidence=evidence or [],
    )


def _evidence(path: str, line: int, kind: str, msg: str) -> Evidence:
    return Evidence(kind=kind, message=msg,
                    location=Location(path=path, line=line, col=1))


# 常用 libc / RTOS / CMSIS 函数白名单：17.3 隐式声明判定的已知外部符号
LIBC_WHITELIST: set[str] = set("""
memcpy memmove memset memcmp strlen strcpy strncpy strcat strncat strcmp strncmp
strchr strrchr strstr strtok snprintf sprintf vsnprintf printf fprintf vprintf
puts putchar scanf sscanf fscanf getchar gets
atoi atol atof strtol strtoul strtod abs labs
malloc calloc realloc free
exit abort qsort bsearch rand srand time clock difftime
pow sqrt sin cos tan asin acos atan atan2 exp log log10 floor ceil fabs fmod
isdigit isalpha isalnum isspace isupper islower toupper tolower
fopen fclose fread fwrite fflush fseek ftell remove rename
assert setjmp longjmp
__aeabi_memcpy __aeabi_memcpy4 __aeabi_memset
xTaskCreate vTaskDelete vTaskDelay vTaskDelayUntil xTaskGetTickCount taskENTER_CRITICAL
taskEXIT_CRITICAL portDISABLE_INTERRUPTS portENABLE_INTERRUPTS
xQueueSend xQueueReceive xQueueCreate xSemaphoreGive xSemaphoreTake xSemaphoreCreateBinary
xSemaphoreCreateMutex xSemaphoreCreateCounting vSemaphoreDelete
uxQueueMessagesWaiting vQueueDelete
osThreadNew osDelay osKernelStart osMessageQueuePut osMessageQueueGet osSemaphoreAcquire
osSemaphoreRelease osMutexAcquire osMutexRelease osTimerStart osTimerStop
HAL_Init HAL_GPIO_Init HAL_GPIO_Write HAL_GPIO_Read HAL_UART_Transmit HAL_UART_Receive
HAL_SPI_Transmit HAL_SPI_Receive HAL_I2C_Transmit HAL_I2C_Receive HAL_Delay
NVIC_EnableIRQ NVIC_SetPriority NVIC_DisableIRQ
""".split())


# ---------------------------------------------------------------------------
# 单文件规则。统一签名 (f, ctx, active)：
#   active 为本次调用中生效的 rule_id 集合 —— 同一检查函数服务多条规则时
#   （如 21.3/21.6/MSC30 共用 API 扫描），按 active 过滤输出，避免重复报告。
# ---------------------------------------------------------------------------


def check_unused_macro(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 2.5：宏定义未被使用（含 #ifdef/#undef 引用计数为 0）。"""
    used: set[str] = set()
    pp_text = "\n".join(p.text for p in f.lex.pp_lines)
    for t in f.lex.tokens:
        if t.kind == "ident":
            used.add(t.value)
    out = []
    for p in f.lex.pp_lines:
        if p.directive != "define" or not p.macro_name:
            continue
        name = p.macro_name
        if name in used:
            continue
        if re.search(rf"\b{re.escape(name)}\b", pp_text.replace(p.text, "", 1)):
            continue   # 被其它指令（#ifdef/#undef/#if defined）引用
        out.append(_alert(
            "MISRA C:2012 2.5", Severity.NOTE,
            f"宏 {name} 在本翻译单元中未被使用", f.path, p.line,
            evidence=[_evidence(f.path, p.line, "macro", f"#define {name} ...")],
        ))
    return out


def check_unsigned_suffix(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 7.2：>= 0x80000000 的整型常量无 u/U 后缀。"""
    out = []
    for t in f.lex.tokens:
        if t.kind != "number":
            continue
        v = t.value
        if not re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", v):
            continue
        suffix = v[-1]
        if suffix in "uU":
            continue
        try:
            num = int(v, 0)
        except ValueError:
            continue
        if num >= 0x8000_0000:
            out.append(_alert(
                "MISRA C:2012 7.2", Severity.NOTE,
                f"常量 {v} 不小于 0x80000000 但缺少 u/U 后缀，符号性依赖实现",
                f.path, t.line, "CWE-681",
                [_evidence(f.path, t.line, "code", f"常量字面量：{v}")],
            ))
    return out


_SIDE_EFFECT_OPS = {"++", "--", "=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=",
                    "<<=", ">>="}


def check_logic_side_effect(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 13.5：&& / || 右操作数含持续副作用。

    自 &&/|| 向后扫描至表达式边界（; } , 或配平后多出的 ) ]，或下一个 &&/||），
    途中进入括号也持续检查：副作用必须可在右操作数任意嵌套处被发现。
    """
    out = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "punct" or t.value not in ("&&", "||"):
                continue
            j = i + 1
            depth = 0
            found = None
            while j < len(toks):
                tk = toks[j]
                if tk.kind == "punct":
                    if tk.value in ("(", "["):
                        depth += 1
                    elif tk.value in (")", "]"):
                        if depth == 0:
                            break
                        depth -= 1
                    elif depth == 0 and (tk.value in (";", "}", ",", "?", ":")
                                         or tk.value in ("&&", "||")):
                        break
                    elif tk.value in _SIDE_EFFECT_OPS:
                        found = ("副作用运算符 " + tk.value, tk)
                        break
                elif tk.kind == "ident" and j + 1 < len(toks) \
                        and toks[j + 1].value == "(":
                    found = (f"函数调用 {tk.value}()", tk)
                    break
                j += 1
            if found:
                desc, tk = found
                out.append(_alert(
                    "MISRA C:2012 13.5", Severity.WARNING,
                    f"逻辑 {t.value} 的右操作数包含持续副作用（{desc}），"
                    "因短路求值其执行不保证", f.path, tk.line, "CWE-784",
                    [_evidence(f.path, tk.line, "code",
                               f"{t.value} 右侧：{desc}")],
                ))
    return out


def check_for_counter(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 14.2（简版）：for 控制变量在循环体内被赋值/自增自减。"""
    out = []
    for func in f.functions:
        toks = func.tokens
        i = 0
        while i < len(toks):
            t = toks[i]
            if t.kind == "keyword" and t.value == "for" and i + 1 < len(toks) \
                    and toks[i + 1].value == "(":
                close = _match_forward(toks, i + 1, "(", ")")
                if close == -1:
                    i += 1
                    continue
                header = toks[i + 2 : close]
                ctrl = _for_control_var(header)
                body_end = -1
                if close + 1 < len(toks) and toks[close + 1].value == "{":
                    body_end = _match_forward(toks, close + 1, "{", "}")
                body = toks[close + 2 : body_end] if body_end != -1 else []
                if ctrl:
                    for k, tk in enumerate(body):
                        if tk.kind != "ident" or tk.value != ctrl:
                            continue
                        nxt = body[k + 1].value if k + 1 < len(body) else ""
                        prv = body[k - 1].value if k > 0 else ""
                        if nxt in ("=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=",
                                   "++", "--") or prv in ("++", "--"):
                            out.append(_alert(
                                "MISRA C:2012 14.2", Severity.WARNING,
                                f"for 循环控制变量 {ctrl} 在循环体内被修改",
                                f.path, tk.line, "CWE-834",
                                [_evidence(f.path, tk.line, "code",
                                           f"{ctrl} 被修改于循环体内")],
                            ))
                            break
                i = max(close, body_end, i + 1)
                continue
            i += 1
    return out


def _match_forward(toks: list[CToken], open_idx: int, op: str, cl: str) -> int:
    depth = 0
    for j in range(open_idx, len(toks)):
        if toks[j].kind == "punct":
            if toks[j].value == op:
                depth += 1
            elif toks[j].value == cl:
                depth -= 1
                if depth == 0:
                    return j
    return -1


def _for_control_var(header: list[CToken]) -> str | None:
    """for 头第一段（首个 ; 之前）中被赋值的标识符。"""
    seg = []
    for tk in header:
        if tk.kind == "punct" and tk.value == ";":
            break
        seg.append(tk)
    for k in range(len(seg) - 1):
        if seg[k].kind == "ident" and seg[k + 1].kind == "punct" \
                and seg[k + 1].value == "=":
            return seg[k].value
    return None


def check_goto(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 15.2：禁止 goto。"""
    out = []
    for func in f.functions:
        for t in func.tokens:
            if t.kind == "keyword" and t.value == "goto":
                out.append(_alert(
                    "MISRA C:2012 15.2", Severity.WARNING,
                    f"函数 {func.name} 中使用了 goto，破坏单入单出结构",
                    f.path, t.line, "CWE-670",
                    [_evidence(f.path, t.line, "code", "goto 语句")],
                ))
    return out


def check_single_return(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 15.5：单一退出点。"""
    out = []
    for func in f.functions:
        returns = [t for t in func.tokens if t.kind == "keyword" and t.value == "return"]
        if len(returns) > 1:
            extra = returns[1]
            out.append(_alert(
                "MISRA C:2012 15.5", Severity.NOTE,
                f"函数 {func.name} 存在 {len(returns)} 个 return，违反单一退出点",
                f.path, extra.line,
                evidence=[_evidence(f.path, r.line, "code", "return 语句")
                          for r in returns],
            ))
    return out


def check_switch_rules(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 16.4（缺 default）与 16.6（case 少于 2）。"""
    out = []
    for func, switches in f.switches:
        for sw in switches:
            if not sw.has_default and "MISRA C:2012 16.4" in active:
                out.append(_alert(
                    "MISRA C:2012 16.4", Severity.WARNING,
                    f"函数 {func.name} 第 {sw.line} 行的 switch 缺少 default 标签",
                    f.path, sw.line, None,
                    [_evidence(f.path, sw.line, "code", "switch 块无 default")],
                ))
            if sw.case_count < 2 and "MISRA C:2012 16.6" in active:
                out.append(_alert(
                    "MISRA C:2012 16.6", Severity.WARNING,
                    f"函数 {func.name} 第 {sw.line} 行的 switch 仅有 {sw.case_count} 个 "
                    "case 标签（要求至少 2 个）", f.path, sw.line, None,
                    [_evidence(f.path, sw.line, "code",
                               f"case 标签数 = {sw.case_count}")],
                ))
    return out


def check_recursion(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 17.2：直接递归（间接递归依赖阶段二调用图）。"""
    out = []
    for func in f.functions:
        for callee, line in func.calls_in_body():
            if callee == func.name:
                out.append(_alert(
                    "MISRA C:2012 17.2", Severity.ERROR,
                    f"函数 {func.name} 直接递归调用自身，嵌入式栈深不可控",
                    f.path, line, "CWE-674",
                    [_evidence(f.path, line, "code", f"{func.name}() 递归调用点")],
                ))
                break
    return out


# 禁用 API 清单（调用名 -> (规则, 严重级, 消息前缀, CWE)）
_BANNED_APIS: dict[str, tuple[str, Severity, str, str | None]] = {
    **{n: ("MISRA C:2012 21.3", Severity.WARNING, "stdca 禁用的内存分配/转换函数", "CWE-676")
       for n in ("malloc", "calloc", "realloc", "free")},
    **{n: ("MISRA C:2012 21.3", Severity.WARNING, "禁止使用的数值转换函数", "CWE-190")
       for n in ("atof", "atoi", "atol", "atoll")},
    **{n: ("MISRA C:2012 21.3", Severity.WARNING, "禁止使用的进程控制函数", "CWE-676")
       for n in ("exit", "abort", "getenv", "bsearch", "qsort", "system")},
    **{n: ("MISRA C:2012 21.6", Severity.NOTE, "嵌入式场景禁用的 stdio 输入/输出函数", "CWE-676")
       for n in ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf",
                 "vsnprintf", "scanf", "fscanf", "sscanf", "getchar", "putchar",
                 "puts", "gets", "fopen", "fclose", "fread", "fwrite", "fflush")},
    "rand": ("CERT C MSC30-C", Severity.WARNING,
             "rand() 非密码学安全随机源，安全场景应使用硬件 RNG", "CWE-338"),
    "srand": ("CERT C MSC30-C", Severity.WARNING,
              "srand 种子化的 rand() 序列可预测，安全场景应使用硬件 RNG", "CWE-337"),
    "random": ("CERT C MSC30-C", Severity.WARNING,
               "random() 非密码学安全随机源", "CWE-338"),
}

# 格式串必须为字面量的函数（第一个参数即格式串）
_FORMAT_FUNCS = {"printf", "sprintf", "snprintf", "vprintf", "vsprintf", "vsnprintf"}


def check_banned_apis(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 21.3/21.6、CERT MSC30-C、ECDET-CWE-242：禁用 API 调用扫描。"""
    out = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            if t.value == "gets":
                if "ECDET-CWE-242" in active:
                    out.append(_alert(
                        "ECDET-CWE-242", Severity.ERROR,
                        "gets() 读取长度无界，C11 标准已删除该函数，必然缓冲区溢出风险",
                        f.path, t.line, "CWE-242",
                        [_evidence(f.path, t.line, "api", "gets() 调用")],
                    ))
                continue
            hit = _BANNED_APIS.get(t.value)
            if hit and hit[0] in active:
                rule, sev, prefix, cwe = hit
                out.append(_alert(
                    rule, sev, f"{prefix}：{t.value}()", f.path, t.line, cwe,
                    [_evidence(f.path, t.line, "api", f"{t.value}() 调用点")],
                ))
    return out


def check_format_string(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """CERT FIO30-C：格式串非字面量。"""
    out = []
    for func in f.functions:
        toks = func.tokens
        for i, t in enumerate(toks):
            if t.kind != "ident" or t.value not in _FORMAT_FUNCS:
                continue
            if i + 1 >= len(toks) or toks[i + 1].value != "(":
                continue
            first = toks[i + 2] if i + 2 < len(toks) else None
            if first is not None and first.kind != "string":
                out.append(_alert(
                    "CERT C FIO30-C", Severity.ERROR,
                    f"{t.value}() 的格式串为变量而非字面量，存在格式串注入风险",
                    f.path, t.line, "CWE-134",
                    [_evidence(f.path, t.line, "api",
                               f"{t.value}(变量, ...) 而非字面量格式串")],
                ))
    return out


def check_reserved_ident(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 21.1：定义保留标识符。"""
    out = []
    seen: set[tuple[str, int]] = set()

    def bad(name: str) -> bool:
        return "__" in name or (name.startswith("_") and len(name) > 1 and name[1].isupper())

    for p in f.lex.pp_lines:
        if p.directive == "define" and p.macro_name and bad(p.macro_name) \
                and (p.macro_name, p.line) not in seen:
            seen.add((p.macro_name, p.line))
            out.append(_alert(
                "MISRA C:2012 21.1", Severity.WARNING,
                f"宏名 {p.macro_name} 属于 C 标准保留标识符（下划线+大写/双下划线）",
                f.path, p.line, "CWE-709",
                [_evidence(f.path, p.line, "macro", f"#define {p.macro_name}")],
            ))
    for func in f.functions:
        if bad(func.name) and (func.name, func.def_line) not in seen:
            seen.add((func.name, func.def_line))
            out.append(_alert(
                "MISRA C:2012 21.1", Severity.WARNING,
                f"函数名 {func.name} 属于 C 标准保留标识符",
                f.path, func.def_line, "CWE-709",
                [_evidence(f.path, func.def_line, "code", func.signature)],
            ))
    return out


def check_macro_parens(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """CERT PRE31-C：函数宏体内参数每次出现必须加括号。"""
    out = []
    for p in f.lex.pp_lines:
        if p.directive != "define" or not p.is_function_like or not p.params:
            continue
        body_toks = lex_c(p.body).tokens
        for i, bt in enumerate(body_toks):
            if bt.kind != "ident" or bt.value not in p.params:
                continue
            prev_ok = i > 0 and body_toks[i - 1].value == "("
            next_ok = i + 1 < len(body_toks) and body_toks[i + 1].value == ")"
            if not (prev_ok and next_ok):
                out.append(_alert(
                    "CERT C PRE31-C", Severity.WARNING,
                    f"宏 {p.macro_name} 的参数 {bt.value} 在宏体中未加括号，"
                    "展开后可能因运算符优先级出错", f.path, p.line, "CWE-789",
                    [_evidence(f.path, p.line, "macro", f"#define {p.macro_name}(...) {p.body}")],
                ))
                break
    return out


_STRCPY_LIT_RE = re.compile(
    r'\b(strcpy|strncpy|memcpy)\s*\(\s*([A-Za-z_]\w*)\s*,\s*("[^"]*"|[^,)]+?)\s*'
    r'(?:,\s*(\d+|sizeof\s*\([^)]*\))\s*)?\)')


def check_buffer_copy(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """CERT STR31-C（常量核对版）：strcpy/strncpy/memcpy 目标空间不足。"""
    out = []
    arr_sizes = {a.name: a.size for a in f.arrays}
    for func in f.functions:
        for callee, line in func.calls_in_body():
            if callee not in ("strcpy", "strncpy", "memcpy"):
                continue
            src = f.lex.source_lines[line - 1] if line - 1 < len(f.lex.source_lines) else ""
            m = _STRCPY_LIT_RE.search(src)
            if not m:
                continue
            api, dst, second, third = m.group(1), m.group(2), m.group(3), m.group(4)
            if dst not in arr_sizes:
                continue
            size = arr_sizes[dst]
            need = -1
            if api == "strcpy" and second.startswith('"'):
                need = len(_unquote(second)) + 1
            elif api in ("strncpy", "memcpy") and third and third.isdigit():
                need = int(third)
            if need > size:
                out.append(_alert(
                    "CERT C STR31-C", Severity.ERROR,
                    f"{api}() 写入目标数组 {dst}[{size}] 需要 {need} 字节，缓冲区溢出",
                    f.path, line, "CWE-120",
                    [_evidence(f.path, line, "api", f"{api}({dst}, ...) 需要 {need} > {size}")],
                ))
    return out


def _unquote(s: str) -> str:
    """处理字符串字面量（含基本转义）的长度计算。"""
    body = s[1:-1]
    return re.sub(r'\\[0tnr\\0"\'x[0-9a-fA-F]{1,2}]', "X", body)


_Scanf_RE = re.compile(r'\b(scanf|sscanf|fscanf)\s*\(')


def check_scanf_unbounded(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """ECDET-CWE-1284：scanf 家族 %s 无宽度限定。"""
    out = []
    for func in f.functions:
        for callee, line in func.calls_in_body():
            if callee not in ("scanf", "sscanf", "fscanf"):
                continue
            src = f.lex.source_lines[line - 1] if line - 1 < len(f.lex.source_lines) else ""
            if not _Scanf_RE.search(src):
                continue
            m = re.search(r'"([^"]*)"', src)
            if not m:
                continue
            fmt = m.group(1)
            if "%s" not in fmt:
                continue
            if re.search(r"%\d+s", fmt):    # 有宽度限定的 %10s 合规
                continue
            out.append(_alert(
                "ECDET-CWE-1284", Severity.ERROR,
                f"{callee}() 的格式串含无宽度限定的 %s，读取长度无界，缓冲区溢出风险",
                f.path, line, "CWE-1284",
                [_evidence(f.path, line, "api", f'格式串 "{fmt}" 中 %s 无宽度')],
            ))
    return out


def check_array_index(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """CERT ARR30-C（常量下标版）：数组常量下标越界（排除声明行自身）。"""
    out = []
    arr_sizes = {a.name: a.size for a in f.arrays}
    type_words = {"void", "char", "short", "int", "long", "float", "double",
                  "signed", "unsigned", "_Bool", "struct", "union", "enum"}
    toks = f.lex.tokens
    for i, t in enumerate(toks):
        if t.kind != "ident" or t.value not in arr_sizes:
            continue
        # 声明形态排除：标识符前是类型（关键字或 typedef 名）则是声明而非访问
        if i > 0 and (toks[i - 1].value in type_words or
                      (toks[i - 1].kind == "ident" and toks[i - 1].value.endswith("_t"))):
            continue
        if i + 3 >= len(toks):
            continue
        if toks[i + 1].value == "[" and toks[i + 2].kind == "number" \
                and toks[i + 3].value == "]":
            try:
                idx = int(toks[i + 2].value, 0)
            except ValueError:
                continue
            if idx >= arr_sizes[t.value]:
                out.append(_alert(
                    "CERT C ARR30-C", Severity.ERROR,
                    f"数组 {t.value}[{arr_sizes[t.value]}] 以常量下标 {idx} 越界访问",
                    f.path, t.line, "CWE-787",
                    [_evidence(f.path, t.line, "code",
                               f"{t.value}[{idx}]，声明大小 {arr_sizes[t.value]}")],
                ))
    return out


_WIDTH_TABLE: dict[str, int] = {}
for _k in ("uint8_t", "u8", "U8", "UINT8", "UINT8_T"):
    _WIDTH_TABLE[_k] = 8
for _k in ("int8_t", "s8", "S8", "INT8", "INT8_T"):
    _WIDTH_TABLE[_k] = 8
for _k in ("uint16_t", "u16", "U16", "UINT16", "UINT16_T"):
    _WIDTH_TABLE[_k] = 16
for _k in ("int16_t", "s16", "S16", "INT16", "INT16_T"):
    _WIDTH_TABLE[_k] = 16
for _k in ("uint32_t", "u32", "U32", "UINT32", "UINT32_T"):
    _WIDTH_TABLE[_k] = 32
for _k in ("int32_t", "s32", "S32", "INT32", "INT32_T"):
    _WIDTH_TABLE[_k] = 32

_TRUNC_RE = re.compile(
    r"(?:^|[;{])\s*(?:static\s+|const\s+|volatile\s+|register\s+)*"
    r"(u?int(?:8|16|32)_t|[uUsS](?:8|16|32)(?:_t)?|UINT(?:8|16|32)(?:_T)?)\s+"
    r"([A-Za-z_]\w*)\s*=\s*(-?\s*(?:0[xX][0-9a-fA-F]+|\d+))[uUlL]*\s*[;,]")


def check_literal_truncation(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """ECDET-CWE-197：定宽类型初始化字面量超出表示范围。"""
    out = []
    for idx, text in enumerate(f.lex.clean_lines, start=1):
        for m in _TRUNC_RE.finditer(text):
            tname, var, lit = m.group(1), m.group(2), m.group(3).replace(" ", "")
            width = _WIDTH_TABLE.get(tname)
            if not width:
                continue
            try:
                val = int(lit, 0)
            except ValueError:
                continue
            signed = tname[0].lower() == "i" or tname[0].lower() == "s"
            lo = -(1 << (width - 1)) if signed else 0
            hi = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
            if not (lo <= val <= hi):
                shown = val & ((1 << width) - 1)
                out.append(_alert(
                    "ECDET-CWE-197", Severity.ERROR,
                    f"{tname} {var} = {lit} 超出 {width} 位表示范围，实际截断为 {shown}",
                    f.path, idx, "CWE-197",
                    [_evidence(f.path, idx, "code", f"合法范围 [{lo}, {hi}]，字面量 {lit}")],
                ))
    return out


def check_unused_params(f: FileFacts, ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """ECDET-CWE-563：函数参数未在函数体内使用。"""
    out = []
    for func in f.functions:
        body_idents = {t.value for t in func.tokens if t.kind == "ident"}
        for p in func.params:
            if p not in body_idents and p not in ("void", "..."):
                out.append(_alert(
                    "ECDET-CWE-563", Severity.NOTE,
                    f"函数 {func.name} 的参数 {p} 在函数体内未被使用",
                    f.path, func.def_line, "CWE-563",
                    [_evidence(f.path, func.def_line, "code", func.signature)],
                ))
    return out


# ---------------------------------------------------------------------------
# 跨文件（工程级）规则
# ---------------------------------------------------------------------------

_ISR_PAT = re.compile(r"(IRQHandler|_isr|_ISR|InterruptHandler|IrqHandler)$", re.I)


def _name_usage_map(ctx: ProjectContext) -> dict[str, set[str]]:
    """统计每个标识符出现在哪些文件（任何 token 出现即算引用）。"""
    name_files: dict[str, set[str]] = {}
    for f in ctx.facts:
        for t in f.lex.tokens:
            if t.kind == "ident":
                name_files.setdefault(t.value, set()).add(f.path)
    return name_files


def check_single_tu_funcs(ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 8.7：仅单翻译单元引用的函数应 static。"""
    out: list[Alert] = []
    name_files = _name_usage_map(ctx)
    for f in ctx.facts:
        if not f.path.endswith(".c"):
            continue
        for func in f.functions:
            name = func.name
            if name == "main" or _ISR_PAT.search(name):
                continue
            context_src = "\n".join(
                f.lex.source_lines[max(0, func.def_line - 2):func.def_line + 1])
            if "__attribute__" in context_src:
                continue
            files = name_files.get(name, {f.path})
            if len(files) == 1:
                out.append(_alert(
                    "MISRA C:2012 8.7", Severity.NOTE,
                    f"函数 {name} 仅在 {f.path} 中被引用，建议声明为 static 收窄链接域",
                    f.path, func.def_line,
                    evidence=[_evidence(f.path, func.def_line, "code", func.signature)],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


def check_single_tu_vars(ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 8.9：仅单翻译单元引用的全局变量应 static。"""
    out: list[Alert] = []
    name_files = _name_usage_map(ctx)
    for f in ctx.facts:
        if not f.path.endswith(".c"):
            continue
        for gname, gline, is_static in f.global_vars:
            if is_static:
                continue
            files = name_files.get(gname, {f.path})
            if len(files) == 1:
                out.append(_alert(
                    "MISRA C:2012 8.9", Severity.NOTE,
                    f"全局变量 {gname} 仅在 {f.path} 中被引用，建议声明为 static",
                    f.path, gline,
                    evidence=[_evidence(f.path, gline, "code", "全局定义")],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


def check_implicit_decl(ctx: ProjectContext, active: set[str]) -> list[Alert]:
    """MISRA 17.3：调用点无可见原型的函数（白名单兜底，suspected 级）。"""
    out: list[Alert] = []
    for f in ctx.facts:
        if not f.path.endswith(".c"):
            continue
        # 本文件可见声明：本文件函数 + include 的工程头文件声明 + 全工程声明
        visible = set(ctx.project_decls) | LIBC_WHITELIST
        visible |= {fn.name for fn in f.functions}
        visible |= _includes_transitive(f, ctx)
        for func in f.functions:
            for callee, line in func.calls_in_body():
                if callee in visible:
                    continue
                out.append(_alert(
                    "MISRA C:2012 17.3", Severity.WARNING,
                    f"调用 {callee}() 前无可见原型（隐式声明），行为未定义",
                    f.path, line, "CWE-758",
                    [_evidence(f.path, line, "api", f"{callee}() 调用点")],
                    provenance=Provenance.SUSPECTED,
                ))
    return out


def _includes_transitive(f: FileFacts, ctx: ProjectContext) -> set[str]:
    """本文件 include 的工程头文件中声明的函数名（一层展开，简化不递归）。

    PPLine.text 的引号内容已被遮蔽，包含目标须从原始行提取。
    """
    declared: set[str] = set()
    for p in f.lex.pp_lines:
        if p.directive != "include":
            continue
        raw_line = (f.lex.source_lines[p.line - 1]
                    if p.line - 1 < len(f.lex.source_lines) else "")
        m = re.search(r'#\s*include\s*"([^"]+)"', raw_line)
        if not m:
            continue
        inc = m.group(1).replace("\\", "/")
        for other in ctx.facts:
            other_norm = other.path.replace("\\", "/")
            if other_norm.endswith(".h") and other_norm.endswith(inc):
                declared |= other.declared_funcs
    return declared


def _collect_decls(f: FileFacts) -> set[str]:
    """从头文件净化行提取函数原型名：`... name(...);` 形态。"""
    names: set[str] = set()
    for text in f.lex.clean_lines:
        s = text.strip()
        if not s or s.startswith("#") or "{" in s or "=" in s:
            continue
        m = re.match(r"^[\w\s\*]+?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*;$", s)
        if m and m.group(1) not in ("if", "for", "while", "switch", "return", "sizeof"):
            names.add(m.group(1))
    return names


def finalize_facts(facts: list[FileFacts]) -> ProjectContext:
    """构建工程上下文（计算头文件声明集）。"""
    for f in facts:
        if f.path.endswith(".h"):
            f.declared_funcs = _collect_decls(f)
    ctx = ProjectContext(facts=facts)
    ctx.project_decls = {fn.name for f in facts for fn in f.functions}
    for f in facts:
        ctx.project_decls |= f.declared_funcs
    return ctx


# ---------------------------------------------------------------------------
# MISRA 10.x 整型转换族（方案 3.3.3 UsualArithType 伪代码的可判定实现）
# ---------------------------------------------------------------------------

_ARITH_OPS = {"+", "-", "*", "/", "%", "&", "|", "^"}
_ASSIGN_STOP = {";", "{"}


def _rhs_tokens(toks: list[CToken], start: int) -> tuple[list[CToken], int]:
    """收集赋值 rhs 的 token（至顶层分号），返回 (tokens, 下一索引)。"""
    expr: list[CToken] = []
    depth = 0
    j = start
    while j < len(toks):
        v = toks[j].value
        if toks[j].kind == "punct":
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
    return expr, j


_FOLD_OPS = {"+": lambda a, b: a + b, "-": lambda a, b: a - b,
             "*": lambda a, b: a * b, "&": lambda a, b: a & b,
             "|": lambda a, b: a | b, "^": lambda a, b: a ^ b}


def _literal_value(text: str) -> Optional[int]:
    """字面量数值（含一元负号/进制/整型后缀）；无法解析返回 None。"""
    t = text.strip()
    sign = 1
    if t.startswith(("+", "-")):
        sign = -1 if t[0] == "-" else 1
        t = t[1:]
    body = t.rstrip("uUlL")
    if not body:
        return None
    try:
        return sign * int(body, 0)
    except ValueError:
        return None


def _literal_result(text: str) -> dict:
    et = literal_type(text)
    if et is None:
        return {"kind": "unknown"}
    return {"kind": "literal", "type": et, "value": _literal_value(text)}


def _resolve_expr(expr: list[CToken], types: dict) -> dict:
    """rhs 表达式分类解析。

    返回 {"kind": "literal|ident|binary|unknown", ...}；literal 携带
    value 供"值可表示性"判定；双字面量二元做常量折叠（1u+2u → 3u）；
    cast/取址/调用/sizeof 等一律 unknown（不猜 → 不误报）。
    """
    expr = [t for t in expr if not (t.kind == "punct" and t.value == ",")]
    if not expr:
        return {"kind": "unknown"}
    # 一元负号 + 数字 → 负字面量
    if len(expr) == 2 and expr[0].value in "+-" and expr[1].kind == "number":
        return _literal_result(expr[0].value + expr[1].value)
    if len(expr) == 1:
        t = expr[0]
        if t.kind == "number":
            return _literal_result(t.value)
        if t.kind == "ident":
            return {"kind": "ident", "type": types.get(t.value), "name": t.value}
        return {"kind": "unknown"}
    # cast 显式转换 → 合规路径，跳过
    if expr[0].value == "(":
        return {"kind": "unknown"}
    if expr[0].value in ("&", "*"):
        return {"kind": "unknown"}
    # 二元：operand op operand（3 token）
    if len(expr) == 3 and expr[1].kind == "punct":
        op = expr[1].value

        def operand(t: CToken) -> dict:
            if t.kind == "ident":
                return {"kind": "ident", "type": types.get(t.value), "name": t.value}
            if t.kind == "number":
                return _literal_result(t.value)
            return {"kind": "unknown"}

        left, right = operand(expr[0]), operand(expr[2])
        if op in _ARITH_OPS and left["type"] and right["type"]:
            # 双字面量常量折叠：结果按值取基本类型（1u+2u → 3u）
            if (left["kind"] == "literal" and right["kind"] == "literal"
                    and left.get("value") is not None
                    and right.get("value") is not None):
                fold = _FOLD_OPS.get(op)
                v = fold(left["value"], right["value"]) if fold else None
                if v is not None:
                    folded = _literal_result(str(v))
                    if folded["kind"] == "literal":
                        return folded
            composite = usual_arith(left["type"], right["type"])
            return {"kind": "binary", "op": op, "left": left,
                    "right": right, "type": composite}
        return {"kind": "unknown"}
    return {"kind": "unknown"}


def check_rule_10_x(f: FileFacts, ctx: ProjectContext,
                    active: set[str]) -> list[Alert]:
    """MISRA C:2012 10.3 / 10.4（方案 3.3.3 示例的可判定实现）。

    10.3：赋值（含初始化）rhs 基本类型秩高于 lhs 或符号性不同 → 告警；
          字面量 rhs 采取宽松口径（仅负值赋无符号告警），避免小常量误报。
    10.4：双操作数均为已知变量且提升后符号性不同 → 告警。
    cast 显式转换视为合规路径；无法解析的表达式一律不猜。
    """
    want_103 = "MISRA C:2012 10.3" in active
    want_104 = "MISRA C:2012 10.4" in active
    if not (want_103 or want_104):
        return []
    out: list[Alert] = []
    types = build_type_table(f.lex, f.func_lines, functions=f.functions)
    toks = f.lex.tokens
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind != "ident" or i + 1 >= len(toks) or toks[i + 1].value != "=":
            i += 1
            continue
        lhs_type = types.get(t.value)
        expr, nxt = _rhs_tokens(toks, i + 2)
        parsed = _resolve_expr(expr, types)
        if lhs_type is not None and parsed["kind"] != "unknown":
            rhs_type: EssentialType = parsed["type"]
            if want_103 and rhs_type is not None:
                if parsed["kind"] == "literal":
                    # 字面量宽松口径：值可被 lhs 表示即合规（避免 uint8 x=3 类
                    # 高频误报）；超界（含负值赋无符号）才告警
                    v = parsed.get("value")
                    if v is not None:
                        lo, hi = lhs_type.bounds()
                        if not (lo <= v <= hi):
                            out.append(_alert(
                                "MISRA C:2012 10.3", Severity.WARNING,
                                f"赋值 {t.value}：字面量 {v} 超出 "
                                f"{lhs_type.label()} 表示范围 [{lo}, {hi}]",
                                f.path, t.line, "CWE-190",
                                [_evidence(f.path, t.line, "type",
                                           f"{lhs_type.label()} 无法表示 {v}")],
                            ))
                elif (rhs_type.rank > lhs_type.rank
                        or rhs_type.signed != lhs_type.signed):
                    out.append(_alert(
                        "MISRA C:2012 10.3", Severity.WARNING,
                        f"赋值 {t.value}：rhs 为{rhs_type.label()}，"
                        f"lhs 为{lhs_type.label()}，发生"
                        f"{'秩收窄' if rhs_type.rank > lhs_type.rank else '符号性改变'}",
                        f.path, t.line, "CWE-197",
                        [_evidence(f.path, t.line, "type",
                                   f"{lhs_type.label()} = {rhs_type.label()}")],
                    ))
            if want_104 and parsed["kind"] == "binary":
                lt, rt = parsed["left"]["type"], parsed["right"]["type"]
                if (parsed["left"]["kind"] == "ident"
                        and parsed["right"]["kind"] == "ident"
                        and integer_promote(lt).signed
                        != integer_promote(rt).signed):
                    ln = parsed["left"]["name"]
                    rn = parsed["right"]["name"]
                    out.append(_alert(
                        "MISRA C:2012 10.4", Severity.WARNING,
                        f"运算符 {parsed['op']} 混用符号性：{ln}（{lt.label()}）"
                        f"与 {rn}（{rt.label()}），常规算术转换后为"
                        f"{usual_arith(lt, rt).label()}",
                        f.path, expr[1].line, "CWE-190",
                        [_evidence(f.path, expr[1].line, "type",
                                   f"{ln} {parsed['op']} {rn} 符号性混用")],
                    ))
        i = max(nxt, i + 1)
    return out


# ---------------------------------------------------------------------------
# 规则注册表：rule_id -> (作用域, 检查函数)
# ---------------------------------------------------------------------------

FILE_RULES = {
    "MISRA C:2012 2.5": check_unused_macro,
    "MISRA C:2012 7.2": check_unsigned_suffix,
    "MISRA C:2012 13.5": check_logic_side_effect,
    "MISRA C:2012 14.2": check_for_counter,
    "MISRA C:2012 15.2": check_goto,
    "MISRA C:2012 15.5": check_single_return,
    "MISRA C:2012 16.4": check_switch_rules,
    "MISRA C:2012 16.6": check_switch_rules,
    "MISRA C:2012 17.2": check_recursion,
    "MISRA C:2012 21.1": check_reserved_ident,
    "MISRA C:2012 21.3": check_banned_apis,
    "MISRA C:2012 21.6": check_banned_apis,
    "CERT C PRE31-C": check_macro_parens,
    "CERT C MSC30-C": check_banned_apis,
    "CERT C STR31-C": check_buffer_copy,
    "CERT C ARR30-C": check_array_index,
    "CERT C FIO30-C": check_format_string,
    "ECDET-CWE-242": check_banned_apis,
    "ECDET-CWE-1284": check_scanf_unbounded,
    "ECDET-CWE-197": check_literal_truncation,
    "ECDET-CWE-563": check_unused_params,
    "MISRA C:2012 10.3": check_rule_10_x,
    "MISRA C:2012 10.4": check_rule_10_x,
}

PROJECT_RULES = {
    "MISRA C:2012 8.7": check_single_tu_funcs,
    "MISRA C:2012 8.9": check_single_tu_vars,
    "MISRA C:2012 17.3": check_implicit_decl,
}
