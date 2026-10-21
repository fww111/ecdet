"""C 程序结构解析 —— 基于词法 token 的轻量结构恢复。

从 LexResult 中恢复：函数定义（名称/参数/函数体区间）、switch 块
（case 数/default 有无）、数组声明（定宽下界）、调用点、宏定义。
供句法类 MISRA/CERT 规则消费。不追求完整 AST，追求"够 MVP 规则集可靠使用"。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ecdet.l3_analysis.builtin_rules.ctokens import CToken, LexResult

_TYPE_KEYWORDS = {"void", "char", "short", "int", "long", "float", "double",
                  "signed", "unsigned", "_Bool", "struct", "union", "enum"}
_STORAGE_KEYWORDS = {"static", "extern", "const", "volatile", "register", "inline",
                     "restrict", "typedef", "auto"}
_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "do", "else", "return",
                     "sizeof", "case", "default", "goto", "break", "continue"}


@dataclass
class FunctionInfo:
    name: str
    signature: str                     # 净化后的签名文本
    start_line: int                    # 签名文本起始行（含回看的返回类型，仅供证据展示）
    body_open_line: int                # 函数体 { 所在行
    body_close_line: int               # 函数体 } 所在行
    def_line: int = 0                  # 函数名所在行（告警定位与行归属判定用）
    tokens: list[CToken] = field(default_factory=list)   # 函数体内部 token（不含签名）
    params: list[str] = field(default_factory=list)      # 参数名
    param_types: list[str] = field(default_factory=list)  # 参数类型文本（与 params 对齐）

    @property
    def n_returns(self) -> int:
        return sum(1 for t in self.tokens if t.kind == "keyword" and t.value == "return")

    @property
    def has_goto(self) -> bool:
        return any(t.kind == "keyword" and t.value == "goto" for t in self.tokens)

    def calls_in_body(self) -> list[tuple[str, int]]:
        """函数体内 `ident (` 形态的调用点：(被调名, 行)。"""
        out = []
        toks = self.tokens
        for i, t in enumerate(toks):
            if t.kind == "ident" and i + 1 < len(toks) and toks[i + 1].value == "(":
                # 排除声明形态：标识符前是类型关键字（如 `unsigned char name(`）
                prev = toks[i - 1].value if i > 0 else ""
                if prev not in _TYPE_KEYWORDS:
                    out.append((t.value, t.line))
        return out


@dataclass
class SwitchInfo:
    line: int                          # switch 关键字行
    case_count: int                    # 直接子 case 标签数
    has_default: bool                  # 直接子 default 标签


@dataclass
class ArrayDecl:
    name: str
    size: int                          # 显式整型常量大小；无显式大小为 -1
    line: int
    is_global: bool
    type_text: str = ""


def _match_paren(tokens: list[CToken], open_idx: int) -> int:
    """返回与 tokens[open_idx]（必须是 ( [ { 之一）配对的索引；未配到返回 -1。"""
    pairs = {"(": ")", "[": "]", "{": "}"}
    closer = pairs[tokens[open_idx].value]
    depth = 0
    for j in range(open_idx, len(tokens)):
        v = tokens[j].value
        if tokens[j].kind != "punct":
            continue
        if v == tokens[open_idx].value:
            depth += 1
        elif v == closer:
            depth -= 1
            if depth == 0:
                return j
    return -1


def parse_functions(lex: LexResult) -> list[FunctionInfo]:
    """识别顶层函数定义。

    判定规则：顶层（花括号深度 0）出现 `{`，且回溯跳过空白后紧邻 `)`，
    `(` 前的标识符为函数名，且函数名不是控制关键字 —— 认定为函数定义。
    struct/union/enum 定义、初始化列表（`=` 前导）天然不满足“紧邻 )”，被排除。
    """
    toks = lex.tokens
    funcs: list[FunctionInfo] = []
    spans: list[tuple[int, int]] = []          # (brace_idx, close_idx)
    depth = 0
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind != "punct":
            i += 1
            continue
        if t.value == "{":
            if depth == 0:
                info = _try_function_at(toks, i)
                if info:
                    close = _match_paren(toks, i)
                    if close == -1:
                        depth += 1
                        i += 1
                        continue
                    info.body_close_line = toks[close].line
                    funcs.append(info)
                    spans.append((i, close))
                    i = close + 1
                    continue
            depth += 1
        elif t.value == "}":
            depth = max(0, depth - 1)
        i += 1
    # 按花括号索引区间填充函数体 token（签名不在区间内，单行函数不混入）
    for f, (open_idx, close_idx) in zip(funcs, spans):
        f.tokens = toks[open_idx + 1 : close_idx]
    return funcs


def _try_function_at(toks: list[CToken], brace_idx: int) -> FunctionInfo | None:
    j = brace_idx - 1
    while j >= 0 and toks[j].value in (")",):
        close_paren = j                      # toks[j] == ')'
        open_paren = _match_paren_backward(toks, close_paren)
        if open_paren <= 0:
            return None
        k = open_paren - 1
        if k < 0 or toks[k].kind != "ident":
            return None
        name_tok = toks[k]
        if name_tok.value in _CONTROL_KEYWORDS or name_tok.value == "attribute":
            return None
        # 名字前必须还有类型/修饰 token（排除 `name(...) {` 的裸调用误判）
        if k == 0:
            return None
        prev = toks[k - 1]
        if prev.kind == "punct" and prev.value in (";", "}", ",", "*", ")"):
            # `void (*fp)(void) {` 不存在；`int f(void); int g(void) {` —— prev 为 ; 合法
            pass
        params, param_types = _param_decls(toks[open_paren + 1 : close_paren])
        sig_start = max(0, k - 6)
        signature = " ".join(t.value for t in toks[sig_start : close_paren + 1])
        return FunctionInfo(
            name=name_tok.value,
            signature=signature,
            start_line=toks[sig_start].line,
            def_line=name_tok.line,
            body_open_line=toks[brace_idx].line,
            body_close_line=-1,
            params=params,
            param_types=param_types,
        )
    return None


def _match_paren_backward(toks: list[CToken], close_idx: int) -> int:
    depth = 0
    for j in range(close_idx, -1, -1):
        if toks[j].kind != "punct":
            continue
        if toks[j].value == ")":
            depth += 1
        elif toks[j].value == "(":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _param_decls(param_tokens: list[CToken]) -> tuple[list[str], list[str]]:
    """解析参数声明 → (参数名列表, 参数类型文本列表)。

    每个顶层逗号段：最后的有效标识符为参数名，其余为类型
    （无类型文本时回退 "int"，兼容 `f(a, b)` 旧式写法）。
    """
    names: list[str] = []
    types: list[str] = []
    depth = 0
    seg: list[CToken] = []

    def flush(segment: list[CToken]) -> None:
        if not segment:
            return
        all_text = " ".join(t.value for t in segment)
        if all_text.strip() in ("void", ""):
            return
        idents = [t for t in segment
                  if t.kind == "ident" and t.value not in _TYPE_KEYWORDS
                  and t.value not in _STORAGE_KEYWORDS]
        name = idents[-1].value if idents else ""
        # 指针属于类型文本：`char *p` → ctype "char *"，名字 "p"
        type_parts = [t.value for t in segment if not (idents and t is idents[-1])]
        ctype = " ".join(type_parts).strip()
        if name:
            names.append(name)
            types.append(ctype or "int")

    for t in param_tokens:
        if t.kind == "punct":
            if t.value in "([{":
                depth += 1
            elif t.value in ")]}":
                depth -= 1
            elif t.value == "," and depth == 0:
                flush(seg)
                seg = []
                continue
        seg.append(t)
    flush(seg)
    return names, types


def _param_names(param_tokens: list[CToken]) -> list[str]:
    """从参数 token 序列提取参数名：取每个顶层逗号段最后一个标识符。"""
    names: list[str] = []
    depth = 0
    last_idents: list[str] = []
    seg_idents: list[str] = []
    for t in param_tokens:
        if t.kind == "punct":
            if t.value in "([{":
                depth += 1
            elif t.value in ")]}":
                depth -= 1
            elif t.value == "," and depth == 0:
                if seg_idents:
                    names.append(seg_idents[-1])
                seg_idents = []
            continue
        if depth == 0 and t.kind == "ident" and t.value not in _TYPE_KEYWORDS \
                and t.value not in _STORAGE_KEYWORDS:
            seg_idents.append(t.value)
    if seg_idents:
        names.append(seg_idents[-1])
    return [n for n in names if n]


def parse_switches(func: FunctionInfo) -> list[SwitchInfo]:
    """解析函数体内 switch 块（含嵌套归属：内层 case 不计入外层）。"""
    toks = func.tokens
    switches: list[SwitchInfo] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind == "keyword" and t.value == "switch":
            # switch ( ... ) { ... }
            j = i + 1
            while j < len(toks) and toks[j].value != "(":
                j += 1
            if j >= len(toks):
                break
            close = _match_paren(toks, j)
            brace = close + 1 if close != -1 else -1
            if brace < len(toks) and brace != -1 and toks[brace].value == "{":
                end = _match_paren(toks, brace)
                if end == -1:
                    i += 1
                    continue
                sw = _scan_switch_body(toks, brace, end)
                switches.append(sw)
                i = brace + 1      # 继续扫描块内部，嵌套 switch 亦独立报告
                continue
        i += 1
    return switches


def _scan_switch_body(toks: list[CToken], open_idx: int, end_idx: int) -> SwitchInfo:
    case_count = 0
    has_default = False
    depth = 0
    j = open_idx + 1
    while j < end_idx:
        t = toks[j]
        if t.kind == "punct":
            if t.value in "([{":
                depth += 1
            elif t.value in ")]}":
                depth -= 1
            j += 1
            continue
        if depth == 0 and t.kind == "keyword":
            if t.value == "case":
                case_count += 1
            elif t.value == "default":
                has_default = True
            elif t.value == "switch":
                # 嵌套 switch：整体跳过
                k = j + 1
                while k < end_idx and toks[k].value != "(":
                    k += 1
                if k < end_idx:
                    close = _match_paren(toks, k)
                    if close != -1 and close + 1 < end_idx and toks[close + 1].value == "{":
                        nested_end = _match_paren(toks, close + 1)
                        j = nested_end + 1 if nested_end != -1 else end_idx
                        continue
        j += 1
    return SwitchInfo(line=toks[open_idx - 1].line if open_idx > 0 else toks[open_idx].line,
                      case_count=case_count, has_default=has_default)


_ARRAY_DECL_RE = re.compile(
    r"(?:^|[;{])\s*(?:static\s+|const\s+|volatile\s+|extern\s+)*"
    r"((?:unsigned\s+|signed\s+|struct\s+\w+\s+|enum\s+\w+\s+|long\s+|short\s+)*"
    r"(?:void|char|short|int|long|float|double|_Bool|u?int(?:8|16|32|64)_t|\w+_t|BOOL|U8|U16|U32|S8|S16|S32|u8|u16|u32|s8|s16|s32|tU8|tU16|tU32)\s*\**\s*)"
    r"([A-Za-z_]\w*)\s*\[\s*(\d+|[A-Z][A-Z0-9_]*)\s*\]"
)


def _numeric_defines(lex: LexResult) -> dict[str, int]:
    """文件内纯数字 #define 宏表（如 LEN → 8），供数组大小解析。"""
    out: dict[str, int] = {}
    for p in lex.pp_lines:
        if p.directive == "define" and p.macro_name and not p.is_function_like:
            body = p.body.strip()
            if re.fullmatch(r"\d+", body):
                out[p.macro_name] = int(body)
    return out


def parse_array_decls(lex: LexResult, func_lines: set[int]) -> list[ArrayDecl]:
    """逐行正则识别 `type name[N];` 形态的数组声明。

    N 支持十进制常量与文件内纯数字宏（如 SENSOR_HISTORY_LEN）。
    """
    decls: list[ArrayDecl] = []
    defines = _numeric_defines(lex)
    for idx, line_text in enumerate(lex.clean_lines, start=1):
        s = line_text.strip()
        if not s or s.startswith("#"):
            continue
        # 语句边界（行首/;/{ 之后）匹配，兼容单行多语句写法
        for m in _ARRAY_DECL_RE.finditer(s):
            size_text = m.group(3)
            if size_text.isdigit():
                size = int(size_text)
            else:
                size = defines.get(size_text, -1)
                if size < 0:
                    continue      # 非本文件数字宏的大小（表达式/外部宏）不参与
            decls.append(
                ArrayDecl(
                    name=m.group(2),
                    size=size,
                    line=idx,
                    is_global=idx not in func_lines,
                    type_text=m.group(1).strip(),
                )
            )
    return decls
