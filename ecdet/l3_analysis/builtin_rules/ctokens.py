"""C 源码词法器 —— 自研规则引擎的基础设施。

对源码做容错词法分析：剥离注释、遮蔽字符串与字符字面量内容、
抽取预处理指令行，输出带行列号的 token 流与"净化行文本"。
规则检查全部基于净化文本进行，避免注释/字符串误匹配。

已知局限（MVP，阶段二由 Clang 前端替代补齐）：
  - 不做宏展开与条件编译求值，#if 分支内的代码同样参与检查；
  - 不处理 K&R 旧式函数定义、行拼接（反斜杠续行）以外的方言扩展。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# C 语言标点/运算符（按长度降序尝试匹配，避免 <= 被拆成 < 和 =）
_PUNCTS = [
    "...", "<<=", ">>=",
    "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
    "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "##",
    "+", "-", "*", "/", "%", "=", "<", ">", "!", "~", "&", "^", "|",
    "?", ":", ";", ",", ".", "(", ")", "[", "]", "{", "}",
]

_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
    "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while", "inline", "restrict", "_Bool", "_Complex", "_Imaginary",
}


@dataclass
class CToken:
    kind: str          # ident / number / string / char / punct / keyword
    value: str
    line: int
    col: int


@dataclass
class PPLine:
    """一条预处理指令。directives 如 #include/#define/#ifdef 等。"""

    directive: str                 # include / define / undef / if / ifdef ...
    text: str                      # 去掉 # 后的完整指令文本
    line: int
    # 仅 #define 有效：
    macro_name: Optional[str] = None
    is_function_like: bool = False
    params: list[str] = field(default_factory=list)
    body: str = ""


@dataclass
class LexResult:
    path: str
    tokens: list[CToken]           # 不含预处理指令行内的 token
    pp_lines: list[PPLine]
    clean_lines: list[str]         # 注释与字符串内容被遮蔽后的逐行文本
    source_lines: list[str]        # 原始行
    n_lines: int

    def line_text(self, line: int, strip: bool = True) -> str:
        if 1 <= line <= len(self.clean_lines):
            s = self.clean_lines[line - 1]
            return s.strip() if strip else s
        return ""


def _mask_string_like(src: str) -> tuple[str, str]:
    """返回 (净化文本, 原始文本副本)。净化规则：
    - 行/块注释内容替换为空格（保留换行，维持行号）；
    - 字符串与字符字面量内部字符替换为空格（保留引号本身）。
    """
    out: list[str] = []
    i, n = 0, len(src)
    state = "code"            # code / line_comment / block_comment / str / char
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.extend("  ")
                i += 2
            elif c == "/" and nxt == "*":
                state = "block_comment"
                out.extend("  ")
                i += 2
            elif c == '"':
                state = "str"
                out.append(c)
                i += 1
            elif c == "'":
                state = "char"
                out.append(c)
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append(c)
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.extend("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif state in ("str", "char"):
            quote = '"' if state == "str" else "'"
            if c == "\\" and nxt:
                out.extend("  ")
                i += 2
            elif c == quote:
                state = "code"
                out.append(c)
                i += 1
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
    return "".join(out), src


def lex_c(source: str, path: str = "<memory>") -> LexResult:
    """词法分析主入口。"""
    clean, _ = _mask_string_like(source)
    source_lines = source.splitlines()
    clean_lines = clean.splitlines()
    while len(clean_lines) < len(source_lines):
        clean_lines.append("")

    tokens: list[CToken] = []
    pp_lines: list[PPLine] = []

    line_starts = [0]
    for ln in clean_lines:
        line_starts.append(line_starts[-1] + len(ln) + 1)

    i, n = 0, len(clean)
    line, col = 1, 1

    def advance(k: int) -> None:
        nonlocal i, line, col
        for _ in range(k):
            if i < n and clean[i] == "\n":
                line += 1
                col = 1
            else:
                col += 1
            i += 1

    while i < n:
        c = clean[i]
        if c in " \t\r\n":
            advance(1)
            continue
        # 预处理指令：行首（仅空白前导）的 #
        if c == "#":
            line_start = clean.rfind("\n", 0, i) + 1
            if clean[line_start:i].strip() == "":
                j = clean.find("\n", i)
                if j == -1:
                    j = n
                directive_text = clean[i + 1 : j].strip()
                pp_lines.append(_parse_pp(directive_text, line))
                advance(j - i)
                continue
        # 标识符 / 关键字
        if c.isalpha() or c == "_":
            j = i
            while j < n and (clean[j].isalnum() or clean[j] == "_"):
                j += 1
            word = clean[i:j]
            tokens.append(
                CToken(
                    kind="keyword" if word in _C_KEYWORDS else "ident",
                    value=word,
                    line=line,
                    col=col,
                )
            )
            advance(j - i)
            continue
        # 数字（pp-number 容错：吞掉字母与点号后缀）
        if c.isdigit() or (c == "." and i + 1 < n and clean[i + 1].isdigit()):
            j = i
            seen_e = False
            while j < n:
                ch = clean[j]
                if ch in "0123456789.":
                    j += 1
                elif ch in "eEpP" and j > i:
                    seen_e = True
                    j += 1
                elif ch in "+-" and seen_e and clean[j - 1] in "eEpP":
                    j += 1
                elif (ch.isalpha() or ch == "_"):
                    # 0x1F、10u、1e5f 等后缀
                    j += 1
                else:
                    break
            tokens.append(CToken(kind="number", value=clean[i:j], line=line, col=col))
            advance(j - i)
            continue
        # 字符串/字符字面量（引号已保留在净化文本中）
        if c in "\"'":
            j = i + 1
            while j < n and clean[j] != c and clean[j] != "\n":
                j += 1
            tokens.append(CToken(kind="string" if c == '"' else "char",
                                 value=clean[i : j + 1], line=line, col=col))
            advance(min(j + 1, n) - i)
            continue
        # 标点
        for p in _PUNCTS:
            if clean.startswith(p, i):
                tokens.append(CToken(kind="punct", value=p, line=line, col=col))
                advance(len(p))
                break
        else:
            advance(1)   # 未知字符（$、@、反引号等）跳过

    return LexResult(
        path=path,
        tokens=tokens,
        pp_lines=pp_lines,
        clean_lines=clean_lines,
        source_lines=source_lines,
        n_lines=len(source_lines),
    )


def _parse_pp(text: str, line: int) -> PPLine:
    parts = text.split(None, 1)
    directive = parts[0] if parts else ""
    rest = parts[1].strip() if len(parts) > 1 else ""
    pl = PPLine(directive=directive, text=text, line=line)
    if directive == "define":
        m_name_end = 0
        while m_name_end < len(rest) and (rest[m_name_end].isalnum() or rest[m_name_end] == "_"):
            m_name_end += 1
        name = rest[:m_name_end]
        pl.macro_name = name
        tail = rest[m_name_end:]
        if tail.startswith("("):
            close = tail.find(")")
            params_text = tail[1:close] if close != -1 else tail[1:]
            params = [p.strip() for p in params_text.split(",") if p.strip()]
            pl.is_function_like = True
            pl.params = params
            pl.body = tail[close + 1 :].strip() if close != -1 else ""
        else:
            pl.body = tail.strip()
    return pl
