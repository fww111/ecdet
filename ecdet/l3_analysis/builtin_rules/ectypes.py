"""C 整型基本类型模型（方案 3.3.3 的 UsualArithType / Rank / Signedness）。

MISRA C:2012 Rule 10.x 族的可判定实现基础（ILP32 嵌入式模型）：
  - 整型秩：char/8 位 = 1，short/16 位 = 2，int/32 位（含 ILP32 long）= 3，
    long long/64 位 = 5；
  - 整型提升（C99 6.3.1.1）：秩 < int 的操作数提升为 int（32 位 int 可
    表示全部取值）；
  - 常规算术转换（6.3.1.8）：同符号取高秩；混合时无符号秩 ≥ 有符号秩则
    无符号胜，否则有符号胜；
  - 字面量基本类型：能表示该值的最小类型（MISRA 基本类型模型）。

诚实声明（MVP 简化，见 check_rule_10_3/10_4）：
  - 类型表来自逐行声明扫描（与既有规则同口径），不做多行声明与作用域
    嵌套；typedef 仅覆盖 stdint/常见嵌入式别名；
  - 字面量赋值采取宽松口径（小常量不告警），避免 `uint8_t x = 3` 类
    高频误报；严格 MISRA 语义的常量符号性规则留待接入 Clang 前端。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# 基本类型
# ---------------------------------------------------------------------------

RANK_8 = 1
RANK_16 = 2
RANK_32 = 3
RANK_64 = 5          # 4 留给 ILP32 下与 32 位同宽的 long（已并入 RANK_32）


@dataclass(frozen=True)
class EssentialType:
    """基本类型：秩 + 符号性。"""

    rank: int
    signed: bool

    @property
    def bits(self) -> int:
        return {1: 8, 2: 16, 3: 32, 4: 32, 5: 64}.get(self.rank, 32)

    def label(self) -> str:
        base = {1: "8 位", 2: "16 位", 3: "32 位", 4: "32 位", 5: "64 位"}[self.rank]
        return f"{'有符号' if self.signed else '无符号'}{base}类型"

    def bounds(self) -> tuple[int, int]:
        if self.signed:
            hi = (1 << (self.bits - 1)) - 1
            return -hi - 1, hi
        return 0, (1 << self.bits) - 1


INT8 = EssentialType(RANK_8, True)
UINT8 = EssentialType(RANK_8, False)
INT16 = EssentialType(RANK_16, True)
UINT16 = EssentialType(RANK_16, False)
INT32 = EssentialType(RANK_32, True)
UINT32 = EssentialType(RANK_32, False)
INT64 = EssentialType(RANK_64, True)
UINT64 = EssentialType(RANK_64, False)

# 类型名 → 基本类型（声明扫描用；ILP32：long 与 int 同宽）
_TYPE_ALIASES: dict[str, EssentialType] = {
    "char": INT8, "int8_t": INT8, "s8": INT8, "S8": INT8, "INT8": INT8,
    "uint8_t": UINT8, "u8": UINT8, "U8": UINT8, "UINT8": UINT8,
    "short": INT16, "int16_t": INT16, "s16": INT16, "S16": INT16, "INT16": INT16,
    "uint16_t": UINT16, "u16": UINT16, "U16": UINT16, "UINT16": UINT16,
    "int": INT32, "unsigned": UINT32, "int32_t": INT32, "s32": INT32,
    "S32": INT32, "INT32": INT32,
    "uint32_t": UINT32, "u32": UINT32, "U32": UINT32, "UINT32": UINT32,
    "long": INT32, "unsigned long": UINT32,
    "int64_t": INT64, "uint64_t": UINT64, "long long": INT64,
    "unsigned long long": UINT64, "size_t": UINT32, "BOOL": UINT8,
}


def resolve_type(type_text: str) -> Optional[EssentialType]:
    """类型文本 → 基本类型（未识别返回 None）。"""
    t = " ".join(type_text.replace("*", " ").split())
    # 组合词序归一（"unsigned int" / "int unsigned" 同类）
    words = t.split()
    unsigned = "unsigned" in words
    core = " ".join(w for w in words if w != "unsigned")
    et = _TYPE_ALIASES.get(core)
    if et is not None:
        if unsigned and et.signed:
            return EssentialType(et.rank, False)
        if not unsigned and et is UINT32 and core in ("int", "long"):
            return INT32
        return et
    return None


def integer_promote(t: EssentialType) -> EssentialType:
    """C99 6.3.1.1 整型提升。"""
    if t.rank < RANK_32:
        return INT32          # 32 位 int 可表示 8/16 位全部取值
    return t


def usual_arith(t1: EssentialType, t2: EssentialType) -> EssentialType:
    """C99 6.3.1.8 常规算术转换。"""
    a, b = integer_promote(t1), integer_promote(t2)
    if a == b:
        return a
    if a.signed == b.signed:
        return EssentialType(max(a.rank, b.rank), a.signed)
    unsigned, signed = (a, b) if not a.signed else (b, a)
    if unsigned.rank >= signed.rank:
        return unsigned
    return signed             # 有符号高秩可表示无符号低秩全部取值


_LITERAL_RE = re.compile(r"^(-?)0[xX]([0-9a-fA-F]+)([uUlL]*)$|^(-?)(\d+)([uUlL]*)$")


def literal_type(text: str) -> Optional[EssentialType]:
    """字面量基本类型：能表示该值的最小类型（u/U 后缀 → 无符号）。"""
    m = _LITERAL_RE.match(text.strip())
    if not m:
        return None
    sign = bool(m.group(1) or m.group(4))
    body = m.group(2) or m.group(5)
    suffix = (m.group(3) or m.group(6) or "")
    value = int(body, 16) if m.group(2) else int(body, 10)
    if sign:
        value = -value
    forced_unsigned = "u" in suffix.lower()
    if forced_unsigned:
        # 无符号：取能表示该值的最小无符号类型
        for et in (UINT8, UINT16, UINT32, UINT64):
            _, hi = et.bounds()
            if 0 <= value <= hi:
                return et
        return UINT64
    # 有符号：最小有符号类型
    for et in (INT8, INT16, INT32, INT64):
        lo, hi = et.bounds()
        if lo <= value <= hi:
            return et
    return INT64


# ---------------------------------------------------------------------------
# 声明扫描：文件级类型表（全局 + 函数内局部）
# ---------------------------------------------------------------------------

_DECL_RE = re.compile(
    r"(?:^|[;{}]\s*|\*\s*)"
    r"(?:(?:static|const|volatile|register|extern)\s+)*"
    r"(?P<type>(?:(?:unsigned|signed)\s+)?"
    r"(?:void|char|short(?:\s+int)?|int|long(?:\s+long)?(?:\s+int)?|float|double|_Bool"
    r"|u?int(?:8|16|32|64)_t|[uUsS](?:8|16|32)(?:_t)?|BOOL|UINT(?:8|16|32)|INT(?:8|16|32)"
    r"|[A-Za-z_]\w*_t)"
    r")\s*(?P<ptrs>\*+\s*)?"
    r"(?P<name>[A-Za-z_]\w*)"
    r"(?=\s*(=|;|,|\[))"
)


def build_type_table(lex, func_lines: set[int],
                     functions=None) -> dict[str, EssentialType]:
    """从净化行扫描声明，返回 变量名 → 基本类型。

    函数参数类型由 cstruct 解析结果（functions）合并；
    局部声明（函数行区间内）覆盖同名全局；指针/数组/浮点声明跳过
    （整型规则不适用）。
    """
    table: dict[str, EssentialType] = {}
    for func in (functions or []):
        for pname, ptype in zip(func.params, func.param_types):
            et = resolve_type(ptype)
            if et is not None:
                table.setdefault(pname, et)
    for idx, line in enumerate(lex.clean_lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        is_local = idx in func_lines
        for m in _DECL_RE.finditer(text):
            et = resolve_type(m.group("type"))
            if et is None or m.group("ptrs"):
                continue
            if m.group("type").strip() in ("void", "float", "double", "_Bool"):
                continue
            if is_local:
                table[m.group("name")] = et       # 局部覆盖全局
            else:
                table.setdefault(m.group("name"), et)
    return table
