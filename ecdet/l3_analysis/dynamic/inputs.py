"""激励输入建模（方案 3.3.5 之 MMIO 感知激励建模）。

以 SVD 寄存器语义库转译输入域语义分片：参数名命中寄存器名时按位宽
约束取值域，使变异感知"该参数是 UART 波特率寄存器"而非盲改；
纯参数化目标退化为类型宽度 + 特殊值表（0/边界/回绕点）的确定性采样。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ecdet.l3_analysis.builtin_rules.cstruct import FunctionInfo

# 特殊值表：确定性命中除零/回绕/边界（宽度内截断）
_INT_SPECIALS = [0, 1, -1, 2, 3, 127, 128, 255, 256, 32767, 32768, 65535,
                 65536, 2147483647, -2147483648, 100, 101]

_WIDTH_RE = re.compile(r"(8|16|32|64)")


@dataclass
class ParamSpec:
    name: str
    ctype: str                          # 规范化类型文本
    is_pointer: bool = False
    bits: int = 32                      # 整型位宽
    mmio_reg: str = ""                  # 命中的 SVD 寄存器名（空=无）


@dataclass
class InputModel:
    func: FunctionInfo
    params: list[ParamSpec] = field(default_factory=list)
    specials: list[int] = field(default_factory=lambda: list(_INT_SPECIALS))

    @property
    def n_specials(self) -> int:
        return len(self.specials)


def _norm_type(raw: str) -> tuple[str, bool, int]:
    """参数类型规范化 → (类型文本, 是否指针, 位宽)。"""
    t = " ".join(raw.replace("const", " ").split())
    is_ptr = "*" in t
    bits = 32
    m = _WIDTH_RE.search(t)
    if m:
        bits = int(m.group(1))
    elif "char" in t:
        bits = 8
    elif "short" in t:
        bits = 16
    elif "long long" in t:
        bits = 64
    return t, is_ptr, bits


def build_input_model(func: FunctionInfo, regmap=None) -> InputModel:
    """从函数签名（cstruct 解析的参数类型）与 SVD 寄存器库构建输入模型。

    regmap 提供寄存器名→位宽映射（3.3.2 语义库复用，"一次建模、静动两用"）；
    参数名命中寄存器名时按寄存器位宽收窄取值域。
    """
    spec_names: dict[str, int] = {}
    if regmap is not None:
        for regs in regmap.by_peripheral.values():
            for r in regs.values():
                spec_names[r.name.lower()] = r.size

    params: list[ParamSpec] = []
    for i, pname in enumerate(func.params):
        raw = func.param_types[i] if i < len(func.param_types) else "int"
        ctype, is_ptr, bits = _norm_type(raw)
        ps = ParamSpec(name=pname, ctype=ctype or "int",
                       is_pointer=is_ptr, bits=bits)
        reg = spec_names.get(pname.lower())
        if reg:
            ps.mmio_reg = pname
            ps.bits = min(ps.bits, reg)
        params.append(ps)
    return InputModel(func=func, params=params)


def param_value(spec: ParamSpec, seed: int) -> str:
    """某参数在第 seed 个激励下的 C 实参表达式。

    seed < specials 数：确定性扫特殊值表（按参数名散列错位，保证组合覆盖）；
    否则乘法散列均匀采样值域（位宽约束，MMIO 寄存器参数按寄存器位宽）。
    指针参数生成栈缓冲区引用（由 harness 模板预置）。
    """
    if spec.is_pointer:
        return f"ecdet_buf_{spec.name}"
    signed = not any(u in spec.ctype for u in
                     ("unsigned", "u8", "u16", "u32", "u64", "UINT", "size_t"))
    if seed < len(_INT_SPECIALS):
        v = _INT_SPECIALS[(seed * 7 + len(spec.name)) % len(_INT_SPECIALS)]
    else:
        v = (seed * 2654435761) % (1 << spec.bits)
        if signed and (seed % 2):
            v = -v
    if spec.bits < 32:
        lo = -(1 << (spec.bits - 1)) if signed else 0
        hi = (1 << (spec.bits - 1)) - 1 if signed else (1 << spec.bits) - 1
        v = max(lo, min(hi, v))
    return str(v)
