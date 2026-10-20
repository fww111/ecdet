"""CMSIS-SVD 芯片描述解析器 —— 寄存器语义库（方案 3.3.2）。

SVD（XML，覆盖主流 Cortex-M 厂商）解析为"地址 → 外设/寄存器/访问权限"
映射，注入分析器作为 MMIO 对象模型。只读寄存器被写、只写寄存器被读
等缺陷由此从不可判定变为可检查。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# SVD access 值 → (可读, 可写)
_ACCESS_TABLE: dict[str, tuple[bool, bool]] = {
    "read-only": (True, False),
    "write-only": (False, True),
    "read-write": (True, True),
    "writeOnce": (False, True),
    "read-writeOnce": (True, True),
}


def normalize_access(text: str | None) -> tuple[bool, bool]:
    return _ACCESS_TABLE.get((text or "").strip(), (True, True))   # 未标注按可读写


@dataclass
class Register:
    name: str                    # 寄存器名（大写规范化）
    peripheral: str              # 所属外设名（大写规范化）
    abs_addr: int                # 绝对地址 = base + offset
    size: int                    # 位宽
    access: str                  # 原始 access 字符串

    @property
    def readable(self) -> bool:
        return normalize_access(self.access)[0]

    @property
    def writable(self) -> bool:
        return normalize_access(self.access)[1]


@dataclass
class RegisterMap:
    device: str = ""
    by_peripheral: dict[str, dict[str, Register]] = None  # type: ignore[assignment]
    periph_by_base: dict[int, str] = None                 # type: ignore[assignment]

    def __post_init__(self):
        if self.by_peripheral is None:
            self.by_peripheral = {}
        if self.periph_by_base is None:
            self.periph_by_base = {}

    def lookup(self, addr: int) -> Register | None:
        """按绝对地址查寄存器：精确匹配优先，退化按 4 字节对齐匹配。"""
        reg = self._exact.get(addr)
        if reg:
            return reg
        return self._exact.get(addr & ~0x3)

    @property
    def _exact(self) -> dict[int, Register]:
        if not hasattr(self, "_exact_cache"):
            cache: dict[int, Register] = {}
            for regs in self.by_peripheral.values():
                for r in regs.values():
                    cache.setdefault(r.abs_addr, r)
            self._exact_cache = cache
        return self._exact_cache

    def resolve(self, peripheral: str, reg: str) -> Register | None:
        """按 外设名.寄存器名 查找（大小写不敏感）。"""
        return self.by_peripheral.get(peripheral.upper(), {}).get(reg.upper())


def parse_svd(path: str | Path) -> RegisterMap:
    """解析 SVD 文件。结构异常时抛出异常，由调用方决定降级。"""
    root = ET.parse(str(path)).getroot()

    def _text(el, tag: str, default: str = "") -> str:
        child = el.find(tag)
        return (child.text or "").strip() if child is not None else default

    dev = RegisterMap(device=_text(root, "name"))

    for periph in root.iter("peripheral"):
        pname = _text(periph, "name").upper()
        base_text = _text(periph, "baseAddress")
        if not pname or not base_text:
            continue
        base = int(base_text, 0)
        periph_access = _text(periph, "access", "read-write")
        dev.periph_by_base[base] = pname
        dev.by_peripheral.setdefault(pname, {})

        for reg in periph.iter("register"):
            rname = _text(reg, "name").upper()
            off_text = _text(reg, "addressOffset")
            if not rname or not off_text:
                continue
            size_text = _text(reg, "size", "32")
            try:
                size = int(size_text, 0)
            except ValueError:
                size = 32
            r = Register(
                name=rname.split("[")[0],           # 数组型寄存器名去掉 [0] 后缀
                peripheral=pname,
                abs_addr=base + int(off_text, 0),
                size=size,
                access=_text(reg, "access", periph_access),
            )
            dev.by_peripheral[pname].setdefault(r.name, r)
    return dev
