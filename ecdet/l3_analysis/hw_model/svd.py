"""CMSIS-SVD 芯片描述解析器 —— 寄存器语义库（方案 3.3.2）。

SVD（XML，覆盖主流 Cortex-M 厂商）解析为"地址 → 外设/寄存器/访问权限"
映射，注入分析器作为 MMIO 对象模型。只读寄存器被写、只写寄存器被读
等缺陷由此从不可判定变为可检查。
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

_LOG = logging.getLogger(__name__)


class SVDParseError(ValueError):
    """SVD input or selected parser cannot produce a reliable register map."""


@dataclass(frozen=True)
class RegisterField:
    name: str
    bit_offset: int
    bit_width: int
    access: str = "read-write"
    modified_write_values: str = ""

    @property
    def readable(self) -> bool:
        return normalize_access(self.access)[0]

    @property
    def writable(self) -> bool:
        return normalize_access(self.access)[1]

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
    fields: tuple[RegisterField, ...] = ()
    modified_write_values: str = ""

    @property
    def readable(self) -> bool:
        return normalize_access(self.access)[0]

    @property
    def writable(self) -> bool:
        return normalize_access(self.access)[1]

    @property
    def one_to_clear_mask(self) -> int:
        mask = ((1 << self.size) - 1
                if self.writable and self.modified_write_values == "oneToClear" else 0)
        for item in self.fields:
            bits = ((1 << item.bit_width) - 1) << item.bit_offset
            if item.writable and item.modified_write_values == "oneToClear":
                mask |= bits
            else:
                mask &= ~bits
        return mask


@dataclass
class RegisterMap:
    device: str = ""
    by_peripheral: dict[str, dict[str, Register]] = None  # type: ignore[assignment]
    periph_by_base: dict[int, str] = None                 # type: ignore[assignment]
    parser_backend: str = "builtin"

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


def _text(el: ET.Element, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None else default


def _validate_register(reg: Register) -> None:
    if reg.size <= 0 or reg.size > 4096 or reg.abs_addr < 0:
        raise SVDParseError(f"Invalid SVD register size/address: {reg.peripheral}.{reg.name}")
    used = 0
    for item in reg.fields:
        if item.bit_offset < 0 or item.bit_width <= 0 or item.bit_offset + item.bit_width > reg.size:
            raise SVDParseError(f"Invalid SVD field range: {reg.name}.{item.name}")
        mask = ((1 << item.bit_width) - 1) << item.bit_offset
        if used & mask:
            raise SVDParseError(f"Overlapping SVD fields: {reg.name}.{item.name}")
        used |= mask


def _insert(dev: RegisterMap, reg: Register) -> None:
    _validate_register(reg)
    regs = dev.by_peripheral[reg.peripheral]
    if reg.name in regs:
        raise SVDParseError(f"Duplicate SVD register: {reg.peripheral}.{reg.name}")
    regs[reg.name] = reg


def _field_range(el: ET.Element) -> tuple[int, int]:
    if el.find("bitOffset") is not None:
        return int(_text(el, "bitOffset"), 0), int(_text(el, "bitWidth"), 0)
    if el.find("lsb") is not None:
        low, high = int(_text(el, "lsb"), 0), int(_text(el, "msb"), 0)
    else:
        match = re.fullmatch(r"\[(\d+):(\d+)\]", _text(el, "bitRange"))
        if not match:
            raise SVDParseError("SVD field requires bitOffset/bitWidth, lsb/msb or bitRange")
        high, low = map(int, match.groups())
    return low, high - low + 1


def _validate_xml(root: ET.Element) -> None:
    """Validate values the third-party parser otherwise discards or defaults."""
    identities: dict[tuple[str, str], ET.Element] = {}
    paths: dict[ET.Element, str] = {}
    named_tags = {"peripheral", "cluster", "register", "field"}
    write_values = {"oneToClear", "oneToSet", "oneToToggle", "zeroToClear",
                    "zeroToSet", "zeroToToggle", "clear", "set", "modify"}

    def visit(node: ET.Element, prefix: str = "") -> None:
        if node.tag in named_tags:
            name = _text(node, "name")
            if not name:
                raise SVDParseError(f"SVD {node.tag} requires a name")
            prefix = f"{prefix}.{name}" if prefix else name
            key = (node.tag, prefix.upper())
            if key in identities:
                raise SVDParseError(f"Duplicate SVD {node.tag}: {prefix}")
            identities[key] = node
            paths[node] = prefix.upper()
        for child in node:
            value = (child.text or "").strip()
            if child.tag == "access" and value not in _ACCESS_TABLE:
                raise SVDParseError(f"Invalid SVD access: {value}")
            if child.tag == "modifiedWriteValues" and value not in write_values:
                raise SVDParseError(f"Invalid SVD modifiedWriteValues: {value}")
            if child.tag in {"baseAddress", "addressOffset", "size", "dim", "dimIncrement"}:
                try:
                    number = int(value, 16) if value.lower().startswith('0x') else int(value, 10)
                except ValueError as exc:
                    raise SVDParseError(f"Invalid SVD {child.tag}: {value}") from exc
                minimum = 1 if child.tag in {"size", "dim", "dimIncrement"} else 0
                if number < minimum:
                    raise SVDParseError(f"Invalid SVD {child.tag}: {value}")
            visit(child, prefix)

    visit(root)
    edges: dict[ET.Element, ET.Element] = {}
    for node, path in paths.items():
        reference = node.get("derivedFrom")
        if reference is None:
            continue
        reference = reference.upper()
        prefix = path.split('.')[:-1]
        candidates = ['.'.join(prefix[:length] + [reference])
                      for length in range(len(prefix), -1, -1)]
        source = next((identities[(node.tag, candidate)] for candidate in candidates
                       if (node.tag, candidate) in identities), None)
        if source is None:
            raise SVDParseError(f"Unresolved SVD derivedFrom: {reference}")
        edges[node] = source
    for node in edges:
        chain = set()
        current = node
        while current in edges:
            if current in chain:
                raise SVDParseError("Cyclic SVD derivedFrom")
            chain.add(current)
            current = edges[current]


def _parse_builtin(root: ET.Element) -> RegisterMap:
    # Refuse complex input rather than emit plausible but wrong addresses.
    if any(el.tag in {"cluster", "dim"} or "derivedFrom" in el.attrib for el in root.iter()):
        raise SVDParseError("SVD arrays, clusters and derivedFrom require ecdet[hardware]")
    dev = RegisterMap(device=_text(root, "name"), parser_backend="builtin")
    for periph in root.findall("./peripherals/peripheral"):
        pname = _text(periph, "name").upper()
        base = int(_text(periph, "baseAddress"), 0)
        if not pname:
            raise SVDParseError("SVD peripheral has no name")
        dev.periph_by_base[base] = pname
        dev.by_peripheral[pname] = {}
        access = _text(periph, "access", _text(root, "access", "read-write"))
        size = _text(periph, "size", _text(root, "size", "32"))
        for node in periph.findall("./registers/register"):
            raccess = _text(node, "access", access)
            modified = _text(node, "modifiedWriteValues")
            fields = []
            for item in node.findall("./fields/field"):
                offset, width = _field_range(item)
                fields.append(RegisterField(_text(item, "name").upper(), offset, width,
                                            _text(item, "access", raccess),
                                            _text(item, "modifiedWriteValues", modified)))
            _insert(dev, Register(_text(node, "name").upper(), pname,
                                  base + int(_text(node, "addressOffset"), 0),
                                  int(_text(node, "size", size), 0), raccess,
                                  tuple(fields), modified))
    return dev


def _enum_value(value, default: str = "") -> str:
    return value.value if value is not None else default


def _parse_cmsis(root: ET.Element, parser) -> RegisterMap:
    from lxml import etree
    tree = etree.ElementTree(etree.fromstring(ET.tostring(root, encoding="utf-8")))
    device = parser(tree).get_device()
    dev = RegisterMap(device=device.name or "", parser_backend="cmsis-svd")
    for peripheral in device.get_peripherals():
        pname = peripheral.name.upper()
        dev.periph_by_base[peripheral.base_address] = pname
        dev.by_peripheral[pname] = {}
        for node in peripheral.get_registers():
            access = _enum_value(node.access, "read-write")
            modified = _enum_value(node.modified_write_values)
            fields = tuple(RegisterField(item.name.upper(), item.bit_offset, item.bit_width,
                                         _enum_value(item.access, access),
                                         _enum_value(item.modified_write_values, modified))
                           for item in node.get_fields())
            _insert(dev, Register(node.name.upper(), pname,
                                  peripheral.base_address + node.address_offset,
                                  node.size if node.size is not None else 32, access, fields, modified))
    return dev


def parse_svd(path: str | Path, *, backend: str = "auto") -> RegisterMap:
    """Use cmsis-svd when installed; retain explicit basic parsing without extras.

    backend may be auto, builtin or cmsis-svd. Invalid input never falls back
    from the enhanced parser to a partial basic result.
    """
    if backend not in {"auto", "builtin", "cmsis-svd"}:
        raise ValueError(f"Unknown SVD backend: {backend}")
    path = Path(path)
    try:
        root = ET.parse(path).getroot()
        # Normalize optional XML namespaces for the basic parser and validation.
        for el in root.iter():
            el.tag = el.tag.rsplit("}", 1)[-1]
        if root.tag != "device" or not _text(root, "name") or root.find("peripherals") is None:
            raise SVDParseError("SVD requires a named device and peripherals")
        _validate_xml(root)
        if backend == "builtin":
            return _parse_builtin(root)
        try:
            from cmsis_svd.parser import SVDParser
        except ImportError as exc:
            if backend == "cmsis-svd":
                raise SVDParseError("Install ecdet[hardware] to use the cmsis-svd backend") from exc
            _LOG.warning("SVD basic parser active; install ecdet[hardware] for arrays, clusters and inheritance")
            return _parse_builtin(root)
        return _parse_cmsis(root, SVDParser)
    except SVDParseError:
        raise
    except (ET.ParseError, OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise SVDParseError(f"Cannot parse SVD {path.name}: {exc}") from exc
