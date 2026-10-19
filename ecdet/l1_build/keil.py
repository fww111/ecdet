"""Keil uVision 工程解析器 —— .uvprojx（XML）→ 编译要素。

提取：源文件列表、包含路径（分号分隔）、宏定义（逗号分隔）、
目标芯片提示。翻译为 clang 交叉命令行由 reconstructor 完成。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class KeilProject:
    target_name: str = ""
    device_hint: str = ""
    target_hint: str = ""            # 综合芯片提示（用于报告与 L2 语义标注）
    source_files: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    defines: list[str] = field(default_factory=list)


def parse_uvprojx(path: str | Path) -> KeilProject:
    """解析 .uvprojx。返回 KeilProject；结构异常时抛出异常由调用方降级。"""
    root = ET.parse(str(path)).getroot()
    proj = KeilProject()

    target = root.find(".//Target")
    if target is not None:
        tn = target.find("./TargetName")
        proj.target_name = (tn.text or "").strip() if tn is not None else ""
        device = root.find(".//Device")
        if device is not None and device.text:
            proj.device_hint = device.text.strip()
    proj.target_hint = proj.device_hint or proj.target_name

    # C 编译器设置：Cads/VariousControls/{IncludePath, Define}
    vc = root.find(".//Cads/VariousControls")
    if vc is not None:
        inc = vc.find("./IncludePath")
        if inc is not None and inc.text:
            proj.include_paths = [p.strip() for p in inc.text.split(";") if p.strip()]
        df = vc.find("./Define")
        if df is not None and df.text:
            proj.defines = [d.strip() for d in df.text.split(",") if d.strip()]

    # 文件列表：Files/File/{FileName, FileType, FilePath}
    for f in root.iter("File"):
        ftype = f.find("./FileType")
        name = f.find("./FileName")
        fpath = f.find("./FilePath")
        if ftype is None or name is None or fpath is None:
            continue
        if (ftype.text or "").strip() == "1":     # 1 = C 源文件
            proj.source_files.append((fpath.text or "").strip())
    return proj
