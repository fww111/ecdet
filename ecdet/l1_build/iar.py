"""IAR EWARM 工程解析器 —— .ewp（XML）→ 编译要素。

IAR 工程结构（跨版本容错）：
  configuration > settings > ICCARM：
    CCDefines/name*            宏定义
    CCIncludePath2/state*      包含路径
  group > file > name          源文件（相对工程目录路径）
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IarProject:
    configuration: str = ""
    target_hint: str = ""
    source_files: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    defines: list[str] = field(default_factory=list)


def parse_ewp(path: str | Path) -> IarProject:
    root = ET.parse(str(path)).getroot()
    proj = IarProject()

    conf = root.find(".//configuration")
    if conf is not None:
        proj.configuration = (conf.get("name") or "").strip()

    # IAR 命名空间处理：部分版本带 xmlns，直接按 localname 匹配
    for el in root.iter():
        ln = el.tag.split("}")[-1]
        if ln == "CCDefines":
            for d in el:
                if d.tag.split("}")[-1] == "name" and (d.text or "").strip():
                    proj.defines.append(d.text.strip())
        elif ln == "CCIncludePath2":
            for s in el:
                if s.tag.split("}")[-1] == "state" and (s.text or "").strip():
                    proj.include_paths.append(s.text.strip())
        elif ln == "OGChipSelectEditMenu":   # 芯片型号（如 STM32F407VG）
            for s in el:
                state = (s.text or "").strip()
                if s.tag.split("}")[-1] == "state" and state and not proj.target_hint:
                    proj.target_hint = state.split()[0]
    if not proj.target_hint:
        proj.target_hint = proj.configuration

    # 源文件：group/file/name（.c 结尾）
    for el in root.iter():
        if el.tag.split("}")[-1] == "file":
            for child in el:
                if child.tag.split("}")[-1] == "name":
                    name = (child.text or "").strip()
                    if name.lower().endswith(".c"):
                        proj.source_files.append(name.replace("\\", "/"))
    return proj
