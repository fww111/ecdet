"""统一告警数据模型 —— L2 层核心。

所有引擎（自研规则引擎、cppcheck、clang-tidy、后续抽象解释/符号执行）
的输出都规约到这里的 Alert 结构，再由 L5 层聚合去重。
设计依据：技术方案 3.2 节“将 Clang AST/IR、调用图与 SARIF 告警统一为单一数据模型”。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    """告警严重级别，对齐 SARIF level 并映射 GB/T 30279-2020 分级口径。"""

    ERROR = "error"        # 超危/高危：确定缺陷或安全漏洞
    WARNING = "warning"    # 中危：很可能为缺陷，需评审
    NOTE = "note"          # 低危/提示：规范偏离、可维护性问题

    def to_cn_level(self) -> str:
        """映射 GB/T 30279-2020 漏洞分级（超危/高危/中危/低危）。"""
        return {"error": "高危", "warning": "中危", "note": "低危"}[self.value]


class Provenance(str, Enum):
    """可证明性分级（技术方案 3.3.7）：

    PROVEN    —— 由健全引擎（抽象解释/模型检查）数学证明的结论，阶段二引入；
    DETECTED  —— 引擎检出且经确定性证据核对（如行号/文本回链）确认；
    SUSPECTED —— 疑似告警，需 LLM 研判或人工评审。
    """

    PROVEN = "proven"
    DETECTED = "detected"
    SUSPECTED = "suspected"


@dataclass
class Location:
    """源码位置。路径统一为 POSIX 风格相对路径，保证跨平台指纹一致。"""

    path: str
    line: int = 1
    col: int = 1
    end_line: Optional[int] = None
    end_col: Optional[int] = None

    def rel(self, base: str | Path) -> "Location":
        """以 base 为根转换为相对路径（能转换时）。"""
        try:
            p = Path(self.path).resolve()
            b = Path(base).resolve()
            return Location(
                path=p.relative_to(b).as_posix(),
                line=self.line,
                col=self.col,
                end_line=self.end_line,
                end_col=self.end_col,
            )
        except (ValueError, OSError):
            return self


@dataclass
class Evidence:
    """证据链节点：每条告警必须携带可回溯证据（技术方案 3.3.5/3.3.7）。"""

    kind: str                 # code / type / macro / api / note 等
    message: str              # 证据说明（中文）
    location: Optional[Location] = None
    snippet: str = ""         # 相关源码片段（已去注释空白）


@dataclass
class Alert:
    """统一告警对象。"""

    rule_id: str                              # 如 "MISRA C:2012 15.5"、"CERT C MSC30-C"
    engine: str                               # builtin / cppcheck / clang-tidy / ...
    severity: Severity
    message: str
    location: Location
    cwe: Optional[str] = None                 # 如 "CWE-120"
    provenance: Provenance = Provenance.SUSPECTED
    evidence: list[Evidence] = field(default_factory=list)
    fingerprint: str = ""                     # 聚合去重主键，空则按内容计算

    def compute_fingerprint(self) -> str:
        raw = json.dumps(
            {
                "rule": self.rule_id,
                "path": self.location.path,
                "line": self.location.line,
                "msg": self.message,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return self.fingerprint

    def ensure_fingerprint(self) -> str:
        return self.fingerprint or self.compute_fingerprint()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["provenance"] = self.provenance.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        loc = d["location"]
        evs = [
            Evidence(
                kind=e.get("kind", "note"),
                message=e.get("message", ""),
                location=Location(**e["location"]) if e.get("location") else None,
                snippet=e.get("snippet", ""),
            )
            for e in d.get("evidence", [])
        ]
        return cls(
            rule_id=d["rule_id"],
            engine=d["engine"],
            severity=Severity(d.get("severity", "warning")),
            message=d["message"],
            location=Location(**loc),
            cwe=d.get("cwe"),
            provenance=Provenance(d.get("provenance", "suspected")),
            evidence=evs,
            fingerprint=d.get("fingerprint", ""),
        )


@dataclass
class RuleMeta:
    """规则元数据：驱动规则库分层启停与合规报告生成（技术方案 3.3.3）。"""

    rule_id: str                  # "MISRA C:2012 15.5"
    standard: str                 # MISRA C:2012 / CERT C / GJB 8114-2013
    category: str                 # Mandatory / Required / Advisory
    decidability: str             # syntactic / type-based / dataflow / manual
    title_zh: str                 # 中文规则描述
    cwes: list[str] = field(default_factory=list)
    enabled_by_default: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RuleMeta":
        return cls(
            rule_id=d["rule_id"],
            standard=d["standard"],
            category=d.get("category", "Required"),
            decidability=d.get("decidability", "syntactic"),
            title_zh=d.get("title_zh", ""),
            cwes=d.get("cwes", []),
            enabled_by_default=d.get("enabled_by_default", True),
        )
