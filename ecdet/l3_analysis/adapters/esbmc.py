"""ESBMC 适配器 —— 有界模型检查（BMC），Proven 级结论来源（方案 3.3.4）。

k-归纳/界内完备：验证性质在界内成立 → PROVEN；
反例（VERIFICATION FAILED）→ PROVEN error。
无 harness 的直接文件检查只能覆盖类型/越界浅层性质，MVP 即此口径。
"""

from __future__ import annotations

import re

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.engine import AnalysisTarget, ExternalEngineAdapter

_VERDICT_RE = re.compile(r"(VERIFICATION\s+(?:SUCCESSFUL|FAILED))" r"|^\s*\[\w+\] .*FAILED", re.M)
_PROPERTY_RE = re.compile(r"^\s*\[\w+(?:\.\w+)*\]\s+(.*(?:FAILED|SUCCEEDED))\s*$", re.M)


def parse_esbmc_output(text: str, src_name: str = "") -> list[Alert]:
    """解析 ESBMC 输出。VERIFICATION FAILED → Proven error；SUCCESSFUL 不产出。"""
    out: list[Alert] = []
    if re.search(r"VERIFICATION\s+FAILED", text):
        props = _PROPERTY_RE.findall(text)
        detail = "；".join(p.strip() for p in props[:3]) or "ESBMC 报告性质违反"
        out.append(Alert(
            rule_id="ESBMC-CHECK",
            engine="esbmc",
            severity=Severity.ERROR,
            message=f"有界模型检查发现性质违反（界内完备证明）：{detail}",
            location=Location(path=src_name, line=1),
            provenance=Provenance.PROVEN,
            evidence=[Evidence(kind="api", message="ESBMC VERIFICATION FAILED")],
        ))
    return out


class ESBMCAdapter(ExternalEngineAdapter):
    """ESBMC 引擎适配器：检测到二进制即接入，逐翻译单元做界内验证。"""

    name = "esbmc"
    binary = "esbmc"

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        if not self.available():
            return []
        out: list[Alert] = []
        for rel in target.files:
            if rel.suffix.lower() != ".c":
                continue
            src = (target.root / rel).resolve()
            out.extend(self._check_file(src))
        return out

    def _check_file(self, src, timeout: int = 120) -> list[Alert]:
        output = self._run_cmd(
            ["esbmc", str(src), "--unwind", "5", "--no-pointer-check", "--quiet"],
            timeout=timeout)
        return parse_esbmc_output(output, src.name)
