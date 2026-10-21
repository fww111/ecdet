"""运行时监控子系统（方案 3.3.6，对应 P7）。

"静态怀疑、动态裁决"的执行者：静态通道的 Suspected 级结论转为定向
监测探针，仿真/宿主执行中命中即回填 PoC 证据并升级为 Detected。
MVP 监测探针两类：越界类（ARR30/STR31/MMIO 告警函数）定向激励、
看门狗时序监测（执行超时即事件）；LLM 不变量归纳接口预留（候选须经
静态核验后启用，见 3.3.6 之模型驱动来源）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Provenance
from ecdet.l3_analysis.builtin_rules.checks import FileFacts
from ecdet.l3_analysis.dynamic.engine import DynamicEngine, DynamicFinding

# 可动态裁决的规则族：告警所在函数转为定向探针目标
_PROBE_RULES = {
    "CERT C ARR30-C", "CERT C STR31-C", "ECDET-CWE-242", "ECDET-CWE-197",
    "ECDET-CWE-1284", "ECDET-MMIO-ACCESS", "CERT C FIO30-C",
}


@dataclass
class MonitorResult:
    """监控事件流与裁决结果（方案 3.3.6 输出）。"""

    events: list[DynamicFinding] = field(default_factory=list)
    upgraded: list[Alert] = field(default_factory=list)     # Suspected → Detected
    probed_functions: list[str] = field(default_factory=list)
    skipped_reason: str = ""


def probes_from_alerts(alerts: list[Alert],
                       facts: list[FileFacts]) -> list[str]:
    """从 Suspected 级告警提取定向探针目标函数名。

    仅取可动态裁决规则族（_PROBE_RULES）且告警位于函数区间内的条目。
    """
    targets: list[str] = []
    for a in alerts:
        if a.provenance != Provenance.SUSPECTED and a.rule_id not in _PROBE_RULES:
            continue
        if a.rule_id not in _PROBE_RULES:
            continue
        for f in facts:
            if f.path.replace("\\", "/") != a.location.path.replace("\\", "/"):
                continue
            for func in f.functions:
                if func.def_line <= a.location.line <= func.body_close_line:
                    targets.append(func.name)
    return sorted(set(targets))


class RuntimeMonitor:
    """运行时监控：定向探针 → 仿真/宿主执行 → 事件流 → 回填升级。"""

    def __init__(self, engine: DynamicEngine | None = None):
        self.engine = engine or DynamicEngine()

    def run(self, root: Path, facts: list[FileFacts],
            suspected: list[Alert]) -> MonitorResult:
        if not self.engine.available:
            return MonitorResult(skipped_reason="动态载体不可用（无 gcc）")
        probes = probes_from_alerts(suspected, facts)
        if not probes:
            return MonitorResult(skipped_reason="无可动态裁决的 Suspected 告警")

        events = self.engine.run(root, facts, probe_names=set(probes))
        result = MonitorResult(events=events, probed_functions=probes)

        # 裁决回填：探针函数命中 → 同函数的 Suspected 告警升级 Detected
        hit_funcs = {e.func_name for e in events}
        for a in suspected:
            a_func = _alert_function(a, facts)
            if a_func in hit_funcs and a.provenance == Provenance.SUSPECTED:
                poc = next(e for e in events if e.func_name == a_func)
                a.provenance = Provenance.DETECTED
                a.evidence.append(Evidence(
                    kind="note",
                    message=(f"运行时监控升级：定向激励 seed={poc.replay_seed} "
                             f"复现同类崩溃（{poc.detail}）")))
                result.upgraded.append(a)
        return result


def _alert_function(alert: Alert, facts: list[FileFacts]) -> str:
    for f in facts:
        if f.path.replace("\\", "/") != alert.location.path.replace("\\", "/"):
            continue
        for func in f.functions:
            if func.def_line <= alert.location.line <= func.body_close_line:
                return func.name
    return ""
