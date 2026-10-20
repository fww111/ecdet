"""聚合引擎 —— 跨引擎去重、CWE/MISRA/GJB 三口径映射、可证明性统计。

技术方案 3.3.7：
  - 聚合：同位置同类别合并，保留各引擎独立结论；
  - 映射：每条告警同时携带规范（MISRA/GJB）与漏洞（CWE）双重口径；
  - 可证明性分级：Proven / Detected / Suspected；
  - 合规记录：按 MISRA Compliance 框架输出每规则状态。
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Provenance, RuleMeta, Severity

_MAP_PATH = Path(__file__).parent.parent / "rules_db" / "cwe_map.json"
_GJB_MAP_PATH = Path(__file__).parent.parent / "rules_db" / "gjb_map.json"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"mappings": []}


def _load_cwe_map() -> dict:
    return _load_json(_MAP_PATH)


def _load_gjb_map() -> dict[str, str]:
    """rule_id → GJB 主题（主题级映射，编号待授权文本核实）。"""
    data = _load_json(_GJB_MAP_PATH)
    return {m["rule_id"]: m.get("gjb_topic", "")
            for m in data.get("mappings", [])}


@dataclass
class AggregatedAlert:
    """聚合后的告警簇：同文件+行+规则（或经映射等价的规则）合并。"""

    key: str
    primary: Alert
    engines: list[str] = field(default_factory=list)
    related_rules: list[str] = field(default_factory=list)   # 映射等价规则
    cwes: list[str] = field(default_factory=list)
    provenance: Provenance = Provenance.SUSPECTED

    @property
    def max_severity(self) -> Severity:
        order = {Severity.NOTE: 0, Severity.WARNING: 1, Severity.ERROR: 2}
        best = self.primary.severity
        for a in self._all_alerts:
            if order[a.severity] > order[best]:
                best = a.severity
        return best

    _all_alerts: list[Alert] = field(default_factory=list)


@dataclass
class AggregationResult:
    clusters: list[AggregatedAlert] = field(default_factory=list)
    rule_metas: list[RuleMeta] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.clusters)


def _equivalence_classes() -> dict[str, str]:
    """从映射表构造 规则ID → 等价类代表 的归并关系。"""
    rep: dict[str, str] = {}
    data = _load_cwe_map()
    for m in data.get("mappings", []):
        group = [r for r in (m.get("misra", []) + m.get("cert", []))
                 if not r.endswith(".x")]
        group.append(m["cwe"])
        anchor = group[0]
        for r in group:
            rep.setdefault(r, anchor)
    return rep


def aggregate(alerts: list[Alert], rule_metas: list[RuleMeta]) -> AggregationResult:
    """跨引擎聚合主入口。"""
    equiv = _equivalence_classes()
    meta_index = {r.rule_id: r for r in rule_metas}

    def cluster_key(a: Alert) -> tuple:
        rule_anchor = equiv.get(a.rule_id, a.rule_id)
        return (a.location.path.replace("\\", "/"), a.location.line, rule_anchor)

    groups: dict[tuple, list[Alert]] = defaultdict(list)
    for a in alerts:
        a.ensure_fingerprint()
        groups[cluster_key(a)].append(a)

    clusters: list[AggregatedAlert] = []
    for key, items in groups.items():
        # 主告警取最高严重级；同位置保留全部引擎结论
        sev_order = {Severity.NOTE: 0, Severity.WARNING: 1, Severity.ERROR: 2}
        items_sorted = sorted(items, key=lambda x: sev_order[x.severity], reverse=True)
        primary = items_sorted[0]
        cwes = sorted({a.cwe for a in items if a.cwe})
        if primary.cwe and primary.cwe not in cwes:
            cwes.insert(0, primary.cwe)
        # 可证明性取簇内最强
        prov_order = {Provenance.SUSPECTED: 0, Provenance.DETECTED: 1, Provenance.PROVEN: 2}
        best_prov = max((a.provenance for a in items),
                        key=lambda p: prov_order[p])
        c = AggregatedAlert(
            key=f"{key[0]}:{key[1]}:{key[2]}",
            primary=primary,
            engines=sorted({a.engine for a in items}),
            related_rules=sorted({a.rule_id for a in items}),
            cwes=cwes,
            provenance=best_prov,
        )
        c._all_alerts = items
        clusters.append(c)

    clusters.sort(key=lambda c: (
        {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}[c.max_severity],
        c.primary.location.path, c.primary.location.line,
    ))

    stats = _build_stats(clusters, meta_index)
    return AggregationResult(clusters=clusters, rule_metas=rule_metas, stats=stats)


def _build_stats(clusters: list[AggregatedAlert], meta_index: dict[str, RuleMeta]) -> dict:
    by_sev = Counter(c.max_severity.value for c in clusters)
    by_engine = Counter(e for c in clusters for e in c.engines)
    by_rule = Counter(c.primary.rule_id for c in clusters)
    by_prov = Counter(c.provenance.value for c in clusters)
    by_cwe = Counter(cwe for c in clusters for cwe in c.cwes)
    return {
        "total": len(clusters),
        "error": by_sev.get("error", 0),
        "warning": by_sev.get("warning", 0),
        "note": by_sev.get("note", 0),
        "by_engine": dict(by_engine),
        "by_rule": dict(by_rule),
        "by_provenance": dict(by_prov),
        "by_cwe": dict(by_cwe),
        "provenance_ratio": (by_prov.get("proven", 0) / len(clusters)) if clusters else 0.0,
    }


@dataclass
class ComplianceRecord:
    """MISRA Compliance 框架的单规则合规记录。"""

    rule_id: str
    category: str
    title: str
    status: str                 # compliant（零违例）/ deviation（存在偏离）/ not-applicable
    violation_count: int = 0
    gjb_topic: str = ""         # GJB 8114 主题级映射（编号待授权文本核实）


def build_compliance_records(result: AggregationResult) -> list[ComplianceRecord]:
    """按规则生成合规记录（方案 3.3.7：每规则合规/偏离与证据）。"""
    counts = Counter(c.primary.rule_id for c in result.clusters)
    gjb = _load_gjb_map()
    records: list[ComplianceRecord] = []
    for meta in result.rule_metas:
        n = counts.get(meta.rule_id, 0)
        records.append(
            ComplianceRecord(
                rule_id=meta.rule_id,
                category=meta.category,
                title=meta.title_zh,
                status="compliant" if n == 0 else "deviation",
                violation_count=n,
                gjb_topic=gjb.get(meta.rule_id, ""),
            )
        )
    records.sort(key=lambda r: (-r.violation_count, r.rule_id))
    return records
