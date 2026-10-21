"""SARIF 2.1.0 读写 —— 全系统唯一告警交换格式（技术方案 3.3.7）。

自研引擎与所有外部引擎适配器的输出最终都汇入 SARIF，L5 聚合层只消费 SARIF，
保证“多引擎 → 单一表示”的解耦。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, RuleMeta, Severity

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.NOTE: "note",
}


def build_sarif(alerts: list[Alert], rules: list[RuleMeta], tool_version: str = "0.1.0") -> dict:
    """将统一告警列表构建为 SARIF 2.1.0 文档对象。"""
    rule_index: dict[str, int] = {}
    sarif_rules = []
    for i, r in enumerate(rules):
        rule_index[r.rule_id] = i
        sarif_rules.append(
            {
                "id": r.rule_id,
                "name": r.rule_id.replace(":", "").replace(" ", "_"),
                "shortDescription": {"text": r.title_zh or r.rule_id},
                "properties": {
                    "standard": r.standard,
                    "category": r.category,
                    "decidability": r.decidability,
                    "cwe": r.cwes,
                },
                "defaultConfiguration": {"level": "warning", "enabled": r.enabled_by_default},
            }
        )

    results = []
    for a in alerts:
        loc = a.location
        region = {"startLine": loc.line, "startColumn": loc.col}
        if loc.end_line:
            region["endLine"] = loc.end_line
            if loc.end_col:
                region["endColumn"] = loc.end_col
        fingerprints = a.ensure_fingerprint()
        result = {
            "ruleId": a.rule_id,
            "ruleIndex": rule_index.get(a.rule_id),
            "level": _SEVERITY_TO_LEVEL[a.severity],
            "message": {"text": a.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.path},
                        "region": region,
                    }
                }
            ],
            "partialFingerprints": {"ecdet/v1": fingerprints},
            "properties": {
                "engine": a.engine,
                "cwe": a.cwe,
                "provenance": a.provenance.value,
                "gb_level": a.severity.to_cn_level(),
                **({"triage": a.triage} if a.triage else {}),
            },
        }
        if a.evidence:
            result["properties"]["evidence"] = [
                {
                    "kind": e.kind,
                    "message": e.message,
                    "path": e.location.path if e.location else None,
                    "line": e.location.line if e.location else None,
                    "snippet": e.snippet,
                }
                for e in a.evidence
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ecdet",
                        "version": tool_version,
                        "informationUri": "https://example.invalid/ecdet",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def save_sarif(alerts: list[Alert], rules: list[RuleMeta], out_path: str | Path,
               tool_version: str = "0.1.0") -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(build_sarif(alerts, rules, tool_version), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return out


def load_sarif(path: str | Path) -> tuple[list[Alert], list[RuleMeta]]:
    """读取 SARIF（含外部工具产出），规约为统一模型。"""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    rules_meta: dict[str, RuleMeta] = {}
    alerts: list[Alert] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        engine = driver.get("name", "unknown")
        for r in driver.get("rules", []):
            props = r.get("properties", {})
            rules_meta[r["id"]] = RuleMeta(
                rule_id=r["id"],
                standard=props.get("standard", "OTHER"),
                category=props.get("category", "Required"),
                decidability=props.get("decidability", "syntactic"),
                title_zh=r.get("shortDescription", {}).get("text", ""),
                cwes=props.get("cwe", []),
            )
        for res in run.get("results", []):
            pl = res.get("locations", [{}])[0].get("physicalLocation", {})
            loc = Location(
                path=pl.get("artifactLocation", {}).get("uri", ""),
                line=pl.get("region", {}).get("startLine", 1),
                col=pl.get("region", {}).get("startColumn", 1),
                end_line=pl.get("region", {}).get("endLine"),
                end_col=pl.get("region", {}).get("endColumn"),
            )
            props = res.get("properties", {})
            evidence = [
                Evidence(kind=e.get("kind", "note"), message=e.get("message", ""),
                         location=Location(path=e["path"], line=e["line"]) if e.get("path") else None,
                         snippet=e.get("snippet", ""))
                for e in props.get("evidence", [])
            ]
            alerts.append(
                Alert(
                    rule_id=res.get("ruleId", "unknown"),
                    engine=props.get("engine", engine),
                    severity=Severity.NOTE if res.get("level") == "note"
                    else Severity.WARNING if res.get("level") == "warning" else Severity.ERROR,
                    message=res.get("message", {}).get("text", ""),
                    location=loc,
                    cwe=props.get("cwe"),
                    provenance=Provenance(props.get("provenance", "suspected")),
                    evidence=evidence,
                    fingerprint=res.get("partialFingerprints", {}).get("ecdet/v1", ""),
                    triage=props.get("triage"),
                )
            )
    return alerts, list(rules_meta.values())
