"""对比评测与消融实验框架（方案 3.5，对应 P4/P5/P6 验证）。

指标（方案 3.5.2）：
  - 函数级 Precision/Recall/F1（主口径）与告警级计数；
  - 每千行分析耗时（全量模式）；
  - 可证明性比例（Proven 级结论占比）；
  - LLM 误报过滤量（分诊 FALSE_POSITIVE 数，体现 L4 净贡献）。

消融配置（方案 3.5.3 表 3-3）：
  A0 完整系统 / A1 去 LLM / A2 去硬件语义 / A3 去 RAG。
  A4（去验证闭环）作用于修复建议质量，见 ecdet.l4_llm.fixer 的验收率对比。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
from ecdet.l3_analysis.engine import AnalysisTarget, BuiltinEngine
from ecdet.l4_llm.client import MockLlmClient
from ecdet.l4_llm.triage import triage_alerts

HW_RULE_IDS = {"ECDET-MMIO-ACCESS", "ECDET-ISR-RACE", "ECDET-VOLATILE",
               "ECDET-ISR-BLOCK"}

SKIP_DIRS = {".git", "build", "ecdet_build", "ecdet_reports", ".venv",
             "__pycache__", "node_modules"}


# ---------------------------------------------------------------------------
# 基准真值
# ---------------------------------------------------------------------------


@dataclass
class GTEntry:
    path: str
    func_name: str
    start_line: int
    end_line: int
    label: str                    # vulnerable / clean
    cwe: str = ""


def load_ground_truth(path: str | Path) -> list[GTEntry]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out.append(GTEntry(
            path=d["path"].replace("\\", "/"),
            func_name=d.get("func_name", ""),
            start_line=int(d["start_line"]),
            end_line=int(d["end_line"]),
            label=d.get("label", "clean"),
            cwe=d.get("cwe", ""),
        ))
    return out


def gt_from_corpus(corpus: Path, vulnerable_names: set[str],
                   exclude: set[str] | None = None) -> list[GTEntry]:
    """由语料自身切片生成基准真值（评测管线的自洽测试入口）。

    生产评测应以人工标注的 gt.jsonl 为准（方案 3.5.1）。
    """
    from ecdet.l3_analysis.builtin_rules.checks import build_file_facts
    exclude = exclude or set()
    out = []
    for p in sorted(corpus.rglob("*")):
        if p.suffix.lower() != ".c" or any(s in p.parts for s in SKIP_DIRS):
            continue
        rel = p.relative_to(corpus).as_posix()
        facts = build_file_facts(rel, p.read_text(encoding="utf-8",
                                                  errors="replace"))
        for func in facts.functions:
            if func.name in exclude:
                continue
            out.append(GTEntry(
                path=rel, func_name=func.name, start_line=func.def_line,
                end_line=func.body_close_line,
                label="vulnerable" if func.name in vulnerable_names else "clean"))
    return out


# ---------------------------------------------------------------------------
# 消融配置与执行
# ---------------------------------------------------------------------------


@dataclass
class AblationConfig:
    name: str
    use_llm: bool = True
    use_hw: bool = True
    use_rag: bool = True
    note: str = ""


DEFAULT_ABLATIONS = [
    AblationConfig("A0 完整系统", note="骨架+硬件语义+LLM+RAG"),
    AblationConfig("A1 去 LLM", use_llm=False, note="仅静态骨架（对应 P5）"),
    AblationConfig("A2 去硬件语义", use_hw=False, note="移除 ISR/MMIO 模型（对应 P2）"),
    AblationConfig("A3 去 RAG", use_rag=False, note="LLM 判定不接知识检索"),
]


@dataclass
class ToolRun:
    name: str
    note: str = ""
    alerts: list[Alert] = field(default_factory=list)
    seconds: float = 0.0
    kloc: float = 0.0
    provenance_ratio: float = 0.0
    triage_counts: dict = field(default_factory=dict)
    available: bool = True


def _corpus_files(corpus: Path) -> list[Path]:
    return [p.relative_to(corpus) for p in sorted(corpus.rglob("*"))
            if p.suffix.lower() in (".c", ".h")
            and not any(s in p.parts for s in SKIP_DIRS)]


def _kloc(corpus: Path) -> float:
    total = 0
    for rel in _corpus_files(corpus):
        total += (corpus / rel).read_text(encoding="utf-8",
                                          errors="replace").count("\n") + 1
    return total / 1000.0


def run_ecdet_config(corpus: Path, config: AblationConfig,
                     svd_path: Path | None = None,
                     llm_client=None,
                     rag_conf_threshold: float = 0.6) -> ToolRun:
    """跑一个消融配置：扫描 →（可选）分诊过滤误报 → 计时与统计。"""
    files = _corpus_files(corpus)
    enabled = {r.rule_id for r in BUILTIN_RULES}
    if not config.use_hw:
        enabled -= HW_RULE_IDS
    svd = svd_path if config.use_hw else None

    t0 = time.perf_counter()
    target = AnalysisTarget(root=corpus, files=files, svd_path=svd)
    alerts = BuiltinEngine().run(target, enabled)
    scan_seconds = time.perf_counter() - t0

    triage_counts: dict = {}
    if config.use_llm and alerts:
        client = llm_client or MockLlmClient()
        t1 = time.perf_counter()
        _, _ = triage_alerts(alerts, corpus, client=client,
                             rag_conf_threshold=(rag_conf_threshold
                                                 if config.use_rag else 0.0))
        scan_seconds += time.perf_counter() - t1
        for a in alerts:
            v = (a.triage or {}).get("verdict", "UNTRIAGED")
            triage_counts[v] = triage_counts.get(v, 0) + 1
        alerts = [a for a in alerts
                  if (a.triage or {}).get("verdict") != "FALSE_POSITIVE"]

    n_prov = sum(1 for a in alerts if a.provenance.value == "proven")
    return ToolRun(
        name=config.name, note=config.note, alerts=alerts,
        seconds=scan_seconds, kloc=_kloc(corpus),
        provenance_ratio=(n_prov / len(alerts)) if alerts else 0.0,
        triage_counts=triage_counts,
    )


def run_baseline(corpus: Path, engine) -> ToolRun:
    """外部基线（cppcheck/clang-tidy 等适配器实例）。不可用时 available=False。"""
    name = engine.name
    if not engine.available():
        return ToolRun(name=f"{name}（基线）", note="未安装，跳过", available=False)
    files = _corpus_files(corpus)
    t0 = time.perf_counter()
    alerts = engine.run(AnalysisTarget(root=corpus, files=files), set())
    seconds = time.perf_counter() - t0
    return ToolRun(name=f"{name}（基线）", alerts=alerts, seconds=seconds,
                   kloc=_kloc(corpus))


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------


def _in_func(alert: Alert, g: GTEntry) -> bool:
    return (alert.location.path.replace("\\", "/") == g.path
            and g.start_line <= alert.location.line <= g.end_line)


def compute_metrics(alerts: list[Alert], gt: list[GTEntry]) -> dict:
    """函数级 P/R/F1（主口径）+ 告警级计数（方案 3.5.2 双口径）。"""
    vuln = [g for g in gt if g.label == "vulnerable"]
    clean = [g for g in gt if g.label == "clean"]

    tp = sum(1 for g in vuln if any(_in_func(a, g) for a in alerts))
    fn = len(vuln) - tp
    fp = sum(1 for g in clean if any(_in_func(a, g) for a in alerts))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    tp_a = sum(1 for a in alerts if any(_in_func(a, g) for g in vuln))
    fp_a = sum(1 for a in alerts if any(_in_func(a, g) for g in clean))
    return {
        "func_tp": tp, "func_fn": fn, "func_fp": fp,
        "vulnerable_total": len(vuln), "clean_total": len(clean),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "alert_tp": tp_a, "alert_fp": fp_a,
        "alert_outside_gt": len(alerts) - tp_a - fp_a,
    }


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------


def render_markdown(runs: list[tuple[ToolRun, dict]]) -> str:
    """评测结果表（填充方案表 3-4 模板）。"""
    lines = [
        "# ecdet 评测结果（方案 3.5 表 3-4）",
        "",
        "| 系统配置 | 精确率 | 召回率 | F1 | 函数TP/FN/FP | 告警TP/FP | "
        "千行耗时(s) | 可证明性比例 | LLM过滤 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for run, m in runs:
        if not run.available:
            lines.append(f"| {run.name} | - | - | - | - | - | - | - | "
                         f"{run.note} |")
            continue
        kloc_time = round(run.seconds / run.kloc, 3) if run.kloc else 0.0
        filtered = run.triage_counts.get("FALSE_POSITIVE", 0)
        lines.append(
            f"| {run.name} | {m['precision']:.2%} | {m['recall']:.2%} | "
            f"{m['f1']:.2%} | {m['func_tp']}/{m['func_fn']}/{m['func_fp']} | "
            f"{m['alert_tp']}/{m['alert_fp']} | {kloc_time} | "
            f"{run.provenance_ratio:.1%} | {filtered} |")
    lines.append("")
    lines.append("> 函数级口径：告警落入函数行区间即视为覆盖该函数；"
                 "clean 函数出现任一告警计一次 FP。")
    return "\n".join(lines)
