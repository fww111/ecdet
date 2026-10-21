# -*- coding: utf-8 -*-
"""阶段四：评测框架测试（消融 A0-A3、指标数学、报告渲染）。"""

import json
from pathlib import Path

from ecdet.eval import (
    AblationConfig,
    compute_metrics,
    gt_from_corpus,
    load_ground_truth,
    render_markdown,
    run_baseline,
    run_ecdet_config,
)
from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.engine import DEFAULT_ENGINES

CORPUS = Path(__file__).parent / "fixtures" / "eval_corpus"

# 竞争缺陷以无保护访问侧函数为检测目标（规则定位首个无保护访问行）；
# UART8_IRQHandler 为 ISR 侧写入方，不单独承载告警行。
VULN_FUNCS = {"buf_copy_bad", "TIM6_IRQHandler", "gpio_ro_write",
              "unprotected_reader"}


def _gt():
    return gt_from_corpus(CORPUS, VULN_FUNCS)


def test_gt_generation():
    gt = _gt()
    by_name = {g.func_name: g for g in gt}
    assert by_name["buf_copy_bad"].label == "vulnerable"
    assert by_name["buf_copy_ok"].label == "clean"
    assert by_name["utility_helper"].label == "clean"
    assert all(g.end_line >= g.start_line for g in gt)


def test_load_ground_truth_jsonl(tmp_path):
    p = tmp_path / "gt.jsonl"
    p.write_text(json.dumps({
        "path": "a.c", "func_name": "f", "start_line": 1, "end_line": 9,
        "label": "vulnerable", "cwe": "CWE-120"}) + "\n", encoding="utf-8")
    gt = load_ground_truth(p)
    assert len(gt) == 1 and gt[0].cwe == "CWE-120"


# ---------------- 指标数学 ----------------

def test_metrics_perfect():
    gt = _gt()
    run = run_ecdet_config(CORPUS, AblationConfig("A0 完整系统"),
                           svd_path=CORPUS / "chip.svd")
    m = compute_metrics(run.alerts, gt)
    assert m["func_fn"] == 0, "A0 应检出全部漏洞函数"
    assert m["func_fp"] == 0, "Mock 分诊应过滤 utility_helper 的 8.7 误报"
    assert m["precision"] == 1.0 and m["recall"] == 1.0


def test_metrics_synthetic():
    gt = [
        dict(path="a.c", func_name="v1", start_line=1, end_line=10,
             label="vulnerable"),
        dict(path="a.c", func_name="v2", start_line=12, end_line=20,
             label="vulnerable"),
        dict(path="a.c", func_name="c1", start_line=22, end_line=30,
             label="clean"),
    ]

    def mk(line):
        return Alert(rule_id="R", engine="t", severity=Severity.WARNING,
                     message="m", location=Location(path="a.c", line=line))

    alerts = [mk(5), mk(25)]           # 命中 v1（TP）与 c1（FP），漏 v2（FN）
    m = compute_metrics(alerts, [type("G", (), d)() for d in []] or
                        [_gt_like(d) for d in gt])
    assert m["func_tp"] == 1 and m["func_fn"] == 1 and m["func_fp"] == 1
    assert abs(m["precision"] - 0.5) < 1e-6
    assert abs(m["recall"] - 0.5) < 1e-6
    assert abs(m["f1"] - 0.5) < 1e-6
    assert m["alert_tp"] == 1 and m["alert_fp"] == 1


def _gt_like(d):
    from ecdet.eval import GTEntry
    return GTEntry(path=d["path"], func_name=d["func_name"],
                   start_line=d["start_line"], end_line=d["end_line"],
                   label=d["label"])


# ---------------- 消融差异 ----------------

def test_ablation_a1_no_llm_keeps_fp():
    """A1（去 LLM）：8.7 误报保留 → FP > 0，精确率低于 A0。"""
    gt = _gt()
    run = run_ecdet_config(CORPUS, AblationConfig("A1 去 LLM", use_llm=False),
                           svd_path=CORPUS / "chip.svd")
    m = compute_metrics(run.alerts, gt)
    assert m["func_fp"] >= 1
    assert m["recall"] == 1.0           # 静态骨架仍检出全部漏洞函数

    a0 = run_ecdet_config(CORPUS, AblationConfig("A0"), svd_path=CORPUS / "chip.svd")
    m0 = compute_metrics(a0.alerts, gt)
    assert m0["precision"] > m["precision"]


def test_ablation_a2_no_hw_misses_hw_defects():
    """A2（去硬件语义）：ISR-BLOCK/RO 写漏洞漏检 → 召回下降。"""
    gt = _gt()
    run = run_ecdet_config(CORPUS, AblationConfig("A2 去硬件语义", use_llm=False,
                                                  use_hw=False))
    m = compute_metrics(run.alerts, gt)
    assert m["func_fn"] >= 1, "去掉硬件语义后至少漏检一个硬件类漏洞"
    assert m["recall"] < 1.0

    a0 = run_ecdet_config(CORPUS, AblationConfig("A0", use_llm=False),
                          svd_path=CORPUS / "chip.svd")
    m0 = compute_metrics(a0.alerts, gt)
    assert m0["recall"] > m["recall"]


def test_ablation_a3_no_rag_still_runs():
    """A3（去 RAG）：管线可运行，RAG 不触发。"""
    run = run_ecdet_config(CORPUS, AblationConfig("A3 去 RAG", use_rag=False),
                           svd_path=CORPUS / "chip.svd")
    assert run.alerts is not None
    # 阈值 0 意味着永不触发 RAG
    from ecdet.l4_llm.triage import TriageRunner
    r = TriageRunner(rag_conf_threshold=0.0)
    assert r.rag_conf_threshold == 0.0


# ---------------- 基线与报告 ----------------

def test_baseline_unavailable_marked():
    class FakeEngine:
        name = "notinstalled"
        def available(self):
            return False
        def run(self, target, enabled):
            return []

    br = run_baseline(CORPUS, FakeEngine())
    assert not br.available and br.note == "未安装，跳过"


def test_render_markdown_table():
    gt = _gt()
    run = run_ecdet_config(CORPUS, AblationConfig("A0 完整系统"),
                           svd_path=CORPUS / "chip.svd")
    md = render_markdown([(run, compute_metrics(run.alerts, gt))])
    assert "| A0 完整系统 |" in md
    assert "精确率" in md and "可证明性比例" in md


def test_builtin_engine_present_in_defaults():
    names = [e.name for e in DEFAULT_ENGINES]
    assert "builtin" in names
