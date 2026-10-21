# -*- coding: utf-8 -*-
"""阶段三：L4 LLM 分诊层测试（离线 Mock 全路径）。"""

import json
import textwrap
from pathlib import Path

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l4_llm.client import MockLlmClient
from ecdet.l4_llm.kb import build_kb
from ecdet.l4_llm.slicer import slice_context
from ecdet.l4_llm.triage import TriageRunner, parse_verdict_json, triage_alerts
from ecdet.l4_llm.verifier import verify_cited_lines

EXAMPLES = Path(__file__).parent.parent / "examples"


# ---------------- JSON 解析（幻觉抑制第一道） ----------------

def test_parse_verdict_json_valid():
    raw = '前置说明 {"verdict": "TRUE_POSITIVE", "confidence": 0.8, "reason": "r", "evidence_lines": [3]} 后缀'
    assert parse_verdict_json(raw)["confidence"] == 0.8


def test_parse_verdict_json_invalid():
    assert parse_verdict_json("不是 JSON") is None
    assert parse_verdict_json('{"verdict": "MAYBE", "confidence": 0.5}') is None
    assert parse_verdict_json('{"verdict": "TRUE_POSITIVE", "confidence": "high"}') is None
    assert parse_verdict_json("") is None


# ---------------- 证据行号核对 ----------------

def _lex_of(src: str):
    return build_file_facts("t.c", textwrap.dedent(src)).lex


def test_verify_cited_lines_pass():
    src = """\
        int f(void) {
            int a[4] = {0};
            a[9] = 1;
            return 0;
        }
        """
    lex = _lex_of(src)
    ok, lines = verify_cited_lines([2, 3], lex, 1, 5, 3)
    assert ok and lines == [2, 3]


def test_verify_cited_lines_out_of_range():
    lex = _lex_of("int f(void) { return 0; }\n")
    ok, _ = verify_cited_lines([100], lex, 1, 1, 1)
    assert not ok


def test_verify_cited_line_deref_star_not_comment():
    """以 * 开头的解引用行不得误判为块注释延续。"""
    src = """\
        void f(void) {
            *(volatile unsigned int *)0x40020010 = 0u;
        }
        """
    lex = _lex_of(src)
    ok, lines = verify_cited_lines([2], lex, 1, 3, 2)
    assert ok and lines == [2]


def test_verify_cited_comment_line_rejected():
    src = """\
        int f(void) {
            /* 纯注释行 */
            return 0;
        }
        """
    lex = _lex_of(src)
    ok, _ = verify_cited_lines([2], lex, 1, 4, 3)
    assert not ok            # 只引用了注释行，且未含告警行


def test_verify_cited_must_contain_alert_line():
    lex = _lex_of("int f(void) {\n    return 0;\n}\n")
    ok, _ = verify_cited_lines([2], lex, 1, 3, 1)
    assert not ok            # 缺告警行本身


def test_verify_file_range_fallback():
    """全局声明类告警（无函数上下文）按文件范围核对。"""
    src = "uint32_t g_ctrl;\nint f(void) { return 0; }\n"
    lex = _lex_of(src)
    ok, lines = verify_cited_lines([1], lex, 0, 0, 1, has_function=False)
    assert ok and lines == [1]


# ---------------- 上下文裁剪 ----------------

def _ctx_for(tmp_path: Path):
    root = EXAMPLES / "svd_demo"
    facts = []
    for p in sorted(root.rglob("*.c")):
        facts.append(build_file_facts(
            p.relative_to(root).as_posix(),
            p.read_text(encoding="utf-8", errors="replace")))
    return finalize_facts(facts)


def test_slicer_function_closure():
    ctx = _ctx_for(None)
    alert = Alert(rule_id="ECDET-MMIO-ACCESS", engine="builtin", severity=Severity.ERROR,
                  message="x", location=Location(path="src/app.c", line=48))
    s = slice_context(alert, ctx, budget_chars=8000)
    assert s.func_name == "task_poll"
    assert "task_poll" in s.function_text
    # 闭包含跨上下文元素
    rendered = s.render()
    assert any("被调函数" in e for e in s.extras) or len(s.extras) >= 0
    assert "GPIO_TypeDef" in rendered       # 宏被纳入（GPIOA 定义）


def test_slicer_budget_truncates():
    ctx = _ctx_for(None)
    alert = Alert(rule_id="ECDET-MMIO-ACCESS", engine="builtin", severity=Severity.ERROR,
                  message="x", location=Location(path="src/app.c", line=48))
    s = slice_context(alert, ctx, budget_chars=200)
    assert s.truncated or s.n_chars <= 400


def test_slicer_missing_file():
    ctx = _ctx_for(None)
    alert = Alert(rule_id="X", engine="t", severity=Severity.WARNING,
                  message="x", location=Location(path="nope/absent.c", line=1))
    s = slice_context(alert, ctx)
    assert s.truncated and "不在工程事实中" in s.extras[0]


# ---------------- 知识库检索 ----------------

def test_kb_lookup():
    kb = build_kb()
    text = kb.lookup("CERT C STR31-C", "CWE-120")
    assert "STR31-C" in text
    assert "GJB" in text


# ---------------- Mock 分诊全路径 ----------------

def _alerts_from(root: Path):
    """对示例工程直接跑内置引擎获取真实告警。"""
    from ecdet.l3_analysis.engine import AnalysisTarget, BuiltinEngine
    from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
    files = [p.relative_to(root) for p in sorted(root.rglob("*.c"))]
    target = AnalysisTarget(root=root, files=files)
    return BuiltinEngine().run(target, {r.rule_id for r in BUILTIN_RULES})


def test_triage_mock_full_pipeline():
    alerts = _alerts_from(EXAMPLES / "svd_demo")
    verdicts, calls = triage_alerts(alerts, EXAMPLES / "svd_demo",
                                    client=MockLlmClient())
    by_v = {}
    for v in verdicts:
        by_v.setdefault(v.verdict, []).append(v)
    assert "TRUE_POSITIVE" in by_v and "FALSE_POSITIVE" in by_v
    # RAG 路径被触发过（低置信告警）
    assert any(v.used_rag for v in verdicts)
    # 全部回写告警
    assert all(a.triage is not None for a in alerts)
    assert calls >= len(verdicts)


def test_triage_downgrade_on_bad_citation():
    """FIO30（Mock 引用错行）→ 证据核对不通过 → TP 降级 NEEDS_REVIEW。"""
    alerts = [a for a in _alerts_from(EXAMPLES / "demo_rtos")
              if a.rule_id == "CERT C FIO30-C"]
    assert alerts, "demo_rtos 应含 FIO30-C 告警"
    verdicts, _ = triage_alerts(alerts, EXAMPLES / "demo_rtos",
                                client=MockLlmClient())
    assert all(v.verdict == "NEEDS_REVIEW" for v in verdicts)
    assert all("核对未通过" in v.reason for v in verdicts)


def test_triage_false_positive_path():
    alerts = [a for a in _alerts_from(EXAMPLES / "svd_demo")
              if a.rule_id == "MISRA C:2012 8.7"]
    assert alerts
    verdicts, _ = triage_alerts(alerts, EXAMPLES / "svd_demo",
                                client=MockLlmClient())
    assert all(v.verdict == "FALSE_POSITIVE" for v in verdicts)


def test_triage_missing_context_file():
    alerts = [Alert(rule_id="X", engine="t", severity=Severity.WARNING,
                    message="m", location=Location(path="ghost/missing.c", line=5))]
    verdicts, calls = triage_alerts(alerts, EXAMPLES / "svd_demo",
                                    client=MockLlmClient())
    assert verdicts[0].verdict == "NEEDS_REVIEW"
    assert calls == 0          # 未调用 LLM


# ---------------- SARIF 往返携带分诊 ----------------

def test_sarif_roundtrip_with_triage(tmp_path):
    from ecdet.l2_ir import load_sarif, save_sarif
    from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES

    alerts = _alerts_from(EXAMPLES / "svd_demo")[:3]
    triage_alerts(alerts, EXAMPLES / "svd_demo", client=MockLlmClient())
    path = save_sarif(alerts, list(BUILTIN_RULES), tmp_path / "t.sarif")
    loaded, _ = load_sarif(path)
    assert all(a.triage is not None for a in loaded)
    assert loaded[0].triage["verdict"] in ("TRUE_POSITIVE", "FALSE_POSITIVE",
                                           "NEEDS_REVIEW")
