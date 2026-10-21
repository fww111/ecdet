# -*- coding: utf-8 -*-
"""V1.2 对齐测试：动态通道（3.3.5）、运行时监控（3.3.6）、多智能体编排（3.3.7）。"""

import textwrap
from pathlib import Path

import pytest

from ecdet.l2_ir.model import Alert, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.dynamic import DynamicEngine
from ecdet.l3_analysis.dynamic.harness import compile_harness, generate_harness
from ecdet.l3_analysis.dynamic.inputs import _INT_SPECIALS, build_input_model, param_value
from ecdet.l3_analysis.monitor import RuntimeMonitor, probes_from_alerts
from ecdet.l4_llm.agents import Orchestrator, OrchestratorConfig

pytestmark = pytest.mark.skipif(
    DynamicEngine().available is False, reason="需要 gcc")

DYN_C = textwrap.dedent("""\
    #include <stdint.h>

    int scale_value(int base, int divisor)
    {
        return base / divisor;
    }

    int read_selected(char *buf, int sel)
    {
        const char *p = (sel > 100) ? 0 : buf;
        return p[0];
    }

    int safe_add(int a, int b) { return a + b; }
    """)


@pytest.fixture()
def dyn_root(tmp_path):
    (tmp_path / "vuln_dyn.c").write_text(DYN_C, encoding="utf-8")
    return tmp_path


def _facts(root: Path):
    return [build_file_facts("vuln_dyn.c",
                             (root / "vuln_dyn.c").read_text(encoding="utf-8"))]


# ---------------- 输入建模 ----------------

def test_input_model_types_from_parser(dyn_root):
    facts = _facts(dyn_root)
    ctx = finalize_facts(facts)
    func = next(f for f in ctx.facts[0].functions if f.name == "read_selected")
    model = build_input_model(func)
    buf = next(p for p in model.params if p.name == "buf")
    sel = next(p for p in model.params if p.name == "sel")
    assert buf.is_pointer, "cstruct 解析的参数类型应为 char *"
    assert not sel.is_pointer and sel.ctype == "int"


def test_param_specials_cover_zero():
    """特殊值表含 0 —— 除零 PoC 的确定性来源。"""
    assert 0 in _INT_SPECIALS
    from ecdet.l3_analysis.dynamic.inputs import ParamSpec
    spec = ParamSpec(name="divisor", ctype="int")
    assert param_value(spec, 0).lstrip("-").isdigit()


# ---------------- harness 生成与编译闭环 ----------------

def test_harness_generate_and_compile(dyn_root, tmp_path):
    facts = _facts(dyn_root)
    ctx = finalize_facts(facts)
    func = next(f for f in ctx.facts[0].functions if f.name == "scale_value")
    model = build_input_model(func)
    harness = generate_harness(model, "vuln_dyn.c", n_seeds=17)
    assert "ecdet_combo" in harness.source
    assert '#include "vuln_dyn.c"' in harness.source
    ok, err = compile_harness(harness, tmp_path, [dyn_root])
    assert ok, err
    assert harness.exe_path and harness.exe_path.exists()


def test_harness_stub_loop_for_undefined_symbols(tmp_path):
    """链接期未解析符号 → 自动打桩重编（生成-编译-修正闭环）。"""
    src = textwrap.dedent("""\
        int target_fn(int x) { return helper_one(x) + helper_two(x); }
        """)
    (tmp_path / "stub_target.c").write_text(src, encoding="utf-8")
    facts = [build_file_facts("stub_target.c", src)]
    ctx = finalize_facts(facts)
    func = ctx.facts[0].functions[0]
    model = build_input_model(func)
    harness = generate_harness(model, "stub_target.c", n_seeds=4)
    ok, err = compile_harness(harness, tmp_path, [tmp_path])
    assert ok, err
    assert set(harness.stubs) == {"helper_one", "helper_two"}


def test_poc_replay_seed_consistent(dyn_root):
    """PoC 重放种子与激励索引一致（可复现性契约）。"""
    findings = DynamicEngine(max_functions=8, max_seeds=17).run(
        dyn_root, _facts(dyn_root))
    div = next(f for f in findings if f.func_name == "scale_value")
    assert div.oracle == "CRASH" and "C0000094" in div.detail
    assert div.replay_seed == str(div.seed_idx % 17)


# ---------------- 动态引擎 ----------------

def test_dynamic_engine_triggers(dyn_root):
    findings = DynamicEngine(max_functions=8, max_seeds=17).run(
        dyn_root, _facts(dyn_root))
    by_func = {f.func_name: f for f in findings}
    assert by_func["scale_value"].oracle == "CRASH"
    assert "C0000094" in by_func["scale_value"].detail       # 整数除零
    assert by_func["read_selected"].oracle == "CRASH"
    assert "C0000005" in by_func["read_selected"].detail     # 空指针
    assert "safe_add" not in by_func, "干净函数不得误触发"

    alert = by_func["scale_value"].to_alert()
    assert alert.engine == "dynamic"
    assert alert.provenance == Provenance.DETECTED
    assert alert.location.line >= 3, "告警应定位在函数定义行"


def test_dynamic_alerts_in_function_range(dyn_root):
    """动态告警行必须落在目标函数行区间内（函数级评测可覆盖）。"""
    facts = _facts(dyn_root)
    findings = DynamicEngine(max_functions=8, max_seeds=17).run(dyn_root, facts)
    ctx = finalize_facts(facts)
    for f in findings:
        func = next(fn for fn in ctx.facts[0].functions
                    if fn.name == f.func_name)
        assert func.def_line <= f.def_line <= func.body_close_line


# ---------------- 运行时监控（3.3.6） ----------------

def test_monitor_probes_and_regrade(dyn_root):
    """Suspected 级嫌疑 → 定向探针 → 崩溃命中 → 升级 Detected。"""
    facts = _facts(dyn_root)
    ctx = finalize_facts(facts)
    func = next(f for f in ctx.facts[0].functions if f.name == "scale_value")
    suspected = Alert(
        rule_id="CERT C ARR30-C", engine="builtin-absint",
        severity=Severity.WARNING,
        message="疑似越界路径", location=Location(path="vuln_dyn.c",
                                                  line=func.def_line),
        provenance=Provenance.SUSPECTED)
    probes = probes_from_alerts([suspected], facts)
    assert probes == ["scale_value"]

    result = RuntimeMonitor(
        engine=DynamicEngine(max_functions=8, max_seeds=17)).run(
        dyn_root, facts, [suspected])
    assert result.events, "定向探针应命中崩溃"
    assert suspected in result.upgraded
    assert suspected.provenance == Provenance.DETECTED
    assert any("运行时监控升级" in e.message for e in suspected.evidence)


def test_monitor_no_probe_skipped(dyn_root):
    facts = _facts(dyn_root)
    result = RuntimeMonitor().run(dyn_root, facts, [])
    assert result.events == []
    assert "无可动态裁决" in result.skipped_reason


# ---------------- 多智能体编排（3.3.7） ----------------

EVAL_CORPUS = Path(__file__).parent / "fixtures" / "eval_corpus"


def test_orchestrate_multi_agent_full_pipeline():
    state = Orchestrator(OrchestratorConfig(mock=True)).orchestrate(EVAL_CORPUS)
    agents_logged = {line.split("]")[0].lstrip("[") for line in state.logs}
    assert {"planner", "static", "static-triage", "dynamic",
            "reporter"} <= agents_logged
    dyn_alerts = [a for a in state.static_alerts if a.engine == "dynamic"]
    assert len(dyn_alerts) >= 2, "动态通道 PoC 应入 SARIF 池"
    assert state.llm_calls > 0
    assert all(a.triage is not None for a in state.static_alerts
               if a.engine != "dynamic" and a.severity.value != "note")


def test_orchestrate_single_agent_parity():
    """A6：单智能体串行产出与多智能体一致（组织学消融，检测能力等价）。"""
    multi = Orchestrator(OrchestratorConfig(mock=True)).orchestrate(EVAL_CORPUS)
    single = Orchestrator(OrchestratorConfig(mock=True,
                                             single_agent=True)).orchestrate(
        EVAL_CORPUS)
    assert len(multi.static_alerts) == len(single.static_alerts)
    assert len(multi.dynamic_findings) == len(single.dynamic_findings)


def test_orchestrate_a1_no_llm():
    state = Orchestrator(OrchestratorConfig(mock=True, use_llm=False)
                         ).orchestrate(EVAL_CORPUS)
    assert state.triage_verdicts == []
    assert all(a.triage is None for a in state.static_alerts
               if a.engine != "dynamic")
