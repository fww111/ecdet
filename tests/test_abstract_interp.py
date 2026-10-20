# -*- coding: utf-8 -*-
"""阶段二：抽象解释（常量传播）与 ESBMC 输出解析、GJB 映射测试。"""

import textwrap

from ecdet.l2_ir.model import Provenance
from ecdet.l3_analysis.abstract_interp import propagate_constants, proven_index_check
from ecdet.l3_analysis.adapters.esbmc import parse_esbmc_output
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
from ecdet.l5_report.aggregator import _load_gjb_map


def _absint(src: str):
    facts = [build_file_facts("t.c", textwrap.dedent(src))]
    return facts, proven_index_check(facts)


# ---------------- 常量传播 ----------------

def test_propagate_basic():
    src = """
    int f(void) {
        int a = 5;
        int b = a * 2 + 1;
        int c = b;
        int d = unknown_source();
        int e = a; e++;             /* e 自增后不可靠 */
        return 0;
    }
    """
    facts = [build_file_facts("t.c", textwrap.dedent(src))]
    consts = propagate_constants(facts[0].functions[0])
    assert consts == {"a": 5, "b": 11, "c": 11}
    assert "d" not in consts and "e" not in consts


# ---------------- Proven 越界证明 ----------------

def test_proven_index_out_of_bounds():
    src = """
    int f(void) {
        int a[8] = {0};
        int i = 99;
        a[i] = 1;
        return 0;
    }
    """
    _, alerts = _absint(src)
    assert len(alerts) == 1
    assert alerts[0].provenance == Provenance.PROVEN
    assert alerts[0].rule_id == "CERT C ARR30-C"
    assert "99" in alerts[0].message


def test_proven_negative_index():
    src = """
    int f(void) {
        int a[8] = {0};
        int i = 0 - 3;
        a[i] = 1;
        return 0;
    }
    """
    _, alerts = _absint(src)
    assert len(alerts) == 1 and alerts[0].provenance == Provenance.PROVEN


def test_in_bounds_proven_no_alert():
    """常量传播证明在界内 → 不告警（误报抑制语义）。"""
    src = """
    int f(void) {
        int a[8] = {0};
        int j = 2 * 3 + 1;      /* 7，恰好是最后一个合法下标 */
        a[j] = 1;
        return 0;
    }
    """
    _, alerts = _absint(src)
    assert alerts == []


def test_unknown_index_no_alert():
    """无法折叠的下标不猜（保守，交给数据流/人工）。"""
    src = """
    int f(int n) {
        int a[8] = {0};
        a[n] = 1;
        return 0;
    }
    """
    _, alerts = _absint(src)
    assert alerts == []


def test_literal_index_still_detected_not_proven():
    """字面量下标由 DETECTED 规则负责，抽象解释跳过避免重复。"""
    src = "int f(void) { int a[4] = {0}; a[9] = 1; return 0; }"
    _, alerts = _absint(src)
    assert alerts == []


# ---------------- ESBMC 输出解析 ----------------

def test_esbmc_failed_to_proven():
    text = """
    Type-checking... 
    [overflow.min] arithmetic overflow on add FAILED
    [pointer.invalid] dereference check FAILED
    VERIFICATION FAILED
    """
    alerts = parse_esbmc_output(text, "x.c")
    assert len(alerts) == 1
    assert alerts[0].engine == "esbmc"
    assert alerts[0].provenance == Provenance.PROVEN
    assert alerts[0].severity.value == "error"
    assert "overflow" in alerts[0].message


def test_esbmc_successful_no_alert():
    assert parse_esbmc_output("VERIFICATION SUCCESSFUL", "x.c") == []


# ---------------- GJB 主题映射 ----------------

def test_gjb_map_consistent():
    gjb = _load_gjb_map()
    assert len(gjb) >= 20
    builtin_ids = {r.rule_id for r in BUILTIN_RULES}
    unknown = set(gjb) - builtin_ids
    assert not unknown, f"gjb_map.json 中存在未知规则 ID：{unknown}"
