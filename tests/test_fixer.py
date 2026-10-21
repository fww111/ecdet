# -*- coding: utf-8 -*-
"""阶段三后半：LLM 修复建议与 ToolLoopVerify 验证闭环测试。"""

import json
import textwrap
from pathlib import Path

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l4_llm.fixer import (
    FixProposer,
    FixVerifier,
    MockFixClient,
    apply_patch,
    extract_patched_function,
)

EXAMPLES = Path(__file__).parent.parent / "examples"


# ---------------- 补丁应用与解析 ----------------

def test_apply_patch_replaces_region():
    src = "int a;\nint f(void) {\n    return 0;\n}\nint b;\n"
    out = apply_patch(src, 2, 4, "int f(void) {\n    return 1;\n}")
    assert out == "int a;\nint f(void) {\n    return 1;\n}\nint b;\n"


def test_extract_patched_function_plain():
    raw = json.dumps({"patched_function": "int f(void) { return 1; }",
                      "explanation": "改返回值"}, ensure_ascii=False)
    parsed = extract_patched_function(raw)
    assert parsed["patched_function"] == "int f(void) { return 1; }"
    assert parsed["explanation"] == "改返回值"


def test_extract_patched_function_with_fence():
    raw = '```json\n{"patched_function": "```c\\nint f(void) { return 1; }\\n```", ' \
          '"explanation": ""}\n```'
    parsed = extract_patched_function(raw)
    assert parsed["patched_function"] == "int f(void) { return 1; }"


def test_extract_patched_function_invalid():
    assert extract_patched_function("not json") == {}
    assert extract_patched_function('{"patched_function": ""}') == {}


# ---------------- 验证闭环三路径 ----------------

def _alert_for(root: Path, rule: str, path: str, line: int) -> Alert:
    return Alert(rule_id=rule, engine="builtin", severity=Severity.ERROR,
                 message="test", location=Location(path=path, line=line))


def _ctx_for(root: Path):
    facts = []
    for p in sorted(root.rglob("*.c")):
        facts.append(build_file_facts(
            p.relative_to(root).as_posix(),
            p.read_text(encoding="utf-8", errors="replace")))
    return finalize_facts(facts)


def test_fix_str31_verified(tmp_path):
    """STR31：Mock 正确补丁 → 原告警消除 + 无新 error + gcc 语法通过 → 采纳。"""
    ctx = _ctx_for(EXAMPLES / "demo_rtos")
    alert = _alert_for(EXAMPLES / "demo_rtos", "CERT C STR31-C",
                       "src/sensor.c", 37)
    proposal = FixProposer(MockFixClient()).propose(alert, ctx)
    assert proposal.patched_code, "Mock 应给出补丁"
    verifier = FixVerifier(EXAMPLES / "demo_rtos", use_compiler=True)
    src = (EXAMPLES / "demo_rtos" / "src" / "sensor.c").read_text(encoding="utf-8")
    proposal = verifier.verify(proposal, ctx, src)
    assert proposal.verified, proposal.fail_reason
    assert "strncpy" in proposal.patched_code
    assert "@@ -" in proposal.diff and "strncpy" in proposal.diff
    assert "strcpy(" not in proposal.patched_code


def test_fix_no_change_rejected():
    """Mock 无变化路径 → 拒绝（补丁未改变函数）。"""
    ctx = _ctx_for(EXAMPLES / "demo_rtos")
    alert = _alert_for(EXAMPLES / "demo_rtos", "MISRA C:2012 17.2",
                       "src/sensor.c", 28)
    proposal = FixProposer(MockFixClient()).propose(alert, ctx)
    verifier = FixVerifier(EXAMPLES / "demo_rtos", use_compiler=False)
    src = (EXAMPLES / "demo_rtos" / "src" / "sensor.c").read_text(encoding="utf-8")
    proposal = verifier.verify(proposal, ctx, src)
    assert not proposal.verified
    assert "未改变" in proposal.fail_reason


def test_fix_not_in_function_rejected():
    """全局告警（ISR-RACE 定位声明行附近但不在函数内）→ 无法生成补丁。"""
    ctx = _ctx_for(EXAMPLES / "svd_demo")
    alert = _alert_for(EXAMPLES / "svd_demo", "ECDET-ISR-RACE",
                       "src/app.c", 22)     # g_ctrl 声明行
    proposal = FixProposer(MockFixClient()).propose(alert, ctx)
    assert not proposal.verified
    assert "不在函数内" in proposal.fail_reason


def test_fix_proposer_unparsable_output():
    """LLM 输出不可解析 → 空补丁 + 失败原因，不进入验证。"""

    class BadClient:
        def complete(self, system, user):
            return "我不会输出 JSON"

    ctx = _ctx_for(EXAMPLES / "demo_rtos")
    alert = _alert_for(EXAMPLES / "demo_rtos", "CERT C STR31-C",
                       "src/sensor.c", 37)
    proposal = FixProposer(BadClient()).propose(alert, ctx)
    assert not proposal.patched_code
    assert "不可解析" in proposal.fail_reason


def test_fix_alert_gone_check(tmp_path):
    """静态重扫口径：补丁后原告警仍存在 → 拒绝（用内存语料精确控制）。"""
    src = textwrap.dedent("""\
        #include <string.h>
        void f(void) {
            char b[4];
            strcpy(b, "too long");
        }
        """)
    root = tmp_path
    (root / "m.c").write_text(src, encoding="utf-8")
    ctx = finalize_facts([build_file_facts("m.c", src)])
    # Mock 的 STR31 正确补丁把 strcpy 换成限长 strncpy → 原告警应消除
    alert = _alert_for(root, "CERT C STR31-C", "m.c", 4)
    proposal = FixProposer(MockFixClient()).propose(alert, ctx)
    verifier = FixVerifier(root, use_compiler=True)
    proposal = verifier.verify(proposal, ctx, src)
    assert proposal.verified, proposal.fail_reason
