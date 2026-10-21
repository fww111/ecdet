# -*- coding: utf-8 -*-
"""动态通道补强测试：LLM harness 修正闭环（3.3.5）与三级载体梯度。"""

import textwrap
from pathlib import Path

import pytest

from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.dynamic import DynamicEngine
from ecdet.l3_analysis.dynamic.carriers import (
    HostCarrier,
    RenodeCarrier,
    UnicornCarrier,
    pick_carrier,
    probe_carriers,
)
from ecdet.l3_analysis.dynamic.harness import compile_harness, generate_harness
from ecdet.l3_analysis.dynamic.inputs import build_input_model
from ecdet.l3_analysis.dynamic.llm_fix import (
    LlmHarnessFixer,
    extract_patched_harness,
)

pytestmark = pytest.mark.skipif(not HostCarrier.available(), reason="需要 gcc")

# ---------------- extract_patched_harness ----------------


def test_extract_patched_harness_plain():
    raw = '{"patched_harness": "int main(void){return 0;}", "changes": "补 include"}'
    got = extract_patched_harness(raw)
    assert got == ("int main(void){return 0;}", "补 include")


def test_extract_patched_harness_fence():
    raw = '```json\n{"patched_harness": "```c\\nint x;\\n```", "changes": ""}\n```'
    got = extract_patched_harness(raw)
    assert got is not None and got[0] == "int x;"


def test_extract_patched_harness_invalid():
    assert extract_patched_harness("不会输出 JSON") is None
    assert extract_patched_harness('{"patched_harness": ""}') is None
    assert extract_patched_harness("") is None


# ---------------- LLM 修正闭环 ----------------

BROKEN_C = textwrap.dedent("""\
    #include <stdint.h>
    int broken_fn(int mode)
    {
        undefined_helper_abc(mode);      /* 未定义符号：打桩可修 */
        return (unknown_type_xyz *) 0;   /* 类型不存在：打桩不可修，需 LLM */
    }
    """)


def test_llm_fixer_recovers_uncompilable_harness(tmp_path):
    """确定性打桩失败 → LLM 修正（Fake：修复坏行）→ 编译通过。

    直接验证 compile_harness 的"编译日志回传 → LLM 重写 → 再编译"
    闭环机制（方案 3.3.5）。
    """
    good_c = textwrap.dedent("""\
        #include <stdint.h>
        int simple_fn(int mode) { return mode * 2; }
        """)
    (tmp_path / "simple.c").write_text(good_c, encoding="utf-8")
    facts = [build_file_facts("simple.c", good_c)]
    ctx = finalize_facts(facts)
    func = next(f for f in ctx.facts[0].functions if f.name == "simple_fn")
    model = build_input_model(func)
    harness = generate_harness(model, "simple.c", n_seeds=2)

    class FakeLlm:
        """确定性 Fake：收到含坏行的源码即删除该行。"""

        def __init__(self):
            self.calls = 0

        def complete(self, system, user):
            self.calls += 1
            import json
            import re
            fm = re.search(r"```c\n(.*?)\n```", user, re.S)
            src_text = fm.group(1) if fm else ""
            fixed = "\n".join(ln for ln in src_text.splitlines()
                              if "ecdet_deliberate_broken_line" not in ln)
            return json.dumps({"patched_harness": fixed,
                               "changes": "删除语法坏行"},
                              ensure_ascii=False)

    # 注入一条真正的语法错误（初始化缺表达式；无打桩模式可修）
    harness.source = harness.source.replace(
        "static const int",
        "int ecdet_deliberate_broken_line = ;\nstatic const int")

    fixer = LlmHarnessFixer(FakeLlm())
    ok, err = compile_harness(harness, tmp_path, [tmp_path], fixer=fixer)
    assert ok, err
    assert fixer.calls >= 1, "LLM 修正闭环应被触发"
    assert "ecdet_deliberate_broken_line" not in harness.source


def test_no_fixer_fails_gracefully(tmp_path):
    """无 fixer 且打桩不可修复 → 明确失败（不挂起）。"""
    (tmp_path / "broken.c").write_text(BROKEN_C, encoding="utf-8")
    facts = [build_file_facts("broken.c", BROKEN_C)]
    ctx = finalize_facts(facts)
    func = next(f for f in ctx.facts[0].functions if f.name == "broken_fn")
    model = build_input_model(func)
    harness = generate_harness(model, "broken.c", n_seeds=2)
    ok, err = compile_harness(harness, tmp_path, [tmp_path])
    assert not ok and err


def test_engine_with_fixer_still_finds_crashes(tmp_path):
    """修正钩子不影响正常路径：除零 PoC 照常触发。"""
    src = textwrap.dedent("""\
        #include <stdint.h>
        int scale_value(int base, int divisor) { return base / divisor; }
        """)

    class NoopClient:
        """编译一次通过时不应被调用的客户端探针。"""

        calls = 0

        def complete(self, system, user):
            NoopClient.calls += 1
            return "不输出有效 JSON"

    (tmp_path / "m.c").write_text(src, encoding="utf-8")
    facts = [build_file_facts("m.c", src)]
    engine = DynamicEngine(max_functions=4, max_seeds=17,
                           fixer=LlmHarnessFixer(NoopClient()))
    findings = engine.run(tmp_path, facts)
    assert any(f.func_name == "scale_value" for f in findings)
    assert NoopClient.calls == 0, "编译一次通过时不得触发 LLM 修正"


# ---------------- 三级载体梯度 ----------------


def test_carrier_probe_reports_all_tiers():
    infos = {c.name: c for c in probe_carriers()}
    assert set(infos) == {"host", "unicorn", "renode"}
    assert infos["host"].tier == 1 and infos["host"].available
    assert infos["unicorn"].tier == 2 and not infos["unicorn"].available
    assert "unicorn" in infos["unicorn"].note
    assert infos["renode"].tier == 3 and not infos["renode"].available


def test_pick_carrier_prefers_highest_throughput():
    carrier, info = pick_carrier()
    assert carrier is HostCarrier and info.available


def test_pick_carrier_explicit_unavailable():
    carrier, info = pick_carrier("renode")
    assert carrier is None and info.available is False
