# -*- coding: utf-8 -*-
"""内置规则测试：每条规则一个触发用例 + 关键防误报用例。"""

from ecdet.l3_analysis.builtin_rules.checks import (
    build_file_facts,
    finalize_facts,
    FILE_RULES,
    PROJECT_RULES,
)
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES

ALL_IDS = {r.rule_id for r in BUILTIN_RULES}


def _run_file(src: str, rules: set[str] | None = None, path="t.c"):
    facts = [build_file_facts(path, src)]
    ctx = finalize_facts(facts)
    active = rules or ALL_IDS
    alerts = []
    seen: dict = {}
    for rid, fn in FILE_RULES.items():
        if rid in active:
            seen.setdefault(fn, set()).add(rid)
    for fn, rids in seen.items():
        alerts.extend(fn(facts[0], ctx, rids))
    project_seen: dict = {}
    for rid, fn in PROJECT_RULES.items():
        if rid in active:
            project_seen.setdefault(fn, set()).add(rid)
    for fn, rids in project_seen.items():
        alerts.extend(fn(ctx, rids))
    return alerts


def _rule_ids(alerts):
    return {a.rule_id for a in alerts}


# ---------------- 触发用例 ----------------

def test_rule_goto():
    alerts = _run_file("void f(void) { goto end; end: ; }")
    assert "MISRA C:2012 15.2" in _rule_ids(alerts)


def test_rule_multi_return():
    alerts = _run_file("int f(int x) { if (x) return 1; return 0; }")
    assert "MISRA C:2012 15.5" in _rule_ids(alerts)


def test_rule_switch_default_and_two_cases():
    src = "int f(int v) { switch (v) { case 1: return 1; } return 0; }"
    ids = _rule_ids(_run_file(src))
    assert "MISRA C:2012 16.4" in ids
    assert "MISRA C:2012 16.6" in ids


def test_rule_recursion():
    alerts = _run_file("int f(int n) { return f(n - 1); }")
    assert "MISRA C:2012 17.2" in _rule_ids(alerts)


def test_rule_strcpy_overflow():
    src = 'void f(void) { char b[4]; strcpy(b, "too long string"); }'
    alerts = _run_file(src)
    assert "CERT C STR31-C" in _rule_ids(alerts)
    assert any(a.severity.value == "error" for a in alerts)


def test_rule_array_index():
    src = "int f(void) { int a[3] = {0}; a[5] = 1; return a[0]; }"
    alerts = _run_file(src)
    assert "CERT C ARR30-C" in _rule_ids(alerts)


def test_rule_truncation():
    src = "void f(void) { uint8_t x = 300; (void)x; }"
    alerts = _run_file(src)
    assert "ECDET-CWE-197" in _rule_ids(alerts)
    assert "uint8_t x = 300 超出 8 位" in alerts[0].message


def test_rule_gets():
    alerts = _run_file('void f(void) { char b[8]; gets(b); }')
    assert "ECDET-CWE-242" in _rule_ids(alerts)


def test_rule_scanf_unbounded():
    alerts = _run_file('void f(void) { char b[8]; (void)scanf("%s", b); }')
    assert "ECDET-CWE-1284" in _rule_ids(alerts)


def test_rule_format_string():
    alerts = _run_file('void f(const char *p) { printf(p); }')
    assert "CERT C FIO30-C" in _rule_ids(alerts)


def test_rule_rand():
    alerts = _run_file("int f(void) { return rand(); }")
    assert "CERT C MSC30-C" in _rule_ids(alerts)


def test_rule_macro_parens():
    src = "#define MUL(a, b) (a * b)\nvoid f(void) { int r = MUL(1, 2); (void)r; }"
    alerts = _run_file(src)
    assert "CERT C PRE31-C" in _rule_ids(alerts)


def test_rule_logic_side_effect_inc():
    src = "int f(int a) { int c = 0; if (a > 0 && c++ > 1) { c = 2; } return c; }"
    alerts = _run_file(src)
    assert "MISRA C:2012 13.5" in _rule_ids(alerts)


def test_rule_logic_side_effect_call():
    src = "int g(void) { return 1; } int f(int a) { return (a > 0) || g(); }"
    alerts = _run_file(src)
    assert "MISRA C:2012 13.5" in _rule_ids(alerts)


def test_rule_for_counter_modified():
    src = "int f(void) { int i; int s = 0; for (i = 0; i < 10; i++) { i = i + 2; s += i; } return s; }"
    alerts = _run_file(src)
    assert "MISRA C:2012 14.2" in _rule_ids(alerts)


def test_rule_reserved_ident():
    alerts = _run_file("void __my_func(void) { }")
    assert "MISRA C:2012 21.1" in _rule_ids(alerts)


def test_rule_banned_atoi():
    alerts = _run_file('void f(const char *s) { (void)atoi(s); }')
    assert "MISRA C:2012 21.3" in _rule_ids(alerts)


def test_rule_stdio_printf():
    alerts = _run_file('void f(void) { (void)printf("hi"); }')
    assert "MISRA C:2012 21.6" in _rule_ids(alerts)


def test_rule_unused_macro():
    alerts = _run_file("#define NEVER_USED 42\nvoid f(void) { }")
    assert "MISRA C:2012 2.5" in _rule_ids(alerts)


def test_rule_unsigned_suffix():
    alerts = _run_file("unsigned long f(void) { return 0xFFFFFFFF00000000; }")
    assert "MISRA C:2012 7.2" in _rule_ids(alerts)


def test_rule_unused_param():
    alerts = _run_file("int f(int used, int unused) { return used; }")
    assert "ECDET-CWE-563" in _rule_ids(alerts)


def test_rule_implicit_decl():
    alerts = _run_file("int f(void) { return totally_unknown_fn(); }")
    assert "MISRA C:2012 17.3" in _rule_ids(alerts)


def test_rule_single_tu_var():
    src = "int g_only_here = 1;\nint f(void) { return g_only_here; }"
    alerts = _run_file(src)
    assert "MISRA C:2012 8.9" in _rule_ids(alerts)


# ---------------- 防误报用例 ----------------

def test_clean_code_no_alerts():
    src = """#include <stdint.h>

static uint8_t s_state;

static int step(int v)
{
    uint8_t local = 5u;
    int arr[4] = {0, 1, 2, 3};

    if (v < 0) {
        return -1;
    }
    arr[0] = local;
    s_state = (uint8_t)v;
    return arr[0] + v;
}

int main(void)
{
    return step(1);
}
"""
    alerts = _run_file(src)
    ids = _rule_ids(alerts)
    # 干净代码：不触发任何高危/规范违例
    assert not (ids & {
        "CERT C STR31-C", "CERT C ARR30-C", "CERT C FIO30-C", "CERT C MSC30-C",
        "CERT C PRE31-C", "ECDET-CWE-242", "ECDET-CWE-197", "ECDET-CWE-1284",
        "MISRA C:2012 15.2", "MISRA C:2012 16.4", "MISRA C:2012 17.2",
        "MISRA C:2012 13.5", "MISRA C:2012 14.2", "MISRA C:2012 21.1",
        "MISRA C:2012 21.3", "MISRA C:2012 17.3", "MISRA C:2012 8.9",
    }), alerts


def test_macro_parens_ok_not_flagged():
    src = "#define MUL(a, b) ((a) * (b))\nvoid f(void) { int r = MUL(1, 2); (void)r; }"
    alerts = _run_file(src, rules={"CERT C PRE31-C"})
    assert alerts == []


def test_scanf_with_width_ok():
    alerts = _run_file('void f(void) { char b[8]; (void)scanf("%7s", b); }',
                       rules={"ECDET-CWE-1284"})
    assert alerts == []


def test_array_decl_line_not_flagged_as_access():
    alerts = _run_file("void f(void) { int a[4] = {0}; a[3] = 1; (void)a; }",
                       rules={"CERT C ARR30-C"})
    assert alerts == []


def test_strcpy_fitting_ok():
    alerts = _run_file('void f(void) { char b[16]; strcpy(b, "short"); (void)b; }',
                       rules={"CERT C STR31-C"})
    assert alerts == []


def test_isr_not_flagged_as_single_tu():
    alerts = _run_file("void EXTI0_IRQHandler(void) { }",
                       rules={"MISRA C:2012 8.7"})
    assert alerts == []


def test_rule_implicit_decl_header_prototype_resolved():
    """回归：include 目标曾因 PPLine.text 遮蔽而解析失败（原型被视为不可见）。

    本地头文件中声明的函数不应再报 17.3。
    """
    header = "int sensor_read(void);\n"
    src = '#include "sensor.h"\nint main(void) { return sensor_read(); }\n'
    h_facts = build_file_facts("sensor.h", header)
    c_facts = build_file_facts("main.c", src)
    ctx = finalize_facts([h_facts, c_facts])
    alerts = ctx_rule17(ctx)
    assert alerts == [], alerts


def ctx_rule17(ctx):
    from ecdet.l3_analysis.builtin_rules.checks import PROJECT_RULES
    fn = PROJECT_RULES["MISRA C:2012 17.3"]
    return fn(ctx, {"MISRA C:2012 17.3"})
