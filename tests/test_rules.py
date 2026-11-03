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
    assert "MISRA C:2012 15.1" in _rule_ids(alerts)


def test_rule_goto_backward():
    alerts = _run_file("void f(void) { loop: ; goto loop; }")
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
    assert "MISRA C:2012 20.7" in _rule_ids(alerts)


def test_rule_macro_side_effect():
    src = ("#define MAX(a, b) ((a) > (b) ? (a) : (b))\n"
           "int f(void) { int i = 0; int r = MAX(i++, 0); return r + i; }")
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
    assert "MISRA C:2012 21.7" in _rule_ids(alerts)


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
        "MISRA C:2012 15.1", "MISRA C:2012 15.2",
        "MISRA C:2012 16.4", "MISRA C:2012 17.2",
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


# ---------------- 2026-11 缺口核验批次：触发用例 ----------------

def test_rule_bitfield_type():
    alerts = _run_file("struct S { unsigned char a : 3; };")
    assert "MISRA C:2012 6.1" in _rule_ids(alerts)


def test_rule_bitfield_type_ok():
    alerts = _run_file("struct S { unsigned int a : 3; };",
                       rules={"MISRA C:2012 6.1"})
    assert alerts == []


def test_rule_ptr_to_int():
    alerts = _run_file("unsigned int f(int *p) { return (unsigned int)p; }")
    assert "MISRA C:2012 11.4" in _rule_ids(alerts)


def test_rule_int_to_ptr():
    alerts = _run_file("void f(void) { char *p = (char *)0x40000000; (void)p; }")
    assert "MISRA C:2012 11.4" in _rule_ids(alerts)


def test_rule_const_qualifier_removed():
    alerts = _run_file("void f(const char *s) { char *p = (char *)s; (void)p; }")
    assert "MISRA C:2012 11.8" in _rule_ids(alerts)


def test_rule_ptr_type_mismatch():
    alerts = _run_file("void f(char *p) { int *q = (int *)p; (void)q; }")
    assert "MISRA C:2012 11.3" in _rule_ids(alerts)


def test_rule_ptr_cast_same_type_ok():
    alerts = _run_file("void f(char *p) { char *q = (char *)p; (void)q; }",
                       rules={"MISRA C:2012 11.3", "MISRA C:2012 11.4",
                              "MISRA C:2012 11.8", "CERT C INT36-C"})
    assert alerts == []


def test_rule_const_overflow_signed():
    alerts = _run_file("int f(void) { int x = 2000000000 + 1000000000; return x; }")
    assert "CERT C INT32-C" in _rule_ids(alerts)


def test_rule_const_wrap_unsigned():
    alerts = _run_file("unsigned f(void) { unsigned x = 4294967295u + 2u; return x; }")
    assert "CERT C INT30-C" in _rule_ids(alerts)


def test_rule_const_arithmetic_in_range_ok():
    alerts = _run_file("int f(void) { int x = 100 + 200; return x; }",
                       rules={"CERT C INT32-C", "CERT C INT30-C", "ECDET-CWE-190"})
    assert alerts == []


def test_rule_shift_count_overflow():
    alerts = _run_file("int f(void) { unsigned int x = 1u; return (int)(x << 32); }")
    assert "MISRA C:2012 12.2" in _rule_ids(alerts)


def test_rule_shift_count_literal():
    alerts = _run_file("int f(void) { return 1 << 40; }")
    assert "MISRA C:2012 12.2" in _rule_ids(alerts)


def test_rule_shift_count_boundary_ok():
    alerts = _run_file("int f(void) { return 1 << 31; }",
                       rules={"MISRA C:2012 12.2"})
    assert alerts == []


def test_rule_sizeof_side_effect():
    alerts = _run_file("int f(void) { int x = 1; return (int)sizeof(x++); }")
    assert "MISRA C:2012 13.6" in _rule_ids(alerts)


def test_rule_sizeof_plain_operand_ok():
    alerts = _run_file("int f(void) { int x = 1; return (int)sizeof(x); }",
                       rules={"MISRA C:2012 13.6"})
    assert alerts == []


def test_rule_invariant_condition():
    alerts = _run_file("int f(void) { if (1) { return 2; } return 0; }")
    assert "MISRA C:2012 14.3" in _rule_ids(alerts)


def test_rule_unreachable_after_return():
    alerts = _run_file("int f(void) { return 1; int x = 2; return x; }")
    assert "MISRA C:2012 2.1" in _rule_ids(alerts)


def test_rule_switch_case_fallthrough():
    src = ("int f(int x) { switch (x) { case 1: x = 2; case 2: return 3; "
           "default: return 0; } }")
    alerts = _run_file(src)
    assert "MISRA C:2012 16.3" in _rule_ids(alerts)


def test_rule_return_local_address():
    alerts = _run_file("int *f(void) { int x = 1; return &x; }")
    assert "MISRA C:2012 18.6" in _rule_ids(alerts)


def test_rule_vla():
    alerts = _run_file("int f(int n) { int a[n]; a[0] = 1; return a[0]; }")
    assert "MISRA C:2012 18.8" in _rule_ids(alerts)


def test_rule_fixed_array_ok():
    alerts = _run_file("int f(void) { int a[4]; a[0] = 1; return a[0]; }",
                       rules={"MISRA C:2012 18.8"})
    assert alerts == []


def test_rule_pp_condition_not_boolean():
    alerts = _run_file("#if 2\nint x;\n#endif\n")
    assert "MISRA C:2012 20.8" in _rule_ids(alerts)


def test_rule_pp_stringize_operator():
    alerts = _run_file("#define STR(x) #x\nint f(void) { return 0; }")
    assert "MISRA C:2012 20.10" in _rule_ids(alerts)


def test_rule_copy_source_oob():
    src = "void f(void) { char src[4]; char dst[8]; memcpy(dst, src, 8); }"
    alerts = _run_file(src)
    assert "MISRA C:2012 21.17" in _rule_ids(alerts)


def test_rule_copy_source_in_bounds_ok():
    src = "void f(void) { char src[4]; char dst[8]; memcpy(dst, src, 4); }"
    alerts = _run_file(src, rules={"MISRA C:2012 21.17"})
    assert alerts == []


def test_rule_assignment_in_if():
    alerts = _run_file("int f(int a, int b) { if (a = b) { return a; } return 0; }")
    assert "CERT C EXP45-C" in _rule_ids(alerts)


def test_rule_free_address_of_object():
    alerts = _run_file("void f(void) { int x; free(&x); }")
    assert "CERT C MEM34-C" in _rule_ids(alerts)


def test_rule_free_array():
    alerts = _run_file("void f(void) { char b[4]; free(b); }")
    assert "CERT C MEM34-C" in _rule_ids(alerts)


def test_rule_hardcoded_secret():
    alerts = _run_file('char *password = "secret123";')
    assert "CERT C MSC41-C" in _rule_ids(alerts)


def test_rule_secret_in_comment_not_flagged():
    alerts = _run_file('// password = "secret123"\nint f(void) { return 0; }',
                       rules={"CERT C MSC41-C"})
    assert alerts == []


def test_rule_large_stack_array():
    alerts = _run_file("void f(void) { int big[512]; big[0] = 1; }")
    assert "ECDET-CWE-785" in _rule_ids(alerts)


def test_rule_small_stack_array_ok():
    alerts = _run_file("void f(void) { int a[64]; a[0] = 1; }",
                       rules={"ECDET-CWE-785"})
    assert alerts == []


def test_rule_external_object_defined_twice():
    ctx = finalize_facts([
        build_file_facts("a.c", "int g_dup = 1;\n"),
        build_file_facts("b.c", "int g_dup = 2;\n"),
    ])
    fn = PROJECT_RULES["MISRA C:2012 8.5"]
    alerts = fn(ctx, {"MISRA C:2012 8.5"})
    assert len(alerts) == 2
    assert all(a.rule_id == "MISRA C:2012 8.5" for a in alerts)


def test_rule_external_object_static_ok():
    ctx = finalize_facts([
        build_file_facts("a.c", "static int g_a = 1;\n"),
        build_file_facts("b.c", "static int g_a = 2;\n"),
    ])
    fn = PROJECT_RULES["MISRA C:2012 8.5"]
    assert fn(ctx, {"MISRA C:2012 8.5"}) == []


def test_rule_goto_forward_ok():
    alerts = _run_file("void f(void) { goto end; end: ; }",
                       rules={"MISRA C:2012 15.2"})
    assert alerts == []


# ---------------- 代码评审回归（PR #2 留言） ----------------

def test_rule_memcpy_int_array_in_bounds_ok():
    """int 数组字节容量 = 元素数 × 4，8 字节拷贝不越界。"""
    src = "void f(void) { int src[4]; int dst[4]; memcpy(dst, src, 8); }"
    alerts = _run_file(src, rules={"MISRA C:2012 21.17"})
    assert alerts == []


def test_rule_memcpy_uint16_array_oob():
    """uint16_t 数组字节容量 = 元素数 × 2，5 字节拷贝越界。"""
    src = "void f(void) { uint16_t src[2]; uint8_t dst[8]; memcpy(dst, src, 5); }"
    alerts = _run_file(src)
    assert "MISRA C:2012 21.17" in _rule_ids(alerts)


def test_rule_local_pointer_qual_cast():
    src = 'void f(void) { const char *s = "x"; char *p = (char *)s; (void)p; }'
    alerts = _run_file(src)
    assert "MISRA C:2012 11.8" in _rule_ids(alerts)


def test_rule_global_pointer_qual_cast():
    src = 'const int *gp; void f(void) { int *p = (int *)gp; (void)p; }'
    alerts = _run_file(src)
    assert "MISRA C:2012 11.8" in _rule_ids(alerts)


def test_rule_local_ptr_to_int():
    src = "unsigned int f(void) { char *p = 0; return (unsigned int)p; }"
    alerts = _run_file(src)
    assert "MISRA C:2012 11.4" in _rule_ids(alerts)


def test_rule_const_expr_precedence_no_false_positive():
    """乘法优先级高于加法：2000000000 + 1000000000 * 0 不溢出。"""
    alerts = _run_file("int f(void) { int x = 2000000000 + 1000000000 * 0; return x; }",
                       rules={"CERT C INT32-C", "CERT C INT30-C", "ECDET-CWE-190"})
    assert alerts == []


def test_rule_const_expr_precedence_real_overflow():
    """1 + 2 * 2000000000 = 4000000001，超出 int32。"""
    alerts = _run_file("int f(void) { int x = 1 + 2 * 2000000000; return x; }")
    assert "CERT C INT32-C" in _rule_ids(alerts)


def test_rule_const_expr_paren_overflow():
    alerts = _run_file("int f(void) { int x = (2000000000 + 1000000000) * 0; return x; }")
    assert "CERT C INT32-C" in _rule_ids(alerts)


def test_rule_static_local_addr_not_flagged():
    src = "int *f(void) { static int x; return &x; }"
    alerts = _run_file(src, rules={"MISRA C:2012 18.6", "ECDET-CWE-562"})
    assert alerts == []
