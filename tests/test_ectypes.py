# -*- coding: utf-8 -*-
"""C 整型提升模型与 MISRA 10.3/10.4 测试（方案 3.3.3 UsualArithType 实现）。"""

import textwrap

from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.builtin_rules.ectypes import (
    INT8,
    INT32,
    INT64,
    UINT32,
    UINT8,
    UINT64,
    build_type_table,
    integer_promote,
    literal_type,
    resolve_type,
    usual_arith,
)

# ---------------- 类型模型 ----------------


def test_resolve_type_aliases():
    assert resolve_type("uint8_t") == UINT8
    assert resolve_type("unsigned char") == UINT8
    assert resolve_type("int") == INT32
    assert resolve_type("unsigned int") == UINT32
    assert resolve_type("unsigned long") == UINT32        # ILP32
    assert resolve_type("uint32_t") == UINT32
    assert resolve_type("float") is None
    assert resolve_type("my_struct_t") is None


def test_integer_promotion():
    assert integer_promote(UINT8) == INT32                # 8 位提升为 int
    assert integer_promote(INT32) == INT32
    assert integer_promote(UINT32) == UINT32              # 秩 >= int 不提升


def test_usual_arith_conversions():
    assert usual_arith(UINT8, UINT8) == INT32             # 提升后同 int
    assert usual_arith(UINT32, INT32) == UINT32           # 混算：无符号同秩胜
    assert usual_arith(INT32, UINT8) == INT32             # 有符号高秩胜
    assert usual_arith(UINT64, INT32) == UINT64           # 无符号高秩胜
    assert usual_arith(INT64, UINT32) == INT64            # 有符号高秩可表示


def test_literal_type_smallest_fitting():
    assert literal_type("3") == INT8
    assert literal_type("300").rank == 2                  # int16 可表示
    assert literal_type("40000").rank == 3
    assert literal_type("1u").signed is False
    assert literal_type("0xFFFFFFFF") == INT64            # 超出 int32 → int64
    assert literal_type("-1") == INT8
    assert literal_type("10000000000") == INT64


def test_type_table_globals_and_locals():
    src = textwrap.dedent("""\
        #include <stdint.h>
        static uint32_t g_counter;
        int g_flag;
        static int helper(int v)
        {
            uint8_t local = 1u;
            return local + v;
        }
        """)
    facts = build_file_facts("t.c", src)
    table = build_type_table(facts.lex, facts.func_lines,
                             functions=facts.functions)
    assert table["g_counter"] == UINT32
    assert table["g_flag"] == INT32
    assert table["local"] == UINT8
    assert table["v"] == INT32


# ---------------- MISRA 10.3 ----------------


def _run10(src: str):
    from tests.test_rules import _run_file
    return [a for a in _run_file(textwrap.dedent(src))
            if a.rule_id.startswith("MISRA C:2012 10")]


def test_103_signedness_change():
    src = """\
        #include <stdint.h>
        int32_t dst;
        uint32_t src_v;
        void f(void) { dst = src_v; }
        """
    alerts = _run10(src)
    assert len(alerts) == 1 and alerts[0].rule_id == "MISRA C:2012 10.3"
    assert "符号性改变" in alerts[0].message


def test_103_rank_narrowing():
    src = """\
        #include <stdint.h>
        uint8_t dst;
        int32_t src_v;
        void f(void) { dst = src_v; }
        """
    alerts = _run10(src)
    assert len(alerts) == 1 and "秩收窄" in alerts[0].message


def test_103_negative_literal_to_unsigned():
    src = """\
        #include <stdint.h>
        uint32_t dst;
        void f(void) { dst = -1; }
        """
    alerts = _run10(src)
    assert len(alerts) == 1
    assert "-1" in alerts[0].message and "超出" in alerts[0].message


def test_103_out_of_range_literal():
    src = """\
        #include <stdint.h>
        uint8_t dst;
        void f(void) { dst = 300; }
        """
    alerts = _run10(src)
    assert len(alerts) == 1 and "300" in alerts[0].message


def test_103_promoted_binary_to_unsigned():
    """u8+u8 提升为有符号 int → 赋无符号触发 10.3（严格 MISRA 行为）。"""
    src = """\
        #include <stdint.h>
        uint32_t dst;
        uint8_t a;
        uint8_t b;
        void f(void) { dst = a + b; }
        """
    alerts = _run10(src)
    assert any(a.rule_id == "MISRA C:2012 10.3" for a in alerts)


# ---------------- MISRA 10.4 ----------------


def test_104_mixed_signedness_operands():
    src = """\
        #include <stdint.h>
        int32_t s;
        uint32_t u;
        int32_t dst;
        void f(void) { dst = s + u; }
        """
    alerts = _run10(src)
    assert any(a.rule_id == "MISRA C:2012 10.4" for a in alerts)
    assert any("混用符号性" in a.message for a in alerts)


# ---------------- 防误报 ----------------


def test_10x_clean_code_no_alerts():
    src = """\
        #include <stdint.h>
        uint32_t dst;
        void f(void)
        {
            uint8_t small = 3;          /* 字面量宽松口径 */
            uint32_t u = 7;
            uint32_t w = 1u + 2u;       /* 常量折叠后无符号可表示 */
            uint32_t m = 0xFFFFFFFFu;
            int32_t s = 0;
            s = -5;                     /* 有符号可表示 */
            uint32_t arr[4] = {0};
            arr[0] = 1u;                /* lhs 数组跳过 */
            int r = unknown_call(1);    /* 调用 rhs 跳过 */
            s = (int32_t)u;             /* cast 合规路径 */
            for (int i = 0; i < 3; i++) {
                s = s + i;              /* 同为有符号 int32 */
            }
            (void)small; (void)w; (void)m; (void)r;
        }
        """
    assert _run10(src) == []


def test_103_cast_is_compliant_path():
    src = """\
        #include <stdint.h>
        uint8_t dst;
        int32_t src_v;
        void f(void) { dst = (uint8_t)src_v; }
        """
    assert _run10(src) == []
