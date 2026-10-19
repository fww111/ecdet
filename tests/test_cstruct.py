# -*- coding: utf-8 -*-
"""L3 结构解析测试：函数边界、switch 归属、数组声明。"""

from ecdet.l3_analysis.builtin_rules.cstruct import (
    parse_array_decls,
    parse_functions,
    parse_switches,
)
from ecdet.l3_analysis.builtin_rules.ctokens import lex_c


def _funcs(src):
    lex = lex_c(src)
    return lex, parse_functions(lex)


def test_function_detection_basic():
    src = """int add(int a, int b) { return a + b; }
void empty(void) { }
"""
    lex, funcs = _funcs(src)
    assert [f.name for f in funcs] == ["add", "empty"]
    add = funcs[0]
    assert add.def_line == 1
    assert add.body_close_line == 1
    assert add.n_returns == 1


def test_struct_and_initializer_not_functions():
    src = """struct point { int x; int y; };
enum color { RED, GREEN };
int table[3] = {1, 2, 3};
typedef struct { int a; } handle_t;
"""
    _, funcs = _funcs(src)
    assert funcs == []


def test_multiline_function_body():
    src = """int calc(int v)
{
    int r = v * 2;
    return r;
}
"""
    _, funcs = _funcs(src)
    assert len(funcs) == 1
    f = funcs[0]
    assert f.body_open_line == 2
    assert f.body_close_line == 5


def test_switch_with_nested():
    src = """int f(int a, int b) {
    switch (a) {
    case 1:
        switch (b) {
        case 2: return 1;
        default: return 2;
        }
    case 3:
        return 3;
    }
    return 0;
}
"""
    lex, funcs = _funcs(src)
    sws = parse_switches(funcs[0])
    assert len(sws) == 2
    outer = sws[0]
    inner = sws[1]
    assert outer.case_count == 2          # 1 和 3，嵌套 case 不计入
    assert not outer.has_default
    assert inner.case_count == 1
    assert inner.has_default


def test_array_decls():
    src = """static uint8_t buf[64];
int global_arr[4] = {0};
void f(void) {
    char local[8];
    int other = 1;
    (void)other; (void)local; (void)buf; (void)global_arr;
}
"""
    lex = lex_c(src)
    funcs = parse_functions(lex)
    func_lines = set()
    for f in funcs:
        func_lines.update(range(f.def_line, f.body_close_line + 1))
    decls = {a.name: a for a in parse_array_decls(lex, func_lines)}
    assert decls["buf"].size == 64 and decls["buf"].is_global
    assert decls["global_arr"].size == 4
    assert "local" in decls and not decls["local"].is_global
    assert "other" not in decls


def test_calls_in_body():
    src = """int f(void) { helper(1); other(); return 0; }
"""
    _, funcs = _funcs(src)
    calls = {name for name, _ in funcs[0].calls_in_body()}
    assert calls == {"helper", "other"}
