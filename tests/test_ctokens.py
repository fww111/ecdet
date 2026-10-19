# -*- coding: utf-8 -*-
"""L3 词法器测试：注释遮蔽、字符串处理、预处理指令、行号保持。"""

from ecdet.l3_analysis.builtin_rules.ctokens import lex_c


def test_line_comment_masked():
    r = lex_c('int x; /* 注释里的 code() 应被遮蔽 */ int y;\n')
    joined = "\n".join(r.clean_lines)
    assert "code" not in joined.replace("int", "")
    assert "注释" not in joined
    toks = [t.value for t in r.tokens]
    assert toks[:2] == ["int", "x"]


def test_block_comment_keeps_line_numbers():
    src = "int a;\n/* 多行\n注释 */\nint b;\n"
    r = lex_c(src)
    b = [t for t in r.tokens if t.value == "b"]
    assert b and b[0].line == 4


def test_string_content_masked_but_kind_kept():
    r = lex_c('const char *s = "printf( should not match";\n')
    strs = [t for t in r.tokens if t.kind == "string"]
    assert len(strs) == 1
    idents = [t.value for t in r.tokens if t.kind == "ident"]
    assert "printf" not in idents
    assert "should" not in idents


def test_pp_lines_collected():
    src = '#include <stdint.h>\n#define A 1\n#define MUL(a,b) ((a)*(b))\nint x;\n'
    r = lex_c(src)
    assert [p.directive for p in r.pp_lines] == ["include", "define", "define"]
    d2 = r.pp_lines[2]
    assert d2.macro_name == "MUL"
    assert d2.is_function_like
    assert d2.params == ["a", "b"]
    assert d2.body == "((a)*(b))"
    # 宏名不得进入普通 token 流
    idents = {t.value for t in r.tokens if t.kind == "ident"}
    assert "MUL" not in idents


def test_pp_directive_only_at_line_start():
    src = 'int a = 1; /* not pp */\nchar c = \'#\';\n'
    r = lex_c(src)
    assert r.pp_lines == []


def test_number_suffixes():
    r = lex_c("unsigned long x = 0x80000000UL;\n")
    nums = [t for t in r.tokens if t.kind == "number"]
    assert nums[0].value == "0x80000000UL"


def test_escaped_quote_in_string():
    r = lex_c('const char *s = "a \\" b"; call_out();\n')
    idents = {t.value for t in r.tokens if t.kind == "ident"}
    assert "call_out" in idents
    assert "b" not in idents
