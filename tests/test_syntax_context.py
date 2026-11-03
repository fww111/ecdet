"""Optional syntax indexes improve bounded context without changing rule facts."""
from types import SimpleNamespace
import json

import pytest

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l4_llm.slicer import slice_context
from ecdet.l4_llm.triage import TriageRunner


@pytest.fixture
def syntax_available():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def alert(line=1, col=1, path='t.c'):
    return Alert('AUDIT', 'audit', Severity.WARNING, 'candidate',
                 Location(path=path, line=line, col=col))


def test_file_facts_preserve_legacy_index_and_original_bytes(syntax_available):
    source='/* 中文 */\r\nint bad(void) { return 1; }\r\n'
    facts=build_file_facts('t.c',source)
    assert facts.source == source
    assert facts.functions[0].name=='bad'
    assert facts.syntax.status=='PASS'
    function=facts.syntax.functions[0]
    assert source.encode()[function.start_byte:function.end_byte].decode()=='int bad(void) { return 1; }'


def test_same_line_function_selection_uses_column_and_exact_bytes(syntax_available):
    source='int left(void) { return 111; } int bad(void) { return 222; }\n'
    result=slice_context(alert(col=source.index('222')+1),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name=='bad'
    assert result.function_text=='int bad(void) { return 222; }'
    assert '111' not in result.function_text
    assert result.truncated  # line-based repair must not remove the other function.
    assert result.provided_ranges[0]['partial_line']
    assert result.syntax_backends[0]['backend']=='tree-sitter'


def test_same_line_callee_is_not_dropped_by_same_line_identity(syntax_available):
    source='int helper(void) { return 5; } int bad(void) { return helper(); }\n'
    result=slice_context(alert(col=source.rindex('helper')+1),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name=='bad'
    assert 'int helper(void) { return 5; }' in '\n'.join(result.extras)
    assert 'int bad(void)' not in '\n'.join(result.extras)


def test_unicode_prefix_does_not_shift_column_selection(syntax_available):
    source='/* 中文注释 */ int left(void) { return 1; } int bad(void) { return 2; }\n'
    result=slice_context(alert(col=source.index('return 2')+1),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name=='bad'
    assert result.function_text.startswith('int bad(')
    assert '中文' not in result.function_text


def test_ast_range_includes_multiline_return_type(syntax_available):
    source='int\nbad(void)\n{\n return 2;\n}\n'
    result=slice_context(alert(line=4),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_start==1
    assert result.function_text.startswith('int\nbad')


def test_pointer_parameter_call_does_not_resolve_same_named_function(syntax_available):
    source='int callback(void) { return 111; }\nint bad(int (*callback)(void)) {\n return callback();\n}\n'
    result=slice_context(alert(line=3),finalize_facts([build_file_facts('t.c',source)]))
    assert 'return 111' not in result.render()
    assert any('callback' in item['name'] and item['reason']=='indirect call' for item in result.unresolved_calls)


def test_member_call_is_unresolved_instead_of_expanding_global_name(syntax_available):
    source='struct Ops { int (*run)(void); };\nint run(void) { return 111; }\nint bad(struct Ops *ops) {\n return ops->run();\n}\n'
    result=slice_context(alert(line=4),finalize_facts([build_file_facts('t.c',source)]))
    assert 'return 111' not in result.render()
    assert any('run' in item['name'] and item['reason']=='indirect call' for item in result.unresolved_calls)


def test_macro_call_does_not_expand_same_named_function(syntax_available):
    caller=build_file_facts('t.c','#define helper(x) (x)\nint bad(void) {\n return helper(1);\n}\n')
    callee=build_file_facts('helper.c','int helper(int x) { return 999; }\n')
    result=slice_context(alert(line=3),finalize_facts([caller,callee]))
    assert '#define helper' in result.render()
    assert 'return 999' not in result.render()
    assert any(item['name']=='helper' and item['reason']=='macro call' for item in result.unresolved_calls)


def test_unavailable_backend_fallback_is_explicit():
    facts=build_file_facts('t.c','int bad(void) {\n return 2;\n}\n')
    facts.syntax=SimpleNamespace(status='UNAVAILABLE',backend='builtin',diagnostics=('install syntax extra',),functions=())
    result=slice_context(alert(line=2),finalize_facts([facts]))
    assert result.func_name=='bad'
    assert result.syntax_backends[0]['status']=='UNAVAILABLE'
    assert result.syntax_backends[0]['selected']=='builtin'
    assert 'install syntax extra' in str(result.syntax_backends)
    assert '基础结构恢复' in result.render()


def test_parse_error_fallback_is_explicit(syntax_available):
    source='int bad(void) {\n return missing( ;\n}\n'
    facts=build_file_facts('t.c',source)
    assert facts.syntax.status=='PARSE_ERROR'
    result=slice_context(alert(line=2),finalize_facts([facts]))
    assert result.syntax_backends[0]['status']=='PARSE_ERROR'
    assert result.syntax_backends[0]['selected']=='builtin'


def test_triage_records_backend_and_exact_source_ranges(syntax_available):
    class Fake:
        def complete(self,*args):
            return json.dumps({'verdict':'TRUE_POSITIVE','confidence':0.9,'reason':'candidate','evidence_lines':[2]})
    result=TriageRunner(Fake()).triage(alert(line=2),finalize_facts([build_file_facts('t.c','int bad(void) {\n return 2;\n}\n')]))
    assert result.context['syntax_backends'][0]['backend']=='tree-sitter'
    assert result.context['provided_ranges'][0]['start_byte']==0


def test_crlf_window_spans_still_reference_original_bytes(syntax_available):
    source='int bad(void) {\r\n'+''.join(f' int x{i} = {i};\r\n' for i in range(30))+' return 2;\r\n}\r\n'
    result=slice_context(alert(line=15),finalize_facts([build_file_facts('t.c',source)]),budget_chars=70)
    assert result.truncated and result.n_chars<=70
    span=result.provided_ranges[0]
    original=source.encode()[span['start_byte']:span['end_byte']].decode()
    assert original.replace('\r\n','\n')==result.function_text
    assert span['start_line']<=15<=span['end_line']


def test_zero_budget_never_publishes_nonexistent_spans(syntax_available):
    result=slice_context(alert(),finalize_facts([build_file_facts('t.c','int bad(void) { return 2; }\n')]),budget_chars=0)
    assert result.function_text==''
    assert result.provided_ranges==[]
    assert result.truncated


def test_ambiguous_same_line_position_does_not_guess_a_function(syntax_available):
    source='    int left(void) { return 1; } int bad(void) { return 2; }\n'
    result=slice_context(alert(col=1),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name=='' and result.function_text==''
    assert result.truncated
    assert result.unresolved_calls[0]['reason']=='ambiguous function position'


def test_static_word_in_comment_does_not_hide_global_callee(syntax_available):
    caller=build_file_facts('t.c','int helper(void);\nint bad(void) { return helper(); }\n')
    callee=build_file_facts('helper.c','int /* static */ helper(void) { return 123; }\n')
    result=slice_context(alert(line=2),finalize_facts([caller,callee]))
    assert 'return 123' in result.render()


def test_conditional_definition_is_not_resolved_as_active_callee(syntax_available):
    caller=build_file_facts('t.c','int helper(void);\nint bad(void) { return helper(); }\n')
    callee=build_file_facts('helper.c','#if 0\nint helper(void) { return 777; }\n#endif\n')
    result=slice_context(alert(line=2),finalize_facts([caller,callee]))
    assert 'return 777' not in result.render()
    assert any(item['name']=='helper' and item['reason']=='conditional definition' for item in result.unresolved_calls)


def test_conditional_call_is_recorded_without_assuming_active_branch(syntax_available):
    source='int helper(void) { return 777; }\nint bad(void) {\n#if FEATURE\n helper();\n#endif\n return 2;\n}\n'
    result=slice_context(alert(line=6),finalize_facts([build_file_facts('t.c',source)]))
    assert 'return 777' not in result.render()
    assert any(item['name']=='helper' and item['reason']=='conditional call' for item in result.unresolved_calls)


def test_conditional_alert_function_requires_preprocessor_review(syntax_available):
    source='#if FEATURE\nint bad(void) { return 2; }\n#endif\n'
    result=slice_context(alert(line=2),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name=='bad'
    assert result.truncated
    assert result.provided_ranges[0]['conditional'] is True
    assert any(item['reason']=='conditional definition' for item in result.unresolved_calls)


def test_global_prefix_on_function_line_is_not_inside_function(syntax_available):
    source='int global=1; int bad(void) { return global; }\n'
    ctx=finalize_facts([build_file_facts('t.c',source)])
    global_slice=slice_context(alert(col=1),ctx)
    assert global_slice.func_name==''
    function_slice=slice_context(alert(col=source.index('return')+1),ctx)
    assert function_slice.func_name=='bad'


def test_global_suffix_on_function_line_is_not_inside_function(syntax_available):
    source='int bad(void) { return 2; } int global=1;\n'
    result=slice_context(alert(col=source.index('global')+1),finalize_facts([build_file_facts('t.c',source)]))
    assert result.func_name==''
