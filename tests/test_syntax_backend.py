"""Optional C syntax extraction preserves source ranges and uncertainty."""
import builtins

import pytest

from ecdet.l3_analysis.syntax import parse_c_syntax


@pytest.fixture
def enhanced():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def test_functions_have_precise_multiline_and_same_line_ranges(enhanced):
    source='static int\nfirst(int a) { return a; } int second(void) { return first(2); }\n'
    index=parse_c_syntax(source,'m.c',backend='tree-sitter')
    assert index.status=='PASS'
    assert [f.name for f in index.functions]==['first','second']
    first,second=index.functions
    assert first.is_static and first.params==('a',)
    assert first.start_line==1 and first.def_line==2 and first.end_line==2
    assert first.signature=='static int\nfirst(int a)'
    raw=source.encode('utf-8')
    assert raw[first.start_byte:first.end_byte].decode()=='static int\nfirst(int a) { return a; }'
    assert raw[second.start_byte:second.end_byte].decode()=='int second(void) { return first(2); }'
    assert second.start_col==source.splitlines()[1].index('int second')+1
    assert second.end_col==len(source.splitlines()[1])+1
    assert [(c.name,c.kind,c.line) for c in second.calls]==[('first','direct',2)]


def test_utf8_columns_are_character_columns_bytes_remain_exact(enhanced):
    source='void f(void) { /*汉字*/ target(); }\n'
    index=parse_c_syntax(source,'中文.c')
    call=index.functions[0].calls[0]
    assert call.start_col==source.index('target')+1
    assert call.end_col==source.index('target')+len('target()')+1
    assert source.encode()[call.start_byte:call.end_byte].decode()=='target()'


def test_calls_exclude_comments_strings_and_mark_parameter_or_local_shadow(enhanced):
    source='''void f(void (*callback)(int)) {
      /* ghost(); */ const char *s="hidden()";
      int (*local)(int) = callback;
      callback(1); local(2); obj->method(3); (*callback)(4); real_call(5);
    }'''
    fn=parse_c_syntax(source,'m.c').functions[0]
    assert fn.params==('callback',)
    assert set(fn.local_names)=={'callback','s','local'}
    assert [c.expression for c in fn.calls]==['callback','local','obj->method','(*callback)','real_call']
    assert [c.kind for c in fn.calls]==['indirect','indirect','indirect','indirect','direct']
    assert fn.calls[-1].name=='real_call'
    assert all(c.name=='' for c in fn.calls[:-1])


def test_function_like_macros_are_not_confirmed_direct_calls(enhanced):
    source='#define APPLY(x) real_call(x)\nvoid f(void) { APPLY(2); real_call(3); }\n'
    index=parse_c_syntax(source,'m.c')
    assert [f.name for f in index.functions]==['f']
    assert [(c.name,c.kind) for c in index.functions[0].calls]==[('APPLY','macro'),('real_call','direct')]


def test_conditional_definitions_and_calls_are_explicit_not_active_branches(enhanced):
    source='''#if 0
int hidden(void) { return 1; }
#else
int alternate(void) { return 2; }
#endif
int visible(void) {
#if FEATURE
 hidden();
#endif
 return alternate();
}
'''
    index=parse_c_syntax(source,'m.c')
    assert index.status=='PASS'
    hidden,alternate,visible=index.functions
    assert hidden.conditional and alternate.conditional
    assert not visible.conditional
    assert [(c.name,c.conditional) for c in visible.calls]==[('hidden',True),('alternate',False)]


def test_conditions_and_assignments_have_source_spans(enhanced):
    source='int f(int n) { int x=0; if(n>0) { x=n; } while(x<5) x+=1; return x ? x : n; }'
    index=parse_c_syntax(source,'m.c')
    assert [c.text for c in index.conditions]==['(n>0)','(x<5)','x']
    assert [(a.target,a.operator,a.value) for a in index.assignments]==[('x','=','n'),('x','+=','1')]
    assert all(source.encode()[a.start_byte:a.end_byte].decode()==a.text for a in index.assignments)


def test_function_prototype_does_not_shadow_direct_call(enhanced):
    fn=parse_c_syntax('void f(void) { int helper(int); helper(2); }','m.c').functions[0]
    assert fn.calls[0].kind=='direct' and fn.calls[0].name=='helper'


def test_global_function_pointer_not_resolved_as_a_direct_function(enhanced):
    fn=parse_c_syntax('static int (*handler)(int); int f(void) { return handler(2); }','m.c').functions[0]
    assert fn.calls[0].kind=='indirect' and fn.calls[0].name==''


def test_function_returning_pointer_uses_its_own_parameter_list(enhanced):
    source='int (*factory(int value))(int) { return get_callback(value); }'
    fn=parse_c_syntax(source,'m.c').functions[0]
    assert fn.name=='factory' and fn.params==('value',)
    assert fn.calls[0].name=='get_callback'


def test_nested_function_scope_is_not_published_as_global_index(enhanced):
    source='int outer(void) { int inner(void) { return helper(); } return inner(); }'
    index=parse_c_syntax(source,'gnu.c')
    assert index.status=='ERROR' and index.functions==()
    assert index.diagnostics[0]['kind']=='UNSUPPORTED_NESTED_FUNCTION'


def test_backend_runtime_failure_is_not_silently_basic(monkeypatch,enhanced):
    import tree_sitter_c
    def broken():
        raise RuntimeError('backend failure')
    monkeypatch.setattr(tree_sitter_c,'language',broken)
    result=parse_c_syntax('void f(void) {}','m.c')
    assert result.status=='ERROR' and result.functions==()


@pytest.mark.parametrize('source',['void f( { x(); }','void f(void) { if (1) return;','void f(void) { int x = ; }'])
def test_recovered_tree_not_published_as_reliable_index(enhanced,source):
    index=parse_c_syntax(source,'broken.c')
    assert index.status=='PARSE_ERROR'
    assert index.functions==() and index.conditions==() and index.assignments==()
    assert index.diagnostics and any(d['kind'] in {'ERROR','MISSING'} for d in index.diagnostics)


def test_optional_dependency_unavailable_is_explicit(monkeypatch):
    original=builtins.__import__
    def importing(name,*args,**kwargs):
        if name in {'tree_sitter','tree_sitter_c'}:
            raise ModuleNotFoundError('missing syntax extra',name=name)
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',importing)
    index=parse_c_syntax('void f(void) {}','m.c')
    assert index.status=='UNAVAILABLE'
    assert index.functions==() and index.backend=='tree-sitter'
    assert any('ecdet[syntax]' in d['message'] for d in index.diagnostics)


def test_basic_selection_does_not_claim_ast():
    index=parse_c_syntax('void f(void) {}','m.c',backend='builtin')
    assert index.status=='DISABLED' and index.backend=='builtin'
    assert index.functions==()


def test_unknown_backend_is_error():
    with pytest.raises(ValueError):
        parse_c_syntax('','m.c',backend='unknown')


def test_empty_translation_unit_is_valid(enhanced):
    index=parse_c_syntax('/* only a comment */\n','empty.c')
    assert index.status=='PASS' and index.functions==()
