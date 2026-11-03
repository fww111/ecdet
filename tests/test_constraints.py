import builtins
import hashlib
import importlib.util

import pytest

from ecdet.l3_analysis.constraints import analyze_constraints


OPTIONAL=importlib.util.find_spec('z3') is not None and importlib.util.find_spec('tree_sitter_c') is not None
solver=pytest.mark.skipif(not OPTIONAL,reason='Optional Z3/C syntax dependencies not installed')


def one(source,**kwargs):
    report=analyze_constraints(source,'test.c',**kwargs)
    assert report.status=='COMPLETED',report.to_dict()
    assert len(report.results)==1,report.to_dict()
    return report,report.results[0]


@solver
def test_guarded_array_rejected_negative_is_sat():
    report,r=one('int bad(int n) { int a[8]={0}; if(n<8) return a[n]; return 0; }')
    assert r.status=='SAT'
    assert r.witness['n']<0
    alert=report.alerts()[0]
    assert alert.provenance.value=='suspected'
    assert alert.location.path=='test.c' and alert.location.col==47
    assert '(check-sat)' in r.constraints


@solver
def test_unsigned_guard_has_no_model_oob():
    report,r=one('int good(unsigned n) { int a[8]={0}; if(n<8u) return a[n]; return 0; }')
    assert r.status=='UNSAT'
    assert report.alerts()==[]


@solver
def test_early_returns_and_else_paths():
    _,r=one('int good(int n) { int a[8]={0}; if(n<0) return 0; else { if(n>=8) return 0; } return a[n]; }')
    assert r.status=='UNSAT'


@solver
def test_merge_preserves_different_local_values():
    _,r=one('int merge(int n) { int a[8]={0}; int i=0; if(n>0) i=9; else i=1; return a[i]; }')
    assert r.status=='SAT' and r.witness['n']>0


@solver
def test_fixed_width_parameters_and_integer_promotion():
    _,r=one('#include <stdint.h>\nint small(uint8_t n) { int a[256]={0}; return a[n+1]; }')
    assert r.status=='SAT' and r.witness['n']==255
    assert r.input_types['n']=={'bits':8,'signed':False}


@solver
def test_unsigned_32_add_wrap_is_preserved():
    _,r=one('int wrap(unsigned n) { int a[8]={0}; if(n==0xffffffffu) return a[n+1u]; return 0; }')
    assert r.status=='UNSAT'


@solver
def test_signed_overflow_does_not_become_a_safety_proof():
    _,r=one('int overflow(int n) { int a[8]={0}; if(n==2147483647) return a[(n+1)&7]; return 0; }')
    assert r.status=='UNSUPPORTED' and 'overflow' in r.reason


@solver
def test_signed_add_valid_input_found_with_overflow_excluded():
    _,r=one('int increment(int n) { int a[8]={0}; if(n>=0 && n<2147483647) return a[n+1]; return 0; }')
    assert r.status=='SAT' and 7<=r.witness['n']<2147483647


@solver
@pytest.mark.parametrize('body',[
    'for(int j=0;j<n;j++) a[j]=0; return a[n];',
    'unknown(); return a[n];',
    'return a[n/2];',
    'return a[n<<1];',
    'int *p=a; return a[n];',
    'return a[(unsigned)n];',
    'volatile int x=0; return a[n];',
])
def test_unsupported_never_silently_ignored(body):
    report,r=one('int f(int n) { int a[8]={0}; '+body+' }') if not body.startswith('for') else (None,None)
    if r is None:
        report=analyze_constraints('int f(int n) { int a[8]={0}; '+body+' }','test.c')
    assert report.results
    assert all(r.status=='UNSUPPORTED' for r in report.results)
    assert not report.alerts()


@solver
def test_compound_assignment_rejects_whole_function_not_earlier_partial():
    report=analyze_constraints('void f(int n) { int a[8]; a[n]=0; n+=1; }')
    assert [r.status for r in report.results]==['UNSUPPORTED']


@solver
def test_unknown_solver_resource_limit_is_explicit():
    _,r=one('int f(int n) { int a[8]={0}; return a[n]; }',resource_limit=1)
    assert r.status=='UNKNOWN' and r.reason


@solver
def test_utf8_location_and_source_identity():
    source='// 中文\nint f(int n) { int a[8]={0}; return a[n]; }'
    report,r=one(source)
    assert r.line==2 and r.expression=='a[n]'
    assert report.source_sha256==hashlib.sha256(source.encode()).hexdigest()
    assert r.source_sha256==report.source_sha256


@solver
def test_function_filter_and_missing_function():
    source='int a(int n){int x[2]={0};return x[n];}\nint b(unsigned n){int x[2]={0};if(n<2u)return x[n];return 0;}'
    _,r=one(source,function='b')
    assert r.function=='b' and r.status=='UNSAT'
    assert analyze_constraints(source,function='missing').status=='UNSUPPORTED'


@solver
def test_preprocessing_and_parse_errors_explicit():
    assert analyze_constraints('#define N 8\nint f(int n){int a[N];return a[n];}').status=='UNSUPPORTED'
    assert analyze_constraints('int f( {').status=='UNSUPPORTED'


@solver
def test_wrong_signedness_comparison_uses_usual_conversion():
    _,r=one('int mixed(int n) {int a[8]={0};if(n<8u)return a[n];return 0;}')
    assert r.status=='UNSAT'


@solver
def test_negative_uint8_conversion_uses_modulo_before_promotion():
    _,r=one('#include <stdint.h>\nint f(int n) {int a[256]={0};uint8_t i=n;return a[i];}')
    assert r.status=='UNSAT'


@solver
def test_short_circuit_avoids_unused_overflow_condition():
    _,r=one('int f(int n) {int a[8]={0};if(n<2147483647 && n+1<8 && n>=0)return a[n+1];return 0;}')
    assert r.status=='UNSAT'


@solver
def test_global_type_override_and_uninitialized_scalar_rejected():
    assert analyze_constraints('typedef unsigned int uint8_t; int f(uint8_t n){int a[8];return a[n];}').status=='UNSUPPORTED'
    _,r=one('int f(int n) {int a[8]={0};int i; i=n;return a[i];}')
    assert r.status=='UNSUPPORTED'


@solver
def test_constant_oob_without_parameters():
    _,r=one('int f(void) {int a[8]={0};return a[8];}')
    assert r.status=='SAT' and r.witness=={}


@solver
def test_multiple_accesses_exactly_located():
    report=analyze_constraints('void f(int n) {int a[8]={0};a[0]=1;a[n]=2;}','multi.c')
    assert [r.status for r in report.results]==['UNSAT','SAT']
    assert [r.expression for r in report.results]==['a[0]','a[n]']


@solver
def test_prior_undefined_access_blocks_later_unsat_claim():
    report=analyze_constraints('void f(int n) {int a[8]={0};a[n]=1;a[0]=2;}')
    assert [r.status for r in report.results]==['SAT','UNSUPPORTED']


@solver
def test_block_local_does_not_escape_scope():
    report=analyze_constraints('int f(int n) {int a[8]={0};if(n){int i=0;a[i]=1;}else return 0;return a[i];}')
    assert report.results and all(r.status=='UNSUPPORTED' for r in report.results)


@solver
def test_outer_local_assignment_survives_inner_block():
    _,r=one('int f(int n) {int a[8]={0};int i=0;if(n){i=9;}return a[i];}')
    assert r.status=='SAT' and r.witness['n']!=0


@solver
def test_implementation_defined_narrowing_is_not_modelled():
    _,r=one('int narrow(unsigned n) {int a[8]={0};int i=n;return a[i];}')
    assert r.status=='UNSUPPORTED'


def test_missing_dependency_is_explicit(monkeypatch):
    original=builtins.__import__
    def missing(name,*args,**kwargs):
        if name=='z3':raise ImportError('missing',name='z3')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',missing)
    report=analyze_constraints('int f(int n){int a[8];return a[n];}')
    assert report.status=='UNAVAILABLE' and report.alerts()==[]


@pytest.mark.parametrize('kwargs',[{'timeout_ms':0},{'timeout_ms':True},{'resource_limit':-1}])
def test_invalid_budget(kwargs):
    with pytest.raises(ValueError):analyze_constraints('',**kwargs)
