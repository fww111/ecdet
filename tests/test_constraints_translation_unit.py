import importlib.util
import json
from pathlib import Path
import shutil

import pytest

from ecdet.l3_analysis.constraints_tu import analyze_translation_unit

pytestmark = pytest.mark.skipif(not shutil.which('gcc') or importlib.util.find_spec('z3') is None,
                                reason='Native GCC and Z3 required')


def project(tmp_path, source, header='#define CAP 8\n', flags=()):
    (tmp_path/'settings.h').write_text(header)
    (tmp_path/'unit.c').write_text(source)
    entry=dict(directory=str(tmp_path),file=str(tmp_path/'unit.c'),
               arguments=[shutil.which('gcc'),'-std=c11','-I'+str(tmp_path),*flags,'-c',str(tmp_path/'unit.c')])
    (tmp_path/'compile_commands.json').write_text(json.dumps([entry]))
    return tmp_path


def test_real_header_macro_is_checked_and_guarded_control_is_unsat(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint bad(unsigned n){int a[CAP]={0};return a[n];}\nint good(unsigned n){int a[CAP]={0};if(n<CAP)return a[n];return 0;}')
    result=analyze_translation_unit(root,Path('unit.c'))
    assert result.status=='COMPLETED',result.to_dict()
    assert [(r.function,r.status) for r in result.results]==[('bad','SAT'),('good','UNSAT')]
    assert result.results[0].line==2
    assert result.context['preprocessing']=='complete'
    assert result.context['input_sha256']['settings.h']


def test_build_defines_select_the_actual_branch(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint f(unsigned n){int a[CAP]={0};return a[8];}',
                 '#if LARGE\n#define CAP 16\n#else\n#define CAP 4\n#endif\n',['-DLARGE=1'])
    assert analyze_translation_unit(root,Path('unit.c')).results[0].status=='UNSAT'
    db=json.loads((root/'compile_commands.json').read_text());db[0]['arguments'][3]='-DLARGE=0'
    (root/'compile_commands.json').write_text(json.dumps(db))
    assert analyze_translation_unit(root,Path('unit.c')).results[0].status=='SAT'


def test_typedef_width_is_resolved_from_actual_translation_unit(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint f(uint8_t n){int a[256]={0};return a[n];}',
                 'typedef unsigned int uint8_t;\n')
    report=analyze_translation_unit(root,Path('unit.c'))
    assert report.results[0].status=='SAT',report.to_dict()
    assert report.results[0].input_types['n']=={'bits':32,'signed':False}


def test_unknown_global_state_is_not_a_safe_result(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint index; int f(void){int a[CAP]={0};return a[index];}')
    report=analyze_translation_unit(root,Path('unit.c'))
    assert report.results[0].status=='UNSUPPORTED'
    assert not report.alerts()


def test_compiler_failure_is_an_error(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint f(void){int a[CAP]={0};return a[missing];}')
    report=analyze_translation_unit(root,Path('unit.c'))
    assert report.status=='ERROR' and not report.alerts()


def test_missing_compiler_is_unavailable(tmp_path):
    root=project(tmp_path,'int f(void){int a[8]={0};return a[8];}')
    db=json.loads((root/'compile_commands.json').read_text());db[0]['arguments'][0]='compiler-that-does-not-exist'
    (root/'compile_commands.json').write_text(json.dumps(db))
    assert analyze_translation_unit(root,Path('unit.c')).status=='UNAVAILABLE'


def test_ambiguous_configuration_is_not_guessed(tmp_path):
    root=project(tmp_path,'int f(void){int a[8]={0};return a[8];}')
    db=json.loads((root/'compile_commands.json').read_text());db.append(db[0])
    (root/'compile_commands.json').write_text(json.dumps(db))
    assert analyze_translation_unit(root,Path('unit.c')).status=='UNSUPPORTED'


def test_empty_query_set_does_not_claim_safety(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint f(void){return CAP;}')
    assert analyze_translation_unit(root,Path('unit.c')).status=='NO_QUERIES'


def test_header_functions_are_not_reported_as_source_functions(tmp_path):
    root=project(tmp_path,'#include "settings.h"\nint f(unsigned n){int a[8]={0};return a[n];}',
                 'static int helper(unsigned n){int a[4]={0};return a[n];}\n')
    report=analyze_translation_unit(root,Path('unit.c'))
    assert [r.function for r in report.results]==['f']


def test_constraints_cli_uses_the_translation_unit(tmp_path):
    from ecdet.advanced_cli import analyze_constraint_files
    root=project(tmp_path,'#include "settings.h"\nint f(unsigned n){int a[CAP]={0};return a[n];}')
    receipt,alerts=analyze_constraint_files(root,[Path('unit.c')])
    assert receipt['status_counts']=={'SAT':1} and len(alerts)==1


def test_solver_error_does_not_become_no_queries(tmp_path,monkeypatch):
    import z3
    root=project(tmp_path,'int f(unsigned n){int a[8]={0};return a[n];}')
    def fail(*args):raise z3.Z3Exception('injected test error')
    monkeypatch.setattr('ecdet.l3_analysis.constraints._Function.solve',fail)
    report=analyze_translation_unit(root,Path('unit.c'))
    assert report.status=='ERROR' and not report.alerts()


def test_standard_headers_and_empty_macros_preserve_target_validation(tmp_path):
    root=project(tmp_path,'#include <stdint.h>\n#include <stdio.h>\nint f(uint8_t n){int a[256]={0};return a[n];}')
    report=analyze_translation_unit(root,Path('unit.c'))
    assert report.context['preprocessing']=='complete',report.to_dict()
    assert report.results[0].status=='UNSAT',report.to_dict()
