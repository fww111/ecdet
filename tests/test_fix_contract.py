"""Repair acceptance must replay evidence and keep skipped checks distinct."""
import json
import shutil

import pytest

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l4_llm.client import LlmTransportError
from ecdet.l4_llm.fixer import FixProposer, FixVerifier, fix_candidate_allowed, fix_candidate_status


SOURCE = '#include <string.h>\nvoid f(void) { char b[4]; strcpy(b, "too long"); }\n'
FIXED = 'void f(void) { char b[4]; strncpy(b, "too long", sizeof(b)-1); b[sizeof(b)-1] = 0; }'


class FakeClient:
    def __init__(self, code):
        self.code = code
    def complete(self, system, user):
        return json.dumps({'patched_function': self.code, 'explanation': 'candidate'})


def proposal(tmp_path, code=FIXED, source=SOURCE, rule='CERT C STR31-C', engine='builtin'):
    (tmp_path/'m.c').write_text(source, encoding='utf-8')
    ctx = finalize_facts([build_file_facts('m.c',source)])
    alert = Alert(rule,engine,Severity.ERROR,'test',Location('m.c',2))
    return ctx,FixProposer(FakeClient(code)).propose(alert,ctx)


def test_missing_compiler_never_counts_as_pass(tmp_path, monkeypatch):
    ctx,item = proposal(tmp_path)
    monkeypatch.setattr(shutil,'which',lambda name:None)
    item = FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['compile']['status'] == 'SKIPPED'


def test_external_engine_is_unsupported_not_silently_clean(tmp_path):
    ctx,item = proposal(tmp_path,engine='clang-tidy')
    item = FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['static_replay']['status'] == 'UNSUPPORTED'


@pytest.mark.parametrize('code', ['int unrelated(void) { return 0; }',
                                'void f(int changed) { char b[4]; strncpy(b,"too long",3); }',
                                'void f(void) { }', 'void f(void) { return; }'])
def test_function_identity_or_obvious_logic_removal_is_rejected(tmp_path,code):
    ctx,item = proposal(tmp_path,code)
    item = FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['patch_scope']['status'] == 'FAIL'


@pytest.mark.parametrize('extra',['int outside;', 'void other(void) {}'])
def test_same_line_outside_function_edit_is_rejected(tmp_path,extra):
    ctx,item = proposal(tmp_path,FIXED+' '+extra)
    item = FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['patch_scope']['status'] == 'FAIL'


def test_removing_only_executable_write_is_rejected(tmp_path):
    source = 'void f(void) { int a[2]; a[2]=1; }\n'
    (tmp_path/'m.c').write_text(source,encoding='utf-8')
    ctx = finalize_facts([build_file_facts('m.c',source)])
    alert = Alert('CERT C ARR30-C','builtin',Severity.ERROR,'test',Location('m.c',1))
    item = FixProposer(FakeClient('void f(void) { int a[2]; }')).propose(alert,ctx)
    item = FixVerifier(tmp_path).verify(item,ctx,source)
    assert not item.verified
    assert item.validation['patch_scope']['status'] == 'FAIL'


def test_line_shifts_do_not_turn_existing_error_into_new_error(tmp_path):
    source = '#include <string.h>\nvoid f(void) {\n char b[4];\n int a[2];\n strcpy(b,"too long");\n a[2]=1;\n}\n'
    code = 'void f(void) {\n char b[4];\n int a[2];\n strncpy(b,"too long",3);\n b[3]=0;\n a[2]=1;\n}'
    ctx,item = proposal(tmp_path,code,source)
    item.alert_line=5
    verifier=FixVerifier(tmp_path)
    verifier._gcc='fake-gcc'
    verifier._compile_check=lambda *args:(True,'')
    item=verifier.verify(item,ctx,source)
    assert item.verified,item.fail_reason


def test_compile_check_uses_matching_compilation_database(tmp_path,monkeypatch):
    (tmp_path/'m.c').write_text(SOURCE,encoding='utf-8')
    (tmp_path/'compile_commands.json').write_text(json.dumps([{'directory':str(tmp_path),'file':'m.c','arguments':['gcc','-DPROJECT_FLAG=1','-std=c11','-c','m.c','-o','m.o']}]),encoding='utf-8')
    seen=[]
    def running(cmd,**kwargs):
        seen.append((cmd,kwargs))
        return type('Done',(),{'returncode':0,'stdout':'','stderr':''})()
    monkeypatch.setattr('ecdet.l4_llm.fixer.subprocess.run',running)
    verifier=FixVerifier(tmp_path)
    verifier._gcc='gcc'
    assert verifier._compile_check('m.c',SOURCE)==(True,'')
    assert '-DPROJECT_FLAG=1' in seen[0][0]
    assert '-std=c11' in seen[0][0] and '-std=gnu89' not in seen[0][0]
    assert '-o' not in seen[0][0] and '-c' not in seen[0][0]
    assert seen[0][1]['cwd']==str(tmp_path)


def test_unreproduced_alert_is_not_verified(tmp_path):
    ctx,item = proposal(tmp_path,rule='ECDET-CWE-197')
    item = FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['baseline']['status'] == 'FAIL'


def test_new_second_error_of_existing_rule_is_rejected(tmp_path):
    source = '#include <string.h>\nvoid f(void) { char b[4]; int a[2]; strcpy(b,"too long"); a[2]=1; }\n'
    fixed = 'void f(void) { char b[4]; int a[2]; strncpy(b,"too long",3); a[2]=1; a[3]=2; }'
    ctx,item = proposal(tmp_path,fixed,source)
    item = FixVerifier(tmp_path).verify(item,ctx,source)
    assert not item.verified
    assert item.validation['new_errors']['status'] == 'FAIL'


def test_hardware_rule_is_replayed_with_svd(tmp_path):
    source = 'typedef struct {unsigned CTRL;} GPIO_TypeDef;\n#define GPIOA ((GPIO_TypeDef *)0x40000000)\nvoid f(void) { GPIOA->CTRL |= 1u; }\n'
    svd = '<device><name>A</name><peripherals><peripheral><name>GPIOA</name><baseAddress>0x40000000</baseAddress><registers><register><name>CTRL</name><addressOffset>0</addressOffset><size>32</size><access>read-write</access><modifiedWriteValues>oneToClear</modifiedWriteValues></register></registers></peripheral></peripherals></device>'
    (tmp_path/'chip.svd').write_text(svd,encoding='utf-8')
    (tmp_path/'m.c').write_text(source,encoding='utf-8')
    ctx = finalize_facts([build_file_facts('m.c',source)])
    alert = Alert('ECDET-MMIO-W1C','builtin-hw',Severity.WARNING,'test',Location('m.c',3))
    item = FixProposer(FakeClient('void f(void) { GPIOA->CTRL |= 2u; }')).propose(alert,ctx)
    item = FixVerifier(tmp_path,svd_path=tmp_path/'chip.svd').verify(item,ctx,source)
    assert not item.verified
    assert item.validation['static_replay']['status'] == 'FAIL'


def test_valid_hardware_fix_replays_original_and_compiles(tmp_path):
    source = 'typedef struct {unsigned CTRL;} GPIO_TypeDef;\n#define GPIOA ((GPIO_TypeDef *)0x40000000)\nvoid f(void) { GPIOA->CTRL |= 1u; }\n'
    (tmp_path/'chip.svd').write_text('<device><name>A</name><peripherals><peripheral><name>GPIOA</name><baseAddress>0x40000000</baseAddress><registers><register><name>CTRL</name><addressOffset>0</addressOffset><size>32</size><access>read-write</access><modifiedWriteValues>oneToClear</modifiedWriteValues></register></registers></peripheral></peripherals></device>',encoding='utf-8')
    (tmp_path/'m.c').write_text(source,encoding='utf-8')
    ctx=finalize_facts([build_file_facts('m.c',source)])
    alert=Alert('ECDET-MMIO-W1C','builtin-hw',Severity.WARNING,'test',Location('m.c',3))
    item=FixProposer(FakeClient('void f(void) { GPIOA->CTRL = 1u; }')).propose(alert,ctx)
    item=FixVerifier(tmp_path).verify(item,ctx,source)
    assert item.verified,item.fail_reason
    assert item.validation['baseline']['status']=='PASS'
    assert item.validation['compile']['status']=='PASS'


@pytest.mark.parametrize('triage,allowed,status',[
    (None,True,'UNCONFIRMED_CANDIDATE'),
    ({'verdict':'TRUE_POSITIVE','verified':True},True,'EVIDENCE_CHECKED_CANDIDATE'),
    ({'verdict':'TRUE_POSITIVE','verified':False},False,'REVIEW_REQUIRED'),
    ({'verdict':'FALSE_POSITIVE','verified':True},False,'REVIEW_REQUIRED'),
    ({'verdict':'NEEDS_REVIEW','verified':False},False,'REVIEW_REQUIRED'),
    ({'verdict':'TRUE_POSITIVE','verified':True,'review_pending':True},False,'REVIEW_PENDING'),
])
def test_candidate_gate_does_not_promote_untriaged_alerts(triage,allowed,status):
    item=Alert('CERT C STR31-C','builtin',Severity.ERROR,'test',Location('m.c',2),triage=triage)
    assert fix_candidate_allowed(item)==allowed
    assert fix_candidate_status(item)==status


def test_truncated_function_does_not_become_replacement(tmp_path):
    ctx,_=proposal(tmp_path)
    alert=Alert('CERT C STR31-C','builtin',Severity.ERROR,'test',Location('m.c',2))
    item=FixProposer(FakeClient(FIXED),budget_chars=10).propose(alert,ctx)
    assert not item.patched_code
    assert item.validation['generation']['status']=='SKIPPED'


def test_compiler_adapter_exception_is_scoped_to_proposal(tmp_path):
    ctx,item=proposal(tmp_path)
    verifier=FixVerifier(tmp_path)
    verifier._gcc='fake'
    def failed(*args): raise OSError('cannot create compiler input')
    verifier._compile_check=failed
    item=verifier.verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['compile']['status']=='ERROR'


def test_fix_transport_failure_becomes_failed_proposal(tmp_path):
    class Failing:
        def complete(self,*args): raise LlmTransportError('offline')
    ctx,_ = proposal(tmp_path)
    alert = Alert('CERT C STR31-C','builtin',Severity.ERROR,'test',Location('m.c',2))
    item = FixProposer(Failing()).propose(alert,ctx)
    assert not item.verified and item.fail_reason
    assert item.validation['generation']['status'] == 'ERROR'


@pytest.mark.parametrize('content',[None,[],123,'{"patched_function":"void f(void){}","explanation":1}'])
def test_bad_fix_responses_are_rejected(tmp_path,content):
    class Bad:
        def complete(self,*args):return content
    ctx,_ = proposal(tmp_path)
    alert = Alert('CERT C STR31-C','builtin',Severity.ERROR,'test',Location('m.c',2))
    item = FixProposer(Bad()).propose(alert,ctx)
    assert item.fail_reason and not item.patched_code


def test_full_project_context_is_preserved(tmp_path):
    source = '#include <string.h>\nvoid f(void) { char b[4]; strcpy(b,"too long"); helper(); }\n'
    fixed = 'void f(void) { char b[4]; strncpy(b,"too long",3); helper(); }'
    ctx,item = proposal(tmp_path,fixed,source)
    (tmp_path/'other.c').write_text('void helper(void) {}\n',encoding='utf-8')
    verifier = FixVerifier(tmp_path)
    verifier._compile_check = lambda *args:(True,'')
    verifier._gcc = 'fake-gcc'
    item = verifier.verify(item,ctx,source)
    assert item.verified,item.fail_reason
    assert item.validation['static_replay']['status'] == 'PASS'
    assert item.validation['behavior']['status'] == 'SKIPPED'


def test_replay_uses_current_helper_not_stale_context(tmp_path):
    old='int helper(void) { return 1; }\n'
    current='int helper(void) { return 2; }\n'
    ctx=finalize_facts([build_file_facts('helper.c',old)])
    (tmp_path/'helper.c').write_text(current,encoding='utf-8')
    verifier=FixVerifier(tmp_path)
    assert verifier._sources(ctx)['helper.c']==current


def test_target_snapshot_must_match_current_disk(tmp_path):
    ctx,item=proposal(tmp_path)
    (tmp_path/'m.c').write_text(SOURCE.replace('too long','new source'),encoding='utf-8')
    item=FixVerifier(tmp_path).verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['snapshot']['status']=='FAIL'


def test_memory_only_context_source_is_explicit(tmp_path):
    ctx,item=proposal(tmp_path)
    ctx.facts.append(build_file_facts('memory_only.c','void helper(void) {}\n'))
    verifier=FixVerifier(tmp_path)
    verifier._gcc='fake'
    verifier._compile_check=lambda *args:(True,'')
    item=verifier.verify(item,ctx,SOURCE)
    assert not item.verified
    assert item.validation['native_replay']['status']=='UNSUPPORTED'
    assert item.validation['snapshot']['sources']['memory_only.c']=='context-memory'
    assert item.validation['snapshot']['sources']['m.c']=='disk'
