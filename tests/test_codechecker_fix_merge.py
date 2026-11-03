"""Merged fix acceptance keeps local contracts and mandatory native replay."""
from pathlib import Path

import pytest

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.codechecker_verifier import NativeFixValidator
from ecdet.l4_llm.fixer import FixProposal, FixVerifier


SOURCE = 'int f(int value)\n{\n    int *p = 0;\n    return *p + value;\n}\n'
PATCH = 'int f(int value)\n{\n    int result = value;\n    return result;\n}'


def setup(tmp_path, **kwargs):
    (tmp_path/'m.c').write_text(SOURCE, encoding='utf-8')
    context = finalize_facts([build_file_facts('m.c', SOURCE)])
    proposal = FixProposal('core.NullDereference','m.c','f',1,5,SOURCE,
        patched_code=PATCH,source_engine='codechecker',alert_line=4,alert_col=12)
    verifier = FixVerifier(tmp_path, **kwargs)
    return context,proposal,verifier


def test_native_configuration_matches_original_analysis(tmp_path):
    _,_,verifier=setup(tmp_path,profile='industrial',enable=['native-rule'],disable=['other-rule'])
    assert verifier._native.profile=='industrial'
    assert verifier._native.enable==['native-rule']
    assert verifier._native.disable==['other-rule']


def test_codechecker_acceptance_requires_native_success(tmp_path):
    context,proposal,verifier=setup(tmp_path)
    verifier._gcc='test-compiler'
    verifier._compile_check=lambda *args:(True,'')
    calls=[]
    verifier._native.verify=lambda candidate,source:(calls.append((candidate,source)) is not None or True,'')
    result=verifier.verify(proposal,context,SOURCE)
    assert result.verified and len(calls)==1
    assert result.validation['native_replay']['status']=='PASS'
    assert result.validation['baseline']['status']=='PASS'
    assert result.validation['compile']['status']=='PASS'


def test_codechecker_unreproduced_native_baseline_is_rejected(tmp_path):
    context,proposal,verifier=setup(tmp_path)
    verifier._gcc='test-compiler';verifier._compile_check=lambda *args:(True,'')
    verifier._native.last_validation={'baseline':'FAIL','static_replay':'SKIPPED'}
    verifier._native.verify=lambda *args:(False,'Original native finding did not reproduce')
    result=verifier.verify(proposal,context,SOURCE)
    assert not result.verified
    assert result.validation['baseline']['status']=='FAIL'
    assert result.validation['native_replay']['status']=='FAIL'


def test_explicit_compile_skip_never_counts_as_verified(tmp_path):
    context,proposal,verifier=setup(tmp_path,use_compiler=False)
    def forbidden(*args):raise AssertionError('Native replay must not bypass the compiler gate')
    verifier._native.verify=forbidden
    result=verifier.verify(proposal,context,SOURCE)
    assert not result.verified and result.validation['compile']['status']=='SKIPPED'


def test_native_exception_is_isolated_to_the_proposal(tmp_path):
    context,proposal,verifier=setup(tmp_path)
    verifier._gcc='test-compiler';verifier._compile_check=lambda *args:(True,'')
    def failed(*args):raise RuntimeError('Analyzer task failed')
    verifier._native.verify=failed
    result=verifier.verify(proposal,context,SOURCE)
    assert not result.verified and result.validation['native_replay']['status']=='ERROR'


def native_fixture(tmp_path, baseline, after=()):
    root=tmp_path/'root';root.mkdir()
    workspace=tmp_path/'workspace';workspace.mkdir()
    for folder in [root,workspace]:(folder/'m.c').write_text(SOURCE,encoding='utf-8')
    verifier=NativeFixValidator(root)
    verifier._workspace=workspace;verifier._artifacts=tmp_path
    verifier._baseline=list(baseline)
    verifier._snapshot=lambda:None
    verifier._scan=lambda label:list(after)
    proposal=FixProposal('core.NullDereference','m.c','f',1,5,SOURCE,
        patched_code=PATCH,source_engine='codechecker',alert_line=4,alert_col=12)
    return verifier,proposal


def alert(engine='codechecker',line=4,col=12,rule='core.NullDereference',fingerprint=''):
    return Alert(rule,engine,Severity.ERROR,'fixture',Location('m.c',line,col),fingerprint=fingerprint)


@pytest.mark.parametrize('wrong',[alert(engine='builtin'),alert(line=3),alert(col=1),alert(rule='other')])
def test_native_baseline_must_match_engine_rule_and_exact_location(tmp_path,wrong):
    verifier,proposal=native_fixture(tmp_path,[wrong])
    ok,reason=verifier.verify(proposal,PATCH+'\n')
    assert not ok and verifier.last_validation['baseline']=='FAIL'


def test_native_success_preserves_original_project_and_workspace(tmp_path):
    verifier,proposal=native_fixture(tmp_path,[alert()])
    assert verifier.verify(proposal,PATCH+'\n')==(True,'')
    assert (verifier.root/'m.c').read_text(encoding='utf-8')==SOURCE
    assert (verifier._workspace/'m.c').read_text(encoding='utf-8')==SOURCE


def test_native_error_instance_count_is_not_hidden_by_same_fingerprint(tmp_path):
    existing=alert(line=20,rule='other.error',fingerprint='same-report-hash')
    verifier,proposal=native_fixture(tmp_path,[alert(),existing],[existing,existing])
    ok,_=verifier.verify(proposal,PATCH+'\n')
    assert not ok and verifier.last_validation['new_errors']=='FAIL'


def test_native_existing_instance_with_changed_report_hash_is_not_new(tmp_path):
    before=alert(line=20,rule='other.error',fingerprint='before-report-hash')
    after=alert(line=20,rule='other.error',fingerprint='after-report-hash')
    verifier,proposal=native_fixture(tmp_path,[alert(),before],[after])
    assert verifier.verify(proposal,PATCH+'\n')==(True,'')
    assert verifier.last_validation['new_errors']=='PASS'


def test_native_stale_workspace_cannot_be_accepted(tmp_path):
    verifier,proposal=native_fixture(tmp_path,[alert()])
    (verifier._workspace/'m.c').write_text(SOURCE.replace('value','stale'),encoding='utf-8')
    assert verifier.verify(proposal,PATCH+'\n')[0] is False


def test_automatic_svd_is_shared_by_builtin_and_native_replay(tmp_path):
    source='typedef struct {unsigned CTRL;} GPIO_TypeDef;\n#define GPIOA ((GPIO_TypeDef *)0x40000000)\nvoid f(void) { GPIOA->CTRL |= 1u; }\n'
    svd=tmp_path/'chip.svd'
    svd.write_text('<device><name>A</name><peripherals><peripheral><name>GPIOA</name><baseAddress>0x40000000</baseAddress><registers><register><name>CTRL</name><addressOffset>0</addressOffset><size>32</size><access>read-write</access><modifiedWriteValues>oneToClear</modifiedWriteValues></register></registers></peripheral></peripherals></device>',encoding='utf-8')
    (tmp_path/'m.c').write_text(source,encoding='utf-8')
    context=finalize_facts([build_file_facts('m.c',source)])
    proposal=FixProposal('ECDET-MMIO-W1C','m.c','f',3,3,
        'void f(void) { GPIOA->CTRL |= 1u; }',
        patched_code='void f(void) { GPIOA->CTRL = 1u; }',
        source_engine='builtin-hw',alert_line=3)
    verifier=FixVerifier(tmp_path)
    verifier._gcc='test-compiler';verifier._compile_check=lambda *args:(True,'')
    seen=[]
    def native(candidate,modified):
        seen.append(verifier._native.svd_path)
        return True,''
    verifier._native.verify=native
    result=verifier.verify(proposal,context,source)
    assert result.verified,result.fail_reason
    assert seen==[svd]
    assert result.validation['baseline']['status']=='PASS'
    assert result.validation['static_replay']['status']=='PASS'
def test_deep_project_snapshot_keeps_generated_build_inputs(tmp_path, monkeypatch):
    import os
    import pytest
    from ecdet.l3_analysis.codechecker_verifier import NativeFixValidator

    if os.name != "nt":
        pytest.skip("Windows native path limit")
    root = tmp_path / ("project_" + "x" * 55)
    generated = root / "ecdet_build" / "cmake" / "CMakeFiles" / "generated" / "platform.h"
    generated.parent.mkdir(parents=True)
    generated.write_text("#define PLATFORM_VALUE 7\n", encoding="utf-8")
    (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    validator = NativeFixValidator(root)
    monkeypatch.setattr(validator, "_scan", lambda label: [])
    validator._snapshot()
    copied = validator._workspace / generated.relative_to(root)
    assert copied.read_bytes() == generated.read_bytes()
    assert validator._workspace.resolve().is_relative_to(root.resolve())
    from ecdet.l3_analysis.engine import collect_sources
    assert collect_sources(root) == [Path("main.c")]
    validator._snapshot()  # Reuse must not descend into generated reports.
