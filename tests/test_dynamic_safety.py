"""LLM harness integrity and exact dynamic-to-static evidence matching."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from ecdet.l2_ir.model import Alert, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.dynamic.engine import DynamicEngine, DynamicFinding
from ecdet.l3_analysis.dynamic.harness import compile_harness, generate_harness
from ecdet.l3_analysis.dynamic.inputs import build_input_model
from ecdet.l3_analysis.dynamic.llm_fix import LlmHarnessFixer, extract_patched_harness
from ecdet.l3_analysis.monitor import RuntimeMonitor


def generated(tmp_path):
    source = 'int target(int value) { return value + 1; }\n'
    (tmp_path/'target.c').write_text(source, encoding='utf-8')
    facts = build_file_facts('target.c', source)
    harness = generate_harness(build_input_model(facts.functions[0]), 'target.c', 2)
    harness.source = harness.source.replace('static const int', 'int broken = ;\nstatic const int')
    return harness


@pytest.mark.parametrize('replacement', ['empty_main', 'delete_call', 'change_inputs', 'remove_observer'])
def test_compiling_repair_cannot_remove_harness_contract(tmp_path, monkeypatch, replacement):
    harness = generated(tmp_path)
    original = harness.source
    if replacement == 'empty_main':
        patched = 'int main(void) { return 0; }'
    elif replacement == 'delete_call':
        patched = original.replace('target(ecdet_combo[idx][0])', '0')
    elif replacement == 'change_inputs':
        patched = original.replace('target(ecdet_combo[idx][0])', 'target(0)')
    else:
        patched = original.replace('printf("ok\\n");', '')
    patched = patched.replace('int broken = ;\n', '')
    fake = SimpleNamespace(fix=lambda *args: (patched, 'repair'))
    results = iter([SimpleNamespace(returncode=1,stderr='invalid source'),
                    SimpleNamespace(returncode=0,stderr='')])
    monkeypatch.setattr('ecdet.l3_analysis.dynamic.harness.subprocess.run', lambda *a, **k: next(results))
    ok, reason = compile_harness(harness,tmp_path,[tmp_path],fixer=fake)
    assert not ok
    assert 'contract' in reason.lower()
    assert harness.exe_path is None


def test_harness_retry_uses_latest_compile_log(tmp_path, monkeypatch):
    harness = generated(tmp_path)
    logs = []
    def fix(source, error):
        logs.append(error)
        return source.replace('int broken = ;\n', ''), 'repair'
    results=iter([SimpleNamespace(returncode=1,stderr='initial_error'),
                  SimpleNamespace(returncode=1,stderr='latest_error'),
                  SimpleNamespace(returncode=0,stderr='')])
    monkeypatch.setattr('ecdet.l3_analysis.dynamic.harness.subprocess.run',lambda *a,**k:next(results))
    ok, _ = compile_harness(harness,tmp_path,[tmp_path],fixer=SimpleNamespace(fix=fix))
    assert ok
    assert logs == ['initial_error', 'latest_error']


def test_harness_endpoint_failure_is_local():
    def fail(*args):
        raise RuntimeError('endpoint down')
    fixer=LlmHarnessFixer(SimpleNamespace(complete=fail))
    assert fixer.fix('int main(void){}','error') is None
    assert fixer.last_error
    assert fixer.attempts[-1]['status'] == 'ERROR'


@pytest.mark.parametrize('response', [[], {}, '{"patched_harness": "int x;", "changes": 42}', '{"patched_harness": "int x;"}'])
def test_harness_response_contract_is_strict(response):
    assert extract_patched_harness(response) is None


def monitor_case(tmp_path, event, *, file='a.c', rule='CERT C ARR30-C'):
    facts=[build_file_facts(name, 'int shared(void) {\n return 1;\n}\n') for name in ['a.c','b.c']]
    alert=Alert(rule_id=rule, engine='audit', severity=Severity.WARNING,
                message='candidate',location=Location(path=file,line=2),provenance=Provenance.SUSPECTED)
    engine=SimpleNamespace(available=True, run=lambda *a,**k:[event])
    result=RuntimeMonitor(engine).run(tmp_path,facts,[alert])
    return alert,result


def finding(**changes):
    values=dict(func_name='shared',target_rel='a.c',oracle='UB',rule_id='ECDET-DYN-UB',
                detail='bounds violation',seed_idx=0,replay_seed='0',args_preview='')
    values.update(changes)
    return DynamicFinding(**values)


def test_generic_crash_does_not_prove_static_defect(tmp_path):
    alert,result=monitor_case(tmp_path,finding(oracle='CRASH',detail='divide by zero'))
    assert result.events and result.upgraded == []
    assert alert.provenance == Provenance.SUSPECTED


def test_other_file_same_function_does_not_upgrade(tmp_path):
    event=finding(source_line=2,defect_class='array-bounds',confirmed_rule_ids=['CERT C ARR30-C'])
    alert,result=monitor_case(tmp_path,event,file='b.c')
    assert result.upgraded == []
    assert alert.provenance == Provenance.SUSPECTED


def test_different_defect_or_line_does_not_upgrade(tmp_path):
    for updates in [dict(defect_class='divide-by-zero'),dict(source_line=1)]:
        values=dict(source_line=2,defect_class='array-bounds',confirmed_rule_ids=['CERT C ARR30-C'])
        values.update(updates)
        alert,result=monitor_case(tmp_path,finding(**values))
        assert not result.upgraded
        assert alert.provenance == Provenance.SUSPECTED


def test_exact_event_association_can_upgrade(tmp_path):
    event=finding(source_line=2,defect_class='array-bounds',confirmed_rule_ids=['CERT C ARR30-C'])
    alert,result=monitor_case(tmp_path,event)
    assert result.upgraded == [alert]
    assert alert.provenance == Provenance.DETECTED
    assert 'a.c:2' in alert.evidence[-1].message


def test_missing_target_execution_marker_is_not_a_finding(tmp_path,monkeypatch):
    harness=generated(tmp_path)
    harness.exe_path=tmp_path/'harness.exe'
    monkeypatch.setattr('ecdet.l3_analysis.dynamic.engine.subprocess.run',
                        lambda *a,**k: SimpleNamespace(returncode=1,stderr='',stdout=''))
    assert DynamicEngine()._run_oracle(harness,0)[0] == ''
