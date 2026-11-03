import json

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l4_llm.agents import Orchestrator, OrchestratorConfig


def setup_case(tmp_path, monkeypatch):
    (tmp_path/'m.c').write_text('int f(void) {\n return 1;\n}\n',encoding='utf-8')
    alert=Alert(rule_id='AUDIT',engine='builtin',severity=Severity.ERROR,
                message='candidate',location=Location(path='m.c',line=2))
    monkeypatch.setattr('ecdet.l4_llm.agents.run_all_engines',lambda *a,**k:([alert],[]))
    class Fake:
        mode='fake'
        def complete(self,*args):
            return json.dumps({'verdict':'FALSE_POSITIVE','confidence':0.9,
                               'reason':'candidate','evidence_lines':[2]})
    monkeypatch.setattr('ecdet.l4_llm.agents.MockLlmClient',Fake)
    return alert


def test_high_risk_fp_default_changes_state_to_review(tmp_path,monkeypatch):
    alert=setup_case(tmp_path,monkeypatch)
    state=Orchestrator(OrchestratorConfig(use_dynamic=False,max_fix_targets=0)).orchestrate(tmp_path)
    assert alert.triage['verdict']=='NEEDS_REVIEW'
    assert alert.triage['suggested_verdict']=='FALSE_POSITIVE'
    assert alert.triage['review_pending']
    assert state.review_queue[0]['auto_accepted'] is False


def test_explicit_acceptance_is_recorded(tmp_path,monkeypatch):
    alert=setup_case(tmp_path,monkeypatch)
    state=Orchestrator(OrchestratorConfig(use_dynamic=False,auto_accept=True)).orchestrate(tmp_path)
    assert alert.triage['verdict']=='FALSE_POSITIVE'
    assert state.review_queue[0]['auto_accepted'] is True


def test_budget_exhaustion_returns_review_and_real_call_count(tmp_path,monkeypatch):
    alert=setup_case(tmp_path,monkeypatch)
    state=Orchestrator(OrchestratorConfig(use_dynamic=False,max_llm_calls=0)).orchestrate(tmp_path)
    assert alert.triage['verdict']=='NEEDS_REVIEW'
    assert state.llm_calls==0
    assert state.llm_budget['refused_calls']>=1


def test_invalid_fp_never_becomes_auto_accepted_queue_item(tmp_path,monkeypatch):
    alert=setup_case(tmp_path,monkeypatch)
    class NoEvidence:
        def complete(self,*args):
            return json.dumps({'verdict':'FALSE_POSITIVE','confidence':0.9,'reason':'guess','evidence_lines':[]})
    monkeypatch.setattr('ecdet.l4_llm.agents.MockLlmClient',NoEvidence)
    state=Orchestrator(OrchestratorConfig(use_dynamic=False,auto_accept=True)).orchestrate(tmp_path)
    assert state.review_queue[0]['status']=='PENDING'
    assert state.review_queue[0]['auto_accepted'] is False
    assert alert.triage['review_pending'] is True
