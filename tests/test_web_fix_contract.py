"""Web fixes use the same verification gate as CLI and orchestration."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from ecdet.l3_analysis.engine import AnalysisTarget, BuiltinEngine
from ecdet.webui.runner import ScanRunner
from ecdet.webui.store import Store


@pytest.fixture(autouse=True)
def isolate_codechecker_from_web_contract_tests(monkeypatch):
    """Exercise real builtin rules and repair gates without an external tool run.

    CodeChecker execution and native fix replay have their own acceptance tests.
    These cases verify missing compiler, protected review, and selection behavior.
    """
    monkeypatch.setattr('ecdet.l3_analysis.engine.CodeCheckerEngine.rules',lambda self:[])
    monkeypatch.setattr('ecdet.l3_analysis.engine.CodeCheckerEngine.run',lambda self,target,enabled:[])


def prepare(tmp_path, source):
    workspace=tmp_path/'workspace';workspace.mkdir()
    (workspace/'m.c').write_text(source,encoding='utf-8')
    store=Store(tmp_path/'data.db')
    project=store.add_project('test','path',str(workspace),str(workspace))
    run=store.add_run(project,{'triage':'off'})
    store.set_run_status(run,'done')
    runner=ScanRunner.__new__(ScanRunner)
    runner.store=store;runner.data_dir=tmp_path/'data'
    return workspace,store,run,runner


def test_missing_compiler_cannot_verify_web_patch(tmp_path,monkeypatch):
    source='#include <string.h>\nvoid f(void) {\n char b[4];\n strcpy(b,"too long");\n}\n'
    workspace,store,run,runner=prepare(tmp_path,source)
    monkeypatch.setattr('ecdet.l4_llm.fixer.shutil.which',lambda _:None)
    job=store.add_fix_job(run)
    runner._execute_fixes(job,run,mode='apply')
    assert store.latest_fix_job(run)['accepted']==0
    assert (workspace/'m.c').read_text(encoding='utf-8')==source
    proposals=store.list_fixes(run)
    assert proposals and proposals[0]['validation']['compile']['status']=='SKIPPED'


def test_stale_high_risk_false_positive_is_not_repaired(tmp_path):
    source='#include <string.h>\nvoid f(void) {\n char b[4];\n strcpy(b,"too long");\n}\n'
    workspace,store,run,runner=prepare(tmp_path,source)
    store.put_alerts(run,[{'rule_id':'CERT C STR31-C','engine':'builtin','severity':'error',
        'path':'m.c','line':4,'message':'x','cwe':None,'provenance':'detected',
        'triage':{'verdict':'NEEDS_REVIEW','suggested_verdict':'FALSE_POSITIVE','review_pending':True},
        'evidence':[],'fingerprint':'test'}])
    selected=store.list_alerts(run)[0]['id']
    job=store.add_fix_job(run,[selected])
    runner._execute_fixes(job,run,alert_ids=[selected],mode='apply')
    assert store.latest_fix_job(run)['applied']==0
    assert store.latest_fix_job(run)['accepted']==0
    assert (workspace/'m.c').read_text(encoding='utf-8')==source


def test_invalid_selected_ids_do_not_expand_to_all_candidates(tmp_path):
    source='#include <string.h>\nvoid f(void) {\n char b[4];\n strcpy(b,"too long");\n}\n'
    workspace,store,run,runner=prepare(tmp_path,source)
    job=store.add_fix_job(run,[999999])
    runner._execute_fixes(job,run,alert_ids=[999999],mode='apply')
    assert store.latest_fix_job(run)['applied']==0
    assert store.list_fixes(run)==[]
    assert (workspace/'m.c').read_text(encoding='utf-8')==source
