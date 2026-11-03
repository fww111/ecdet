"""The CodeChecker merge preserves web metadata and strict repair gates."""
import json
from pathlib import Path
from types import SimpleNamespace

from ecdet.l2_ir.model import Alert, Location, Provenance, RuleMeta, Severity
from ecdet.webui.runner import ScanRunner
from ecdet.webui.store import Store


def setup_run(tmp_path, params):
    workspace=tmp_path/'workspace';workspace.mkdir()
    (workspace/'main.cpp').write_text('void f(void) { char b[4]; }\n',encoding='utf-8')
    (workspace/'device.svd').write_text('<device/>',encoding='utf-8')
    store=Store(tmp_path/'web.db')
    project=store.add_project('merge','path',str(workspace),str(workspace))
    run=store.add_run(project,params)
    runner=ScanRunner.__new__(ScanRunner)
    runner.store=store;runner.data_dir=tmp_path/'data'
    return workspace,store,run,runner


def test_scan_keeps_cpp_native_metadata_and_analysis_configuration(tmp_path,monkeypatch):
    workspace,store,run,runner=setup_run(tmp_path,{
        'no_build':True,'triage':'off','profile':'industrial',
        'enable':['clang-diagnostic-test'],'disable':['disabled-checker']})
    received={}
    def scan(target,**options):
        received.update(target=target,options=options)
        target.artifact_dir.mkdir(parents=True)
        (target.artifact_dir/'latest.json').write_text(json.dumps({'status':'COMPLETED'}))
        alert=Alert('clang-diagnostic-test','codechecker',Severity.WARNING,'test',
            Location('main.cpp',1),provenance=Provenance.SUSPECTED,
            properties={'analyzer':'clangsa','native_checker':'test'})
        return [alert],[RuleMeta(alert.rule_id,'CodeChecker','Required','tool','test')]
    monkeypatch.setattr('ecdet.webui.runner.run_all_engines',scan)
    runner._execute(run)
    assert Path('main.cpp') in received['target'].files
    assert received['options']['enable']==['clang-diagnostic-test']
    assert received['options']['disable']==['disabled-checker']
    assert received['target'].svd_path==workspace/'device.svd'
    assert store.list_alerts(run)[0]['properties']['analyzer']=='clangsa'
    assert store.get_run(run)['stats']['codechecker']['status']=='COMPLETED'


def test_repair_runs_native_scans_but_never_bypasses_shared_verifier(tmp_path,monkeypatch):
    workspace,store,run,runner=setup_run(tmp_path,{
        'profile':'industrial','enable':['extra'],'disable':['off']})
    store.set_run_status(run,'done')
    source=(workspace/'main.cpp').read_bytes()
    source_text=(workspace/'main.cpp').read_text(encoding='utf-8')
    calls=[];construct={};proposals=[]
    alert=Alert('CERT C STR31-C','builtin',Severity.ERROR,'test',Location('main.cpp',1),
                provenance=Provenance.DETECTED)
    def scan(target,**options):
        calls.append((target,options))
        return [alert],[]
    class Proposer:
        def __init__(self,client):
            from ecdet.l4_llm.budget import BudgetedClient
            assert isinstance(client,BudgetedClient)
            self.client=client
        def propose(self, candidate, ctx):
            self.client.complete('system','user')
            proposal=SimpleNamespace(func_name='f',fail_reason='',verified=False,
                explanation='test',diff='',to_props=lambda:{'validation':{'compile':{'status':'SKIPPED'}}})
            proposals.append(proposal)
            return proposal
    class Verifier:
        def __init__(self,root,**options):
            construct.update(options);self.svd_path=options['svd_path']
        def _prepare(self,ctx):
            assert any(f.path=='main.cpp' for f in ctx.facts)
        def verify(self,proposal,ctx,current):
            assert current==source_text
            proposal.fail_reason='Compiler validation not completed'
            return proposal
    monkeypatch.setattr('ecdet.webui.runner.run_all_engines',scan)
    monkeypatch.setattr('ecdet.l4_llm.fixer.FixProposer',Proposer)
    monkeypatch.setattr('ecdet.l4_llm.fixer.FixVerifier',Verifier)
    monkeypatch.setattr('ecdet.l4_llm.fixer.MockFixClient',lambda:SimpleNamespace(
        mode='fake',complete=lambda *args:'{}'))
    job=store.add_fix_job(run)
    runner._execute_fixes(job,run,mode='suggest')
    assert construct['svd_path']==workspace/'device.svd'
    assert construct['profile']=='industrial'
    assert construct['enable']==['extra'] and construct['disable']==['off']
    assert len(calls)==2
    assert [c[0].artifact_dir.name for c in calls]==['round-1','final']
    assert all(c[1]['profile']=='industrial' and c[1]['enable']==['extra'] for c in calls)
    final=store.latest_fix_job(run)
    assert final['accepted']==0 and final['rejected']==1
    assert final['final_stats']['llm_budget']['calls']==1
    assert store.list_fixes(run)[0]['validation']['compile']['status']=='SKIPPED'
    assert (workspace/'main.cpp').read_bytes()==source
