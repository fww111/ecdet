"""Unavailable backends must be visible rather than resemble a clean scan."""
from ecdet.l3_analysis.engine import AnalysisTarget, ClangTidyAdapter, run_all_engines


def test_scheduler_records_unavailable_engine(tmp_path, monkeypatch, caplog):
    engine = ClangTidyAdapter()
    monkeypatch.setattr(engine, 'available', lambda: False)
    alerts, _ = run_all_engines(AnalysisTarget(tmp_path), engines=[engine])
    assert alerts == []
    assert 'clang-tidy unavailable' in caplog.text


def test_direct_adapter_records_unavailable_engine(tmp_path, monkeypatch, caplog):
    engine = ClangTidyAdapter()
    monkeypatch.setattr(engine, 'available', lambda: False)
    assert engine.run(AnalysisTarget(tmp_path), set()) == []
    assert 'executable not found' in caplog.text


def test_external_diagnostics_receive_report_rule_metadata(tmp_path,monkeypatch):
    from ecdet.l2_ir.model import Alert,Location,Severity
    from ecdet.l2_ir.sarif import build_sarif
    engine=ClangTidyAdapter()
    monkeypatch.setattr(engine,'available',lambda:True)
    monkeypatch.setattr(engine,'run',lambda *args:[Alert(rule_id='clang-analyzer-core.NullDereference',
        engine='clang-tidy',severity=Severity.WARNING,message='issue',location=Location(path='m.c',line=2))])
    alerts,metas=run_all_engines(AnalysisTarget(tmp_path),engines=[engine])
    assert any(meta.rule_id==alerts[0].rule_id for meta in metas)
    assert build_sarif(alerts,metas)['runs'][0]['results'][0]['ruleIndex']==0
