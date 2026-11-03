"""An explicit firmware carrier must never execute the host source harness."""
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts
from ecdet.l3_analysis.dynamic.engine import DynamicEngine


def test_explicit_renode_is_not_silently_executed_as_host(tmp_path, monkeypatch):
    engine=DynamicEngine(carrier='renode')
    monkeypatch.setattr(DynamicEngine,'available',property(lambda self:True))
    def wrong_backend(*args,**kwargs):
        raise AssertionError('Explicit Renode selection reached host execution')
    monkeypatch.setattr(engine,'_fuzz_one',wrong_backend)
    facts=[build_file_facts('demo.c','int target(int n) { return n; }')]
    assert engine.run(tmp_path,facts)==[]
    assert engine.last_run[0]['status']=='UNSUPPORTED'
    assert 'firmware' in engine.last_run[0]['reason']
