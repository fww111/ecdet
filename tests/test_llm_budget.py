"""All LLM stages debit the same thread-safe call budget."""
from concurrent.futures import ThreadPoolExecutor

import pytest

from ecdet.l4_llm.budget import BudgetedClient, LlmCallBudget, CallBudgetExceeded


class FakeClient:
    mode = 'fake'
    def __init__(self):
        self.calls = 0
    def complete(self, system, user):
        self.calls += 1
        return '{}'


def test_budget_shared_across_triage_retry_patch_and_harness():
    budget = LlmCallBudget(3)
    raw = FakeClient()
    clients = [BudgetedClient(raw,budget,stage) for stage in ['triage','patch','harness']]
    for client in clients:
        assert client.complete('s','u') == '{}'
    with pytest.raises(CallBudgetExceeded):
        clients[0].complete('retry','u')
    assert raw.calls == budget.calls == 3
    assert budget.snapshot()['refused_calls'] == 1
    assert {r['stage'] for r in budget.snapshot()['attempts']} == {'triage','patch','harness'}


def test_concurrent_budget_does_not_overspend():
    budget = LlmCallBudget(2)
    raw = FakeClient()
    client = BudgetedClient(raw,budget,'triage')
    def call(_):
        try:
            return client.complete('s','u')
        except CallBudgetExceeded:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(call, range(20)))
    assert results.count('{}') == raw.calls == budget.calls == 2
    assert budget.snapshot()['refused_calls'] == 18


def test_failure_consumes_attempt_and_does_not_record_prompt_or_secrets():
    class Broken(FakeClient):
        base_url = 'http://user:password@127.0.0.1:8000/v1?key=secret'
        def complete(self, system, user):
            raise RuntimeError('API secret material')
    budget=LlmCallBudget(1)
    with pytest.raises(RuntimeError):
        BudgetedClient(Broken(),budget,'patch').complete('secret prompt','source')
    snapshot=budget.snapshot()
    assert snapshot['calls'] == 1
    assert snapshot['attempts'][0]['status'] == 'ERROR'
    assert 'secret' not in str(snapshot)
    assert 'password' not in str(snapshot)


def test_zero_budget_is_valid_and_negative_budget_rejected():
    with pytest.raises(CallBudgetExceeded):
        BudgetedClient(FakeClient(), LlmCallBudget(0),'triage').complete('s','u')
    with pytest.raises(ValueError):
        LlmCallBudget(-1)


def test_evaluation_uses_the_same_total_call_limit(tmp_path):
    from ecdet.eval import AblationConfig,run_ecdet_config
    (tmp_path/'m.c').write_text('\n'.join(f'int f{i}(void) {{ return 1; }}' for i in range(10)),encoding='utf-8')
    class LowConfidence(FakeClient):
        def complete(self,*args):
            self.calls+=1
            return '{"verdict":"NEEDS_REVIEW","confidence":0.1,"reason":"review","evidence_lines":[]}'
    raw=LowConfidence()
    result=run_ecdet_config(tmp_path,AblationConfig('bounded',use_dynamic=False,max_llm_calls=2),llm_client=raw)
    assert raw.calls==2
    assert result.llm_budget['calls']==2
    assert result.llm_budget['refused_calls']>0
