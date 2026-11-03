"""A bounded, shared counter for actual model-call attempts across stages."""
from __future__ import annotations

from threading import Lock
from urllib.parse import urlsplit, urlunsplit

from ecdet.l4_llm.client import LlmTransportError


class CallBudgetExceeded(LlmTransportError):
    pass


class LlmCallBudget:
    def __init__(self, max_calls: int = 64):
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls < 0:
            raise ValueError('max_calls must be a nonnegative integer')
        self.max_calls = max_calls
        self.calls = 0
        self.refused_calls = 0
        self._attempts: list[dict] = []
        self._lock = Lock()

    def reserve(self, stage: str, mode: str, model: str = '', endpoint: str = '') -> int:
        with self._lock:
            if self.calls >= self.max_calls:
                self.refused_calls += 1
                raise CallBudgetExceeded(f'LLM call budget exhausted ({self.calls}/{self.max_calls})')
            ticket = self.calls
            self.calls += 1
            self._attempts.append({'stage': stage, 'mode': mode, 'model': model, 'endpoint':endpoint,
                                   'status': 'RUNNING'})
            return ticket

    def finish(self, ticket: int, status: str) -> None:
        with self._lock:
            self._attempts[ticket]['status'] = status

    def snapshot(self) -> dict:
        with self._lock:
            return {'max_calls': self.max_calls, 'calls': self.calls,
                    'refused_calls': self.refused_calls,
                    'attempts': [dict(item) for item in self._attempts]}


class BudgetedClient:
    def __init__(self, client, budget: LlmCallBudget, stage: str):
        self.client, self.budget, self.stage = client, budget, stage
        self.mode = getattr(client, 'mode',
                            'mock' if type(client).__name__.startswith('Mock') else 'fake')
        self.model = getattr(client, 'model', '')
        address = urlsplit(getattr(client, 'base_url', ''))
        host = address.hostname or ''
        if ':' in host:
            host = f'[{host}]'
        if address.port:
            host += f':{address.port}'
        self.base_url = urlunsplit((address.scheme, host, address.path, '', ''))

    def complete(self, system: str, user: str) -> str:
        ticket = self.budget.reserve(self.stage, self.mode, self.model, self.base_url)
        try:
            result = self.client.complete(system, user)
        except Exception:
            self.budget.finish(ticket, 'ERROR')
            raise
        self.budget.finish(ticket, 'PASS')
        return result
