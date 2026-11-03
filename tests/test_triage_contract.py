"""Triage contracts: fail closed, retain evidence and trace actual context."""
import json

import pytest

from ecdet.l2_ir.model import Alert, Location, Severity
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l4_llm.client import LlmTransportError, OpenAICompatClient
from ecdet.l4_llm.slicer import slice_context
from ecdet.l4_llm.triage import TriageRunner, parse_verdict_json, triage_alerts

SOURCE = 'int bad(void) {\n int a[1];\n a[2] = 1;\n return 0;\n}\n'


def alert(path='t.c', line=3):
    return Alert(rule_id='CERT C ARR30-C', engine='audit', severity=Severity.ERROR,
                 message='out of bounds', location=Location(path=path, line=line))


def payload(**changes):
    data = dict(verdict='TRUE_POSITIVE', confidence=0.9, reason='source evidence', evidence_lines=[3])
    data.update(changes)
    return data


class SequenceClient:
    mode = 'fake'
    model = 'deterministic-test'

    def __init__(self, *values):
        self.values, self.calls, self.prompts = values, 0, []

    def complete(self, system, user):
        self.prompts.append(user)
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        if isinstance(value, Exception):
            raise value
        return json.dumps(value) if isinstance(value, dict) else value


@pytest.mark.parametrize('field', ['verdict', 'confidence', 'reason', 'evidence_lines'])
def test_missing_required_field_rejected(field):
    data = payload()
    del data[field]
    assert parse_verdict_json(json.dumps(data)) is None


@pytest.mark.parametrize('confidence', [float('nan'), float('inf'), -float('inf'), True, None, '0.9', -0.1, 1.1])
def test_invalid_confidence_rejected(confidence):
    assert parse_verdict_json(json.dumps(payload(confidence=confidence))) is None


@pytest.mark.parametrize('lines', [[3.9], [True], [0], [-1], [float('nan')], [float('inf')], ['3'], '3'])
def test_invalid_citation_type_rejected(lines):
    assert parse_verdict_json(json.dumps(payload(evidence_lines=lines))) is None


@pytest.mark.parametrize('raw', [[], None, 1, '[]', 'prefix ' + json.dumps(payload()), json.dumps(payload()) + ' trailing'])
def test_non_object_or_surrounded_response_rejected(raw):
    assert parse_verdict_json(raw) is None


@pytest.mark.parametrize('verdict', ['TRUE_POSITIVE', 'FALSE_POSITIVE'])
@pytest.mark.parametrize('lines', [[], [3, 999]])
def test_tp_fp_have_same_evidence_gate(verdict, lines):
    client = SequenceClient(payload(verdict=verdict, evidence_lines=lines))
    ctx = finalize_facts([build_file_facts('t.c', SOURCE)])
    result = TriageRunner(client).triage(alert(), ctx)
    assert result.verdict == 'NEEDS_REVIEW'
    assert not result.verified
    assert result.cited_lines == lines
    assert result.evidence_status == 'FAIL'


def test_low_final_confidence_stays_review_and_attempts_are_retained():
    client = SequenceClient(payload(confidence=0.1), payload(confidence=0.2))
    result = TriageRunner(client).triage(alert(), finalize_facts([build_file_facts('t.c', SOURCE)]))
    assert result.verdict == 'NEEDS_REVIEW'
    assert result.used_rag and result.llm_calls == 2
    assert len(result.attempts) == 2
    assert result.to_alert_props()['semantic_status'] == 'UNVERIFIED'
    assert result.client_mode == 'fake'


def test_parse_or_transport_failure_can_recover_with_history():
    ctx = finalize_facts([build_file_facts('t.c', SOURCE)])
    for first in ['invalid', LlmTransportError('offline'), ValueError('bad adapter')]:
        result = TriageRunner(SequenceClient(first, payload())).triage(alert(), ctx)
        assert result.verdict == 'TRUE_POSITIVE' and result.verified
        assert [item['status'] for item in result.attempts] == ['ERROR', 'PASS']


def test_final_failure_isolated_and_missing_context_clears_old_verdict(tmp_path):
    missing = alert('missing.c')
    missing.triage = {'verdict': 'TRUE_POSITIVE', 'verified': True}
    (tmp_path / 't.c').write_text(SOURCE, encoding='utf-8')
    second = alert()
    verdicts, _ = triage_alerts([missing, second], tmp_path, client=SequenceClient(ValueError('bad adapter')))
    assert [v.verdict for v in verdicts] == ['NEEDS_REVIEW', 'NEEDS_REVIEW']
    assert missing.triage['verdict'] == 'NEEDS_REVIEW'
    assert second.triage['verdict'] == 'NEEDS_REVIEW'


def test_unalerted_callee_file_is_loaded(tmp_path):
    (tmp_path / 't.c').write_text('int helper(void);\nint bad(void) {\n return helper();\n}\n', encoding='utf-8')
    (tmp_path / 'helper.c').write_text('int helper(void) {\n return 9;\n}\n', encoding='utf-8')
    client = SequenceClient(payload())
    result, _ = triage_alerts([alert()], tmp_path, client=client)
    assert 'return 9;' in client.prompts[0]
    assert 'helper.c' in result[0].context['loaded_files']
    assert result[0].context['provided_ranges']


def test_same_named_static_functions_resolve_in_calling_file():
    a = build_file_facts('a.c', 'static int helper(void) { return 111; }\n')
    b = build_file_facts('b.c', 'static int helper(void) { return 222; }\nint bad(void) {\n return helper();\n}\n')
    result = slice_context(alert('b.c'), finalize_facts([a, b]))
    assert 'return 222;' in result.render()
    assert 'return 111;' not in result.render()


def test_other_file_static_function_is_not_resolved_as_global():
    a = build_file_facts('a.c', 'static int helper(void) { return 111; }\n')
    b = build_file_facts('b.c', 'int helper(void);\nint bad(void) {\n return helper();\n}\n')
    result = slice_context(alert('b.c'), finalize_facts([a, b]))
    assert 'return 111;' not in result.render()
    assert any(item['name'] == 'helper' for item in result.unresolved_calls)


def test_truncated_context_is_visible_and_keeps_alert_line():
    source = 'int bad(void) {\n' + ''.join(' int x%d = %d;\n' % (i, i) for i in range(100)) + ' return 0;\n}\n'
    result = slice_context(alert(line=50), finalize_facts([build_file_facts('t.c', source)]), budget_chars=100)
    assert result.truncated
    assert result.n_chars <= 100
    assert any(r['start_line'] <= 50 <= r['end_line'] for r in result.provided_ranges)


def test_client_rejects_non_string_message_content(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return json.dumps({'choices': [{'message': {'content': []}}]}).encode()
    monkeypatch.setattr('urllib.request.urlopen', lambda *args, **kwargs: Response())
    with pytest.raises(LlmTransportError):
        OpenAICompatClient().complete('system', 'user')


def test_duplicate_json_fields_and_non_string_reason_rejected():
    assert parse_verdict_json('{"verdict":"TRUE_POSITIVE","verdict":"FALSE_POSITIVE",'
                              '"confidence":0.9,"reason":"r","evidence_lines":[3]}') is None
    assert parse_verdict_json(json.dumps(payload(reason={'text': 'reason'}))) is None
    assert parse_verdict_json(json.dumps(payload(confidence=10 ** 400))) is None


def test_error_fp_requires_review_but_explicit_policy_is_recorded():
    ctx = finalize_facts([build_file_facts('t.c', SOURCE)])
    client = SequenceClient(payload(verdict='FALSE_POSITIVE'))
    pending = TriageRunner(client).triage(alert(), ctx)
    assert pending.verdict == 'NEEDS_REVIEW'
    assert pending.verified and pending.suggested_verdict == 'FALSE_POSITIVE'
    assert pending.review_pending
    accepted = TriageRunner(client, auto_accept=True).triage(alert(), ctx)
    assert accepted.verdict == 'FALSE_POSITIVE' and not accepted.review_pending


def test_invalid_fp_cannot_be_auto_accepted():
    ctx = finalize_facts([build_file_facts('t.c', SOURCE)])
    result = TriageRunner(SequenceClient(payload(verdict='FALSE_POSITIVE', evidence_lines=[])),
                          auto_accept=True).triage(alert(), ctx)
    assert result.verdict == 'NEEDS_REVIEW' and not result.verified


def test_citation_must_be_in_actual_truncated_excerpt():
    source = 'int bad(void) {\n' + ''.join(' int x%d = %d;\n' % (i, i) for i in range(100)) + ' return 0;\n}\n'
    result = TriageRunner(SequenceClient(payload(evidence_lines=[3, 50])), budget_chars=100).triage(
        alert(line=50), finalize_facts([build_file_facts('t.c', source)]))
    assert result.verdict == 'NEEDS_REVIEW' and not result.verified
    assert result.cited_lines == [3, 50]


def test_rag_trigger_and_acceptance_threshold_are_independent():
    ctx = finalize_facts([build_file_facts('t.c', SOURCE)])
    result = TriageRunner(SequenceClient(payload(confidence=0.1)), rag_conf_threshold=0).triage(alert(), ctx)
    assert result.verdict == 'NEEDS_REVIEW' and not result.used_rag and result.llm_calls == 1
