"""Run four controlled triage cases against an explicitly configured endpoint."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from urllib.parse import urlsplit, urlunsplit

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0,str(PROJECT))

from ecdet.l2_ir.model import Alert, Location, Provenance, Severity
from ecdet.l2_ir.sarif import build_sarif
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.builtin_rules.rules_meta import get_rule_meta
from ecdet.l4_llm.budget import BudgetedClient, LlmCallBudget
from ecdet.l4_llm.client import OpenAICompatClient
from ecdet.l4_llm.triage import TriageRunner, TriageVerdict


@dataclass
class Configuration:
    base_url: str = ''
    model: str = ''
    api_key: str = field(default='',repr=False)
    credential_source: str = 'anonymous'
    error_type: str = ''


def load_configuration(base_url=None, model=None, settings_db=None) -> Configuration:
    settings={}
    error=''
    if settings_db is not None:
        path=Path(settings_db).expanduser().resolve()
        if path.is_file():
            try:
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as connection:
                    settings=dict(connection.execute(
                        "SELECT key,value FROM settings WHERE key IN ('llm_mode','llm_base_url','llm_model','llm_api_key')"))
            except sqlite3.Error as exc:
                error=type(exc).__name__
        else:
            error='SettingsDatabaseMissing'
    real_settings=settings if settings.get('llm_mode')=='real' else {}
    key=os.environ.get('ECODET_LLM_API_KEY') or real_settings.get('llm_api_key') or ''
    source=('environment' if os.environ.get('ECODET_LLM_API_KEY') else
            'settings-db' if real_settings.get('llm_api_key') else 'anonymous')
    return Configuration(
        base_url=(base_url or os.environ.get('ECODET_LLM_BASE_URL') or real_settings.get('llm_base_url') or '').rstrip('/'),
        model=model or os.environ.get('ECODET_LLM_MODEL') or real_settings.get('llm_model') or '',
        api_key=key,credential_source=source,error_type=error)


def _endpoint(address: str) -> str:
    try:
        parsed=urlsplit(address)
        host=parsed.hostname or ''
        if ':' in host:
            host=f'[{host}]'
        if parsed.port:
            host+=f':{parsed.port}'
        return urlunsplit((parsed.scheme,host,parsed.path,'',''))
    except ValueError:
        return '<invalid-endpoint>'


def _redact(value, secrets):
    if isinstance(value,str):
        for secret in secrets:
            if secret:
                value=value.replace(secret,'[REDACTED]')
        return value
    if isinstance(value,list):
        return [_redact(item,secrets) for item in value]
    if isinstance(value,dict):
        return {key:_redact(item,secrets) for key,item in value.items()}
    return value


def validate_llm_endpoint(output_dir, *, base_url=None, model=None, settings_db=None,
                          max_calls=8, timeout=30, client=None) -> dict:
    """client injection is for labelled fake tests; CLI never selects a mock."""
    output=Path(output_dir).resolve()
    output.mkdir(parents=True,exist_ok=True)
    config=load_configuration(base_url,model,settings_db)
    fixture=PROJECT/'examples/llm_validation'
    source=(fixture/'samples.c').read_text(encoding='utf-8')
    cases=json.loads((fixture/'cases.json').read_text(encoding='utf-8'))
    context=finalize_facts([build_file_facts('samples.c',source)])
    budget=LlmCallBudget(max_calls)
    configured=bool(config.base_url and config.model)
    mode=getattr(client,'mode','fake') if client is not None else 'real' if configured else 'not_configured'
    runner=None
    configuration_error=''
    if configured:
        try:
            parsed=urlsplit(config.base_url)
            if parsed.scheme not in {'http','https'} or not parsed.hostname:
                raise ValueError('Invalid endpoint')
            raw_client=client if client is not None else OpenAICompatClient(
                base_url=config.base_url,model=config.model,api_key=config.api_key or None,timeout=timeout)
            runner=TriageRunner(BudgetedClient(raw_client,budget,'controlled-validation'))
        except (TypeError,ValueError) as exc:
            configuration_error=type(exc).__name__
    records=[]
    alerts=[]
    for case in cases:
        # Ground truth is deliberately not passed to the alert or prompt.
        alert=Alert(rule_id=case['rule_id'],engine='validation-candidate',severity=Severity.WARNING,
                    message=case['message'],location=Location(path='samples.c',line=case['line']),
                    provenance=Provenance.SUSPECTED)
        before=budget.calls
        started=time.perf_counter()
        if runner is None:
            verdict=TriageVerdict(alert.rule_id,'samples.c',case['line'],'NEEDS_REVIEW',0.0,
                                   '端点未配置或配置无效，未执行模型调用',client_mode=mode,model=config.model)
        else:
            verdict=runner.triage(alert,context)
        alert.triage=verdict.to_alert_props()
        alerts.append(alert)
        eligible=verdict.verified and verdict.verdict in {'TRUE_POSITIVE','FALSE_POSITIVE'}
        records.append({'id':case['id'],'function':case['function'],'line':case['line'],
                        'status':'EXECUTED' if runner is not None else 'NOT_RUN',
                        'seconds':time.perf_counter()-started,'calls':budget.calls-before,
                        'expected_verdict':case['expected_verdict'],'final_verdict':verdict.verdict,
                        'verified':verdict.verified,'expected_match':verdict.verdict==case['expected_verdict'] if eligible else None,
                        'triage':alert.triage})
    snapshot=budget.snapshot()
    structured=sum(any(attempt['status']=='PASS' for attempt in item['triage']['attempts']) for item in records)
    if not configured:
        status='NOT_CONFIGURED'
    elif configuration_error or structured==0:
        status='ERROR'
    else:
        status='COMPLETED'
    result={'status':status,'mode':mode,'endpoint':_endpoint(config.base_url),'model':config.model,
            'credential_source':config.credential_source,'configuration_error':configuration_error or config.error_type,
            'fixture_sha256':hashlib.sha256(source.encode('utf-8')).hexdigest(),
            'summary':{'total_cases':len(records),'executed_cases':sum(item['status']=='EXECUTED' for item in records),
                       'calls':budget.calls,'transport_successes':sum(item['status']=='PASS' for item in snapshot['attempts']),
                       'structured_cases':structured,'correct_suggestions':sum(item['expected_match'] is True for item in records),
                       'incorrect_suggestions':sum(item['expected_match'] is False for item in records),
                       'needs_review':sum(item['final_verdict']=='NEEDS_REVIEW' for item in records)},
            'budget':snapshot,'cases':records,
            'interpretation':'COMPLETED means controlled calls and statistics finished; it is not a model-quality pass or a project detection benchmark.'}
    secrets=[config.api_key]
    result=_redact(result,secrets)
    rules={case['rule_id']:get_rule_meta(case['rule_id']) for case in cases}
    sarif=_redact(build_sarif(alerts,[rule for rule in rules.values() if rule is not None]),secrets)
    (output/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
    (output/'results.sarif').write_text(json.dumps(sarif,ensure_ascii=False,indent=2,allow_nan=False),encoding='utf-8')
    return result


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url')
    parser.add_argument('--model')
    parser.add_argument('--settings-db')
    parser.add_argument('--output-dir',default=str(PROJECT/'ecdet_reports/llm_endpoint_validation'))
    parser.add_argument('--max-calls',type=int,default=8)
    parser.add_argument('--timeout',type=int,default=30)
    args,unknown=parser.parse_known_args(argv)
    if unknown:
        parser.error('Unsupported option. Credentials must come from environment or settings database.')
    if args.max_calls < 0 or args.timeout <= 0:
        parser.error('Call limit must be nonnegative and timeout must be positive.')
    result=validate_llm_endpoint(args.output_dir,base_url=args.base_url,model=args.model,
                                 settings_db=args.settings_db,max_calls=args.max_calls,timeout=args.timeout)
    print(json.dumps({key:result[key] for key in ('status','mode','endpoint','model','summary')},ensure_ascii=False,indent=2))
    return 0 if result['status']=='COMPLETED' else 2 if result['status']=='NOT_CONFIGURED' else 1


if __name__=='__main__':
    raise SystemExit(main())
