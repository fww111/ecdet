"""Endpoint validation harness tests use labelled fake clients, never real APIs."""
import json
import re
import sqlite3
import pytest

from scripts.validate_llm_endpoint import validate_llm_endpoint, load_configuration, main


def clear_environment(monkeypatch):
    for name in ('ECODET_LLM_BASE_URL','ECODET_LLM_MODEL','ECODET_LLM_API_KEY'):
        monkeypatch.delenv(name,raising=False)


class FakeClient:
    mode='fake'
    model='fake-model'
    base_url='http://fake.invalid/v1'
    def __init__(self):
        self.prompts=[]
    def complete(self,system,user):
        index=len(self.prompts)
        self.prompts.append((system,user))
        line=int(re.search(r'位置：samples.c:(\d+)',user).group(1))
        return json.dumps({'verdict':['TRUE_POSITIVE','FALSE_POSITIVE','TRUE_POSITIVE','FALSE_POSITIVE'][index],
                           'confidence':0.9,'reason':'controlled fake response','evidence_lines':[line]})


def test_missing_configuration_does_not_send_requests(tmp_path,monkeypatch):
    clear_environment(monkeypatch)
    monkeypatch.setattr('scripts.validate_llm_endpoint.OpenAICompatClient',lambda **kwargs: (_ for _ in ()).throw(AssertionError('network client constructed')))
    result=validate_llm_endpoint(tmp_path)
    assert result['status']=='NOT_CONFIGURED'
    assert result['summary']['calls']==0
    assert (tmp_path/'validation.json').is_file()
    assert main(['--output-dir',str(tmp_path/'cli')])==2


def test_fake_results_are_labelled_and_expectations_not_sent(tmp_path):
    client=FakeClient()
    result=validate_llm_endpoint(tmp_path,base_url=client.base_url,model=client.model,client=client)
    assert result['status']=='COMPLETED'
    assert result['mode']=='fake'
    assert result['summary']['correct_suggestions']==4
    assert result['summary']['needs_review']==0
    assert result['summary']['calls']==4
    assert all('expected_verdict' not in system+user for system,user in client.prompts)
    sarif=json.loads((tmp_path/'results.sarif').read_text(encoding='utf-8'))
    assert all(r['properties']['engine']=='validation-candidate' for r in sarif['runs'][0]['results'])
    assert all(r['properties']['provenance']=='suspected' for r in sarif['runs'][0]['results'])


def test_all_transport_failures_are_error_not_model_acceptance(tmp_path):
    class Failing(FakeClient):
        def complete(self,*args):
            raise RuntimeError('endpoint failure')
    result=validate_llm_endpoint(tmp_path,base_url='http://fake.invalid/v1',model='fake',client=Failing())
    assert result['status']=='ERROR'
    assert result['summary']['needs_review']==4
    assert result['summary']['structured_cases']==0
    assert result['summary']['correct_suggestions']==0


def test_all_malformed_responses_are_error(tmp_path):
    class Malformed(FakeClient):
        def complete(self,*args):
            return 'not a structured verdict'
    result=validate_llm_endpoint(tmp_path,base_url='http://fake.invalid/v1',model='fake',client=Malformed())
    assert result['status']=='ERROR'
    assert result['summary']['structured_cases']==0


def test_settings_are_read_only_and_secrets_not_saved(tmp_path,monkeypatch):
    clear_environment(monkeypatch)
    db=tmp_path/'settings.db'
    con=sqlite3.connect(db)
    con.execute('CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT)')
    con.executemany('INSERT INTO settings VALUES (?,?)',[
        ('llm_mode','real'),('llm_base_url','http://user:password@fake.invalid/v1?key=hidden'),
        ('llm_model','test-model'),('llm_api_key','api-test-secret')])
    con.commit();con.close()
    before=db.read_bytes()
    config=load_configuration(settings_db=db)
    assert config.api_key=='api-test-secret'
    result=validate_llm_endpoint(tmp_path/'out',settings_db=db,client=FakeClient())
    assert result['credential_source']=='settings-db'
    for path in (tmp_path/'out').glob('*'):
        if path.is_file():
            text=path.read_text(encoding='utf-8')
            assert 'api-test-secret' not in text and 'password' not in text and 'hidden' not in text
    assert db.read_bytes()==before


def test_total_calls_still_bounded(tmp_path):
    result=validate_llm_endpoint(tmp_path,base_url='http://fake.invalid/v1',model='fake',client=FakeClient(),max_calls=1)
    assert result['summary']['calls']==1
    assert result['summary']['needs_review']>=3
    assert result['budget']['refused_calls']>=1


def test_cli_rejects_key_argument_without_echoing_it(capsys):
    secret='private-test-key-value'
    with pytest.raises(SystemExit) as error:
        main(['--api-key',secret])
    assert error.value.code==2
    output=capsys.readouterr()
    assert secret not in output.out+output.err


def test_secret_echo_in_model_reason_is_redacted(tmp_path,monkeypatch):
    secret='private-test-secret-value'
    monkeypatch.setenv('ECODET_LLM_API_KEY',secret)
    class Echo(FakeClient):
        def complete(self,system,user):
            response=json.loads(super().complete(system,user))
            response['reason']=secret
            return json.dumps(response)
    result=validate_llm_endpoint(tmp_path,base_url='http://fake.invalid/v1',model='fake',client=Echo())
    assert secret not in json.dumps(result)
    assert secret not in (tmp_path/'results.sarif').read_text(encoding='utf-8')
