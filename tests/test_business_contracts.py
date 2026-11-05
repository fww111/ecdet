"""Execute explicit business oracles; failures in the runner are not defects."""
import json
import shutil
from pathlib import Path

import pytest

from ecdet.l3_analysis.business_contracts import run_contracts


def fixture(tmp_path, source='int accept(int enabled){return 1;}', harness=None):
    root=tmp_path/'project';root.mkdir()
    (root/'unit.c').write_text(source,encoding='utf-8')
    spec=tmp_path/'contracts.json'
    (tmp_path/'oracle.c').write_text(harness or '''
#include "ecdet_contract.h"
int accept(int);
int main(void){ECDET_CHECK(accept(0)==0);ECDET_CHECK(accept(1)==1);ECDET_PASS();}
''',encoding='utf-8')
    spec.write_text(json.dumps({'version':1,'contracts':[{
        'id':'GATE','source':'unit.c','function':'accept','harness':'oracle.c',
        'requirement':'Disabled state must reject; enabled state must accept.'}]}),encoding='utf-8')
    return root,spec


@pytest.mark.parametrize('source,status,count',[
    ('int accept(int enabled){return 1;}','FAIL',1),
    ('int accept(int enabled){return enabled!=0;}','PASS',0),
    ('int accept(int enabled){return broken;}','ERROR',0),
])
def test_real_oracle_pair(tmp_path,source,status,count):
    if not shutil.which('gcc'):pytest.skip('Native GCC required')
    root,spec=fixture(tmp_path,source)
    receipt,alerts=run_contracts(root,spec,tmp_path/'out')
    assert receipt['results'][0]['status']==status
    assert len(alerts)==count
    if alerts:
        assert alerts[0].engine=='business-contract'
        assert alerts[0].properties['contract_id']=='GATE'


def test_empty_oracle_does_not_pass(tmp_path):
    root,spec=fixture(tmp_path,harness='int main(void){return 0;}')
    receipt,alerts=run_contracts(root,spec,tmp_path/'out')
    assert receipt['results'][0]['status']=='ERROR'
    assert not alerts


def test_target_not_executed_does_not_pass(tmp_path):
    root,spec=fixture(tmp_path,harness='''
#include "ecdet_contract.h"
int accept(int);
int main(void){if(0){ECDET_CHECK(accept(0)==0);}ECDET_PASS();}
''')
    receipt,alerts=run_contracts(root,spec,tmp_path/'out')
    assert receipt['results'][0]['status']=='ERROR'
    assert not alerts


def test_missing_compiler_is_unsupported(tmp_path):
    root,spec=fixture(tmp_path)
    receipt,alerts=run_contracts(root,spec,tmp_path/'out',compiler='ecdet-nonexistent-compiler')
    assert receipt['results'][0]['status']=='UNSUPPORTED'
    assert not alerts


def test_contract_path_escape_rejected(tmp_path):
    root,spec=fixture(tmp_path)
    data=json.loads(spec.read_text());data['contracts'][0]['source']='../oracle.c'
    spec.write_text(json.dumps(data))
    with pytest.raises(ValueError):run_contracts(root,spec,tmp_path/'out')


def test_timeout_is_not_a_defect(tmp_path):
    root,spec=fixture(tmp_path,'int accept(int enabled){for(;;){} return 1;}')
    receipt,alerts=run_contracts(root,spec,tmp_path/'out',timeout=0.2)
    assert receipt['results'][0]['status']=='TIMEOUT'
    assert not alerts


def test_stale_executable_cannot_hide_compile_failure(tmp_path):
    root,spec=fixture(tmp_path,'int accept(int enabled){return enabled!=0;}')
    good,_=run_contracts(root,spec,tmp_path/'out')
    assert good['results'][0]['status']=='PASS'
    (root/'unit.c').write_text('int accept(int enabled){return missing_name;}')
    bad,alerts=run_contracts(root,spec,tmp_path/'out')
    assert bad['results'][0]['status']=='ERROR' and not alerts
    assert bad['results'][0]['artifact_dir']!=good['results'][0]['artifact_dir']


@pytest.mark.parametrize('value',[float('nan'),0,-1,True,61])
def test_invalid_timeout_rejected(tmp_path,value):
    root,spec=fixture(tmp_path)
    with pytest.raises(ValueError):run_contracts(root,spec,tmp_path/'out',timeout=value)


def test_cli_merges_contract_alert_and_receipt(tmp_path,monkeypatch):
    from ecdet import cli
    root,spec=fixture(tmp_path)
    monkeypatch.setattr(cli,'run_all_engines',lambda *a,**kw:([],[]))
    out=tmp_path/'scan'
    assert cli.main(['scan',str(root),'--no-build','--contracts',str(spec),'-o',str(out)])==1
    results=json.loads((out/'results.sarif').read_text(encoding='utf-8'))['runs'][0]['results']
    assert results[0]['ruleId']=='ECDET-BUSINESS-CONTRACT'
    assert results[0]['properties']['engine']=='business-contract'
    assert (out/'business-contracts/contracts.json').is_file()


def test_cli_contract_error_cannot_return_clean(tmp_path,monkeypatch):
    from ecdet import cli
    root,spec=fixture(tmp_path)
    monkeypatch.setattr(cli,'run_all_engines',lambda *a,**kw:([],[]))
    assert cli.main(['scan',str(root),'--no-build','--contracts',str(spec),
                     '--contract-compiler','not-a-real-compiler','-o',str(tmp_path/'scan')])==2
