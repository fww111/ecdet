"""Actual tool probes and explicit incomplete-analysis status handling."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from ecdet.l3_analysis.adapters.esbmc import ESBMCAdapter
from ecdet.l3_analysis.engine import AnalysisTarget, collect_sources


def project(tmp_path, code='int main(void){return 0;}'):
    root=tmp_path/'工程';root.mkdir()
    (root/'main.c').write_text(code,encoding='utf-8')
    return AnalysisTarget(root,collect_sources(root),artifact_dir=tmp_path/'reports')


def receipt(target):
    return json.loads((target.artifact_dir/'esbmc/receipt.json').read_text(encoding='utf-8'))


@pytest.mark.parametrize('code,returncode,status',[
    ('ERROR: PARSING ERROR',6,'ERROR'),
    ('VERIFICATION SUCCESSFUL',2,'ERROR'),
    ('',0,'ERROR'),
    ('unwinding assertion loop 1\nVERIFICATION FAILED',1,'BOUND_EXHAUSTED')])
def test_incomplete_tool_result_is_not_clean(tmp_path,monkeypatch,code,returncode,status):
    target=project(tmp_path)
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: subprocess.CompletedProcess(a[0],returncode,code,''))
    alerts=ESBMCAdapter().run(target,set())
    assert receipt(target)['status']==status
    assert alerts[0].rule_id=='ECDET-ESBMC-INCOMPLETE'
    assert alerts[0].properties['is_defect'] is False


def test_library_without_entry_is_unsupported(tmp_path,monkeypatch):
    target=project(tmp_path,'int helper(void){return 0;}')
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    alerts=ESBMCAdapter().run(target,set())
    assert receipt(target)['status']=='UNSUPPORTED'
    assert alerts[0].severity.value=='error'


def test_missing_binary_is_unsupported(tmp_path,monkeypatch):
    target=project(tmp_path)
    monkeypatch.setattr(shutil,'which',lambda _: None)
    assert ESBMCAdapter().run(target,set())[0].properties['analysis_status']=='UNSUPPORTED'


@pytest.mark.parametrize('stdout,stderr',[(b'partial output',None),('partial output',None),
    (b'partial output','partial error'),('partial output',b'partial error'),(None,None)])
def test_timeout_has_receipt_and_status(tmp_path,monkeypatch,stdout,stderr):
    target=project(tmp_path)
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    def timeout(*a,**k):raise subprocess.TimeoutExpired(a[0],1,output=stdout,stderr=stderr)
    monkeypatch.setattr(subprocess,'run',timeout)
    assert ESBMCAdapter().run(target,set())[0].properties['analysis_status']=='TIMEOUT'
    output=(target.artifact_dir/'esbmc/run.log').read_text()
    if stdout:assert 'partial output' in output
    if stderr:assert 'partial error' in output


def test_full_project_copy_includes_headers_and_pointer_checks(tmp_path,monkeypatch):
    target=project(tmp_path,'#include "api.h"\nint main(void){return helper();}')
    (target.root/'include').mkdir()
    (target.root/'include/api.h').write_text('int helper(void);')
    (target.root/'helper.c').write_text('int helper(void){return 1;}')
    target.files=collect_sources(target.root)
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    def check(command,**kw):
        assert '--no-pointer-check' not in command
        assert any(p.endswith('helper.c') for p in command)
        work=Path(kw['cwd']);assert str(work).isascii()
        assert (work/'include/api.h').read_bytes()==(target.root/'include/api.h').read_bytes()
        assert '-I'+str(work/'include') in command
        return subprocess.CompletedProcess(command,0,'VERIFICATION SUCCESSFUL','')
    monkeypatch.setattr(subprocess,'run',check)
    assert ESBMCAdapter().run(target,set())==[]
    assert receipt(target)['status']=='PASS'


@pytest.mark.parametrize('value',['nan','0','-1'])
def test_invalid_timeout_is_error(tmp_path,monkeypatch,value):
    target=project(tmp_path)
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    monkeypatch.setenv('ECDET_ESBMC_TIMEOUT',value)
    assert ESBMCAdapter().run(target,set())[0].properties['analysis_status']=='ERROR'


@pytest.mark.parametrize('index,expected',[(2,'FAIL'),(1,'PASS')])
def test_real_esbmc_bounds_pair(tmp_path,index,expected):
    if not shutil.which(os.environ.get('ECDET_ESBMC','esbmc')):pytest.skip('ESBMC unavailable')
    target=project(tmp_path,'int main(void){int a[2]={0,1};return a['+str(index)+'];}')
    alerts=ESBMCAdapter().run(target,set())
    assert receipt(target)['status']==expected
    if expected=='FAIL':
        assert alerts[0].rule_id=='ESBMC-CHECK'
        assert alerts[0].location.path=='main.c'
    else:assert not alerts


def test_hardware_counterexample_requires_board_review(tmp_path,monkeypatch):
    target=project(tmp_path)
    target.svd_path=target.root/'device.svd'
    monkeypatch.setattr(shutil,'which',lambda _: 'esbmc')
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: subprocess.CompletedProcess(a[0],1,'VERIFICATION FAILED',''))
    alert=ESBMCAdapter().run(target,set())[0]
    assert alert.provenance.value=='suspected'
    assert alert.properties['hardware_execution'] is False
    assert alert.properties['needs_hardware_review'] is True
