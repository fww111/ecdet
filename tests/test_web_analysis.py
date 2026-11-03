"""Web analysis contracts, run status, and artifact isolation."""
from pathlib import Path

import pytest

from ecdet.webui.analysis import normalize_request, artifact_path, constraint_status


@pytest.fixture()
def project(tmp_path):
    (tmp_path/'driver.c').write_text('int LLVMFuzzerTestOneInput(void) { return 0; }')
    (tmp_path/'code.c').write_text('int f(int n) { int a[4]={0}; return a[n]; }')
    (tmp_path/'test.elf').write_bytes(b'\x7fELF'+bytes(40))
    (tmp_path/'board.repl').write_text('cpu: CPU.CortexM @ sysbus\n')
    return tmp_path


@pytest.mark.parametrize('payload', [None, [], 'constraints', {'kind':'unknown'}, {'kind':[]}, {'kind':{}},
    {'kind':'fuzz','harness':'driver.c','runs':True},
    {'kind':'constraints','timeout_ms':0},
    {'kind':'fuzz','harness':'../escape.c'},
    {'kind':'fuzz','harness':'driver.c','sources':'code.c'},
    {'kind':'firmware','firmware':'test.elf','platform':'board.repl','expected':['READY'],'seconds':float('nan')},
    {'kind':'firmware','firmware':'test.elf','platform':'board.repl','expected':['READY'],'input_hex':'zz'},
    {'kind':'firmware','firmware':'test.elf','platform':'board.repl','expected':'READY'},
    {'kind':'firmware','firmware':'test.elf','platform':'board.repl'},
])
def test_invalid_requests_rejected(project,payload):
    with pytest.raises(ValueError):normalize_request(project,payload)


def test_normalization_keeps_project_relative_paths(project):
    data=normalize_request(project,{'kind':'fuzz','harness':str(project/'driver.c'),'sources':['code.c']})
    assert data['harness']=='driver.c' and data['sources']==['code.c']
    assert data['runs']==5000


def test_selected_constraint_file(project):
    data=normalize_request(project,{'kind':'constraints','source':'code.c','function':'f'})
    assert data['source']=='code.c' and data['function']=='f'


@pytest.mark.parametrize('counts,status', [({'SAT':1},'FINDING'),({'UNSAT':2},'PASS'),
    ({'SAT':1,'UNSUPPORTED':1},'PARTIAL'),({'UNSAT':1,'ERROR':1},'ERROR'),
    ({'UNAVAILABLE':1},'UNAVAILABLE'),({'UNSUPPORTED':1},'UNSUPPORTED'),
    ({'UNKNOWN':1},'UNKNOWN'),({},'UNSUPPORTED')])
def test_constraint_states_do_not_hide_incomplete_checks(counts,status):
    assert constraint_status(counts)==status


def test_artifact_download_cannot_leave_run(project):
    (project/'output').mkdir()
    (project/'output/log.txt').write_text('log')
    assert artifact_path(project/'output','log.txt').name=='log.txt'
    for path in ['../code.c',str(project/'code.c'),'missing.log','']:
        with pytest.raises(ValueError):artifact_path(project/'output',path)


@pytest.fixture()
def ui(tmp_path):
    import threading
    from ecdet.webui import WebUI
    server=WebUI(tmp_path/'data',port=0)
    http=server.make_server()
    worker=threading.Thread(target=http.serve_forever,daemon=True);worker.start()
    yield server,f'http://127.0.0.1:{http.server_address[1]}'
    http.shutdown();http.server_close();worker.join(timeout=3)


def request(base,path,payload=None,raw=None):
    import json
    import urllib.request
    body=raw if raw is not None else json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(base+path,data=body,headers={'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(req,timeout=10)


@pytest.mark.parametrize('raw',[b'{',b'null',b'[]',b'false',b'"text"',b'{"kind":[]}'])
def test_http_invalid_json_objects_return_400_without_queueing(ui,project,raw):
    import urllib.error
    server,base=ui
    pid=server.store.add_project('demo','path',str(project),str(project))
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(base,f'/api/projects/{pid}/analyze',raw=raw)
    assert exc.value.code==400
    assert server.store.list_runs(pid)==[]


def test_tool_settings_are_separate_from_llm_credentials(ui,project):
    import json
    server,base=ui
    server.store.set_setting('llm_api_key','private-test-value')
    with request(base,'/api/analysis-tools/settings',{'clang_path':str(project/'absent.exe'),'renode_path':''}) as response:
        payload=json.load(response)
    assert payload['clang_path'].endswith('absent.exe')
    assert 'private-test-value' not in str(payload)
    assert server.store.get_settings()['llm_api_key']=='private-test-value'
    with request(base,'/api/analysis-tools') as response:
        tools=json.load(response)
    assert not tools['tools']['fuzz']['available']
    assert 'private-test-value' not in str(tools)


def test_missing_compiler_persists_failed_analysis_and_downloadable_report(ui,project):
    import json
    import time
    import urllib.error
    server,base=ui
    server.store.set_setting('analysis_clang',str(project/'absent.exe'))
    pid=server.store.add_project('demo','path',str(project),str(project))
    with request(base,f'/api/projects/{pid}/analyze',{'kind':'fuzz','harness':'driver.c'}) as response:
        run_id=json.load(response)['run_id']
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        run=server.store.get_run(run_id)
        if run['status'] in {'failed','done'}:break
        time.sleep(.02)
    assert run['status']=='failed' and run['stats']['analysis']['status']=='UNAVAILABLE'
    with request(base,f'/api/runs/{run_id}/analysis') as response:
        payload=json.load(response)
    assert payload['status']=='UNAVAILABLE' and payload['summary']['alerts']==0
    assert any(a['path']=='report.html' for a in payload['artifacts'])
    with request(base,f'/api/runs/{run_id}/artifact?path=report.html') as response:
        assert response.headers['Content-Type']=='application/octet-stream'
        assert 'attachment' in response.headers['Content-Disposition']
        assert 'report.html' in response.headers['Content-Disposition']
        assert response.read()
    with pytest.raises(urllib.error.HTTPError) as exc:
        request(base,f'/api/runs/{run_id}/artifact?path=../ecdet_web.db')
    assert exc.value.code==400
    with request(base,f'/api/runs/{run_id}/sarif') as response:
        assert json.load(response)['runs'][0]['results']==[]


def test_unexpected_backend_exception_becomes_recorded_error(ui,project,monkeypatch):
    import json
    import time
    server,base=ui
    def raise_error(*args,**kwargs):raise RuntimeError('controlled backend failure')
    monkeypatch.setattr('ecdet.webui.analysis.analyze_constraint_files',raise_error)
    pid=server.store.add_project('demo','path',str(project),str(project))
    run_id=server.runner.submit_analysis(pid,{'kind':'constraints'})
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        run=server.store.get_run(run_id)
        if run['status'] in {'failed','done'}:break
        time.sleep(.02)
    assert run['status']=='failed'
    assert run['stats']['analysis']['status']=='ERROR'
    with request(base,f'/api/runs/{run_id}/analysis') as response:
        result=json.load(response)
    assert result['status']=='ERROR' and result['details']['error_type']=='RuntimeError'


def test_artifact_canonical_path_outside_run_is_rejected(project,monkeypatch):
    folder=project/'output';folder.mkdir()
    link=folder/'linked.c'
    original=Path.resolve
    def canonical(path,*args,**kwargs):
        # Model a filesystem link without requiring Windows link privileges.
        return project/'code.c' if path==link else original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'resolve',canonical)
    with pytest.raises(ValueError):artifact_path(folder,'linked.c')
