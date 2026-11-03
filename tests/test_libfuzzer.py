"""Adapter status/evidence boundaries; real tools are covered by the acceptance script."""
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from ecdet.l3_analysis.dynamic.libfuzzer import LibFuzzerEngine, generate_byte_harness, parse_coverage, _source_location


@pytest.fixture()
def project(tmp_path):
    (tmp_path/'driver.c').write_text(generate_byte_harness('parse_packet'))
    return tmp_path


def fake_tool(monkeypatch, project, mode='complete'):
    import ecdet.l3_analysis.dynamic.libfuzzer as module
    tool=project/'clang.exe';tool.write_bytes(b'fake tool')
    monkeypatch.setattr(module,'discover_clang',lambda explicit: str(tool))
    def run(command, **kwargs):
        if '--version' in command:
            return SimpleNamespace(returncode=0,stdout='Test Clang',stderr='')
        if '-dumpmachine' in command:
            return SimpleNamespace(returncode=0,stdout='x86_64-pc-linux-gnu',stderr='')
        if '-o' in command:
            if mode=='compile_fail':
                return SimpleNamespace(returncode=1,stdout='',stderr='syntax error')
            Path(command[command.index('-o')+1]).write_bytes(b'test executable')
            return SimpleNamespace(returncode=0,stdout='',stderr='')
        if any(str(arg).startswith('-artifact_prefix=') for arg in command):
            if mode=='timeout':raise subprocess.TimeoutExpired(command,1,stderr=b'#2 INITED cov: 1 ft: 1')
            if mode=='os_error':raise OSError('could not start')
            if mode in {'crash','replay_fail'}:
                folder=Path(next(arg.split('=',1)[1] for arg in command if arg.startswith('-artifact_prefix=')))
                (folder/'crash-one').write_bytes(b'input')
            failed=mode in {'crash','replay_fail','no_artifact'}
            return SimpleNamespace(returncode=77 if failed else 0,
                stdout='' if mode=='no_coverage' else '#2 INITED cov: 1 ft: 1\n#10 DONE cov: 3 ft: 4\nstat::number_of_executed_units: 10',stderr='')
        return SimpleNamespace(returncode=77 if mode=='crash' else 0,stdout='',
            stderr=f'ERROR: AddressSanitizer: example\n{project.as_posix()}/driver.c:5:2')
    monkeypatch.setattr(module.subprocess,'run',run)
    return tool


@pytest.mark.parametrize('arguments', [{'runs':0},{'timeout':False},{'max_len':-1}])
def test_invalid_budgets(arguments):
    with pytest.raises(ValueError):LibFuzzerEngine(**arguments)


def test_missing_compiler_has_no_findings(monkeypatch,project):
    monkeypatch.setattr('ecdet.l3_analysis.dynamic.libfuzzer.discover_clang',lambda explicit:None)
    result=LibFuzzerEngine().run(project,Path('driver.c'),project/'out')
    assert result.status=='UNAVAILABLE' and not result.alerts
    assert Path(result.receipt_path).is_file()


def test_outside_project_source_rejected(project):
    result=LibFuzzerEngine().run(project,project.parent/'outside.c',project/'out')
    assert result.status=='INVALID_INPUT' and not result.alerts


@pytest.mark.parametrize('mode,expected', [('complete','COMPLETED'),('compile_fail','COMPILE_ERROR'),
    ('timeout','TIMEOUT'),('os_error','ERROR'),('no_artifact','UNVERIFIED'),
    ('replay_fail','UNVERIFIED'),('no_coverage','UNVERIFIED')])
def test_failure_and_incomplete_runs_never_emit_confirmed_findings(monkeypatch,project,mode,expected):
    tool=fake_tool(monkeypatch,project,mode)
    result=LibFuzzerEngine(clang=str(tool)).run(project,Path('driver.c'),project/'out')
    assert result.status==expected and not result.alerts


def test_replayed_artifact_is_required_for_detected_evidence(monkeypatch,project):
    tool=fake_tool(monkeypatch,project,'crash')
    result=LibFuzzerEngine(clang=str(tool)).run(project,Path('driver.c'),project/'out')
    assert result.status=='FINDING' and len(result.alerts)==1
    assert result.alerts[0].provenance.value=='detected'
    assert result.alerts[0].location.line==5
    assert result.metadata['replays'][0]['status']=='REPRODUCED'


def test_corpus_directories_and_relative_files(monkeypatch,project):
    tool=fake_tool(monkeypatch,project)
    seed=project/'seeds';seed.mkdir();(seed/'one').write_bytes(b'abc')
    result=LibFuzzerEngine(clang=str(tool)).run(project,Path('driver.c'),project/'out',corpus=[Path('seeds')])
    assert result.status=='COMPLETED'
    assert result.metadata['corpus'][0]['bytes']==3


def test_oversize_corpus_rejected(monkeypatch,project):
    tool=fake_tool(monkeypatch,project)
    (project/'seed').write_bytes(bytes(20))
    result=LibFuzzerEngine(clang=str(tool),max_len=4).run(project,Path('driver.c'),project/'out',corpus=[Path('seed')])
    assert result.status=='INVALID_INPUT' and not result.alerts


def test_coverage_receipt_uses_instrumented_counts():
    result=parse_coverage('#2 INITED cov: 2 ft: 3\n#18 NEW cov: 7 ft: 9\nstat::number_of_executed_units: 100')
    assert (result['initial_edges'],result['final_edges'],result['executed_units'])==(2,7,100)


def test_unknown_source_location_does_not_invent_a_precise_line(project):
    assert _source_location('AddressSanitizer: error without symbols',project,project/'driver.c') is None


@pytest.mark.parametrize('name', ['x;return 0;', 'f()', ''])
def test_harness_template_rejects_invalid_function_names(name):
    with pytest.raises(ValueError):generate_byte_harness(name)
