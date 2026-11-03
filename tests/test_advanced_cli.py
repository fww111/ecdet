"""Production command entrypoints must expose the three integrated backends."""
import subprocess
import sys

import pytest


@pytest.mark.parametrize('command', ['fuzz', 'constraints', 'firmware'])
def test_advanced_command_help(command):
    result = subprocess.run([sys.executable, '-m', 'ecdet', command, '--help'],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert '--output' in result.stdout


def test_scan_exposes_constraint_backend():
    result = subprocess.run([sys.executable, '-m', 'ecdet', 'scan', '--help'],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0
    assert '--constraints' in result.stdout


@pytest.mark.parametrize('command,arguments', [
    ('fuzz', ['.', '--harness', 'demo.c', '--runs', '0']),
    ('constraints', ['.', '--timeout-ms', '-1']),
    ('firmware', ['demo.elf', '--platform', 'demo.repl', '--seconds', 'nan']),
    ('firmware', ['demo.elf', '--platform', 'demo.repl', '--input-hex', 'zz']),
])
def test_invalid_run_parameters_are_rejected_before_execution(command, arguments):
    result = subprocess.run([sys.executable, '-m', 'ecdet', command, *arguments],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 2


def test_unavailable_renode_has_no_false_alert(tmp_path):
    import json
    from ecdet.cli import main
    firmware = tmp_path / 'test.elf'
    firmware.write_bytes(b'\x7fELF' + bytes(48))
    platform = tmp_path / 'test.repl'
    platform.write_text('cpu: CPU.CortexM @ sysbus\n')
    output = tmp_path / 'output'
    result = main(['firmware', str(firmware), '--platform', str(platform),
                   '--expect', 'READY', '--renode', str(tmp_path/'missing.exe'), '-o', str(output)])
    assert result == 2
    assert json.loads((output/'analysis.json').read_text(encoding='utf-8'))['status'] == 'NOT_AVAILABLE'
    sarif = json.loads((output/'results.sarif').read_text(encoding='utf-8'))
    assert not sarif['runs'][0]['results']


def test_constraint_command_preserves_model_and_sarif_metadata(tmp_path):
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    import json
    from ecdet.cli import main
    source = tmp_path / 'bounded.c'
    source.write_text('int access(int i) { int a[4]; if(i == 4) return a[i]; return 0; }\n')
    output = tmp_path / 'output'
    assert main(['constraints', str(source), '-o', str(output)]) == 1
    receipt = json.loads((output/'analysis.json').read_text(encoding='utf-8'))
    assert receipt['status_counts'].get('SAT') == 1
    sarif = json.loads((output/'results.sarif').read_text(encoding='utf-8'))
    result = sarif['runs'][0]['results'][0]
    assert result['ruleIndex'] is not None
    assert result['properties']['provenance'] == 'suspected'
    assert (output/'report.html').is_file()


def test_file_level_solver_error_is_not_hidden_by_an_earlier_unsat(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from ecdet.advanced_cli import analyze_constraint_files
    (tmp_path/'case.c').write_text('int f(void) { return 0; }')
    report=SimpleNamespace(to_dict=lambda:{'status':'ERROR','results':[{'status':'UNSAT'}]}, alerts=lambda:[])
    monkeypatch.setattr('ecdet.l3_analysis.constraints.analyze_constraints',lambda *a,**k:report)
    receipt,alerts=analyze_constraint_files(tmp_path,[tmp_path/'case.c'])
    assert receipt['status_counts']['ERROR']==1
    assert not alerts
