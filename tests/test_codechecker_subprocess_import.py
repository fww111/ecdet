"""Native jobs must import the same source package outside the project cwd."""
from pathlib import Path
import subprocess
import sys

from ecdet.l3_analysis.adapters.codechecker import _analyzer_environment


def test_child_environment_preserves_explicit_pythonpath(monkeypatch, tmp_path):
    monkeypatch.setenv('PYTHONPATH', str(tmp_path))
    env=_analyzer_environment()
    import os
    paths=env['PYTHONPATH'].split(os.pathsep)
    assert Path(paths[0])==Path(__file__).resolve().parents[1]
    assert str(tmp_path) in paths


def test_package_import_from_unrelated_workdir(tmp_path):
    result=subprocess.run([sys.executable,'-c',
        'from ecdet.l3_analysis import codechecker_bridge; print(codechecker_bridge.__file__)'],
        cwd=tmp_path, env=_analyzer_environment(),capture_output=True,
        encoding='utf-8',errors='replace',timeout=20)
    assert result.returncode==0,result.stderr
    assert 'codechecker_bridge.py' in result.stdout
