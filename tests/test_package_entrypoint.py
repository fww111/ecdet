"""The documented python -m ecdet commands must work after installation."""
import os
import subprocess
import sys


def run_package(*args):
    return subprocess.run([sys.executable, '-m', 'ecdet', *args], capture_output=True,
                          text=True, encoding='utf-8', timeout=20,
                          env={**os.environ, 'PYTHONIOENCODING':'utf-8'})


def test_module_help_entrypoint():
    result=run_package('--help')
    assert result.returncode==0,result.stderr
    assert 'serve' in result.stdout and 'scan' in result.stdout


def test_module_rules_entrypoint():
    result=run_package('rules')
    assert result.returncode==0,result.stderr
    assert 'ECDET-MMIO-W1C' in result.stdout
