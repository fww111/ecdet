"""Keep real-tool integration fixtures independent of local cross-build artifacts."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def native_project_copy(source, destination):
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(
        'build*', '.ecdet*', 'ecdet_build', 'ecdet_reports',
        'compile_commands.json', 'reports', '__pycache__'))
    compiler=shutil.which('gcc') or shutil.which('clang')
    if compiler is None:return
    headers={destination,*[p.parent for p in destination.rglob('*.h')]}
    # This fixture intentionally contains implicit declarations as test inputs.
    # Keep their warnings while allowing the remaining analyses to execute.
    standard='gnu89' if source.name=='vulnerable_c' else 'c11'
    entries=[dict(directory=str(destination),file=str(p),arguments=[compiler,
        '-std='+standard,*['-I'+str(d) for d in sorted(headers)],'-c',str(p)])
        for p in destination.rglob('*.c')]
    (destination/'compile_commands.json').write_text(json.dumps(entries),encoding='utf-8')


@pytest.fixture(autouse=True)
def isolated_native_integration_projects(request,tmp_path,tmp_path_factory,monkeypatch):
    module=request.module
    name=module.__name__.split('.')[-1]
    if name in {'test_cli_e2e','test_fixer','test_webui','test_eval','test_dynamic_agents'}:
        compiler=shutil.which('gcc')
        if compiler:
            from ecdet.l1_build import reconstructor
            triple=subprocess.check_output([compiler,'-dumpmachine'],text=True).strip()
            monkeypatch.setattr(reconstructor,'_TARGET_TRIPLE_DEFAULT',triple)
    if name in {'test_cli_e2e','test_fixer','test_webui'}:
        source=module.EXAMPLES;destination=tmp_path_factory.mktemp('integration_examples')
        for project in ('demo_rtos','vulnerable_c','svd_demo','keil_demo'):
            native_project_copy(source/project,destination/project)
        # init-ccdb's Keil parser test must generate its own database.
        (destination/'keil_demo/compile_commands.json').unlink(missing_ok=True)
        monkeypatch.setattr(module,'EXAMPLES',destination)
    if name=='test_eval' or (name=='test_dynamic_agents' and request.node.name.startswith('test_orchestrate_')):
        symbol='CORPUS' if name=='test_eval' else 'EVAL_CORPUS'
        destination=tmp_path/'eval_corpus'
        native_project_copy(getattr(module,symbol),destination)
        monkeypatch.setattr(module,symbol,destination)
