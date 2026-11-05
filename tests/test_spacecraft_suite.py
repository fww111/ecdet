"""Immutable eight-project corpus: defect roots and explicit false-positive guards."""
import json,hashlib
from functools import lru_cache
from pathlib import Path
import pytest
from ecdet.l3_analysis.engine import AnalysisTarget, BuiltinEngine, collect_sources, run_all_engines

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/'examples/spacecraft_suite/manifest.json').read_text(encoding='utf-8'))

@lru_cache(None)
def alerts(name):
    item=next(p for p in MANIFEST['projects'] if p['name']==name)
    root=ROOT/item['path'];svd=root/'SPC3000.svd'
    return run_all_engines(AnalysisTarget(root,collect_sources(root),svd_path=svd if svd.exists() else None),engines=[BuiltinEngine()])[0]

@pytest.mark.parametrize('case',[d for d in MANIFEST['defects'] if d['required_engine']=='builtin'],ids=lambda d:d['id'])
def test_seeded_static_defect_root(case):
    assert any(a.rule_id==case['rule'] and a.location.path==case['file'] and a.location.line==case['line'] for a in alerts(case['project'])),case

@pytest.mark.parametrize('case',MANIFEST['excluded_expectations'],ids=lambda d:d['project'])
def test_confirmed_false_rule_expectation_removed(case):
    assert not any(a.rule_id==case['rule'] for a in alerts(case['project']))

@pytest.mark.parametrize('project',MANIFEST['projects'],ids=lambda d:d['name'])
def test_project_layout_and_truth(project):
    root=ROOT/project['path']
    assert len(list((root/'src').glob('*.c')))>=5
    assert list((root/'include').glob('*.h'))
    assert (root/'CMakeLists.txt').is_file()
    assert json.loads((root/'defects.json').read_text(encoding='utf-8'))
    assert all(hashlib.sha256((root/n).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==h for n,h in project['normalized_source_sha256'].items())
    assert sum(len(p.read_text(encoding='utf-8').splitlines()) for p in [*root.glob('src/*.c'),*root.glob('include/*.h')])>=600
