"""Real-tool acceptance; the test is skipped when clang-tidy is unavailable."""
from pathlib import Path
import os

import pytest

from scripts.validate_clang_tidy import find_clang_tidy, validate_clang_tidy


def test_explicit_missing_tool_is_not_reported_as_pass(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_clang_tidy(tmp_path / 'missing-clang-tidy.exe', tmp_path / 'out')


def test_real_clang_tidy_positive_negative_and_adapter(tmp_path):
    binary = find_clang_tidy()
    if binary is None:
        pytest.skip('real clang-tidy not available; set ECDET_CLANG_TIDY')
    result = validate_clang_tidy(binary, tmp_path / 'real tool 验收')
    assert result['status'] == 'PASS', result
    assert 'LLVM version' in result['version']
    assert result['cases']['null_bad.c']['target_diagnostics'] == 1
    assert result['cases']['null_good.c']['target_diagnostics'] == 0
    assert result['adapter']['bad_target_diagnostics'] == 1
    assert result['adapter']['good_target_diagnostics'] == 0
    warning = next(a for a in result['adapter']['alerts']
                   if a['rule_id'] == 'clang-analyzer-core.NullDereference')
    assert Path(warning['location']['path']).name == 'null_bad.c'
    assert (warning['location']['line'],warning['location']['col']) == (5,12)
    assert result['cases']['null_bad.c']['compile_errors'] == 0
    assert result['cases']['null_good.c']['compile_errors'] == 0
    assert result['sarif']['target_rules'] == ['clang-analyzer-core.NullDereference']
    assert Path(result['sarif']['path']).is_file()


def test_explicit_binary_overrides_existing_environment_and_restores_it(tmp_path,monkeypatch):
    binary=find_clang_tidy()
    if binary is None:
        pytest.skip('real clang-tidy not available')
    wrong=str(tmp_path/'missing-clang-tidy.exe')
    monkeypatch.setenv('ECDET_CLANG_TIDY',wrong)
    assert find_clang_tidy(binary)==binary
    result=validate_clang_tidy(binary,tmp_path/'override')
    assert result['status']=='PASS'
    assert Path(result['adapter']['command'][0]).samefile(binary)
    assert os.environ['ECDET_CLANG_TIDY']==wrong
