"""Regression coverage for clang-tidy diagnostic ingestion and execution status."""

import json
import logging
import subprocess

import pytest

from ecdet.l2_ir.model import Severity
from ecdet.l3_analysis.adapters.clang_tidy import parse_clang_tidy_output, run_clang_tidy
from ecdet.l3_analysis.engine import AnalysisTarget


DIAGNOSTIC = "src/a.c:12:3: warning: possible null dereference [clang-analyzer-core.NullDereference]"


def _target(tmp_path):
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{"directory": str(tmp_path), "file": "src/a.c", "arguments": ["clang", "-c", "src/a.c"]}]),
        encoding="utf-8",
    )
    return AnalysisTarget(root=tmp_path)


def test_binary_override_is_used_for_availability_and_execution(monkeypatch,tmp_path):
    from ecdet.l3_analysis.engine import ClangTidyAdapter
    binary='D:/tools/LLVM/bin/clang-tidy.exe'
    monkeypatch.setenv('ECDET_CLANG_TIDY',binary)
    monkeypatch.setattr('shutil.which',lambda name: binary if name==binary else None)
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command,0,DIAGNOSTIC,'')
    monkeypatch.setattr(subprocess,'run',run)
    assert ClangTidyAdapter().available()
    assert len(run_clang_tidy(_target(tmp_path)))==1
    assert commands[0][0]==binary


def test_running_adapter_normalizes_project_paths_without_rebinding_external_files(monkeypatch,tmp_path):
    internal=tmp_path/'src'/'a.c'
    external=tmp_path.parent/'external.c'
    stdout=f'{internal}:12:3: warning: issue [check]\n{external}:2:1: warning: other [check]'
    monkeypatch.setattr(subprocess,'run',lambda command,**kwargs:subprocess.CompletedProcess(command,0,stdout,''))
    alerts=run_clang_tidy(_target(tmp_path))
    assert alerts[0].location.path=='src/a.c'
    assert alerts[1].location.path==external.as_posix()


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_parse_both_streams(stream):
    alerts = parse_clang_tidy_output(DIAGNOSTIC if stream == "stdout" else "", DIAGNOSTIC if stream == "stderr" else "")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.location.path == "src/a.c"
    assert (alert.location.line, alert.location.col) == (12, 3)
    assert alert.severity == Severity.WARNING
    assert alert.rule_id == "clang-analyzer-core.NullDereference"
    assert alert.evidence


@pytest.mark.parametrize("path,expected", [
    (r"C:\work dir\src\a.c", "C:/work dir/src/a.c"),
    ("D:/项目/src/a.c", "D:/项目/src/a.c"),
    ("/home/user/src/a.c", "/home/user/src/a.c"),
])
def test_parse_absolute_paths(path, expected):
    alerts = parse_clang_tidy_output(f"{path}:12:3: error: invalid declaration [clang-diagnostic-error]", "")
    assert len(alerts) == 1
    assert alerts[0].location.path == expected
    assert alerts[0].severity == Severity.ERROR


def test_duplicate_diagnostics_across_streams_are_merged():
    alerts = parse_clang_tidy_output(DIAGNOSTIC + "\n" + DIAGNOSTIC, DIAGNOSTIC)
    assert len(alerts) == 1


def test_different_checks_messages_and_columns_are_retained():
    others = [DIAGNOSTIC.replace(":12:3:", ":12:4:"),
              DIAGNOSTIC.replace("possible null dereference", "a different path"),
              DIAGNOSTIC.replace("clang-analyzer-core.NullDereference", "bugprone-unchecked-optional-access")]
    assert len(parse_clang_tidy_output(DIAGNOSTIC, "\n".join(others))) == 4


def test_noise_and_empty_output_are_ignored():
    assert parse_clang_tidy_output("1 warning generated.\n", "Suppressed 1 warnings.") == []
    assert parse_clang_tidy_output("", "") == []


def test_run_retains_stderr_diagnostics(monkeypatch, tmp_path):
    target = _target(tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", DIAGNOSTIC))
    assert len(run_clang_tidy(target)) == 1


def test_missing_binary_is_reported(monkeypatch, tmp_path, caplog):
    def missing(*args, **kwargs):
        raise FileNotFoundError("clang-tidy")
    monkeypatch.setattr(subprocess, "run", missing)
    assert run_clang_tidy(_target(tmp_path)) == []
    assert "unavailable" in caplog.text


def test_timeout_is_reported_and_partial_diagnostics_retained(monkeypatch, tmp_path, caplog):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 7, output=b"", stderr=DIAGNOSTIC.encode())
    monkeypatch.setattr(subprocess, "run", timeout)
    assert len(run_clang_tidy(_target(tmp_path), timeout=7)) == 1
    assert "timed out" in caplog.text


def test_compile_failure_is_reported_and_diagnostics_retained(monkeypatch, tmp_path, caplog):
    output = "src/a.c:2:1: error: unknown type name 'x' [clang-diagnostic-error]\nError while processing src/a.c."
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "", output))
    alerts = run_clang_tidy(_target(tmp_path))
    assert len(alerts) == 1
    assert "compilation failed" in caplog.text


def test_nonzero_exit_without_compiler_error_is_reported(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "", "invalid options"))
    assert run_clang_tidy(_target(tmp_path)) == []
    assert "exited with status 2" in caplog.text


def test_startup_error_is_reported(monkeypatch, tmp_path, caplog):
    def denied(*args, **kwargs):
        raise PermissionError("access denied")
    monkeypatch.setattr(subprocess, "run", denied)
    assert run_clang_tidy(_target(tmp_path)) == []
    assert "could not start" in caplog.text


def test_warning_text_containing_error_is_not_a_compiler_failure(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="ecdet.l3_analysis.adapters.clang_tidy")
    output = DIAGNOSTIC.replace("possible null dereference", "message should not contain error: prefix")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, ""))
    assert len(run_clang_tidy(_target(tmp_path))) == 1
    assert "completed: 1 diagnostics" in caplog.text
    assert "compilation failed" not in caplog.text


def test_successful_zero_diagnostics_is_distinct_from_failure(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="ecdet.l3_analysis.adapters.clang_tidy")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""))
    assert run_clang_tidy(_target(tmp_path)) == []
    assert "completed: 0 diagnostics" in caplog.text
    assert not any(record.levelno >= logging.WARNING for record in caplog.records)


@pytest.mark.parametrize("data", ["not json", "{}", '[{"file": 7}]'])
def test_invalid_compilation_database_is_reported(tmp_path, caplog, data):
    (tmp_path / "compile_commands.json").write_text(data, encoding="utf-8")
    assert run_clang_tidy(AnalysisTarget(root=tmp_path)) == []
    assert "invalid compilation database" in caplog.text


def test_missing_compilation_database_is_reported(tmp_path, caplog):
    assert run_clang_tidy(AnalysisTarget(root=tmp_path)) == []
    assert "compilation database missing" in caplog.text
