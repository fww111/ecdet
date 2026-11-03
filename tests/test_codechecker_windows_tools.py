"""Windows analyzer discovery must preserve a working checker query."""

import os
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from ecdet.l3_analysis.adapters import codechecker as adapter


def test_llvm_mingw_wrapper_uses_same_version_cc1_driver(tmp_path, monkeypatch):
    wrapper = tmp_path / "clang.exe"
    driver = tmp_path / "clang-23.exe"
    other = tmp_path / "clang-22.exe"
    for path in (wrapper, driver, other):
        path.touch()

    def run(command, **kwargs):
        if command[1:] == ["--version"]:
            return CompletedProcess(command, 0, "clang version 23.1.4", "")
        if Path(command[0]) == driver:
            return CompletedProcess(command, 0, "CHECKERS:\ncore.NullDereference", "")
        return CompletedProcess(command, 1, "", "unknown argument: -cc1")

    monkeypatch.setattr(adapter.subprocess, "run", run)
    assert adapter._clangsa_driver(str(wrapper)) == str(driver)


def test_normal_clang_driver_is_preserved(tmp_path, monkeypatch):
    wrapper = tmp_path / "clang.exe"
    (tmp_path / "clang-23.exe").touch()
    monkeypatch.setattr(adapter.subprocess, "run", lambda command, **kwargs:
                        CompletedProcess(command, 0, "CHECKERS:\ncore.NullDereference", ""))
    assert adapter._clangsa_driver(str(wrapper)) == str(wrapper)


@pytest.mark.skipif(os.name != "nt", reason="Windows analyzer binary paths")
def test_windows_drive_separator_preserves_analyzer_name():
    import ecdet.l3_analysis.codechecker_bridge  # Installs upstream fixes.
    from codechecker_analyzer import analyzer_context, arg

    for parser in (arg.analyzer_binary, analyzer_context.analyzer_binary):
        name, path = parser(r"clangsa:C:\Program Files\LLVM\bin\clang.exe")
        assert name == "clangsa"
        assert path == r"C:\Program Files\LLVM\bin\clang.exe"
        assert parser("clangsa:/usr/bin/clang") == ("clangsa", "/usr/bin/clang")


@pytest.mark.skipif(os.name != "nt", reason="Windows analyzer discovery")
def test_explicit_clangsa_choice_is_preserved(monkeypatch):
    value = r"clangsa:D:\my-tools\clang.exe;gcc:C:\gcc\gcc.exe"
    monkeypatch.setenv("CC_ANALYZER_BIN", value)
    monkeypatch.setattr(adapter, "_clangsa_driver", lambda _: pytest.fail(
        "An explicit analyzer choice must not be replaced"))
    assert adapter._analyzer_environment()["CC_ANALYZER_BIN"] == value
