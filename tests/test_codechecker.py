"""CodeChecker integration contracts; native CTU is exercised separately."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from ecdet.incremental import diff_baseline, save_baseline
from ecdet.l1_build.reconstructor import reconstruct
from ecdet.l2_ir import Alert, Location, Severity, load_sarif, save_sarif
from ecdet.l3_analysis.adapters.codechecker import _find_ccdb, parse_codechecker_json
from ecdet.l3_analysis.codechecker_catalog import rule_metas
from ecdet.l3_analysis.codechecker_runner import run
from ecdet.l3_analysis.engine import AnalysisTarget, resolve_enabled


def catalog():
    return {"analyzers": [{"name": "clangsa", "path": "clang", "version": "23"}],
            "checkers": [{"name": "core.NullDereference", "analyzer": "clangsa",
                          "description": "Null pointer", "status": "enabled",
                          "labels": ["severity:HIGH", "profile:default",
                                     "cwe-vulnerabilities:cwe-476"]}],
            "capabilities": {"ctu": True, "statistical_analysis": False}}


def report(root):
    return {"file": {"original_path": str(root / "a.c")}, "line": 4, "column": 5,
            "checker_name": "core.NullDereference", "analyzer_name": "clangsa",
            "severity": "CRITICAL", "message": "null pointer", "report_hash": "native-hash",
            "review_status": "unreviewed", "bug_path_events": [
                {"file": {"original_path": str(root / "a.c")},
                 "line": i + 1, "column": 3, "message": f"step {i}"}
                for i in range(35)]}


def test_native_metadata_full_path_and_sarif_roundtrip(tmp_path):
    row = report(tmp_path)
    suppressed = dict(row, review_status="suppress")
    alerts = parse_codechecker_json(json.dumps({"reports": [row, suppressed]}), tmp_path, catalog())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == Severity.ERROR and a.cwe == "CWE-476"
    assert a.fingerprint == "native-hash" and len(a.evidence) == 36
    assert a.evidence[-1].location.col == 3
    path = save_sarif(alerts, rule_metas(catalog()), tmp_path / "result.sarif")
    doc = json.loads(path.read_text(encoding="utf-8"))
    locations = doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 35
    loaded, metas = load_sarif(path)
    assert loaded[0].properties == a.properties
    assert loaded[0].evidence[-1].location.col == 3
    assert metas[0].properties["analyzer"] == "clangsa"


def test_invalid_report_is_not_a_clean_scan(tmp_path):
    with pytest.raises(RuntimeError):
        parse_codechecker_json("bad json", tmp_path)
    with pytest.raises(RuntimeError):
        parse_codechecker_json("{}", tmp_path)


def test_checker_defaults_are_honored():
    data = catalog()
    data["checkers"].append({"name": "alpha.dev", "analyzer": "clangsa",
                             "status": "disabled", "labels": []})
    metas = rule_metas(data)
    enabled = resolve_enabled(metas, None, None, None)
    assert "core.NullDereference" in enabled and "alpha.dev" not in enabled
    assert "alpha.dev" in resolve_enabled(metas, None, None, ["alpha.dev"])


def test_inactive_native_checker_is_not_marked_compliant():
    from ecdet.l5_report import aggregate, build_compliance_records

    metas = rule_metas(catalog())
    records = build_compliance_records(aggregate([], metas))
    assert records[0].status == "not_evaluated"
    metas[0].properties["analyzed"] = True
    records = build_compliance_records(aggregate([], metas))
    assert records[0].status == "no_findings"


def test_import_native_sarif_preserves_path_and_hash(tmp_path):
    path = tmp_path / "native.sarif"
    step = {"location": {"message": {"text": "source to sink"},
                         "physicalLocation": {"artifactLocation": {"uri": "a.c"},
                                               "region": {"startLine": 3}}}}
    path.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "CodeChecker"}},
        "results": [{"ruleId": "R", "level": "error", "message": {"text": "bug"},
                     "partialFingerprints": {"bugHash": "stable"},
                     "codeFlows": [{"threadFlows": [{"locations": [step]}]}]}]}]}), encoding="utf-8")
    alerts, metas = load_sarif(path)
    assert alerts[0].fingerprint == "stable" and alerts[0].evidence[0].location.line == 3
    out = save_sarif(alerts, metas, tmp_path / "roundtrip.sarif")
    assert json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"][0]["codeFlows"]


def test_existing_database_preserves_quoted_commands(tmp_path):
    original = json.dumps([{"directory": str(tmp_path), "file": "a.c",
                            "command": '"C:/Program Files/LLVM/bin/clang.exe" -DTEST=1 -c a.c'}])
    (tmp_path / "compile_commands.json").write_text(original, encoding="utf-8")
    stale = tmp_path / "ecdet_build"
    stale.mkdir()
    (stale / "compile_commands.json").write_text("[]", encoding="utf-8")
    result = reconstruct(tmp_path)
    assert result.method == "existing-ccdb"
    assert (tmp_path / "compile_commands.json").read_text(encoding="utf-8") == original
    assert _find_ccdb(tmp_path) == tmp_path / "compile_commands.json"


def test_makefile_fallback_retains_flag_prefixes_and_macro_values(tmp_path):
    from ecdet.l1_build.reconstructor import _scan_makefile_flags

    (tmp_path / "Makefile").write_text("CFLAGS += -Iinclude -DBOARD=7 -DDEBUG\n", encoding="utf-8")
    includes, defines = _scan_makefile_flags(tmp_path)
    assert includes == ["-I" + (tmp_path / "include").as_posix()]
    assert defines == ["-DBOARD=7", "-DDEBUG"]


def test_partial_baseline_preserves_unscanned_findings(tmp_path):
    a = Alert("R1", "codechecker", Severity.ERROR, "a", Location("a.c"), fingerprint="a")
    b = Alert("R2", "codechecker", Severity.ERROR, "b", Location("b.c"), fingerprint="b")
    path = save_baseline([a, b], tmp_path / "baseline.json")
    old = json.loads(path.read_text(encoding="utf-8"))
    diff = diff_baseline({"a", "b"}, [], baseline=old, scanned_paths={"a.c"})
    assert diff.resolved_count == 1 and diff.unscanned_count == 1
    save_baseline([], path, previous=old, scanned_paths={"a.c"})
    updated = json.loads(path.read_text(encoding="utf-8"))
    assert updated["fingerprints"] == ["b"] and updated["alerts"][0]["fingerprint"] == "b"
    legacy = diff_baseline({"unknown"}, [], scanned_paths={"a.c"})
    assert legacy.resolved_count == 0 and legacy.unscanned_count == 1


@pytest.mark.parametrize("analysis_exit", [0, 3])
@pytest.mark.parametrize("selected_file", ["a.c", "api.h"])
def test_persistent_runner_ctu_context_and_failures(tmp_path, monkeypatch, analysis_exit, selected_file):
    from ecdet.l3_analysis import codechecker_runner as runner

    entries = [{"directory": str(tmp_path), "file": str(tmp_path / f),
                "arguments": ["clang", "-c", str(tmp_path / f)]}
               for f in ("a.c", "b.c")]
    (tmp_path / "compile_commands.json").write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(runner, "load_catalog", lambda *args: catalog())
    calls = []

    def fake_run(args, **kwargs):
        if "-dumpfullversion" in args:
            return subprocess.CompletedProcess(args, 0, "13.3.0", "")
        calls.append(args)
        if args[1] == "analyze":
            Path(args[args.index("--output") + 1]).mkdir(exist_ok=True)
            code = analysis_exit if "--ctu-analyze" in args else 0
            return subprocess.CompletedProcess(args, code, "analyzer output", "")
        output = Path(args[args.index("--output") + 1])
        output.write_text(json.dumps({"reports": [report(tmp_path)]})
                          if args[args.index("--export") + 1] == "json" else "{}",
                          encoding="utf-8")
        return subprocess.CompletedProcess(args, 2, "", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    target = AnalysisTarget(tmp_path, [Path(selected_file)], artifact_dir=tmp_path / "native",
                            rule_disable=["core.NullDereference"])
    if analysis_exit:
        with pytest.raises(RuntimeError, match="翻译单元分析失败"):
            run(target, "fake-codechecker", 10)
    else:
        assert run(target, "fake-codechecker", 10)[0].fingerprint == "native-hash"
    latest = json.loads((tmp_path / "native/latest.json").read_text(encoding="utf-8"))
    work = Path(latest["run_dir"])
    assert latest["status"] == ("failed" if analysis_exit else "complete")
    assert (work / "results.json").is_file() and (work / "analyze.log").is_file()
    assert "--file" not in next(args for args in calls if "--ctu-collect" in args)
    assert "--file" in next(args for args in calls if "--ctu-analyze" in args)
    cfg = json.loads((work / "effective-config.json").read_text(encoding="utf-8"))
    assert cfg["analyze"][-2:] == ["--disable", "core.NullDereference"]
    assert "context-free-v2" in cfg["analyze"]


def test_make_dependencies_keep_spaces_and_windows_separators(tmp_path):
    from ecdet.l3_analysis.codechecker_paths import parse_make_dependencies, split_command

    directory = tmp_path / "folder with spaces"
    source = directory / "a.c"
    text = "__dummy: " + str(source).replace(" ", "\\ ") + " \\\n  header.h\n"
    parsed = parse_make_dependencies(text, str(tmp_path))
    assert parsed == [str(source), str(tmp_path / "header.h")]
    native = "clang '--sysroot=C:\\Program Files\\ARM' -c 'C:\\code folder\\a.c'"
    assert split_command(native) == ["clang", "--sysroot=C:\\Program Files\\ARM",
                                     "-c", "C:\\code folder\\a.c"]


def test_source_only_incremental_database_keeps_ctu_providers(tmp_path, monkeypatch):
    from ecdet.l3_analysis.adapters import codechecker as adapter

    (tmp_path / "caller.c").write_text("int caller(void);", encoding="utf-8")
    (tmp_path / "provider.c").write_text("int provider(void);", encoding="utf-8")
    monkeypatch.setattr(adapter, "_which", lambda *args: "clang")
    monkeypatch.setattr(adapter, "_compiler_works", lambda *args: True)
    monkeypatch.setattr(adapter, "_c_standard_headers_work", lambda *args: True)
    monkeypatch.setattr(adapter, "_cxx_standard_headers_work", lambda *args: True)
    target = AnalysisTarget(tmp_path, [Path("caller.c")])
    database = adapter._write_fallback_ccdb(target, tmp_path / "commands.json", ["clangsa"], {})
    entries = json.loads(database.read_text(encoding="utf-8"))
    assert {Path(row["file"]).name for row in entries} == {"caller.c", "provider.c"}
    selected, full_scan = adapter._selected_translation_units(target, database)
    assert len(selected) == 1 and not full_scan


@pytest.mark.skipif(os.name != "nt", reason="Native Windows SARIF paths")
def test_native_gcc_sarif_windows_paths_are_not_prefixed_twice(tmp_path):
    import ecdet.l3_analysis.codechecker_bridge  # Installs native compatibility.
    from codechecker_report_converter.report.parser.sarif import Parser

    source = tmp_path / "中文 code.c"
    source.write_text("int x;", encoding="utf-8")
    parser = Parser()
    parser.original_uri_base_ids = {"PWD": {"uri": tmp_path.as_uri() + "/"}}
    for uri in (str(source), source.as_uri()):
        found = parser._get_file({"artifactLocation": {"uri": uri, "uriBaseId": "PWD"}})
        assert Path(found.path).resolve() == source.resolve()


def test_web_store_preserves_analyzer_metadata(tmp_path):
    from ecdet.webui.store import Store

    store = Store(tmp_path / "store.sqlite")
    pid = store.add_project("p", "path", "ref", str(tmp_path))
    rid = store.add_run(pid, {})
    data = {"rule_id": "R", "engine": "codechecker", "severity": "error",
            "path": "a.c", "line": 1, "message": "m", "provenance": "suspected",
            "properties": {"codechecker": {"analyzer_name": "clangsa"}}}
    store.put_alerts(rid, [data])
    rows = store.list_alerts(rid)
    assert rows[0]["properties"] == data["properties"]
    assert store.get_alert(rows[0]["id"])["properties"] == data["properties"]


def test_timeout_retains_partial_diagnostics(tmp_path, monkeypatch):
    from ecdet.l3_analysis import codechecker_runner as runner

    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"directory": str(tmp_path), "file": str(tmp_path / "a.c"),
         "arguments": ["clang", "-c", str(tmp_path / "a.c")]}]), encoding="utf-8")
    data = catalog()
    data["capabilities"]["ctu"] = False
    monkeypatch.setattr(runner, "load_catalog", lambda *args: data)

    def timeout(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 1, output=b"partial analyzer output")

    monkeypatch.setattr(runner.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="失败"):
        run(AnalysisTarget(tmp_path, [Path("a.c")], artifact_dir=tmp_path / "native"),
            "fake-codechecker", 1)
    latest = json.loads((tmp_path / "native/latest.json").read_text(encoding="utf-8"))
    assert latest["status"] == "failed" and latest["phases"][-1]["timed_out"]
    assert "partial analyzer output" in (Path(latest["run_dir"]) / "analyze.log").read_text(encoding="utf-8")
