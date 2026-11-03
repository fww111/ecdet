"""Enhanced SVD metadata through CLI scan, SARIF and HTML reporting."""

import json
from pathlib import Path

import pytest

from ecdet.cli import main
from ecdet.eval import HW_RULE_IDS
from ecdet.l3_analysis.engine import BuiltinEngine
from ecdet.l3_analysis.hw_model.svd import parse_svd


DEMO = Path(__file__).parent.parent / "examples" / "svd_enhanced_demo"


def test_w1c_participates_in_hardware_ablation():
    assert "ECDET-MMIO-W1C" in HW_RULE_IDS


def test_enhanced_demo_expands_all_registers():
    pytest.importorskip("cmsis_svd")
    regmap = parse_svd(DEMO / "chip.svd", backend="cmsis-svd")
    expected = {
        base + offset
        for base in (0x40000000, 0x40001000)
        for offset in (0, 0x10, 0x14, 0x104)
    }
    registers = [r for group in regmap.by_peripheral.values() for r in group.values()]
    assert len(registers) == 8
    assert {r.abs_addr for r in registers} == expected
    for peripheral, base in (("GPIOA", 0x40000000), ("GPIOB", 0x40001000)):
        ctrl = regmap.resolve(peripheral, "CTRL")
        assert ctrl is not None
        assert ctrl.one_to_clear_mask == 3
        assert len(ctrl.fields) == 2
        assert not regmap.lookup(base + 0x14).writable


def test_enhanced_scan_reports_hardware_evidence(tmp_path, monkeypatch):
    pytest.importorskip("cmsis_svd")
    monkeypatch.setattr("ecdet.l3_analysis.engine._make_default_engines", lambda: [BuiltinEngine()])
    exit_code = main(["scan", str(DEMO), "--no-build", "-o", str(tmp_path)])
    assert exit_code == 1
    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    results = run["results"]
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "ECDET-MMIO-W1C" in rules
    source = (DEMO / "main.c").read_text(encoding="utf-8").splitlines()

    def line_of(statement):
        return next(i for i, line in enumerate(source, 1) if statement in line)

    w1c = [r for r in results if r["ruleId"] == "ECDET-MMIO-W1C"]
    assert len(w1c) == 2
    assert {r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in w1c} == {
        line_of("GPIOA->CTRL |= FLAG_READY"),
        line_of("0x40001000 |= FLAG_READY"),
    }
    assert {r["level"] for r in w1c} == {"warning"}
    for result in w1c:
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "main.c"
        assert result["properties"]["engine"] == "builtin-hw"
        assert result["properties"]["evidence"]
    for address in ("0x40000000", "0x40001000"):
        assert any(address.lower() in json.dumps(r, ensure_ascii=False).lower() for r in w1c)
    assert not any(
        r["ruleId"] == "ECDET-MMIO-W1C"
        and r["locations"][0]["physicalLocation"]["region"]["startLine"] == line_of("GPIOA->CTRL = FLAG_READY")
        for r in results
    )
    access = [r for r in results if r["ruleId"] == "ECDET-MMIO-ACCESS"]
    assert len(access) == 3
    for address in ("0x40000014", "0x40000104", "0x40001104"):
        assert any(address.lower() in json.dumps(r, ensure_ascii=False).lower() for r in access)
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "ECDET-MMIO-W1C" in html
    assert "0x40000014" in html
    assert "证据" in html
