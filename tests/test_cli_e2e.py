# -*- coding: utf-8 -*-
"""CLI 端到端测试：scan demo_rtos 全流程 + 报告产物校验。"""

import json
from pathlib import Path

import pytest

from ecdet.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_scan_demo_rtos(tmp_path, capsys):
    code = main(["scan", str(EXAMPLES / "demo_rtos"),
                 "--no-build", "-o", str(tmp_path)])
    out = capsys.readouterr().out
    assert "扫描完成" in out
    assert "demo_rtos" in out

    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    # sensor.c / comm.c 中埋设的缺陷必须被检出
    assert "CERT C STR31-C" in rule_ids          # strcpy 17 字节 → name[8]
    assert "CERT C ARR30-C" in rule_ids          # s_history[8]
    assert "ECDET-CWE-197" in rule_ids           # uint8_t gain = 300
    assert "MISRA C:2012 17.2" in rule_ids       # sensor_filter 递归
    assert "MISRA C:2012 15.2" in rule_ids       # goto
    assert "CERT C FIO30-C" in rule_ids          # printf(s_mode_name)
    assert "CERT C MSC30-C" in rule_ids          # rand()
    assert "ECDET-CWE-1284" in rule_ids          # scanf %s
    assert "MISRA C:2012 16.4" in rule_ids       # switch 无 default

    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "嵌入式代码检测报告" in html
    assert "合规记录" in html
    assert "证据链" in html or "证据" in html

    # main.c 是干净参照：其中不得出现 error 级告警
    main_errors = [r for r in results
                   if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                   .endswith("main.c") and r["level"] == "error"]
    assert main_errors == []


def test_scan_vulnerable_single_file(tmp_path, capsys):
    code = main(["scan", str(EXAMPLES / "vulnerable_c"), "--no-build",
                 "-o", str(tmp_path)])
    out = capsys.readouterr().out
    assert "扫描完成" in out


def test_exit_code_reflects_errors(tmp_path):
    assert main(["scan", str(EXAMPLES / "demo_rtos"), "--no-build",
                 "-o", str(tmp_path)]) == 1     # 存在 error → 退出码 1


def test_rules_listing(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "MISRA C:2012" in out
    assert "CERT C" in out


def test_report_from_sarif(tmp_path, capsys):
    main(["scan", str(EXAMPLES / "vulnerable_c"), "--no-build", "-o", str(tmp_path)])
    code = main(["report", str(tmp_path / "results.sarif"),
                 "-o", str(tmp_path / "regen.html")])
    assert code == 0
    assert (tmp_path / "regen.html").exists()


def test_scan_svd_demo(tmp_path, capsys):
    """阶段二端到端：SVD 自动发现 → 硬件语义规则 + Proven 分级入 SARIF。"""
    code = main(["scan", str(EXAMPLES / "svd_demo"), "--no-build",
                 "-o", str(tmp_path)])
    out = capsys.readouterr().out
    assert "MMIO 权限检查启用" in out

    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "ECDET-MMIO-ACCESS" in rule_ids
    assert "ECDET-ISR-RACE" in rule_ids
    assert "ECDET-VOLATILE" in rule_ids
    assert "ECDET-ISR-BLOCK" in rule_ids
    provs = {r["properties"]["provenance"] for r in results}
    assert "proven" in provs        # 抽象解释/ESBMC 级结论存在（engine 字段区分）

    engines = {r["properties"]["engine"] for r in results}
    assert "builtin-hw" in engines

    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "GJB 8114" in html       # 合规记录含 GJB 主题映射列


def test_cli_triage_mock(tmp_path, capsys):
    """阶段三端到端：scan → triage（Mock LLM）→ 分诊结论入 SARIF 与报告。"""
    main(["scan", str(EXAMPLES / "svd_demo"), "--no-build", "-o", str(tmp_path)])
    code = main(["triage", str(tmp_path / "results.sarif"),
                 "--project", str(EXAMPLES / "svd_demo"),
                 "--mock", "-o", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "L4 分诊完成" in out
    assert "LLM 调用" in out

    sarif = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    triaged = [r for r in results if "triage" in r["properties"]]
    assert triaged, "分诊结论应回写 SARIF properties"
    verdicts = {r["properties"]["triage"]["verdict"] for r in triaged}
    assert verdicts <= {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
    assert "TRUE_POSITIVE" in verdicts and "FALSE_POSITIVE" in verdicts

    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "LLM 分诊结果" in html
    assert "误报" in html


def test_init_ccdb_keil(tmp_path, capsys):
    """对 keil_demo（仅 uvprojx，无 CMakeLists）执行 init-ccdb 应走 keil-xml 通道。"""
    code = main(["init-ccdb", str(EXAMPLES / "keil_demo")])
    out = capsys.readouterr().out
    assert code == 0
    assert "keil-xml" in out
    assert "STM32F407VGTx" in out
