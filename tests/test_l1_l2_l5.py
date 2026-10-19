# -*- coding: utf-8 -*-
"""L1 构建复现 / L2 SARIF / L5 聚合测试。"""

import json
from pathlib import Path

from ecdet.l1_build.iar import parse_ewp
from ecdet.l1_build.keil import parse_uvprojx
from ecdet.l1_build.reconstructor import reconstruct
from ecdet.l2_ir import Alert, Evidence, Location, Provenance, RuleMeta, Severity, load_sarif, save_sarif
from ecdet.l5_report import aggregate, build_compliance_records

EXAMPLES = Path(__file__).parent.parent / "examples"


# ---------------- L1：Keil / IAR ----------------

def test_parse_keil_uvprojx():
    proj = parse_uvprojx(EXAMPLES / "demo_rtos" / "keil" / "demo.uvprojx")
    assert proj.device_hint == "STM32F407VGTx"
    assert "../include" in proj.include_paths
    assert "USE_STDPERIPH_DRIVER" in proj.defines
    assert "../src/main.c".replace("/", "\\") in proj.source_files or \
        "../src/main.c" in proj.source_files
    assert len(proj.source_files) == 3


def test_parse_iar_ewp(tmp_path):
    ewp = tmp_path / "demo.ewp"
    ewp.write_text("""<?xml version="1.0"?>
<project>
  <configuration name="Debug">
    <settings>
      <configuration>
        <name>ICCARM</name>
        <CCDefines><name>DEBUG=1</name><name>BOARD_V2</name></CCDefines>
        <CCIncludePath2><state>../inc</state><state>$PROJ_DIR$/drivers</state></CCIncludePath2>
      </configuration>
    </settings>
  </configuration>
  <group>
    <name>App</name>
    <file><name>../src/main.c</name></file>
    <file><name>../src/util.c</name></file>
  </group>
</project>
""", encoding="utf-8")
    proj = parse_ewp(ewp)
    assert "DEBUG=1" in proj.defines and "BOARD_V2" in proj.defines
    assert "../inc" in proj.include_paths
    assert len(proj.source_files) == 2


def test_reconstruct_directory_scan(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main(void) { return 0; }", encoding="utf-8")
    res = reconstruct(tmp_path)
    assert res.method == "directory-scan"
    assert len(res.commands) == 1
    assert res.ccdb_path and res.ccdb_path.exists()
    data = json.loads(res.ccdb_path.read_text(encoding="utf-8"))
    assert data[0]["arguments"][0] == "clang"


def test_reconstruct_keil_project(tmp_path):
    """uvprojx 存在时走 keil-xml 通道，命令行携带 -I 与 -D。"""
    proj_dir = tmp_path / "keil"
    proj_dir.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }", encoding="utf-8")
    (proj_dir / "demo.uvprojx").write_text(
        (EXAMPLES / "demo_rtos" / "keil" / "demo.uvprojx").read_text(encoding="utf-8"),
        encoding="utf-8")
    res = reconstruct(tmp_path)
    assert res.method == "keil-xml"
    assert res.target_hint == "STM32F407VGTx"
    assert len(res.commands) == 3
    args = res.commands[0].arguments
    assert any(a.startswith("-I") and a.endswith("include") for a in args)
    assert "-DUSE_STDPERIPH_DRIVER" in args


# ---------------- L2：SARIF 往返 ----------------

def _sample_alerts():
    return [
        Alert(rule_id="CERT C ARR30-C", engine="builtin", severity=Severity.ERROR,
              message="数组越界", location=Location(path="src/a.c", line=10),
              cwe="CWE-787", provenance=Provenance.DETECTED,
              evidence=[Evidence(kind="code", message="a[9] 下标越界",
                                 location=Location(path="src/a.c", line=10))]),
        Alert(rule_id="MISRA C:2012 16.4", engine="builtin", severity=Severity.WARNING,
              message="switch 缺 default", location=Location(path="src/a.c", line=20)),
    ]


def _sample_metas():
    return [
        RuleMeta("CERT C ARR30-C", "CERT C", "Required", "syntactic",
                 "常量下标越界", cwes=["CWE-787"]),
        RuleMeta("MISRA C:2012 16.4", "MISRA C:2012", "Required", "syntactic",
                 "switch 缺 default"),
    ]


def test_sarif_roundtrip(tmp_path):
    alerts, metas = _sample_alerts(), _sample_metas()
    path = save_sarif(alerts, metas, tmp_path / "out.sarif")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ecdet"
    assert len(run["results"]) == 2
    assert run["results"][0]["properties"]["cwe"] == "CWE-787"

    loaded_alerts, loaded_metas = load_sarif(path)
    assert len(loaded_alerts) == 2
    a0 = loaded_alerts[0]
    assert a0.rule_id == "CERT C ARR30-C"
    assert a0.severity == Severity.ERROR
    assert a0.location.line == 10
    assert a0.evidence and a0.evidence[0].message == "a[9] 下标越界"


# ---------------- L5：聚合 ----------------

def test_aggregate_dedup_same_location():
    a1 = Alert(rule_id="CERT C ARR30-C", engine="builtin", severity=Severity.ERROR,
               message="数组越界", location=Location(path="a.c", line=5), cwe="CWE-787")
    a2 = Alert(rule_id="CERT C ARR30-C", engine="cppcheck", severity=Severity.WARNING,
               message="arrayIndexOutOfBounds", location=Location(path="a.c", line=5))
    result = aggregate([a1, a2], _sample_metas())
    assert result.total == 1
    c = result.clusters[0]
    assert set(c.engines) == {"builtin", "cppcheck"}
    assert c.max_severity == Severity.ERROR


def test_aggregate_equivalence_merge():
    """STR31-C 与 CWE-120 同位置告警应合并（映射等价类）。"""
    a1 = Alert(rule_id="CERT C STR31-C", engine="builtin", severity=Severity.ERROR,
               message="strcpy 溢出", location=Location(path="a.c", line=7))
    a2 = Alert(rule_id="CWE-120", engine="cppcheck", severity=Severity.ERROR,
               message="buffer overflow", location=Location(path="a.c", line=7))
    result = aggregate([a1, a2], _sample_metas())
    assert result.total == 1
    assert set(result.clusters[0].related_rules) == {"CERT C STR31-C", "CWE-120"}


def test_compliance_records():
    result = aggregate(_sample_alerts(), _sample_metas())
    records = {r.rule_id: r for r in build_compliance_records(result)}
    assert records["CERT C ARR30-C"].status == "deviation"
    assert records["CERT C ARR30-C"].violation_count == 1
    assert records["MISRA C:2012 16.4"].status == "deviation"


def test_stats_fields():
    result = aggregate(_sample_alerts(), _sample_metas())
    s = result.stats
    assert s["total"] == 2 and s["error"] == 1 and s["warning"] == 1
    assert s["by_engine"] == {"builtin": 2}
