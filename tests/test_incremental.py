# -*- coding: utf-8 -*-
"""增量分析测试：影响集计算与告警基线差分（方案 3.3.6）。"""

import textwrap
from pathlib import Path

from ecdet.incremental import (
    BaselineDiff,
    compute_impact_set,
    diff_baseline,
    save_baseline,
    load_baseline_fingerprints,
)
from ecdet.l2_ir.model import Alert, Location, Severity

CORPUS = textwrap.dedent("""\
    #ifndef SENSOR_H
    #define SENSOR_H
    int sensor_read(void);
    #endif
    """)
MAIN_C = textwrap.dedent("""\
    #include "sensor.h"
    int main(void) { return sensor_read(); }
    """)
SENSOR_C = textwrap.dedent("""\
    #include "sensor.h"
    static int level;
    int sensor_read(void) { level++; return level; }
    """)
COMM_C = textwrap.dedent("""\
    #include <stdint.h>
    void comm_send(void) { }
    """)


def _make_corpus(root: Path) -> Path:
    (root / "sensor.h").write_text(CORPUS, encoding="utf-8")
    (root / "main.c").write_text(MAIN_C, encoding="utf-8")
    (root / "sensor.c").write_text(SENSOR_C, encoding="utf-8")
    (root / "comm.c").write_text(COMM_C, encoding="utf-8")
    return root


def test_impact_set_call_closure(tmp_path):
    """改 sensor.c → 调用其函数的 main.c 受影响；无关的 comm.c 不受影响。"""
    root = _make_corpus(tmp_path)
    impact = compute_impact_set(root, ["sensor.c"])
    assert "sensor.c" in impact.affected
    assert impact.reason["sensor.c"] == "changed"
    assert "main.c" in impact.affected
    assert "调用受影响文件的函数" in impact.reason["main.c"]
    assert "comm.c" not in impact.affected


def test_impact_set_include_closure(tmp_path):
    """改 sensor.h → 包含它的 main.c 与 sensor.c 均受影响。"""
    root = _make_corpus(tmp_path)
    impact = compute_impact_set(root, ["sensor.h"])
    assert {"sensor.h", "main.c", "sensor.c"} <= set(impact.affected)
    assert "包含受影响头文件" in impact.reason["main.c"]
    assert "comm.c" not in impact.affected


def test_impact_set_transitive_include(tmp_path):
    """include 闭包传递：a.h ← b.h ← c.c，改 a.h 三者皆受影响。"""
    (tmp_path / "a.h").write_text("#define A 1\n", encoding="utf-8")
    (tmp_path / "b.h").write_text('#include "a.h"\n#define B 2\n', encoding="utf-8")
    (tmp_path / "c.c").write_text('#include "b.h"\nint f(void) { return A + B; }\n',
                                  encoding="utf-8")
    impact = compute_impact_set(tmp_path, ["a.h"])
    assert {"a.h", "b.h", "c.c"} <= set(impact.affected)


# ---------------- 基线差分 ----------------

def _alert(rule: str, path: str, line: int, msg: str = "m") -> Alert:
    return Alert(rule_id=rule, engine="builtin", severity=Severity.WARNING,
                 message=msg, location=Location(path=path, line=line))


def test_baseline_diff_classification():
    old = {_alert("R1", "a.c", 5).compute_fingerprint(),
           _alert("R2", "a.c", 9).compute_fingerprint()}
    alerts = [
        _alert("R1", "a.c", 5),            # 持续
        _alert("R3", "b.c", 12),           # 新增
        _alert("R4", "b.c", 20),           # 新增
    ]
    diff = diff_baseline(old, alerts)
    assert isinstance(diff, BaselineDiff)
    assert len(diff.new) == 2
    assert len(diff.persisting) == 1
    assert diff.resolved_count == 1        # R2 未再出现
    assert "新增 2" in diff.summary


def test_baseline_roundtrip(tmp_path):
    alerts = [_alert("R1", "a.c", 5), _alert("R2", "b.c", 9)]
    path = save_baseline(alerts, tmp_path / "baseline.json")
    fps = load_baseline_fingerprints(path)
    assert fps == {a.ensure_fingerprint() for a in alerts}
    diff = diff_baseline(fps, alerts)
    assert diff.new == [] and diff.resolved_count == 0
    assert len(diff.persisting) == 2
