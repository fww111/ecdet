"""clang-tidy 适配器 —— 依赖 L1 产出的 compile_commands.json。

调用形态：clang-tidy -p <build_dir> --checks='clang-analyzer-*,bugprone-*,cert-*,misc-*' <src>
输出解析：`path:line:col: severity: message [name]` 文本行 → 统一 Alert。
阶段二接入 Clang 前端（L2 统一 IR）后，本适配器与自研引擎共享编译数据库。
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Location, Severity
from ecdet.l3_analysis.engine import AnalysisTarget

_TIDY_LINE = re.compile(
    r"^(?P<path>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<sev>error|warning|note):\s+(?P<msg>.*?)\s+\[(?P<check>[\w\-.,*]+)\]\s*$"
)

_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "note": Severity.NOTE}


def run_clang_tidy(target: AnalysisTarget, timeout: int = 300) -> list[Alert]:
    ccdb = target.root / "build" / "compile_commands.json"
    if not ccdb.exists():
        ccdb = target.root / "compile_commands.json"
    if not ccdb.exists():
        return []

    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    c_files = [e["file"] for e in entries if e["file"].endswith(".c")]
    if not c_files:
        return []

    cmd = ["clang-tidy", "-p", str(ccdb.parent), "--quiet",
           "--checks=clang-analyzer-*,bugprone-*,cert-*,misc-*,readability-*",
           *c_files]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", cwd=str(target.root))
    except (subprocess.TimeoutExpired, OSError):
        return []
    return parse_clang_tidy_output(proc.stdout or "", proc.stderr or "")


def parse_clang_tidy_output(stdout: str, _stderr: str) -> list[Alert]:
    alerts: list[Alert] = []
    for line in stdout.splitlines():
        m = _TIDY_LINE.match(line.strip())
        if not m:
            continue
        alerts.append(
            Alert(
                rule_id=m.group("check"),
                engine="clang-tidy",
                severity=_SEV.get(m.group("sev"), Severity.NOTE),
                message=m.group("msg"),
                location=Location(path=m.group("path"),
                                  line=int(m.group("line")),
                                  col=int(m.group("col"))),
                evidence=[Evidence(kind="api", message=f"clang-tidy check {m.group('check')}")],
            )
        )
    return alerts
