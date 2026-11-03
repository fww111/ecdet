"""clang-tidy 适配器 —— 依赖 L1 产出的 compile_commands.json。

调用形态：clang-tidy -p <build_dir> --checks='clang-analyzer-*,bugprone-*,cert-*,misc-*' <src>
输出解析：`path:line:col: severity: message [name]` 文本行 → 统一 Alert。
阶段二接入 Clang 前端（L2 统一 IR）后，本适配器与自研引擎共享编译数据库。
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Location, Severity
from ecdet.l3_analysis.engine import AnalysisTarget

_TIDY_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<sev>error|warning|note):\s+(?P<msg>.*?)\s+\[(?P<check>[\w\-.,*]+)\]\s*$"
)

_SEV = {"error": Severity.ERROR, "warning": Severity.WARNING, "note": Severity.NOTE}
_LOG = logging.getLogger(__name__)


def _output_text(output: str | bytes | None) -> str:
    # TimeoutExpired may expose bytes even when subprocess.run(text=True).
    return output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output or ""


def _project_locations(alerts: list[Alert], root: Path) -> list[Alert]:
    for alert in alerts:
        path=Path(alert.location.path)
        if path.is_absolute():
            try:
                alert.location.path=path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                pass  # External files must not be relabelled as project sources.
    return alerts


def run_clang_tidy(target: AnalysisTarget, timeout: int = 300) -> list[Alert]:
    ccdb = target.root / "build" / "compile_commands.json"
    if not ccdb.exists():
        ccdb = target.root / "compile_commands.json"
    if not ccdb.exists():
        _LOG.warning("clang-tidy skipped: compilation database missing in %s", target.root)
        return []

    try:
        entries = json.loads(ccdb.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or any(
            not isinstance(entry, dict) or not isinstance(entry.get("file"), str)
            for entry in entries
        ):
            raise ValueError("expected an array of entries with file paths")
    except (OSError, ValueError) as exc:
        _LOG.warning("clang-tidy skipped: invalid compilation database %s: %s", ccdb, exc)
        return []
    c_files = list(dict.fromkeys(e["file"] for e in entries if e["file"].endswith(".c")))
    if not c_files:
        _LOG.info("clang-tidy skipped: compilation database contains no C files")
        return []

    cmd = [os.environ.get('ECDET_CLANG_TIDY') or "clang-tidy", "-p", str(ccdb.parent), "--quiet",
           "--checks=clang-analyzer-*,bugprone-*,cert-*,misc-*,readability-*",
           *c_files]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", cwd=str(target.root))
    except subprocess.TimeoutExpired as exc:
        _LOG.warning("clang-tidy timed out after %s seconds; analysis incomplete", timeout)
        return _project_locations(parse_clang_tidy_output(_output_text(exc.stdout), _output_text(exc.stderr)), target.root)
    except FileNotFoundError:
        _LOG.warning("clang-tidy unavailable: executable not found")
        return []
    except OSError as exc:
        _LOG.warning("clang-tidy could not start: %s", exc)
        return []
    stdout, stderr = _output_text(proc.stdout), _output_text(proc.stderr)
    alerts = _project_locations(parse_clang_tidy_output(stdout, stderr), target.root)
    compiler_error = any(
        alert.severity == Severity.ERROR and alert.rule_id.startswith("clang-diagnostic-")
        for alert in alerts
    ) or bool(re.search(r"^(?:.*:\d+:\d+:\s*)?(?:fatal )?error:",
                        stdout + "\n" + stderr, re.MULTILINE))
    if compiler_error:
        _LOG.warning("clang-tidy compilation failed; analysis incomplete (%d diagnostics)", len(alerts))
    elif proc.returncode:
        _LOG.warning("clang-tidy exited with status %s (%d diagnostics)", proc.returncode, len(alerts))
    else:
        _LOG.info("clang-tidy completed: %d diagnostics", len(alerts))
    return alerts


def parse_clang_tidy_output(stdout: str, stderr: str) -> list[Alert]:
    alerts: list[Alert] = []
    seen: set[tuple[str, ...]] = set()
    for line in (stdout + "\n" + stderr).splitlines():
        m = _TIDY_LINE.match(line.strip())
        if not m:
            continue
        path = m.group("path").replace("\\", "/")
        key = (path, m.group("line"), m.group("col"), m.group("sev"), m.group("msg"), m.group("check"))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            Alert(
                rule_id=m.group("check"),
                engine="clang-tidy",
                severity=_SEV.get(m.group("sev"), Severity.NOTE),
                message=m.group("msg"),
                location=Location(path=path,
                                  line=int(m.group("line")),
                                  col=int(m.group("col"))),
                evidence=[Evidence(kind="api", message=f"clang-tidy check {m.group('check')}")],
            )
        )
    return alerts
