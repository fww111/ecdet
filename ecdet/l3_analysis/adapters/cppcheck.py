"""cppcheck 适配器 —— 输出 XML 转统一 Alert。

调用形态：cppcheck --xml --xml-version=2 --enable=warning,style,portability,performance
         --addon=misra（若安装了 misra.py addon）
方案依据：表 3-1 将 cppcheck MISRA 插件列为可复用技术，本系统在其上补齐。
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Location, Severity
from ecdet.l3_analysis.engine import AnalysisTarget

_SEVERITY_MAP = {"error": Severity.ERROR, "warning": Severity.WARNING}
_MISRA_ID_RE = re.compile(r"misra-c2012-(\d+\.\d+)")


def run_cppcheck(target: AnalysisTarget, timeout: int = 180) -> list[Alert]:
    srcs = [str((target.root / f).resolve()) for f in target.files
            if f.suffix.lower() == ".c"]
    if not srcs:
        return []

    cmd = ["cppcheck", "--xml", "--xml-version=2",
           "--enable=warning,style,portability,performance",
           "--inline-suppr", "-j", "4", *srcs]
    # 探测 misra addon（与 cppcheck 同目录或 PATH）
    addon = _find_misra_addon()
    if addon:
        cmd += ["--addon=" + addon]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError):
        return []
    return parse_cppcheck_xml(proc.stderr or "", proc.stdout or "")


def _find_misra_addon() -> str | None:
    try:
        import shutil
        which = shutil.which("cppcheck")
        if which:
            for cand in (Path(which).parent / "addons" / "misra.py",
                         Path(which).parent / "misra.py",
                         Path(which).with_name("misra.py")):
                if cand.exists():
                    return str(cand)
    except OSError:
        pass
    return None


def parse_cppcheck_xml(err: str, out: str) -> list[Alert]:
    """cppcheck 将结果写到 stderr（XML 模式）。"""
    m = re.search(r"<\?xml.*</results>", err + out, re.S)
    if not m:
        return []
    alerts: list[Alert] = []
    try:
        root = ET.fromstring(m.group(0))
    except ET.ParseError:
        return alerts
    for err_el in root.iter("error"):
        eid = err_el.get("id", "")
        sev = err_el.get("severity", "warning")
        msg = err_el.get("msg", "")
        misra_m = _MISRA_ID_RE.search(eid)
        rule_id = f"MISRA C:2012 {misra_m.group(1)}" if misra_m else f"cppcheck:{eid}"
        for loc_el in err_el.iter("location"):
            alerts.append(
                Alert(
                    rule_id=rule_id,
                    engine="cppcheck",
                    severity=_SEVERITY_MAP.get(sev, Severity.NOTE),
                    message=msg,
                    location=Location(path=loc_el.get("file", ""),
                                      line=int(loc_el.get("line", "1"))),
                    evidence=[Evidence(kind="api", message=f"cppcheck id={eid}")],
                )
            )
    return alerts
