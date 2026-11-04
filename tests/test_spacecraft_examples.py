"""航天器嵌入式样例工程的回归测试。

样例位于 ``examples/spacecraft/<subsystem>``。这些工程刻意包含多类
缺陷，用于验证内置规则在真实星载软件形态下的覆盖能力。测试只运行
内置规则引擎，不依赖 CodeChecker，保证在任意开发机上都能快速执行。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ecdet.l3_analysis.engine import (
    AnalysisTarget,
    BuiltinEngine,
    collect_sources,
    run_all_engines,
)

SPACECRAFT_DIR = Path(__file__).resolve().parents[1] / "examples" / "spacecraft"

BASE_HW_RULES = {
    "ECDET-MMIO-ACCESS",
    "ECDET-ISR-RACE",
    "ECDET-VOLATILE",
}

EXPECTED_RULES = {
    "aocs": {
        "CERT C ARR30-C",
        "CERT C FIO30-C",
        "CERT C STR31-C",
        "ECDET-CWE-197",
        "ECDET-CWE-563",
        "ECDET-CWE-785",
        "ECDET-HW-BITFIELD",
        "ECDET-HW-CRITICAL-PAIR",
        "ECDET-HW-ISR-HEAP",
        "ECDET-HW-VOLATILE-RMW",
        "ECDET-ISR-BLOCK",
        "ECDET-MMIO-ACCESS",
        "ECDET-ISR-RACE",
        "ECDET-VOLATILE",
        "MISRA C:2012 6.1",
        "MISRA C:2012 10.3",
        "MISRA C:2012 12.2",
        "MISRA C:2012 13.5",
        "MISRA C:2012 13.6",
        "MISRA C:2012 14.2",
        "MISRA C:2012 14.3",
        "MISRA C:2012 15.1",
        "MISRA C:2012 15.2",
        "MISRA C:2012 16.4",
        "MISRA C:2012 16.6",
        "MISRA C:2012 17.2",
        "MISRA C:2012 18.8",
        "MISRA C:2012 21.3",
        "MISRA C:2012 21.7",
    },
    "obdh": {
        "CERT C ARR30-C",
        "CERT C EXP45-C",
        "CERT C FIO30-C",
        "CERT C INT30-C",
        "CERT C MEM34-C",
        "CERT C MSC30-C",
        "CERT C PRE31-C",
        "CERT C STR31-C",
        "ECDET-CWE-1284",
        "ECDET-CWE-197",
        "ECDET-HW-VOLATILE-RMW",
        "ECDET-ISR-BLOCK",
        "ECDET-MMIO-ACCESS",
        "ECDET-ISR-RACE",
        "ECDET-VOLATILE",
        "MISRA C:2012 7.2",
        "MISRA C:2012 10.3",
        "MISRA C:2012 12.2",
        "MISRA C:2012 13.6",
        "MISRA C:2012 14.2",
        "MISRA C:2012 15.1",
        "MISRA C:2012 15.2",
        "MISRA C:2012 16.3",
        "MISRA C:2012 16.4",
        "MISRA C:2012 18.8",
        "MISRA C:2012 21.1",
        "MISRA C:2012 21.3",
        "MISRA C:2012 21.7",
    },
    "eps": {
        "CERT C ARR30-C",
        "CERT C EXP45-C",
        "CERT C FIO30-C",
        "ECDET-CWE-197",
        "ECDET-HW-BITFIELD",
        "ECDET-HW-CRITICAL-PAIR",
        "ECDET-HW-ISR-HEAP",
        "ECDET-HW-VOLATILE-RMW",
        "ECDET-ISR-BLOCK",
        "ECDET-MMIO-ACCESS",
        "ECDET-ISR-RACE",
        "ECDET-VOLATILE",
        "MISRA C:2012 6.1",
        "MISRA C:2012 10.3",
        "MISRA C:2012 11.8",
        "MISRA C:2012 12.2",
        "MISRA C:2012 13.6",
        "MISRA C:2012 14.2",
        "MISRA C:2012 15.5",
        "MISRA C:2012 16.3",
        "MISRA C:2012 16.4",
        "MISRA C:2012 21.3",
    },
    "ttc": {
        "CERT C ARR30-C",
        "CERT C EXP45-C",
        "CERT C FIO30-C",
        "CERT C MSC30-C",
        "CERT C MSC41-C",
        "CERT C STR31-C",
        "ECDET-CWE-1284",
        "ECDET-CWE-197",
        "ECDET-CWE-785",
        "ECDET-HW-CRITICAL-PAIR",
        "ECDET-HW-ISR-HEAP",
        "ECDET-HW-VOLATILE-RMW",
        "ECDET-ISR-BLOCK",
        "ECDET-MMIO-ACCESS",
        "ECDET-ISR-RACE",
        "ECDET-VOLATILE",
        "MISRA C:2012 10.3",
        "MISRA C:2012 11.4",
        "MISRA C:2012 12.2",
        "MISRA C:2012 13.6",
        "MISRA C:2012 14.2",
        "MISRA C:2012 15.1",
        "MISRA C:2012 15.2",
        "MISRA C:2012 15.5",
        "MISRA C:2012 16.4",
        "MISRA C:2012 18.6",
        "MISRA C:2012 18.8",
        "MISRA C:2012 21.3",
        "MISRA C:2012 21.7",
    },
}


def _run_sample(name: str):
    root = SPACECRAFT_DIR / name
    target = AnalysisTarget(
        root=root,
        files=collect_sources(root),
        svd_path=root / "SPC3000.svd",
    )
    return run_all_engines(target, engines=[BuiltinEngine()])[0]


@pytest.mark.parametrize("name", sorted(EXPECTED_RULES))
def test_spacecraft_sample_covers_expected_rules(name: str) -> None:
    alerts = _run_sample(name)
    found = {alert.rule_id for alert in alerts}
    missing = (EXPECTED_RULES[name] | BASE_HW_RULES) - found
    assert not missing, f"{name} 样例缺少预期规则命中: {sorted(missing)}"
    assert len(alerts) >= 40, f"{name} 样例告警数量异常: {len(alerts)}"


@pytest.mark.parametrize("name", sorted(EXPECTED_RULES))
def test_spacecraft_sample_layout(name: str) -> None:
    root = SPACECRAFT_DIR / name
    assert (root / "CMakeLists.txt").is_file()
    assert (root / "SPC3000.svd").is_file()

    sources = list((root / "src").glob("*.c"))
    headers = list((root / "include").glob("*.h"))
    assert len(sources) >= 5
    assert len(headers) >= 1

    total_lines = 0
    for path in sources + headers:
        total_lines += len(path.read_text(encoding="utf-8").splitlines())
    assert total_lines >= 600, f"{name} 样例代码量不足: {total_lines} 行"
