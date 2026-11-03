"""CodeChecker analyzer/checker inventory, capabilities and guideline metadata."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path

from ecdet.l2_ir.model import RuleMeta

CORE_PROFILES = ("profile:default", "profile:sensitive", "profile:security",
                 "profile:portability")


def command(binary: str = "CodeChecker") -> list[str]:
    if Path(binary).stem.lower() == "codechecker":
        return [sys.executable, "-m", "ecdet.l3_analysis.codechecker_bridge"]
    return [binary]


def load_catalog(binary: str, env: dict[str, str]) -> dict:
    keys = ("PATH", "PYTHONPATH", "CC_ANALYZER_BIN", "CC_ANALYZERS_FROM_PATH",
            "CC_CLANGSA_PLUGIN_DIR")
    return _load_catalog(binary, tuple((key, env.get(key, "")) for key in keys))


@lru_cache(maxsize=8)
def _load_catalog(binary: str, overrides: tuple[tuple[str, str], ...]) -> dict:
    env = os.environ.copy()
    env.update({key: value for key, value in overrides if value})
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    warnings: list[str] = []

    def output(args: list[str]) -> str:
        try:
            proc = subprocess.run(command(binary) + args, env=env,
                                  capture_output=True, text=True, timeout=60,
                                  encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"CodeChecker 能力探测失败：{exc}") from exc
        if proc.stderr.strip():
            warnings.append(proc.stderr.strip())
        if proc.returncode:
            raise RuntimeError(f"CodeChecker 能力探测失败：{proc.stderr[-2000:]}")
        return proc.stdout

    def query(args: list[str]) -> list[dict]:
        try:
            result = json.loads(output(args))
        except json.JSONDecodeError as exc:
            raise RuntimeError("CodeChecker 能力探测没有返回有效 JSON。") from exc
        if not isinstance(result, list):
            raise RuntimeError("CodeChecker 能力清单应为 JSON 数组。")
        return result

    analyzers = query(["analyzers", "--output", "json"])
    checkers = query(["checkers", "--details", "--output", "json"])
    clang = next((item for item in analyzers if item.get("name") == "clangsa"
                  and item.get("version") != "NOT FOUND"), {})
    clang_path = Path(clang["path"]) if clang.get("path") else None
    mapper = None
    if clang_path:
        major = str(clang.get("version", "")).split(".")[0]
        for name in ("clang-extdef-mapping", f"clang-extdef-mapping-{major}"):
            candidate = clang_path.with_name(name + (".exe" if os.name == "nt" else ""))
            if candidate.is_file():
                mapper = str(candidate)
                break
    stats = any("statisticscollector." in str(item.get("name", "")).lower()
                for item in checkers)
    return {
        "version": version("codechecker"), "analyzers": analyzers,
        "checkers": checkers, "warnings": warnings,
        "capabilities": {
            "ctu": bool(clang_path and mapper), "ctu_mapping_tool": mapper,
            "statistical_analysis": stats,
            "statistical_analysis_reason": ("available" if stats else
                "LLVM 未包含 statisticsCollector/statisticsbased 插件"),
            "infer": any(item.get("name") == "infer" and item.get("path") and
                         item.get("version") != "NOT FOUND" for item in analyzers),
        },
    }


def checker_cwes(checker: dict) -> list[str]:
    return sorted({f"CWE-{match.group(1)}" for label in checker.get("labels", [])
                   if (match := re.search(r"(?:^|:)cwe-(\d+)$", label, re.I))})


def rule_metas(catalog: dict) -> list[RuleMeta]:
    result = []
    for item in catalog["checkers"]:
        labels = item.get("labels") or []
        result.append(RuleMeta(
            rule_id=item["name"], standard="CodeChecker", category="Required",
            decidability="dataflow", title_zh=item.get("description") or item["name"],
            cwes=checker_cwes(item),
            enabled_by_default=(item.get("status") == "enabled" or
                                bool(set(CORE_PROFILES) & set(labels)) or
                                item["name"].startswith(("gcc-analyzer", "infer-"))),
            properties={"analyzer": item.get("analyzer"), "labels": labels,
                        "upstream_status": item.get("status")},
        ))
    return result
