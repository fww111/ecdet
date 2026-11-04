"""引擎编排 —— L3 层调度入口。

引擎接口（Engine）：输入分析目标（文件集 + 规则启停配置），输出统一告警。
内置规则与 CodeChecker 核心静态分析共同运行；CodeChecker 调度
Clang、Clang-Tidy 与 Cppcheck，ESBMC 独立接入。
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from pathlib import Path

from ecdet.l2_ir.model import Alert, RuleMeta, Severity
from ecdet.l3_analysis.builtin_rules.checks import (
    FILE_RULES,
    PROJECT_RULES,
    FileFacts,
    ProjectContext,
    build_file_facts,
    finalize_facts,
)
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES, canonical_rule_id

_LOG = logging.getLogger(__name__)

# 行业配置文件：方案 3.3.3 的裁剪策略（按 Mandatory/Required/Advisory 与行业分层启停）
INDUSTRY_PROFILES: dict[str, set[str]] = {
    # 汽车电子：MISRA 全开，stdio I/O 禁用严格执行
    "automotive": set(),
    # 工控：放宽 stdio（上位机调试常用），其余同默认
    "industrial": {"MISRA C:2012 21.6"},
    # Juliet 基准评测：单文件函数切片不构成完整工程，
    # 链接域/隐式声明类工程级规则必然误报，评测时屏蔽（方案 3.4.1）
    "juliet": {"MISRA C:2012 8.7", "MISRA C:2012 8.9", "MISRA C:2012 17.3"},
}
INDUSTRY_PROFILES["automotive"] = set()   # 全启用


@dataclass
class AnalysisTarget:
    """一次分析的输入：根目录 + 参与分析的源文件（相对根目录路径）。"""

    root: Path
    files: list[Path] = field(default_factory=list)
    svd_path: Path | None = None       # CMSIS-SVD 芯片描述（提供则启用 MMIO 检查）
    artifact_dir: Path | None = None   # CodeChecker 原生报告、配置与日志
    rule_enable: list[str] = field(default_factory=list)
    rule_disable: list[str] = field(default_factory=list)
    analysis_profile: str | None = None

    def read(self, rel: Path) -> str:
        return (self.root / rel).read_text(encoding="utf-8", errors="replace")


class Engine(ABC):
    """分析引擎抽象。name 唯一；available() 决定调度器是否启用。"""

    name: str = "base"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def rules(self) -> list[RuleMeta]: ...

    @abstractmethod
    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]: ...


class BuiltinEngine(Engine):
    """自研内置规则引擎（句法/词法层，阶段一骨架）。"""

    name = "builtin"

    def available(self) -> bool:
        return True

    def rules(self) -> list[RuleMeta]:
        return list(BUILTIN_RULES)

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        facts: list[FileFacts] = []
        for rel in target.files:
            if rel.suffix.lower() not in (".c", ".h", ".cpp", ".cc", ".cxx"):
                continue
            facts.append(build_file_facts(rel.as_posix(), target.read(rel)))
        ctx = finalize_facts(facts)
        ctx.enabled_rules = enabled_rules

        alerts: list[Alert] = []
        # 同一检查函数服务多条规则（如 API 扫描覆盖 21.3/21.6/MSC30/CWE-242），
        # 按"函数一次调用 + 生效规则集"分组调度，避免同一告警重复产出
        file_groups: dict[object, set[str]] = {}
        for rid, fn in FILE_RULES.items():
            if rid in enabled_rules:
                file_groups.setdefault(fn, set()).add(rid)
        for fn, rids in file_groups.items():
            for f in facts:
                alerts.extend(fn(f, ctx, rids))

        project_groups: dict[object, set[str]] = {}
        for rid, fn in PROJECT_RULES.items():
            if rid in enabled_rules:
                project_groups.setdefault(fn, set()).add(rid)
        for fn, rids in project_groups.items():
            alerts.extend(fn(ctx, rids))

        # L3 硬件语义注入（P2，方案 3.3.2）：SVD 提供时含 MMIO 权限检查
        from ecdet.l3_analysis.hw_model.checks_hw import HW_RULES
        from ecdet.l3_analysis.hw_model.context import build_hw_context
        hw = build_hw_context(ctx, target.svd_path)
        hw_groups: dict[object, set[str]] = {}
        for rid, fn in HW_RULES.items():
            if rid in enabled_rules:
                hw_groups.setdefault(fn, set()).add(rid)
        for fn, rids in hw_groups.items():
            alerts.extend(fn(ctx, hw, rids))

        # L3 抽象解释（P4，方案 3.3.4）：常量传播 → 越界下标 Proven 级证明
        if "CERT C ARR30-C" in enabled_rules:
            from ecdet.l3_analysis.abstract_interp import proven_index_check
            alerts.extend(proven_index_check(facts))
        from ecdet.l3_analysis.value_flow import check_value_flow
        alerts.extend(check_value_flow(facts, enabled_rules))
        return alerts


class ExternalEngineAdapter(Engine):
    """外部引擎适配器基类：封装“探测二进制 → 调用 → 输出转 SARIF 语义”。"""

    name = "external"
    binary: str = ""

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def rules(self) -> list[RuleMeta]:
        return []   # 外部引擎规则集由其自身管理，L5 聚合时透传

    def _run_cmd(self, cmd: list[str], timeout: int = 120) -> str:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
            return (r.stdout or "") + (r.stderr or "")
        except (subprocess.TimeoutExpired, OSError):
            return ""


class CppcheckAdapter(ExternalEngineAdapter):
    """cppcheck 适配器：MISRA 插件 addon 调用（方案表 3-1 可复用技术）。"""

    name = "cppcheck"
    binary = "cppcheck"

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        from ecdet.l3_analysis.adapters.cppcheck import run_cppcheck

        if not self.available():
            return []
        return run_cppcheck(target, timeout=180)


class ClangTidyAdapter(ExternalEngineAdapter):
    """clang-tidy 适配器（阶段二接入 Clang 前端时的自然延伸）。"""

    name = "clang-tidy"
    binary = "clang-tidy"

    def available(self) -> bool:
        return shutil.which(os.environ.get('ECDET_CLANG_TIDY') or self.binary) is not None

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        from ecdet.l3_analysis.adapters.clang_tidy import run_clang_tidy

        if not self.available():
            _LOG.warning("clang-tidy unavailable: executable not found; analysis skipped")
            return []
        return run_clang_tidy(target, timeout=180)


class CodeCheckerEngine(Engine):
    """CodeChecker 核心引擎：每次静态扫描均执行并汇总 C/C++ 分析结果。"""

    name = "codechecker"
    binary = "CodeChecker"

    def _binary_path(self) -> str | None:
        binary = shutil.which("CodeChecker") or shutil.which("codechecker")
        if binary:
            return binary
        from importlib.util import find_spec

        # Embedded Python callers need not activate the scripts directory;
        # the project bridge invokes the installed package with this Python.
        return "CodeChecker" if find_spec("codechecker_common") else None

    def available(self) -> bool:
        # CodeChecker 是项目基础依赖，不按“检测到即接入”方式静默跳过。
        return True

    def rules(self) -> list[RuleMeta]:
        from ecdet.l3_analysis.adapters.codechecker import _analyzer_environment
        from ecdet.l3_analysis.codechecker_catalog import load_catalog, rule_metas

        binary = self._binary_path()
        metas = rule_metas(load_catalog(binary, _analyzer_environment())) if binary else []
        manifest = getattr(self, "scan_manifest", {})
        if "enabled_checkers" in manifest:
            active = set(manifest["enabled_checkers"])
            metas = [replace(meta, enabled_by_default=meta.rule_id in active,
                             properties={**meta.properties, "analyzed": meta.rule_id in active})
                     for meta in metas]
        return metas

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        from ecdet.l3_analysis.adapters.codechecker import run_codechecker

        binary = self._binary_path()
        if not binary:
            raise RuntimeError(
                "CodeChecker 是必需的静态分析引擎。请先运行 `uv sync`，"
                "并确认虚拟环境中的 CodeChecker 命令可用。"
            )
        self.scan_manifest = {}
        try:
            timeout = int(os.environ.get("ECODET_CODECHECKER_TIMEOUT", "1800"))
            if timeout <= 0:
                raise ValueError
        except ValueError as exc:
            raise RuntimeError("ECODET_CODECHECKER_TIMEOUT 必须是正整数秒数。") from exc
        return run_codechecker(target, binary=binary, timeout=timeout,
                               on_manifest=lambda value: setattr(self, "scan_manifest", value))


DEFAULT_ENGINES: list[Engine] = [
    CodeCheckerEngine(),
    BuiltinEngine(),
]


def _make_default_engines() -> list[Engine]:
    """延迟导入 ESBMC 适配器，保持模块加载轻量。"""
    from ecdet.l3_analysis.adapters.esbmc import ESBMCAdapter

    return [CodeCheckerEngine(), BuiltinEngine(), ESBMCAdapter()]


def all_rule_metas(engines: list[Engine]) -> list[RuleMeta]:
    """汇总所有可用引擎的规则元数据。"""
    metas: dict[str, RuleMeta] = {}
    for e in engines:
        if e.available():
            for r in e.rules():
                metas.setdefault(r.rule_id, r)
    return list(metas.values())


def project_files(root: Path, skip: set[str] | None = None):
    """Prune generated directories before descent, including deep reports."""
    excluded = skip if skip is not None else {
        ".git", ".svn", "build", "ecdet_build", "node_modules",
        "__pycache__", ".venv", "ecdet_reports"}
    def failed(error):
        raise error

    for directory, dirs, files in os.walk(root, onerror=failed):
        dirs[:] = sorted(name for name in dirs if name not in excluded)
        for name in sorted(files):
            yield Path(directory) / name


def collect_sources(root: Path, extra_skip: set[str] | None = None) -> list[Path]:
    """收集工程源文件（相对路径），供 CLI / 编排层共用。

    遍历前裁剪生成目录，过滤按相对根的 parts 判定，
    避免把工程所在父目录的名称误当成工程内部的排除目录。
    """
    skip = {".git", ".svn", "build", "ecdet_build", "node_modules",
            "__pycache__", ".venv", "ecdet_reports"}
    skip |= extra_skip or set()
    out = []
    for p in sorted(project_files(root, skip)):
        rel = p.relative_to(root)
        if p.suffix.lower() in (".c", ".h", ".cc", ".cpp", ".cxx", ".c++",
                                ".hh", ".hpp", ".hxx") and \
                not any(s in rel.parts for s in skip):
            out.append(rel)
    return out


def resolve_enabled(rules: list[RuleMeta], profile: str | None,
                    disable: list[str] | None, enable: list[str] | None) -> set[str]:
    """解析行业配置 + 显式启停 → 生效规则集。"""
    disabled = {canonical_rule_id(r) for r in INDUSTRY_PROFILES.get(profile or "", set())}
    disabled.update(canonical_rule_id(r) for r in (disable or []))
    enabled_extra = {canonical_rule_id(r) for r in (enable or [])}
    return {r.rule_id for r in rules if r.enabled_by_default and
            r.rule_id not in disabled} | enabled_extra


def run_all_engines(target: AnalysisTarget, profile: str | None = None,
                    disable: list[str] | None = None, enable: list[str] | None = None,
                    engines: list[Engine] | None = None) -> tuple[list[Alert], list[RuleMeta]]:
    """调度全部可用引擎并合并告警。"""
    engs = engines if engines is not None else _make_default_engines()
    usable = []
    for engine in engs:
        if engine.available():
            usable.append(engine)
        else:
            _LOG.warning("%s unavailable; analysis skipped", engine.name)
    metas = all_rule_metas(usable)
    enabled = resolve_enabled(metas, profile, disable, enable)
    configured_target = replace(
        target, rule_enable=[*target.rule_enable, *(enable or [])],
        rule_disable=[*target.rule_disable, *(disable or [])],
        analysis_profile=profile or target.analysis_profile,
    )

    alerts: list[Alert] = []
    for e in usable:
        alerts.extend(e.run(configured_target, enabled))
    metas = all_rule_metas(usable)
    known_rules = {meta.rule_id for meta in metas}
    for alert in alerts:
        if alert.rule_id not in known_rules:
            metas.append(RuleMeta(alert.rule_id, alert.engine, 'Required', 'tool',
                                  alert.rule_id, [alert.cwe] if alert.cwe else []))
            known_rules.add(alert.rule_id)
    return alerts, metas
