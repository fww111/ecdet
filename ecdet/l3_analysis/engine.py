"""引擎编排 —— L3 层调度入口。

引擎接口（Engine）：输入分析目标（文件集 + 规则启停配置），输出统一告警。
内置规则引擎零依赖恒可用；外部引擎（cppcheck/clang-tidy）通过适配器
“检测到即接入”（方案 3.3.3：以 cppcheck 为基补齐、clang-tidy/Semgrep 框架复用）。
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES

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

    def run(self, target: AnalysisTarget, enabled_rules: set[str]) -> list[Alert]:
        from ecdet.l3_analysis.adapters.clang_tidy import run_clang_tidy

        if not self.available():
            return []
        return run_clang_tidy(target, timeout=180)


DEFAULT_ENGINES: list[Engine] = [
    BuiltinEngine(),
    CppcheckAdapter(),
    ClangTidyAdapter(),
]


def _make_default_engines() -> list[Engine]:
    """延迟导入 ESBMC 适配器，保持模块加载轻量。"""
    from ecdet.l3_analysis.adapters.esbmc import ESBMCAdapter

    return [BuiltinEngine(), CppcheckAdapter(), ClangTidyAdapter(), ESBMCAdapter()]


def all_rule_metas(engines: list[Engine]) -> list[RuleMeta]:
    """汇总所有可用引擎的规则元数据。"""
    metas: dict[str, RuleMeta] = {}
    for e in engines:
        if e.available():
            for r in e.rules():
                metas.setdefault(r.rule_id, r)
    return list(metas.values())


def resolve_enabled(rules: list[RuleMeta], profile: str | None,
                    disable: list[str] | None, enable: list[str] | None) -> set[str]:
    """解析行业配置 + 显式启停 → 生效规则集。"""
    disabled = set(INDUSTRY_PROFILES.get(profile or "", set()))
    disabled.update(disable or [])
    enabled_extra = set(enable or [])
    return {r.rule_id for r in rules if r.rule_id not in disabled} | enabled_extra


def run_all_engines(target: AnalysisTarget, profile: str | None = None,
                    disable: list[str] | None = None, enable: list[str] | None = None,
                    engines: list[Engine] | None = None) -> tuple[list[Alert], list[RuleMeta]]:
    """调度全部可用引擎并合并告警。"""
    engs = engines if engines is not None else _make_default_engines()
    usable = [e for e in engs if e.available()]
    metas = all_rule_metas(usable)
    enabled = resolve_enabled(metas, profile, disable, enable)

    alerts: list[Alert] = []
    for e in usable:
        alerts.extend(e.run(target, enabled))
    return alerts, metas
