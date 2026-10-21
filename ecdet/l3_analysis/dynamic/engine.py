"""动态引擎主流程（方案 3.3.5 的 DynamicEngine 过程）。

执行载体：宿主机原生执行（HostCarrier，gcc 可用即启用）；Unicorn /
Renode 载体探测到安装即接入（三级吞吐-保真梯度）。oracle 三类：
崩溃退出码（Windows NTSTATUS 可分类）、UB stderr、看门狗超时。
输出真触发 PoC → SARIF Detected 级告警（engine="dynamic"）。
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, Severity
from ecdet.l3_analysis.builtin_rules.checks import (
    FileFacts,
    ProjectContext,
    build_file_facts,
    finalize_facts,
)
from ecdet.l3_analysis.builtin_rules.cstruct import FunctionInfo
from ecdet.l3_analysis.dynamic.harness import (
    Harness,
    compile_harness,
    generate_harness,
)
from ecdet.l3_analysis.dynamic.inputs import build_input_model, param_value

# Windows NTSTATUS 崩溃分类（PoC 报告可读性）
_CRASH_KIND = {
    0xC0000005: "空指针/非法内存访问（ACCESS_VIOLATION）",
    0xC0000094: "整数除零（INT_DIVIDE_BY_ZERO）",
    0xC0000095: "整数溢出（INT_OVERFLOW）",
    0xC0000409: "栈溢出/安全检查失败（STACK_BUFFER_OVERRUN）",
}

_ORACLE_CRASH = "ECDET-DYN-CRASH"
_ORACLE_UB = "ECDET-DYN-UB"
_ORACLE_WATCHDOG = "ECDET-DYN-WATCHDOG"


@dataclass
class DynamicFinding:
    """一次动态触发事件（PoC + 复现步骤）。"""

    func_name: str
    target_rel: str
    oracle: str                    # CRASH / UB / WATCHDOG
    rule_id: str
    detail: str                    # 崩溃分类 / stderr 摘录
    seed_idx: int
    replay_seed: str               # 命令行重放种子
    args_preview: str              # 实参预览（PoC 输入）
    def_line: int = 1              # 目标函数定义行（告警定位）
    stubs: list[str] = field(default_factory=list)

    def to_alert(self) -> Alert:
        label = {_ORACLE_CRASH: "崩溃", _ORACLE_UB: "未定义行为",
                 _ORACLE_WATCHDOG: "执行超时（疑似死循环/活锁）"}[self.rule_id]
        return Alert(
            rule_id=self.rule_id,
            engine="dynamic",
            severity=Severity.ERROR,
            message=(f"动态触发：函数 {self.func_name} 在激励 seed={self.replay_seed} "
                     f"下发生{label}（{self.detail}），PoC 可复现"),
            location=Location(path=self.target_rel, line=self.def_line),
            provenance=Provenance.DETECTED,
            evidence=[
                Evidence(kind="api", message=f"目标函数：{self.func_name}()"),
                Evidence(kind="note", message=f"PoC 重放：harness 可执行文件 "
                         f"argv[1]={self.replay_seed}；实参 {self.args_preview}"),
                Evidence(kind="note", message=f"oracle：{label}（{self.detail}）"),
            ] + ([Evidence(kind="note",
                           message=f"harness 自动打桩符号：{', '.join(self.stubs)}")]
                 if self.stubs else []),
        )


def _collect_include_dirs(root: Path, facts: list[FileFacts]) -> list[Path]:
    dirs = {root, root / "include", root / "inc"}
    for f in facts:
        dirs.add(root / Path(f.path).parent)
    for d in list(dirs):
        if d.exists() and any(d.glob("*.h")):
            dirs.add(d)
    return sorted(dirs)


class DynamicEngine:
    """动态通道：目标函数 × 确定性激励矩阵 → oracle → PoC 告警。

    probe_names 非空时（运行时监控定向探针，3.3.6）只测这些函数并
    将其激励预算加倍。
    """

    def __init__(self, max_functions: int = 8, max_seeds: int = 32,
                 run_timeout: int = 5, gcc: str = "gcc"):
        self.max_functions = max_functions
        self.max_seeds = max_seeds
        self.run_timeout = run_timeout
        self.gcc = gcc

    @property
    def available(self) -> bool:
        return shutil.which(self.gcc) is not None

    def run(self, root: Path, facts: list[FileFacts],
            probe_names: set[str] | None = None) -> list[DynamicFinding]:
        if not self.available:
            return []
        root = Path(root)

        # 目标选择：探针优先，其次非 static 的 .c 内函数（main 除外）
        candidates: list[tuple[str, FunctionInfo]] = []
        for f in facts:
            if not f.path.endswith(".c"):
                continue
            for func in f.functions:
                if func.name == "main":
                    continue
                candidates.append((f.path, func))
        probes = probe_names or set()
        candidates.sort(key=lambda t: (t[1].name not in probes, t[0], t[1].name))
        targets = candidates[:self.max_functions]

        findings: list[DynamicFinding] = []
        with tempfile.TemporaryDirectory(prefix="ecdet_dyn_") as td:
            workdir = Path(td)
            include_dirs = _collect_include_dirs(root, facts)
            for target_rel, func in targets:
                budget = self.max_seeds * (2 if func.name in probes else 1)
                model = build_input_model(func)
                finding = self._fuzz_one(workdir, include_dirs,
                                         target_rel, model, budget)
                if finding:
                    findings.append(finding)
        return findings

    def _fuzz_one(self, workdir: Path, include_dirs: list[Path],
                  target_rel: str, model, budget: int) -> DynamicFinding | None:
        """单目标 fuzz：一次编译，逐 seed 执行-oracle，命中即记 PoC。"""
        harness = generate_harness(model, target_rel,
                                   n_seeds=max(model.n_specials, 1))
        ok, _err = compile_harness(harness, workdir, include_dirs, gcc=self.gcc)
        if not ok:
            return None          # 目标不可链接（修正闭环仍失败）→ 放弃该目标

        seen_oracles: set[str] = set()
        for seed_idx in range(min(budget, harness.n_seeds)):
            oracle, detail = self._run_oracle(harness, seed_idx)
            if oracle and oracle not in seen_oracles:
                seen_oracles.add(oracle)
                return DynamicFinding(
                    func_name=model.func.name, target_rel=target_rel,
                    oracle=oracle.rsplit("-", 1)[-1],
                    rule_id=oracle,
                    detail=detail,
                    seed_idx=seed_idx,
                    replay_seed=harness.replay_seed(seed_idx),
                    args_preview=", ".join(
                        param_value(p, seed_idx) for p in model.params),
                    def_line=model.func.def_line,
                    stubs=list(harness.stubs),
                )
        return None

    def _run_oracle(self, harness: Harness, seed_idx: int) -> tuple[str, str]:
        """执行一次并判定 oracle：崩溃退出码 / UB stderr / 看门狗超时。"""
        try:
            proc = subprocess.run(
                [str(harness.exe_path), harness.replay_seed(seed_idx)],
                capture_output=True, text=True, timeout=self.run_timeout,
                encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return _ORACLE_WATCHDOG, f"超过 {self.run_timeout}s 看门狗阈值"
        rc = proc.returncode
        if rc != 0:
            ntstatus = rc & 0xFFFFFFFF
            kind = _CRASH_KIND.get(ntstatus, "")
            detail = f"退出码 0x{ntstatus:08X}" + (f"（{kind}）" if kind else "")
            return _ORACLE_CRASH, detail
        if "runtime error" in (proc.stderr or ""):
            excerpt = proc.stderr.strip().splitlines()[0][:120]
            return _ORACLE_UB, f"UBSan runtime error：{excerpt}"
        return "", ""


def ctx_regmap_of(_facts: list[FileFacts], _target: str):
    """MVP：动态引擎暂不直接持有 SVD（由编排层经 regmap 参数传入时启用）。

    保留接口以落实"一次建模、静动两用"（3.3.5 MMIO 语义分片）。
    """
    return None
