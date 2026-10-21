"""LLM 修复建议与工具验证闭环（方案 3.3.5 之 3，对应 P5 幻觉抑制）。

procedure ToolLoopVerify(patch):
    if 编译语法检查失败   : 拒绝
    if 原告警未消除       : 拒绝
    if 引入新的 error 告警: 拒绝
    else 采纳

依据：GPTScan 以静态分析确认削减误报；固件工作以 CWE 驱动 LLM 迭代修补
并经 QEMU 验证（92.4% 修复率）。本实现为静态重扫 + gcc 语法检查的
MVP 验证环，CBMC 界内验证留待 ESBMC 通道扩展。
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Severity
from ecdet.l3_analysis.builtin_rules.checks import (
    FILE_RULES,
    ProjectContext,
    build_file_facts,
    finalize_facts,
)
from ecdet.l4_llm.slicer import slice_context

FIX_SYSTEM_PROMPT = (
    "你是嵌入式 C 代码修复专家。针对给定告警修改该函数，要求："
    "最小改动、不改变函数签名与语义意图、消除告警且不引入新缺陷。"
    '只输出一个 JSON 对象：{"patched_function": "修改后的完整函数源码", '
    '"explanation": "中文修改说明"}。不要输出 JSON 以外内容。'
)


@dataclass
class FixProposal:
    rule_id: str
    path: str
    func_name: str
    func_start: int
    func_end: int
    original_code: str
    patched_code: str = ""
    explanation: str = ""
    verified: bool = False
    fail_reason: str = ""
    diff: str = ""

    def to_props(self) -> dict:
        return {
            "verified": self.verified,
            "explanation": self.explanation,
            "fail_reason": self.fail_reason,
        }


def apply_patch(source: str, start_line: int, end_line: int,
                patched_code: str) -> str:
    """用补丁文本替换源文件 [start_line, end_line] 行区间。"""
    lines = source.splitlines()
    new_lines = lines[:start_line - 1] + patched_code.splitlines() + lines[end_line:]
    return "\n".join(new_lines) + ("\n" if source.endswith("\n") else "")


def _function_alerts(ctx: ProjectContext, path: str, func_name: str,
                     start: int, end: int, active: set[str]) -> dict[str, str]:
    """行区间内的告警映射 rule_id -> 最高严重级。

    复用整文件规则结果再按行过滤，与引擎产出保持一致，避免重放差异。
    """
    norm = path.replace("\\", "/")
    sev_order = {"note": 0, "warning": 1, "error": 2}
    out: dict[str, str] = {}
    for f in ctx.facts:
        if f.path.replace("\\", "/") != norm:
            continue
        seen: dict = {}
        for rid, fn in FILE_RULES.items():
            if rid in active:
                seen.setdefault(fn, set()).add(rid)
        alerts = []
        for fn, rids in seen.items():
            alerts.extend(fn(f, ctx, rids))
        for a in alerts:
            if start <= a.location.line <= end:
                cur = out.get(a.rule_id)
                if cur is None or sev_order[a.severity.value] > sev_order[cur]:
                    out[a.rule_id] = a.severity.value
    return out


def extract_patched_function(raw: str) -> dict:
    """从 LLM 输出解析 {"patched_function": ..., "explanation": ...}。"""
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}
    patched = data.get("patched_function")
    if not isinstance(patched, str) or not patched.strip():
        return {}
    # 剥离可能的 markdown 代码栅栏
    fence = re.match(r"\s*```[cC]?\n(.*?)\n?```\s*$", patched, re.S)
    if fence:
        patched = fence.group(1)
    return {"patched_function": patched.rstrip(),
            "explanation": str(data.get("explanation", ""))[:500]}


class FixProposer:
    """修复建议生成器。client 传 Mock 即离线模式。"""

    def __init__(self, client, budget_chars: int = 8000):
        self.client = client
        self.budget_chars = budget_chars

    def propose(self, alert: Alert, ctx: ProjectContext) -> FixProposal:
        slice_ = slice_context(alert, ctx, self.budget_chars)
        proposal = FixProposal(
            rule_id=alert.rule_id, path=alert.location.path,
            func_name=slice_.func_name, func_start=slice_.func_start,
            func_end=slice_.func_end, original_code=slice_.function_text)
        if not slice_.func_name:
            proposal.fail_reason = "告警不在函数内，无法生成函数级补丁"
            return proposal
        user = "\n".join([
            "## 告警",
            f"规则：{alert.rule_id}；位置：{alert.location.path}:{alert.location.line}",
            f"说明：{alert.message}",
            "",
            "## 当前函数",
            "```c",
            slice_.function_text,
            "```",
            "",
            "## 任务",
            "输出修复后的完整函数（JSON）。",
        ])
        raw = self.client.complete(FIX_SYSTEM_PROMPT, user)
        parsed = extract_patched_function(raw)
        if not parsed:
            proposal.fail_reason = "LLM 输出不可解析（非结构化 JSON）"
            return proposal
        proposal.patched_code = parsed["patched_function"]
        proposal.explanation = parsed["explanation"]
        return proposal


class MockFixClient:
    """确定性 Mock：STR31 给正确补丁；ARR30 给无效补丁；其余原样返回。"""

    def complete(self, system: str, user: str) -> str:
        rule = ""
        m = re.search(r"规则：(.+?)；", user)
        if m:
            rule = m.group(1).strip()
        fm = re.search(r"```c\n(.*?)\n```", user, re.S)
        func = fm.group(1) if fm else ""
        if rule == "CERT C STR31-C":
            patched = re.sub(
                r'strcpy\s*\(\s*(\w+)\s*,\s*("[^"]*")\s*\)',
                r'strncpy(\1, \2, sizeof(\1) - 1);\n    \1[sizeof(\1) - 1] = 0',
                func)
            return json.dumps({
                "patched_function": patched,
                "explanation": "将无界 strcpy 改为限长 strncpy 并补终止符"},
                ensure_ascii=False)
        if rule == "CERT C ARR30-C":
            return json.dumps({
                "patched_function": func,      # 无效补丁：原样返回
                "explanation": "调整访问顺序（Mock：无效补丁路径）"},
                ensure_ascii=False)
        return json.dumps({
            "patched_function": func,
            "explanation": "维持原实现（Mock：无变化路径）"},
            ensure_ascii=False)


class FixVerifier:
    """ToolLoopVerify：静态重扫 + 可选 gcc 语法检查。"""

    def __init__(self, project_root, use_compiler: bool = True):
        self.root = Path(project_root)
        self.use_compiler = use_compiler
        self._gcc = shutil.which("gcc") if use_compiler else None
        self._all_rules = set()          # 由 run 时注入
        self._include_dirs: list[Path] = []

    def _prepare(self, ctx: ProjectContext):
        from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
        self._all_rules = {r.rule_id for r in BUILTIN_RULES}
        dirs = {self.root, self.root / "include", self.root / "inc"}
        for f in ctx.facts:
            dirs.add(self.root / Path(f.path).parent)
        for d in list(dirs):
            if d.exists() and any(d.glob("*.h")):
                dirs.add(d)
        self._include_dirs = sorted(dirs)

    def verify(self, proposal: FixProposal, ctx: ProjectContext,
               source_text: str) -> FixProposal:
        self._prepare(ctx)
        if proposal.patched_code.strip() == proposal.original_code.strip():
            proposal.fail_reason = "补丁未改变函数，拒绝"
            return proposal

        rule_active = {proposal.rule_id} | self._all_rules
        baseline = _function_alerts(ctx, proposal.path, proposal.func_name,
                                    proposal.func_start, proposal.func_end,
                                    rule_active)

        modified = apply_patch(source_text, proposal.func_start,
                               proposal.func_end, proposal.patched_code)
        facts_new = [build_file_facts(proposal.path, modified)]
        ctx_new = finalize_facts(facts_new)
        new_alerts = _function_alerts(ctx_new, proposal.path, proposal.func_name,
                                      proposal.func_start,
                                      proposal.func_start +
                                      len(proposal.patched_code.splitlines()) - 1,
                                      rule_active)
        if proposal.rule_id in new_alerts:
            proposal.fail_reason = "原告警在补丁后仍存在，拒绝"
            return proposal
        new_errors = {r for r, sev in new_alerts.items()
                      if sev == "error" and baseline.get(r) != "error"}
        if new_errors:
            proposal.fail_reason = f"补丁引入新的 error 告警 {sorted(new_errors)}，拒绝"
            return proposal

        # gcc 语法检查（可用时）
        if self._gcc:
            ok, reason = self._compile_check(proposal.path, modified)
            if not ok:
                proposal.fail_reason = f"编译语法检查失败：{reason}"
                return proposal

        proposal.verified = True
        proposal.diff = "\n".join(difflib.unified_diff(
            source_text.splitlines(), modified.splitlines(),
            fromfile=f"a/{proposal.path}", tofile=f"b/{proposal.path}", lineterm=""))
        return proposal

    def _compile_check(self, rel_path: str, modified: str) -> tuple[bool, str]:
        original = self.root / rel_path
        tmp = original.with_suffix(".fixcheck.c")
        try:
            tmp.write_text(modified, encoding="utf-8")
            cmd = [self._gcc, "-fsyntax-only", "-std=gnu89", "-w"]
            cmd += [f"-I{d}" for d in self._include_dirs if d.exists()]
            cmd.append(str(tmp))
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                               encoding="utf-8", errors="replace")
            if r.returncode != 0:
                return False, (r.stderr or r.stdout)[-300:]
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"编译器调用异常：{e}"
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        return True, ""
