"""增量分析与告警基线管理（方案 3.3.6）。

影响集计算：修改文件 → 头文件包含闭包 → 调用图反向闭包 → 受影响文件集合；
告警基线：参照 CodeChecker 的存储/差分机制，新旧告警按指纹差分为
新增 / 已解决 / 持续三类，仅新增告警进入 L4 研判，使深度分析可以
嵌入每日集成而非一次性离线行为。

局限（MVP）：指纹含行号，告警因代码移动而漂移时计为"新增+已解决"
（CodeChecker 以上下文哈希缓解，留待阶段五）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts

# 匹配原始源码行中的本地包含（PPLine.text 的引号内容已被遮蔽，不可用）
INCLUDE_LOCAL_RE = re.compile(r'#\s*include\s*"([^"]+)"')


# ---------------------------------------------------------------------------
# 影响集
# ---------------------------------------------------------------------------


@dataclass
class ImpactSet:
    changed: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)      # 全闭包（含 changed）
    reason: dict[str, str] = field(default_factory=dict)   # 文件 → 纳入原因

    def as_json(self) -> dict:
        return {"changed": self.changed, "affected": self.affected,
                "reason": self.reason}


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def compute_impact_set(root: str | Path, changed: list[str]) -> ImpactSet:
    """方案 3.3.6 影响集：include 反向闭包 + 调用图反向闭包。

    changed 中的文件必须相对 root。返回受影响文件集合（相对路径，posix）。
    """
    root = Path(root)
    changed_norm = [_norm(c) for c in changed]
    changed_set = set(changed_norm)

    # 全工程事实（一次构建，供 include 图与调用图共用）
    paths: list[str] = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".c", ".h") and not any(
                s in p.parts for s in (".git", "build", "ecdet_build", ".venv")):
            paths.append(p.relative_to(root).as_posix())
    facts = [build_file_facts(rel, (root / rel).read_text(encoding="utf-8",
                                                          errors="replace"))
             for rel in paths]
    ctx = finalize_facts(facts)

    # 1) include 图：includer → {included}；解析 "local.h" 相对文件目录再相对 root
    # 注意：PPLine.text 是遮蔽后文本（引号内容已清空），必须读原始行
    include_edges: dict[str, set[str]] = {}
    for f in ctx.facts:
        edges = include_edges.setdefault(_norm(f.path), set())
        base_dir = _norm(str(Path(f.path).parent))
        for p in f.lex.pp_lines:
            if p.directive != "include":
                continue
            raw_line = (f.lex.source_lines[p.line - 1]
                        if p.line - 1 < len(f.lex.source_lines) else "")
            m = INCLUDE_LOCAL_RE.search(raw_line)
            if not m:
                continue
            target = _norm(m.group(1))
            for cand in (f"{base_dir}/{target}" if base_dir != "." else target,
                         target):
                if cand in set(paths):
                    edges.add(cand)
                    break

    # 反向 include 闭包（多轮扩散）
    affected = set(changed_set)
    reason = {c: "changed" for c in changed_norm}
    frontier = set(changed_set)
    while frontier:
        nxt: set[str] = set()
        for includer, included in include_edges.items():
            if includer in affected:
                continue
            if included & frontier:
                affected.add(includer)
                reason[includer] = f"包含受影响头文件（{sorted(included & frontier)[0]}）"
                nxt.add(includer)
        frontier = nxt

    # 2) 调用图反向闭包：文件 A 中函数调用受影响文件中定义的函数 → A 受影响
    func_home: dict[str, str] = {}
    for f in ctx.facts:
        for func in f.functions:
            func_home.setdefault(func.name, _norm(f.path))
    file_calls: dict[str, set[str]] = {}
    for f in ctx.facts:
        callees: set[str] = set()
        for func in f.functions:
            callees.update(name for name, _ in func.calls_in_body())
        file_calls[_norm(f.path)] = callees

    frontier = {a for a in affected if a.endswith(".c") or a.endswith(".h")}
    while frontier:
        nxt: set[str] = set()
        for caller, callees in file_calls.items():
            if caller in affected:
                continue
            hit_callees = {c for c in callees
                           if func_home.get(c) in frontier}
            if hit_callees:
                affected.add(caller)
                home = sorted({func_home[c] for c in hit_callees})[0]
                reason[caller] = f"调用受影响文件的函数（{home}）"
                nxt.add(caller)
        frontier = nxt

    return ImpactSet(changed=changed_norm, affected=sorted(affected),
                     reason=reason)


# ---------------------------------------------------------------------------
# 告警基线
# ---------------------------------------------------------------------------


def save_baseline(alerts: list[Alert], path: str | Path) -> Path:
    """保存当前告警指纹为基线（方案 3.3.6：CodeChecker 式存储）。"""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fingerprints": sorted({a.ensure_fingerprint() for a in alerts}),
        "count": len(alerts),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return out


def load_baseline_fingerprints(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


@dataclass
class BaselineDiff:
    """基线差分结果。已解决仅计数（基线只存指纹，不存告警详情）。"""

    new: list[Alert] = field(default_factory=list)
    persisting: list[Alert] = field(default_factory=list)
    resolved_count: int = 0

    @property
    def summary(self) -> str:
        return (f"新增 {len(self.new)} / 已解决 {self.resolved_count} / "
                f"持续 {len(self.persisting)}")


def diff_baseline(old_fps: set[str], alerts: list[Alert]) -> BaselineDiff:
    """基线差分：指纹在基线中为持续，不在为新增；旧指纹未命中即已解决。

    仅新增告警需要进入 L4 研判（方案 3.3.6）。
    """
    new: list[Alert] = []
    persisting: list[Alert] = []
    for a in alerts:
        (persisting if a.ensure_fingerprint() in old_fps else new).append(a)
    resolved = max(0, len(old_fps) - len(persisting))
    return BaselineDiff(new=new, persisting=persisting, resolved_count=resolved)
