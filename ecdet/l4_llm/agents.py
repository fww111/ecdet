"""多智能体协同框架（方案 3.3.7，对应 P5、P7）。

六类智能体编成（表 3-2）：规划 / 静态研判 / 动态测试 / 运行时监控 /
修复 / 报告。每个智能体是"LLM 推理 + 专用工具集 + 确定性输出校验器"
的组合体；采纳边界：LLM 负责语义决策，工具负责事实与验证，
**LLM 不作最终裁决**——入报告的结论必须携带工具可复核的证据链。

协同协议要点（LangGraph 状态机的确定性 MVP 实现）：
  - 结构化交接：智能体间传递 AgentState（SARIF 引用 + 结构化字段），
    杜绝自由文本的口径漂移；
  - 三类控制流：主链路顺序流水；告警分诊并行扇出（失败可容忍）；
    高危误报判定转人工复核闸门；
  - 成本控制：告警分层路由（低危 note 不过 LLM）、单项目 LLM 预算熔断；
  - 降级回退：single_agent 模式（消融 A6 / Agentless 对照）退化为
    单 LLM 顺序流水线。
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ecdet.l2_ir.model import Alert, Provenance, RuleMeta
from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
from ecdet.l3_analysis.dynamic import DynamicEngine
from ecdet.l3_analysis.engine import AnalysisTarget, collect_sources, run_all_engines
from ecdet.l3_analysis.monitor import MonitorResult, RuntimeMonitor
from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient
from ecdet.l4_llm.fixer import FixProposer, FixVerifier, MockFixClient
from ecdet.l4_llm.triage import TriageRunner, TriageVerdict

# 告警分层路由：note 级不过 LLM（成本控制，方案 3.3.7）
_LLM_MIN_SEVERITY_SKIP = "note"


@dataclass
class AgentState:
    """结构化交接对象：智能体间传递的唯一载体。"""

    repo: Path
    svd_path: Path | None = None
    plan: dict = field(default_factory=dict)
    static_alerts: list[Alert] = field(default_factory=list)
    rule_metas: list[RuleMeta] = field(default_factory=list)
    triage_verdicts: list[TriageVerdict] = field(default_factory=list)
    dynamic_findings: list = field(default_factory=list)
    monitor_result: MonitorResult | None = None
    fixes: list = field(default_factory=list)
    review_queue: list[dict] = field(default_factory=list)   # 高危人工复核闸门
    report_path: Path | None = None
    logs: list[str] = field(default_factory=list)
    llm_calls: int = 0
    seconds: float = 0.0

    def log(self, agent: str, msg: str) -> None:
        self.logs.append(f"[{agent}] {msg}")


@dataclass
class OrchestratorConfig:
    """编排配置（对应消融 A1/A5/A6 的开关面）。"""

    mock: bool = True                    # Mock LLM（离线演示）或真实端点
    llm_url: str | None = None
    llm_model: str | None = None
    use_llm: bool = True                 # A1 关
    use_dynamic: bool = True             # A5 关
    single_agent: bool = False           # A6 开（单智能体串行）
    auto_accept: bool = True             # 人工复核闸门：高危误报判定自动接受与否
    max_fix_targets: int = 5
    triage_workers: int = 4


class _Planner:
    """规划智能体：任务分解 / 引擎路由 / 预算。路由规则确定性优先，
    规划不改写技术结论（表 3-2 约束）。"""

    @staticmethod
    def decompose(state: AgentState, cfg: OrchestratorConfig) -> dict:
        files = collect_sources(state.repo)
        return {
            "files": [f.as_posix() for f in files],
            "channels": {
                "static": True,
                "triage_llm": cfg.use_llm,
                "dynamic": cfg.use_dynamic,
                "monitor": cfg.use_dynamic,       # 监控依赖动态会话
            },
            "budget": {"max_fix_targets": cfg.max_fix_targets,
                       "triage_workers": 1 if cfg.single_agent
                       else cfg.triage_workers},
        }


class Orchestrator:
    """Orchestrate 主流程（方案 3.3.7 伪代码的确定性实现）。"""

    def __init__(self, cfg: OrchestratorConfig | None = None):
        self.cfg = cfg or OrchestratorConfig()

    def orchestrate(self, repo: str | Path,
                    svd_path: Path | None = None) -> AgentState:
        cfg = self.cfg
        state = AgentState(repo=Path(repo).resolve(), svd_path=svd_path)
        t0 = time.perf_counter()

        # 1) 规划智能体
        state.plan = _Planner.decompose(state, cfg)
        state.log("planner", f"任务分解：{len(state.plan['files'])} 文件，"
                             f"通道 {state.plan['channels']}")

        # 2) 静态通道（3.3.3/3.3.4）
        target = AnalysisTarget(root=state.repo,
                                files=[Path(p) for p in state.plan["files"]],
                                svd_path=state.svd_path)
        state.static_alerts, state.rule_metas = run_all_engines(target)
        state.log("static", f"静态通道产出 {len(state.static_alerts)} 条告警")

        # 3) 分诊扇出（3.3.8 静态研判智能体）
        if cfg.use_llm and state.static_alerts:
            client = MockLlmClient() if cfg.mock else OpenAICompatClient(
                base_url=cfg.llm_url, model=cfg.llm_model)
            triage = TriageRunner(client=client)
            ctx = self._build_ctx(state.repo, state.plan["files"])
            eligible = [a for a in state.static_alerts
                        if a.severity.value != _LLM_MIN_SEVERITY_SKIP]
            workers = state.plan["budget"]["triage_workers"]
            if workers > 1 and len(eligible) > 1:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    verdicts = list(pool.map(lambda a: triage.triage(a, ctx),
                                             eligible))
            else:
                verdicts = [triage.triage(a, ctx) for a in eligible]
            for a, v in zip(eligible, verdicts):
                a.triage = v.to_alert_props()      # 结论回写告警（与 triage_alerts 一致）
            state.triage_verdicts = verdicts
            state.llm_calls += sum(v.llm_calls for v in verdicts)
            state.log("static-triage",
                      f"分诊扇出：研判 {len(eligible)} 条（note 级 "
                      f"{len(state.static_alerts) - len(eligible)} 条分层路由跳过），"
                      f"LLM 调用 {state.llm_calls} 次")

        # 4) 动态通道（3.3.5 动态测试智能体）
        if cfg.use_dynamic:
            facts = [build_file_facts(p, (state.repo / p).read_text(
                encoding="utf-8", errors="replace"))
                for p in state.plan["files"] if p.endswith(".c")]
            engine = DynamicEngine()
            if engine.available:
                state.dynamic_findings = engine.run(state.repo, facts)
                for f_ in state.dynamic_findings:
                    state.static_alerts.append(f_.to_alert())
                state.log("dynamic", f"动态通道：{len(state.dynamic_findings)} 个真触发"
                                     f"（PoC 已入 SARIF 池）")
            else:
                state.log("dynamic", "动态载体不可用（无 gcc），跳过")

        # 5) 运行时监控（3.3.6 监控智能体）：Suspected 裁决
        if cfg.use_dynamic:
            facts = [build_file_facts(p, (state.repo / p).read_text(
                encoding="utf-8", errors="replace"))
                for p in state.plan["files"] if p.endswith(".c")]
            monitor = RuntimeMonitor()
            state.monitor_result = monitor.run(
                state.repo, facts,
                [a for a in state.static_alerts
                 if a.provenance == Provenance.SUSPECTED])
            if state.monitor_result.upgraded:
                state.log("monitor",
                          f"运行时裁决：{len(state.monitor_result.upgraded)} 条 "
                          f"Suspected → Detected（PoC 回填）")
            elif state.monitor_result.skipped_reason:
                state.log("monitor", f"监控跳过：{state.monitor_result.skipped_reason}")

        # 6) 修复智能体（3.3.8）：真缺陷 → 补丁 → 工具验证闭环
        confirmed = [a for a in state.static_alerts
                     if (a.triage or {}).get("verdict") == "TRUE_POSITIVE"]
        if cfg.use_llm and confirmed:
            fix_client = MockFixClient() if cfg.mock else OpenAICompatClient(
                base_url=cfg.llm_url, model=cfg.llm_model)
            proposer = FixProposer(fix_client)
            verifier = FixVerifier(state.repo)
            facts = [build_file_facts(p, (state.repo / p).read_text(
                encoding="utf-8", errors="replace"))
                for p in state.plan["files"]]
            ctx = finalize_facts(facts)
            sources = {p: (state.repo / p).read_text(encoding="utf-8",
                                                     errors="replace")
                       for p in state.plan["files"]}
            for a in confirmed[:cfg.max_fix_targets]:
                proposal = proposer.propose(a, ctx)
                src = sources.get(a.location.path.replace("\\", "/"))
                if not proposal.fail_reason and src is not None:
                    proposal = verifier.verify(proposal, ctx, src)
                state.fixes.append(proposal)
            accepted = sum(1 for p_ in state.fixes if p_.verified)
            state.llm_calls += len(state.fixes)
            state.log("repair", f"修复建议 {len(state.fixes)} 条："
                                f"验证闭环采纳 {accepted} / 拒绝 {len(state.fixes) - accepted}")

        # 7) 高危人工复核闸门：LLM 判误报的 error 级告警
        for a in state.static_alerts:
            if a.severity.value != "error":
                continue
            verdict = (a.triage or {}).get("verdict")
            if verdict == "FALSE_POSITIVE":
                item = {"rule_id": a.rule_id, "path": a.location.path,
                        "line": a.location.line,
                        "llm_reason": (a.triage or {}).get("reason", ""),
                        "auto_accepted": cfg.auto_accept}
                state.review_queue.append(item)
        if state.review_queue:
            state.log("gate", f"人工复核闸门：{len(state.review_queue)} 条高危误报判定"
                              f"{'（自动接受，记录留痕）' if cfg.auto_accept else '（挂起待人工）'}")

        state.seconds = time.perf_counter() - t0
        state.log("reporter", f"汇聚完成：告警 {len(state.static_alerts)}，"
                              f"动态 {len(state.dynamic_findings)}，"
                              f"复核 {len(state.review_queue)}，"
                              f"耗时 {state.seconds:.1f}s")
        return state

    @staticmethod
    def _build_ctx(repo: Path, files: list[str]):
        facts = [build_file_facts(p, (repo / p).read_text(encoding="utf-8",
                                                          errors="replace"))
                 for p in files]
        return finalize_facts(facts)
