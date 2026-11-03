"""Bounded LLM triage with strict responses and symmetric evidence gates."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext, build_file_facts, finalize_facts
from ecdet.l4_llm.client import LlmClient, MockLlmClient
from ecdet.l4_llm.kb import KnowledgeBase, build_kb
from ecdet.l4_llm.slicer import ContextSlice, slice_context
from ecdet.l4_llm.verifier import verify_cited_lines

SYSTEM_PROMPT = (
    "你是嵌入式C/C++代码安全告警研判助手。基于给出的代码上下文与规则知识，"
    "提出告警研判建议。只输出一个JSON对象，字段："
    '{"verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW", '
    '"confidence": 0到1的小数, "reason": "中文理由", '
    '"evidence_lines": [你引用的源码行号，必须包含告警行，且都在提供的代码区间内]}。'
    "引用有效不代表缺陷语义已经工具验证。不要输出JSON以外的任何内容。"
)
VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}


@dataclass
class TriageVerdict:
    rule_id: str
    path: str
    line: int
    verdict: str
    confidence: float
    reason: str
    cited_lines: list[int] = field(default_factory=list)
    verified: bool = False  # Legacy field: citation validation only.
    used_rag: bool = False
    llm_calls: int = 0
    attempts: list[dict] = field(default_factory=list)
    context: dict = field(default_factory=dict)
    client_mode: str = "fake"
    model: str = ""
    evidence_status: str = "FAIL"
    semantic_status: str = "UNVERIFIED"
    suggested_verdict: str = "NEEDS_REVIEW"
    review_pending: bool = False

    def to_alert_props(self) -> dict:
        return {
            "verdict": self.verdict, "confidence": round(self.confidence, 3),
            "reason": self.reason, "cited_lines": self.cited_lines,
            "verified": self.verified, "used_rag": self.used_rag,
            "attempts": self.attempts, "context": self.context,
            "client_mode": self.client_mode, "model": self.model,
            "evidence_status": self.evidence_status, "semantic_status": self.semantic_status,
            "suggested_verdict": self.suggested_verdict, "review_pending": self.review_pending,
        }


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def parse_verdict_json(raw: str) -> dict | None:
    """Reject malformed fields rather than coerce model output into evidence."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        data = json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_reject_constant)
    except (ValueError, TypeError):
        return None
    required = {"verdict", "confidence", "reason", "evidence_lines"}
    if not isinstance(data, dict) or not required <= data.keys():
        return None
    verdict, conf = data["verdict"], data["confidence"]
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        return None
    if type(conf) not in (int, float) or not 0 <= conf <= 1 or not math.isfinite(conf):
        return None
    reason, lines = data["reason"], data["evidence_lines"]
    if not isinstance(reason, str) or not reason.strip():
        return None
    if not isinstance(lines, list) or any(type(line) is not int or line <= 0 for line in lines):
        return None
    return {"verdict": verdict, "confidence": float(conf), "reason": reason,
            "evidence_lines": lines}


def apply_review_policy(alert: Alert, verdict: TriageVerdict,
                        auto_accept: bool = False) -> TriageVerdict:
    """Keep high-severity model FP pending unless explicitly accepted."""
    if verdict.verdict == "FALSE_POSITIVE" and alert.severity.value == "error":
        verdict.suggested_verdict = "FALSE_POSITIVE"
        verdict.review_pending = not auto_accept
        if not auto_accept:
            verdict.verdict = "NEEDS_REVIEW"
            verdict.reason += "；高危误报建议待人工复核"
    return verdict


def _build_user_prompt(alert: Alert, slice_: ContextSlice, kb_text: str, with_kb: bool) -> str:
    return "\n".join([
        "## 告警", f"规则：{alert.rule_id}",
        f"严重级：{alert.severity.value}；位置：{alert.location.path}:{alert.location.line}",
        f"告警说明：{alert.message}", f"CWE：{alert.cwe or '未标注'}", "",
        "## 知识参考", kb_text if with_kb and kb_text else "（无）", "",
        "## 代码上下文", slice_.render() or "（上下文不可用）", "",
        "## 任务", "提出该告警的研判建议，并按系统指令输出JSON。",
    ])


class TriageRunner:
    def __init__(self, client: LlmClient | None = None, kb: KnowledgeBase | None = None,
                 budget_chars: int = 8000, rag_conf_threshold: float = 0.6,
                 min_accept_confidence: float = 0.6, auto_accept: bool = False):
        for threshold in (rag_conf_threshold, min_accept_confidence):
            if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError("confidence thresholds must be finite numbers in [0, 1]")
        self.client = client or MockLlmClient()
        self.kb = kb or build_kb()
        self.budget_chars = budget_chars
        self.rag_conf_threshold = rag_conf_threshold
        self.min_accept_confidence = min_accept_confidence
        self.auto_accept = auto_accept

    def triage(self, alert: Alert, ctx: ProjectContext) -> TriageVerdict:
        slice_ = slice_context(alert, ctx, self.budget_chars)
        lex = self._lex_of(ctx, alert.location.path)
        context = {"loaded_files": [f.path for f in ctx.facts],
                   "provided_ranges": slice_.provided_ranges,
                   "unresolved_calls": slice_.unresolved_calls, "truncated": slice_.truncated,
                   "syntax_backends": slice_.syntax_backends}
        if lex is None or not 1 <= alert.location.line <= lex.n_lines:
            return TriageVerdict(alert.rule_id, alert.location.path, alert.location.line,
                                 "NEEDS_REVIEW", 0.0, "上下文文件或告警位置不可用，无法研判",
                                 context=context, client_mode=getattr(self.client, "mode", "fake"),
                                 model=getattr(self.client, "model", ""))
        kb_text = self.kb.lookup(alert.rule_id, alert.cwe)
        verdict = self._judge(alert, slice_, kb_text, with_kb=False)
        if verdict.confidence < self.rag_conf_threshold:
            second = self._judge(alert, slice_, kb_text, with_kb=True)
            second.used_rag = True
            second.llm_calls += verdict.llm_calls
            second.attempts = verdict.attempts + second.attempts
            verdict = second
        verified, _ = verify_cited_lines(verdict.cited_lines, lex, slice_.func_start,
                                         slice_.func_end, alert.location.line,
                                         has_function=bool(slice_.func_name))
        # A valid line absent from the actual supplied excerpt is not evidence.
        if verified:
            norm = alert.location.path.replace("\\", "/")
            verified = all(any(r["path"] == norm and r["start_line"] <= line <= r["end_line"]
                               for r in slice_.provided_ranges) for line in verdict.cited_lines)
        verdict.verified = verified
        verdict.evidence_status = "PASS" if verified else "FAIL"
        verdict.context = context
        if not verified and verdict.verdict in {"TRUE_POSITIVE", "FALSE_POSITIVE"}:
            verdict.verdict = "NEEDS_REVIEW"
            verdict.reason += "；证据行号核对未通过，已降级待复核"
        if verdict.confidence < self.min_accept_confidence and verdict.verdict != "NEEDS_REVIEW":
            verdict.verdict = "NEEDS_REVIEW"
            verdict.reason += "；最终置信度不足，待复核"
        return apply_review_policy(alert, verdict, self.auto_accept)

    def _judge(self, alert: Alert, slice_: ContextSlice, kb_text: str, with_kb: bool) -> TriageVerdict:
        user = _build_user_prompt(alert, slice_, kb_text, with_kb)
        common = dict(rule_id=alert.rule_id, path=alert.location.path, line=alert.location.line,
                      llm_calls=1, client_mode=getattr(self.client, "mode", "fake"),
                      model=getattr(self.client, "model", ""))
        try:
            raw = self.client.complete(SYSTEM_PROMPT, user)
        except Exception as exc:
            # The external client boundary isolates one failure from the batch.
            return TriageVerdict(**common, verdict="NEEDS_REVIEW", confidence=0.0,
                                 reason=f"LLM调用失败：{type(exc).__name__}",
                                 attempts=[{"status": "ERROR", "with_kb": with_kb,
                                            "error_type": type(exc).__name__}])
        parsed = parse_verdict_json(raw)
        if parsed is None:
            return TriageVerdict(**common, verdict="NEEDS_REVIEW", confidence=0.0,
                                 reason="LLM输出不可解析或字段不合格，待复核",
                                 attempts=[{"status": "ERROR", "with_kb": with_kb,
                                            "error_type": "InvalidResponse"}])
        return TriageVerdict(**common, verdict=parsed["verdict"], confidence=parsed["confidence"],
                             reason=parsed["reason"], cited_lines=parsed["evidence_lines"],
                             suggested_verdict=parsed["verdict"],
                             attempts=[{"status": "PASS", "with_kb": with_kb,
                                        "verdict": parsed["verdict"], "confidence": parsed["confidence"]}])

    @staticmethod
    def _lex_of(ctx: ProjectContext, path: str):
        norm = path.replace("\\", "/")
        return next((f.lex for f in ctx.facts if f.path.replace("\\", "/") == norm), None)


def load_project_context(project_root) -> ProjectContext:
    """Shared source-loading policy for CLI, Web and orchestrated triage."""
    from pathlib import Path
    from ecdet.l3_analysis.engine import collect_sources
    root = Path(project_root)
    facts = []
    for rel in collect_sources(root):
        try:
            facts.append(build_file_facts(rel.as_posix(), (root / rel).read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return finalize_facts(facts)


def triage_alerts(alerts: list[Alert], project_root, client: LlmClient | None = None,
                  budget_chars: int = 8000, rag_conf_threshold: float | None = None,
                  min_accept_confidence: float = 0.6, auto_accept: bool = False) -> tuple[list[TriageVerdict], int]:
    """Triage all alerts and always replace their previous model state."""
    context = load_project_context(project_root)
    kwargs = {"budget_chars": budget_chars, "min_accept_confidence": min_accept_confidence,
              "auto_accept": auto_accept}
    if rag_conf_threshold is not None:
        kwargs["rag_conf_threshold"] = rag_conf_threshold
    runner = TriageRunner(client=client, **kwargs)
    verdicts = []
    for alert in alerts:
        verdict = runner.triage(alert, context)
        alert.triage = verdict.to_alert_props()
        verdicts.append(verdict)
    return verdicts, sum(v.llm_calls for v in verdicts)
