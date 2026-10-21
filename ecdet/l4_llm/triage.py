"""告警分诊 Runner —— L4 管线编排（方案 3.3.5）。

procedure LlmTriage(alert):
    ctx  = SliceContext(alert, depth=2, budget)     # 上下文裁剪
    p1   = LlmJudge(alert, ctx)                      # 首判：结构化 JSON
    if p1.confidence < THRESH:                       # 置信度触发检索（A-RAG）
        kb = Retrieve('MISRA|CWE|手册', alert.rule)
        p1 = LlmJudge(alert, ctx + kb)               # 携带知识重判
    if not VerifyLines(p1.evidence, ctx):            # 证据回链：行号核对
        p1.verdict = NEEDS_REVIEW                    # 未通过核对即降级
    return p1
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from ecdet.l2_ir.model import Alert
from ecdet.l3_analysis.builtin_rules.checks import ProjectContext, build_file_facts, finalize_facts
from ecdet.l4_llm.client import LlmClient, LlmTransportError, MockLlmClient
from ecdet.l4_llm.kb import KnowledgeBase, build_kb
from ecdet.l4_llm.slicer import ContextSlice, slice_context
from ecdet.l4_llm.verifier import verify_cited_lines

SYSTEM_PROMPT = (
    "你是嵌入式 C/C++ 代码安全告警研判专家。基于给出的代码上下文与规则知识，"
    "判断告警是否为真实缺陷。只输出一个 JSON 对象，字段："
    '{"verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW", '
    '"confidence": 0到1的小数, "reason": "中文理由", '
    '"evidence_lines": [你引用的源码行号，必须包含告警行，且都在函数区间内]}。'
    "不要输出 JSON 以外的任何内容。"
)

VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"}


@dataclass
class TriageVerdict:
    """单条告警的 LLM 分诊结论。"""

    rule_id: str
    path: str
    line: int
    verdict: str                       # TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
    confidence: float
    reason: str
    cited_lines: list[int] = field(default_factory=list)
    verified: bool = False             # 证据行号核对结果
    used_rag: bool = False
    llm_calls: int = 0

    def to_alert_props(self) -> dict:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "cited_lines": self.cited_lines,
            "verified": self.verified,
            "used_rag": self.used_rag,
        }


def parse_verdict_json(raw: str) -> dict | None:
    """从 LLM 输出中解析判定 JSON；解析失败返回 None（调用方按 NEEDS_REVIEW 处理）。"""
    if not raw:
        return None
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    verdict = str(data.get("verdict", "")).upper()
    if verdict not in VERDICTS:
        return None
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        return None
    lines = data.get("evidence_lines") or []
    if not isinstance(lines, list):
        lines = []
    return {
        "verdict": verdict,
        "confidence": min(max(conf, 0.0), 1.0),
        "reason": str(data.get("reason", ""))[:500],
        "evidence_lines": [int(x) for x in lines if isinstance(x, (int, float))],
    }


def _build_user_prompt(alert: Alert, slice_: ContextSlice,
                       kb_text: str, with_kb: bool) -> str:
    parts = [
        "## 告警",
        f"规则：{alert.rule_id}",
        f"严重级：{alert.severity.value}；位置：{alert.location.path}:{alert.location.line}",
        f"告警说明：{alert.message}",
        f"CWE：{alert.cwe or '未标注'}",
        "",
        "## 知识参考",
        (kb_text if (with_kb and kb_text) else "（无）"),
        "",
        "## 代码上下文",
        slice_.render() or "（上下文不可用）",
        "",
        "## 任务",
        "判断该告警是否为真实缺陷，并按系统指令输出 JSON。",
    ]
    return "\n".join(parts)


class TriageRunner:
    """分诊执行器。client 传 MockLlmClient 即为离线模式。"""

    def __init__(self, client: LlmClient | None = None,
                 kb: KnowledgeBase | None = None,
                 budget_chars: int = 8000,
                 rag_conf_threshold: float = 0.6):
        self.client = client or MockLlmClient()
        self.kb = kb or build_kb()
        self.budget_chars = budget_chars
        self.rag_conf_threshold = rag_conf_threshold

    def triage(self, alert: Alert, ctx: ProjectContext) -> TriageVerdict:
        slice_ = slice_context(alert, ctx, self.budget_chars)
        kb_text = self.kb.lookup(alert.rule_id, alert.cwe)

        v = self._judge(alert, slice_, kb_text, with_kb=False)
        # A-RAG：低置信触发知识检索后重判
        if v.confidence < self.rag_conf_threshold:
            v2 = self._judge(alert, slice_, kb_text, with_kb=True)
            v2.used_rag = True
            v2.llm_calls = v.llm_calls + 1
            v = v2
        # 证据行号核对（幻觉抑制）：函数内告警按函数区间，全局告警按文件范围
        lex = self._lex_of(ctx, alert.location.path)
        if lex is not None:
            verified, ok_lines = verify_cited_lines(
                v.cited_lines, lex, slice_.func_start, slice_.func_end,
                alert.location.line, has_function=bool(slice_.func_name))
        else:
            verified, ok_lines = False, []
        v.cited_lines = ok_lines or v.cited_lines
        v.verified = verified
        if not verified and v.verdict == "TRUE_POSITIVE":
            v.verdict = "NEEDS_REVIEW"
            v.reason += "；证据行号核对未通过，已降级待复核"
        return v

    def _judge(self, alert: Alert, slice_: ContextSlice, kb_text: str,
               with_kb: bool) -> TriageVerdict:
        user = _build_user_prompt(alert, slice_, kb_text, with_kb)
        calls = 1
        try:
            raw = self.client.complete(SYSTEM_PROMPT, user)
        except LlmTransportError as e:
            return TriageVerdict(
                rule_id=alert.rule_id, path=alert.location.path,
                line=alert.location.line, verdict="NEEDS_REVIEW",
                confidence=0.0, reason=f"LLM 调用失败：{e}", llm_calls=calls)
        parsed = parse_verdict_json(raw)
        if parsed is None:
            return TriageVerdict(
                rule_id=alert.rule_id, path=alert.location.path,
                line=alert.location.line, verdict="NEEDS_REVIEW",
                confidence=0.0, reason="LLM 输出不可解析（非结构化 JSON），按幻觉处理",
                llm_calls=calls)
        return TriageVerdict(
            rule_id=alert.rule_id, path=alert.location.path,
            line=alert.location.line, verdict=parsed["verdict"],
            confidence=parsed["confidence"], reason=parsed["reason"],
            cited_lines=parsed["evidence_lines"], llm_calls=calls)

    @staticmethod
    def _lex_of(ctx: ProjectContext, path: str):
        norm = path.replace("\\", "/")
        for f in ctx.facts:
            if f.path.replace("\\", "/") == norm:
                return f.lex
        return None


def triage_alerts(alerts: list[Alert], project_root,
                  client: LlmClient | None = None,
                  budget_chars: int = 8000) -> tuple[list[TriageVerdict], int]:
    """对告警列表执行分诊并回写 alert.triage。返回 (结论列表, LLM 调用次数)。

    project_root：告警相对路径的根目录。上下文文件缺失的告警直接
    NEEDS_REVIEW（不调用 LLM）。
    """
    from pathlib import Path

    root = Path(project_root)
    need_paths = sorted({a.location.path.replace("\\", "/") for a in alerts})
    facts = []
    for rel in need_paths:
        p = root / rel
        if p.exists():
            facts.append(build_file_facts(rel, p.read_text(encoding="utf-8",
                                                            errors="replace")))
    ctx = finalize_facts(facts)
    ctx_index = {f.path.replace("\\", "/") for f in ctx.facts}

    runner = TriageRunner(client=client, budget_chars=budget_chars)
    verdicts: list[TriageVerdict] = []
    for a in alerts:
        if a.location.path.replace("\\", "/") not in ctx_index:
            verdicts.append(TriageVerdict(
                rule_id=a.rule_id, path=a.location.path, line=a.location.line,
                verdict="NEEDS_REVIEW", confidence=0.0,
                reason="上下文文件不可用，无法研判"))
            continue
        v = runner.triage(a, ctx)
        a.triage = v.to_alert_props()
        verdicts.append(v)
    total_calls = sum(v.llm_calls for v in verdicts)
    return verdicts, total_calls
