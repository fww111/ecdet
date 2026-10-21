"""本地知识库与检索（A-RAG 的知识源，方案 3.3.5）。

知识三元组：规则条款（MISRA/CERT/ECDET 元数据）、CWE 描述、GJB 8114 主题。
检索按 rule_id 与 CWE 双键匹配。规模随规则库增长；接入芯片手册片段与
历史缺陷案例后即可支撑方案所述完整 RAG 语义。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
from ecdet.l5_report.aggregator import _load_gjb_map


@dataclass
class KnowledgeBase:
    entries: dict[str, str] = field(default_factory=dict)

    def lookup(self, rule_id: str, cwe: str | None = None) -> str:
        parts = [self.entries.get(rule_id, "")]
        if cwe:
            for rid, text in self.entries.items():
                if cwe in text and rid != rule_id:
                    parts.append(text)
                    break
        return "\n".join(p for p in parts if p).strip()


def build_kb() -> KnowledgeBase:
    kb = KnowledgeBase()
    gjb = _load_gjb_map()
    for meta in BUILTIN_RULES:
        lines = [f"{meta.rule_id}（{meta.category}）：{meta.title_zh}。"]
        if meta.cwes:
            lines.append(f"关联漏洞类型：{'、'.join(meta.cwes)}。")
        gjb_topic = gjb.get(meta.rule_id)
        if gjb_topic:
            lines.append(f"GJB 8114 对应主题：{gjb_topic}。")
        kb.entries[meta.rule_id] = " ".join(lines)
    return kb
