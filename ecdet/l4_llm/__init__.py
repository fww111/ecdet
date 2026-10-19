"""L4 LLM 增强层 —— 阶段三（2027 Q2）实施，本阶段预留接口。

规划（方案 3.3.5）：
  - 上下文裁剪：告警函数 + 深度 2 调用闭包 + 类型/宏，按 token 预算截取；
  - A-RAG：置信度触发检索（MISRA/CERT 条款、CWE 描述、芯片手册、历史案例）；
  - 幻觉抑制：结构化 JSON 输出 + 证据行号程序化核对，未核对通过降级 SUSPECTED；
  - 验证闭环：修复建议经编译 + 静态 + CBMC 验证（方案 3.3.5）；
  - 本地部署：vLLM 承载开源权重，数据不出域。
"""

from __future__ import annotations

from dataclasses import dataclass

from ecdet.l2_ir.model import Alert


@dataclass
class TriageResult:
    """LLM 分诊结论（阶段三返回结构预留）。"""

    verdict: str                 # TRUE_POSITIVE / FALSE_POSITIVE / SUSPECTED
    confidence: float
    reason: str
    verified_lines: list[int]


class LlmTriage:
    """告警分诊接口。阶段一/二返回未研判状态，保持 L5 兼容。"""

    def available(self) -> bool:
        return False

    def triage(self, alert: Alert, context_budget: int = 4096) -> TriageResult:
        return TriageResult(
            verdict="SUSPECTED",
            confidence=0.0,
            reason="L4 LLM 层未启用（阶段三实施）",
            verified_lines=[],
        )
