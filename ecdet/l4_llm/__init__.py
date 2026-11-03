"""L4 LLM 增强层（方案 3.3.5，对应 P5）。

告警分诊管线：上下文裁剪 → LLM 首判（结构化 JSON）→ 低置信触发 RAG 重判
→ 证据行号程序化核对（未通过降级 NEEDS_REVIEW）→ 结论回写告警。

模型响应、引用和最终采纳分别校验，失败限定在当前任务并记录历史。
修复建议按原内置引擎与硬件上下文重放，缺失检查不能算通过。
引用有效不证明缺陷语义；静态与编译通过不证明业务行为等价。

OpenAI兼容客户端可连接本地或远程地址，实际数据范围取决于部署配置。
"""

from ecdet.l4_llm.triage import TriageRunner, TriageVerdict
from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient

__all__ = ["TriageRunner", "TriageVerdict", "MockLlmClient", "OpenAICompatClient"]
