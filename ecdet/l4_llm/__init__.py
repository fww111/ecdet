"""L4 LLM 增强层（方案 3.3.5，对应 P5）。

告警分诊管线：上下文裁剪 → LLM 首判（结构化 JSON）→ 低置信触发 RAG 重判
→ 证据行号程序化核对（未通过降级 NEEDS_REVIEW）→ 结论回写告警。

幻觉抑制三件套：
  1. 强制结构化 JSON 输出，解析失败一律 NEEDS_REVIEW；
  2. evidence_lines 必须落在告警函数行区间内且包含告警行本身，否则降级；
  3. 修复建议（阶段三后半）必须经编译+静态验证闭环后采纳。

部署：OpenAI 兼容接口（vLLM/Ollama/LM Studio），数据不出域；
分级调用由调用方配置（分诊用轻量模型、疑难用强模型）。
"""

from ecdet.l4_llm.triage import TriageRunner, TriageVerdict
from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient

__all__ = ["TriageRunner", "TriageVerdict", "MockLlmClient", "OpenAICompatClient"]
