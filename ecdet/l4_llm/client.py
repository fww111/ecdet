"""LLM 客户端 —— OpenAI 兼容接口 + 确定性 Mock（零第三方依赖）。

OpenAICompatClient 对接 vLLM / Ollama / LM Studio 等本地部署
（`POST {base_url}/chat/completions`），满足行业数据不出域要求。
MockLlmClient 供离线测试与演示：按规则给出确定性判定，并刻意构造
"引用错行"用例驱动证据核对降级路径。
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol


class LlmClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatClient:
    """OpenAI Chat Completions 兼容客户端。"""

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: int = 120):
        self.base_url = (base_url or os.environ.get("ECODET_LLM_BASE_URL",
                                                    "http://127.0.0.1:8000/v1")).rstrip("/")
        self.model = model or os.environ.get("ECODET_LLM_MODEL", "local-model")
        self.api_key = api_key or os.environ.get("ECODET_LLM_API_KEY", "EMPTY")
        self.timeout = timeout

    def complete(self, system: str, user: str) -> str:
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.1,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            raise LlmTransportError(f"LLM 端点不可达或响应异常：{e}") from e
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise LlmTransportError(f"LLM 响应结构异常：{e}") from e


class LlmTransportError(RuntimeError):
    pass


# 确定性真判规则（Mock）：这些规则告警本身即确定性证据，Mock 与引擎结论一致
_MOCK_TP = {"CERT C STR31-C", "CERT C ARR30-C", "ECDET-CWE-242", "ECDET-CWE-197",
            "ECDET-CWE-1284", "ECDET-MMIO-ACCESS", "ECDET-ISR-BLOCK",
            "ECDET-ISR-RACE", "MISRA C:2012 17.2"}
_MOCK_FP = {"MISRA C:2012 8.7", "MISRA C:2012 8.9", "MISRA C:2012 2.5",
            "MISRA C:2012 15.5", "MISRA C:2012 21.6"}


class MockLlmClient:
    """确定性 Mock：覆盖真判/误报/低置信 RAG/引用错行四条路径。"""

    def __init__(self):
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        rule_id = _extract_field(user, "规则：")
        line = _extract_line(user)
        if rule_id in _MOCK_TP:
            return json.dumps({
                "verdict": "TRUE_POSITIVE", "confidence": 0.9,
                "reason": "证据确凿：缺陷模式与代码上下文吻合（Mock 确定性判定）",
                "evidence_lines": [line],
            }, ensure_ascii=False)
        if rule_id == "CERT C FIO30-C":
            # 故意引用函数外行号 → 证据核对不通过 → 降级
            return json.dumps({
                "verdict": "TRUE_POSITIVE", "confidence": 0.85,
                "reason": "格式串为外部可控变量（Mock：引用了错误行以驱动降级路径）",
                "evidence_lines": [line + 5000],
            }, ensure_ascii=False)
        if rule_id in _MOCK_FP:
            return json.dumps({
                "verdict": "FALSE_POSITIVE", "confidence": 0.9,
                "reason": "规范建议类告警，结合上下文不构成实际缺陷（Mock 确定性判定）",
                "evidence_lines": [line],
            }, ensure_ascii=False)
        # 低置信 → 触发 RAG 重判
        if "知识参考" in user and "（无）" not in user.split("知识参考")[1][:50]:
            return json.dumps({
                "verdict": "NEEDS_REVIEW", "confidence": 0.55,
                "reason": "携带领域知识重判后仍不能确证（Mock：RAG 路径）",
                "evidence_lines": [line],
            }, ensure_ascii=False)
        return json.dumps({
            "verdict": "NEEDS_REVIEW", "confidence": 0.35,
            "reason": "证据不足，需要领域知识辅助判断（Mock：低置信路径）",
            "evidence_lines": [line],
        }, ensure_ascii=False)


def _extract_field(user: str, prefix: str) -> str:
    try:
        seg = user.split(prefix, 1)[1]
        return seg.split("（")[0].split("\n")[0].strip()
    except IndexError:
        return ""


def _extract_line(user: str) -> int:
    import re
    m = re.search(r"位置：\S+:(\d+)", user)
    return int(m.group(1)) if m else 1
