"""LLM harness 修正器（方案 3.3.5 之 harness 生成-验证闭环的 LLM 环节）。

确定性打桩修正失败后（编译错误超出未解析符号范畴，如类型不匹配、
缺失头文件），动态测试智能体将 harness 源码与编译日志交 LLM 重写，
产物必须重新通过编译验证——"生成→编译→失败→LLM 修正→再编译"
闭环，未通过验证的修正不投入 fuzzing。
"""

from __future__ import annotations

import json
import re
from typing import Protocol

FIX_SYSTEM_PROMPT = (
    "你是嵌入式 C 编译错误修复专家。修复给定的 fuzzing harness 源码，"
    "使其通过编译。只允许最小修改：调整类型、补 include、修正API用法；"
    '不得删除激励调用。只输出一个 JSON 对象：'
    '{"patched_harness": "修复后的完整源码", "changes": "中文修改说明"}。'
)


class HarnessFixer(Protocol):
    def fix(self, source: str, error_log: str) -> tuple[str, str] | None:
        """返回 (修复后源码, 说明)；无法修复返回 None。"""
        ...


def extract_patched_harness(raw: str) -> tuple[str, str] | None:
    """从 LLM 输出解析 {"patched_harness": ..., "changes": ...}。"""
    if not raw:
        return None
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    patched = data.get("patched_harness")
    if not isinstance(patched, str) or not patched.strip():
        return None
    fence = re.match(r"\s*```[cC]?\n(.*?)\n?```\s*$", patched, re.S)
    if fence:
        patched = fence.group(1)
    return patched, str(data.get("changes", ""))[:300]


class LlmHarnessFixer:
    """基于 OpenAI 兼容客户端的 harness 修正器。"""

    def __init__(self, client):
        self.client = client
        self.calls = 0

    def fix(self, source: str, error_log: str) -> tuple[str, str] | None:
        user = "\n".join([
            "## 待修复的 harness 源码",
            "```c",
            source,
            "```",
            "",
            "## 编译错误日志（节选）",
            "```",
            error_log[-1500:],
            "```",
            "",
            "输出修复后的完整源码（JSON）。",
        ])
        self.calls += 1
        raw = self.client.complete(FIX_SYSTEM_PROMPT, user)
        return extract_patched_harness(raw)
