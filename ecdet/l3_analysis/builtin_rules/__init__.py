"""自研内置规则引擎（词法/结构层）。"""

from ecdet.l3_analysis.builtin_rules.checks import (
    FileFacts,
    ProjectContext,
    build_file_facts,
    finalize_facts,
)
from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES, get_rule_meta

__all__ = [
    "BUILTIN_RULES",
    "FileFacts",
    "ProjectContext",
    "build_file_facts",
    "finalize_facts",
    "get_rule_meta",
]
