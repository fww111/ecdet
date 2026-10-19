"""L2 统一 IR / 程序表示层：告警数据模型与 SARIF 交换格式。"""

from ecdet.l2_ir.model import Alert, Evidence, Location, Provenance, RuleMeta, Severity
from ecdet.l2_ir.sarif import load_sarif, save_sarif

__all__ = [
    "Alert",
    "Evidence",
    "Location",
    "Provenance",
    "RuleMeta",
    "Severity",
    "save_sarif",
    "load_sarif",
]
