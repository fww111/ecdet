"""L5 结果聚合与可证明性输出层。"""

from ecdet.l5_report.aggregator import (
    AggregationResult,
    aggregate,
    build_compliance_records,
)
from ecdet.l5_report.html_report import render_html_report

__all__ = [
    "AggregationResult",
    "aggregate",
    "build_compliance_records",
    "render_html_report",
]
