"""ecdet 命令行入口 —— 五层流水线的调度外壳。

命令：
  ecdet scan <path>        全流程：L1 构建复现 → L3 多引擎扫描 → L5 聚合输出
  ecdet init-ccdb <path>   仅执行 L1 构建复现（产出 compile_commands.json）
  ecdet rules              列出内置规则集
  ecdet report <sarif>     从 SARIF 结果重新生成 HTML 报告
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ecdet import __version__
from ecdet.l1_build import reconstruct
from ecdet.l2_ir import save_sarif
from ecdet.l3_analysis.engine import (
    DEFAULT_ENGINES,
    AnalysisTarget,
    all_rule_metas,
    resolve_enabled,
    run_all_engines,
)
from ecdet.l5_report import aggregate, build_compliance_records, render_html_report


def _collect_sources(root: Path) -> list[Path]:
    skip = {".git", ".svn", "build", "ecdet_build", "node_modules", "__pycache__",
            ".venv", "tests"}
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".c", ".h") and not any(s in p.parts for s in skip):
            out.append(p.relative_to(root))
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"错误：路径不存在 {root}", file=sys.stderr)
        return 2

    # L1 构建复现（--no-build 跳过，直接源码扫描）
    method = "skipped"
    if not args.no_build:
        res = reconstruct(root)
        method = res.method
        for w in res.warnings:
            print(f"[L1] 警告：{w}")

    # L3 多引擎扫描
    files = _collect_sources(root)
    if not files:
        print("错误：未发现 C 源文件", file=sys.stderr)
        return 2
    target = AnalysisTarget(root=root, files=files)
    alerts, metas = run_all_engines(target, profile=args.profile,
                                    disable=args.disable, enable=args.enable)

    # L5 聚合输出
    result = aggregate(alerts, metas)
    records = build_compliance_records(result)

    out_dir = Path(args.output) if args.output else root / "ecdet_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = save_sarif(alerts, metas, out_dir / "results.sarif")
    html_path = render_html_report(result, records,
                                   project_name=root.name,
                                   out_path=out_dir / "report.html")

    s = result.stats
    print(f"\n=== ecdet 扫描完成 ===")
    print(f"工程：{root}")
    print(f"构建复现通道：{method} | 分析文件：{len(files)} 个")
    print(f"告警（去重后）：{s['total']} 条"
          f"（error {s['error']} / warning {s['warning']} / note {s['note']}）")
    if s.get("by_engine"):
        print(f"引擎贡献：{s['by_engine']}")
    if s.get("by_cwe"):
        top = sorted(s['by_cwe'].items(), key=lambda x: -x[1])[:5]
        print(f"CWE Top5：{top}")
    print(f"\nSARIF：{sarif_path}")
    print(f"HTML 报告：{html_path}")
    return 0 if s["error"] == 0 else 1


def cmd_init_ccdb(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    res = reconstruct(root)
    print(f"构建复现通道：{res.method}")
    print(f"编译命令：{len(res.commands)} 条")
    if res.target_hint:
        print(f"目标芯片：{res.target_hint}")
    for w in res.warnings:
        print(f"警告：{w}")
    if res.ccdb_path:
        print(f"编译数据库：{res.ccdb_path}")
        return 0
    return 1


def cmd_rules(args: argparse.Namespace) -> int:
    metas = all_rule_metas(DEFAULT_ENGINES)
    by_std: dict[str, list] = {}
    for m in metas:
        by_std.setdefault(m.standard, []).append(m)
    for std, ms in sorted(by_std.items()):
        print(f"\n[{std}]（{len(ms)} 条）")
        for m in sorted(ms, key=lambda x: x.rule_id):
            flag = "" if m.enabled_by_default else "（默认禁用）"
            print(f"  {m.rule_id:<28} {m.category:<10} {m.decidability:<10} {m.title_zh}{flag}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from ecdet.l2_ir import load_sarif

    alerts, metas = load_sarif(args.sarif)
    result = aggregate(alerts, metas)
    records = build_compliance_records(result)
    out = Path(args.output) if args.output else Path(args.sarif).with_suffix(".html")
    path = render_html_report(result, records, out_path=out)
    print(f"HTML 报告：{path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ecdet",
        description="嵌入式软件代码缺陷与安全漏洞检测系统",
    )
    parser.add_argument("--version", action="version", version=f"ecdet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="全流程扫描")
    p_scan.add_argument("path", help="工程根目录")
    p_scan.add_argument("--profile", choices=["automotive", "industrial"],
                        help="行业配置文件（规则裁剪）")
    p_scan.add_argument("--disable", nargs="*", default=[], help="禁用规则 ID")
    p_scan.add_argument("--enable", nargs="*", default=[], help="额外启用规则 ID")
    p_scan.add_argument("--no-build", action="store_true",
                        help="跳过 L1 构建复现，直接源码扫描")
    p_scan.add_argument("--output", "-o", help="报告输出目录")
    p_scan.set_defaults(func=cmd_scan)

    p_ccdb = sub.add_parser("init-ccdb", help="L1 构建复现")
    p_ccdb.add_argument("path", help="工程根目录")
    p_ccdb.set_defaults(func=cmd_init_ccdb)

    p_rules = sub.add_parser("rules", help="列出规则集")
    p_rules.set_defaults(func=cmd_rules)

    p_report = sub.add_parser("report", help="从 SARIF 生成 HTML 报告")
    p_report.add_argument("sarif", help="SARIF 文件路径")
    p_report.add_argument("--output", "-o", help="输出 HTML 路径")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
