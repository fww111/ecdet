"""ecdet 命令行入口 —— 五层流水线的调度外壳。

命令：
  ecdet scan <path>        全流程：L1 构建复现 → L3 多引擎扫描 → L5 聚合输出
  ecdet init-ccdb <path>   仅执行 L1 构建复现（产出 compile_commands.json）
  ecdet rules              列出内置规则集
  ecdet report <sarif>     从 SARIF 结果重新生成 HTML 报告
"""

from __future__ import annotations

import argparse
import json
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


_SKIP_DIRS = {".git", ".svn", "build", "ecdet_build", "node_modules", "__pycache__",
              ".venv", "tests"}


def _collect_sources(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".c", ".h") and \
                not any(s in p.parts for s in _SKIP_DIRS):
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

    # L3 多引擎扫描（增量模式：影响集收缩扫描范围，方案 3.3.6）
    from ecdet.l3_analysis.engine import collect_sources
    files = collect_sources(root)
    if not files:
        print("错误：未发现 C 源文件", file=sys.stderr)
        return 2

    old_fps = set()
    out_dir = Path(args.output) if args.output else root / "ecdet_reports"
    if args.baseline:
        from ecdet.incremental import load_baseline_fingerprints
        bp = Path(args.baseline)
        if bp.exists():
            old_fps = load_baseline_fingerprints(bp)
            print(f"[增量] 载入基线：{bp}（{len(old_fps)} 条指纹）")
        else:
            print(f"[增量] 基线文件不存在，按全量处理：{bp}")

    if args.changed:
        from ecdet.incremental import compute_impact_set
        changed = [s.strip() for s in args.changed.split(",") if s.strip()]
        impact = compute_impact_set(root, changed)
        known = set(files)
        files = [f for f in files if f.as_posix() in set(impact.affected)]
        print(f"[增量] 影响集：{len(impact.affected)} 个文件"
              f"（改动 {len(changed)}，扫描收缩至 {len(files)}）")
        for f in files:
            print(f"    {f.as_posix()}  ← {impact.reason.get(f.as_posix(), '?')}")
        if not files:
            print("[增量] 影响集为空，无文件需要扫描")
            return 0
        _ = known

    svd_path = None
    if args.svd:
        svd_path = Path(args.svd)
    else:
        candidates = [p for p in sorted(root.rglob("*.svd"))
                      if "ecdet_build" not in p.parts]
        svd_path = candidates[0] if candidates else None
    if svd_path and not svd_path.is_absolute():
        svd_path = root / svd_path
    target = AnalysisTarget(root=root, files=files, svd_path=svd_path)
    if svd_path:
        print(f"[L2] 硬件语义：加载 SVD {svd_path.name}（MMIO 权限检查启用）")
    alerts, metas = run_all_engines(target, profile=args.profile,
                                    disable=args.disable, enable=args.enable)

    # L5 聚合输出
    result = aggregate(alerts, metas)
    records = build_compliance_records(result)

    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = save_sarif(alerts, metas, out_dir / "results.sarif")
    html_path = render_html_report(result, records,
                                   project_name=root.name,
                                   out_path=out_dir / "report.html")

    # 告警基线：差分 + 更新（方案 3.3.6）
    if old_fps or args.save_baseline:
        from ecdet.incremental import diff_baseline, save_baseline
        diff = diff_baseline(old_fps, alerts)
        base_path = save_baseline(alerts, out_dir / "baseline.json")
        if old_fps:
            print(f"[增量] 基线差分：{diff.summary}")
            for a in diff.new[:10]:
                print(f"    [新增] {a.rule_id} @ {a.location.path}:{a.location.line}")
            if len(diff.new) > 10:
                print(f"    … 其余 {len(diff.new) - 10} 条新增略")
        print(f"[增量] 基线已更新：{base_path}")

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


def cmd_triage(args: argparse.Namespace) -> int:
    """L4 告警分诊：SARIF + 工程上下文 → 分诊结论回写 SARIF/HTML 报告。"""
    from ecdet.l2_ir import load_sarif
    from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient
    from ecdet.l4_llm.triage import triage_alerts

    sarif_path = Path(args.sarif)
    if not sarif_path.exists():
        print(f"错误：SARIF 不存在 {sarif_path}", file=sys.stderr)
        return 2
    project = Path(args.project).resolve() if args.project else sarif_path.parent.parent
    alerts, metas = load_sarif(sarif_path)
    if not alerts:
        print("SARIF 中无告警，无需分诊")
        return 0

    # 增量研判：仅对基线之外的新增告警调用 LLM（方案 3.3.6）
    if args.only_new:
        from ecdet.incremental import load_baseline_fingerprints
        old_fps = load_baseline_fingerprints(args.only_new)
        n_skip = sum(1 for a in alerts if a.ensure_fingerprint() in old_fps)
        alerts = [a for a in alerts if a.fingerprint not in old_fps]
        print(f"[增量研判] 基线持续告警 {n_skip} 条跳过，"
              f"仅研判新增 {len(alerts)} 条")
        if not alerts:
            print("无新增告警，完成")
            return 0

    if args.mock:
        client = MockLlmClient()
        print("[L4] 使用 Mock LLM（离线演示模式）")
    else:
        client = OpenAICompatClient(base_url=args.llm_url, model=args.model)
        print(f"[L4] LLM 端点：{client.base_url}（模型 {client.model}）")

    verdicts, calls = triage_alerts(alerts, project, client=client,
                                    budget_chars=args.budget)
    by_v: dict[str, int] = {}
    for v in verdicts:
        by_v[v.verdict] = by_v.get(v.verdict, 0) + 1

    result = aggregate(alerts, metas)
    records = build_compliance_records(result)
    out_dir = Path(args.output) if args.output else sarif_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    save_sarif(alerts, metas, out_dir / "results.sarif")
    render_html_report(result, records, project_name=project.name,
                       out_path=out_dir / "report.html")

    print("\n=== L4 分诊完成 ===")
    print(f"告警：{len(verdicts)} 条 | LLM 调用：{calls} 次")
    for k in ("TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"):
        if by_v.get(k):
            print(f"  {k}: {by_v[k]}")
    print(f"\n分诊后 SARIF：{out_dir / 'results.sarif'}")
    print(f"HTML 报告：{out_dir / 'report.html'}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """L4 修复建议 + ToolLoopVerify 验证闭环。"""
    from ecdet.l2_ir import load_sarif
    from ecdet.l3_analysis.builtin_rules.checks import build_file_facts, finalize_facts
    from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient
    from ecdet.l4_llm.fixer import FixProposer, FixVerifier, MockFixClient

    sarif_path = Path(args.sarif)
    if not sarif_path.exists():
        print(f"错误：SARIF 不存在 {sarif_path}", file=sys.stderr)
        return 2
    project = Path(args.project).resolve() if args.project else sarif_path.parent.parent
    alerts, metas = load_sarif(sarif_path)

    # 只对真缺陷生成补丁（已分诊时取 TRUE_POSITIVE；未分诊时取全部）
    targets = [a for a in alerts
               if (a.triage or {}).get("verdict", "TRUE_POSITIVE") == "TRUE_POSITIVE"]
    if args.max:
        targets = targets[:args.max]
    if not targets:
        print("无待修复告警（无 TRUE_POSITIVE 结论）")
        return 0

    # 构建工程事实
    need = sorted({a.location.path.replace("\\", "/") for a in targets})
    sources: dict[str, str] = {}
    facts = []
    for rel in need:
        p = project / rel
        if p.exists():
            src = p.read_text(encoding="utf-8", errors="replace")
            sources[rel] = src
            facts.append(build_file_facts(rel, src))
    ctx = finalize_facts(facts)

    client = MockFixClient() if args.mock else OpenAICompatClient(
        base_url=args.llm_url, model=args.model)
    mode = "Mock（离线演示）" if args.mock else client.base_url
    print(f"[L4] 修复建议 LLM：{mode}")
    proposer = FixProposer(client)
    verifier = FixVerifier(project, use_compiler=not args.no_compile)

    out_dir = (Path(args.output) if args.output else sarif_path.parent) / "fixes"
    out_dir.mkdir(parents=True, exist_ok=True)
    accepted, rejected = 0, 0
    records = []
    for i, a in enumerate(targets, 1):
        proposal = proposer.propose(a, ctx)
        if not proposal.fail_reason:
            src = sources.get(a.location.path.replace("\\", "/"))
            if src is not None:
                proposal = verifier.verify(proposal, ctx, src)
        tag = "采纳" if proposal.verified else "拒绝"
        accepted += int(proposal.verified)
        rejected += int(not proposal.verified)
        print(f"  [{tag}] {a.rule_id} @ {a.location.path}:{a.location.line}"
              + ("" if proposal.verified else f" —— {proposal.fail_reason}"))
        records.append({
            "rule_id": a.rule_id, "path": a.location.path,
            "line": a.location.line, "func": proposal.func_name,
            "verified": proposal.verified,
            "fail_reason": proposal.fail_reason,
            "explanation": proposal.explanation, "diff": proposal.diff,
        })
        if proposal.verified and proposal.diff:
            patch_name = f"{i:02d}_{a.rule_id.replace(' ', '_').replace(':', '')}_" \
                         f"{Path(a.location.path).stem}.patch"
            (out_dir / patch_name).write_text(proposal.diff + "\n",
                                              encoding="utf-8")

    (out_dir / "fixes.json").write_text(
        json.dumps({"accepted": accepted, "rejected": rejected,
                    "proposals": records}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"\n=== L4 修复闭环完成 ===")
    print(f"建议 {len(records)} 条：采纳 {accepted} / 拒绝 {rejected}"
          f"（验证：静态重扫 + {'gcc 语法检查' if not args.no_compile else '未启用编译检查'}）")
    print(f"补丁与记录：{out_dir}")
    return 0


def cmd_impact(args: argparse.Namespace) -> int:
    """影响集计算：changed → include 反向闭包 → 调用图反向闭包。"""
    from ecdet.incremental import compute_impact_set

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"错误：路径不存在 {root}", file=sys.stderr)
        return 2
    changed = [s.strip() for s in args.changed.split(",") if s.strip()]
    impact = compute_impact_set(root, changed)
    if args.json:
        print(json.dumps(impact.as_json(), ensure_ascii=False, indent=2))
        return 0
    print(f"变更 {len(impact.changed)} 个文件 → 影响集 {len(impact.affected)} 个文件：")
    for f in impact.affected:
        print(f"  {f}  ← {impact.reason.get(f, '?')}")
    return 0


def cmd_orchestrate(args: argparse.Namespace) -> int:
    """六智能体协同全流程（方案 3.3.7 Orchestrate）。"""
    from ecdet.l4_llm.agents import Orchestrator, OrchestratorConfig
    from ecdet.l5_report import aggregate, build_compliance_records, render_html_report

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"错误：路径不存在 {root}", file=sys.stderr)
        return 2

    cfg = OrchestratorConfig(
        mock=args.mock, llm_url=args.llm_url, llm_model=args.model,
        use_llm=not args.no_llm, use_dynamic=not args.no_dynamic,
        single_agent=args.single_agent, auto_accept=not args.no_auto_accept,
        max_fix_targets=args.max_fix)
    mode = "单智能体串行（A6）" if args.single_agent else "多智能体协同"
    print(f"[L4] 编排模式：{mode} | LLM：{'Mock' if args.mock else 'OpenAI 兼容端点'}"
         f" | 动态通道：{'开' if cfg.use_dynamic else '关'}")

    state = Orchestrator(cfg).orchestrate(root)
    for line in state.logs:
        print(f"  {line}")

    # L5 聚合与报告
    result = aggregate(state.static_alerts, state.rule_metas)
    records = build_compliance_records(result)
    out_dir = root / "ecdet_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    save_sarif(state.static_alerts, state.rule_metas, out_dir / "results.sarif")
    html = render_html_report(result, records, project_name=root.name,
                              out_path=out_dir / "report.html")

    if state.review_queue:
        print("\n=== 人工复核闸门（高危误报判定） ===")
        for item in state.review_queue:
            print(f"  {item['rule_id']} @ {item['path']}:{item['line']}")
            print(f"    LLM 理由：{item['llm_reason'][:80]}")

    print(f"\n=== 编排完成 ===")
    print(f"告警 {len(state.static_alerts)} 条 | 动态触发 "
          f"{len(state.dynamic_findings)} | 监控升级 "
          f"{len(state.monitor_result.upgraded) if state.monitor_result else 0} | "
          f"修复采纳 {sum(1 for f in state.fixes if f.verified)}")
    print(f"LLM 调用 {state.llm_calls} 次 | 耗时 {state.seconds:.1f}s")
    print(f"HTML 报告：{html}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Web 控制台：浏览器注册工程 → 后台扫描 → 告警浏览/复核。"""
    from ecdet.webui import WebUI

    data_dir = Path(args.data_dir).resolve()
    print(f"数据目录：{data_dir}")
    WebUI(data_dir, port=args.port).serve()
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
    p_scan.add_argument("--svd", help="CMSIS-SVD 芯片描述文件（缺省自动发现工程内 *.svd）")
    p_scan.add_argument("--baseline", help="上次扫描的基线 JSON（存在则差分并仅报新增）")
    p_scan.add_argument("--save-baseline", action="store_true",
                        help="扫描后将告警指纹存为基线（输出目录 baseline.json）")
    p_scan.add_argument("--changed", help="增量模式：逗号分隔的变更文件（相对根目录），"
                                          "按影响集收缩扫描范围")
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

    p_triage = sub.add_parser("triage", help="L4 LLM 告警分诊（误报过滤/证据核对）")
    p_triage.add_argument("sarif", help="scan 产出的 results.sarif 路径")
    p_triage.add_argument("--project", help="工程根目录（告警相对路径的基准，"
                                           "缺省取 SARIF 上两级）")
    p_triage.add_argument("--llm-url", help="OpenAI 兼容端点"
                                            "（缺省 env ECODET_LLM_BASE_URL 或 vLLM 默认端口）")
    p_triage.add_argument("--model", help="模型名（缺省 env ECODET_LLM_MODEL）")
    p_triage.add_argument("--mock", action="store_true",
                          help="使用确定性 Mock LLM（离线演示/测试）")
    p_triage.add_argument("--budget", type=int, default=8000,
                          help="上下文字符预算（默认 8000）")
    p_triage.add_argument("--only-new", help="增量研判：仅研判基线 JSON 之外的新增告警")
    p_triage.add_argument("--output", "-o", help="输出目录（缺省覆盖原 SARIF 所在目录）")
    p_triage.set_defaults(func=cmd_triage)

    p_fix = sub.add_parser("fix", help="L4 修复建议生成 + ToolLoopVerify 验证闭环")
    p_fix.add_argument("sarif", help="results.sarif 路径（建议先 triage）")
    p_fix.add_argument("--project", help="工程根目录（缺省取 SARIF 上两级）")
    p_fix.add_argument("--llm-url", help="OpenAI 兼容端点（缺省 env）")
    p_fix.add_argument("--model", help="模型名（缺省 env）")
    p_fix.add_argument("--mock", action="store_true", help="使用确定性 Mock LLM")
    p_fix.add_argument("--no-compile", action="store_true",
                       help="跳过 gcc 语法检查（仅静态重扫验证）")
    p_fix.add_argument("--max", type=int, default=20, help="单次处理告警数上限")
    p_fix.add_argument("--output", "-o", help="输出目录")
    p_fix.set_defaults(func=cmd_fix)

    p_impact = sub.add_parser("impact", help="增量影响集计算（方案 3.3.6）")
    p_impact.add_argument("path", help="工程根目录")
    p_impact.add_argument("--changed", required=True,
                          help="逗号分隔的变更文件（相对根目录）")
    p_impact.add_argument("--json", action="store_true", help="输出 JSON")
    p_impact.set_defaults(func=cmd_impact)

    p_orch = sub.add_parser("orchestrate", help="六智能体协同全流程（3.3.7）")
    p_orch.add_argument("path", help="工程根目录")
    p_orch.add_argument("--svd", help="CMSIS-SVD 文件（缺省自动发现）")
    p_orch.add_argument("--mock", action="store_true", help="Mock LLM（离线演示）")
    p_orch.add_argument("--llm-url", help="OpenAI 兼容端点（缺省 env）")
    p_orch.add_argument("--model", help="模型名（缺省 env）")
    p_orch.add_argument("--no-llm", action="store_true", help="跳过 L4 研判/修复（A1）")
    p_orch.add_argument("--no-dynamic", action="store_true",
                        help="跳过动态通道与运行时监控（A5）")
    p_orch.add_argument("--single-agent", action="store_true",
                        help="单智能体串行模式（A6 消融）")
    p_orch.add_argument("--no-auto-accept", action="store_true",
                        help="高危误报判定挂起待人工（缺省自动接受并留痕）")
    p_orch.add_argument("--max-fix", type=int, default=5, help="单次修复目标上限")
    p_orch.set_defaults(func=cmd_orchestrate)

    p_serve = sub.add_parser("serve", help="启动 Web 控制台（零依赖）")
    p_serve.add_argument("--port", type=int, default=8600)
    p_serve.add_argument("--data-dir", default="webui_data",
                         help="数据目录（SQLite + 工作区 + 运行产物）")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
