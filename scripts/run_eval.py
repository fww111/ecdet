# -*- coding: utf-8 -*-
"""对比评测与消融实验脚本（方案 3.5）。

用法：
  # 用语料目录 + 基准真值跑 A0-A3 消融
  uv run python scripts/run_eval.py --corpus tests/fixtures/eval_corpus \
      --gt tests/fixtures/eval_corpus/gt.jsonl --out eval_out

  # 基准真值可由语料函数清单自动生成（自洽模式，人工标注为准）
  uv run python scripts/run_eval.py --corpus <dir> --vuln-funcs f1,f2 --out eval_out

  # 带外部基线（检测到安装即对比：cppcheck / clang-tidy）
  uv run python scripts/run_eval.py --corpus <dir> --gt <gt.jsonl> --with-baselines

输出：eval_out/eval_results.json + eval_out/eval_report.md（表 3-4 模板）。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ecdet.eval import (  # noqa: E402
    DEFAULT_ABLATIONS,
    AblationConfig,
    compute_metrics,
    gt_from_corpus,
    load_ground_truth,
    render_markdown,
    run_baseline,
    run_ecdet_config,
)
from ecdet.l3_analysis.engine import DEFAULT_ENGINES  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="消融与基线对比评测")
    ap.add_argument("--corpus", required=True, help="语料目录")
    ap.add_argument("--gt", help="基准真值 JSONL（缺省按 --vuln-funcs 自洽生成）")
    ap.add_argument("--vuln-funcs", help="逗号分隔的漏洞函数名（自洽模式）")
    ap.add_argument("--out", default="eval_out", help="输出目录")
    ap.add_argument("--configs", default="A0,A1,A2,A3", help="消融配置（逗号分隔）")
    ap.add_argument("--svd", help="SVD 文件（A0/A1/A3 启用 MMIO 检查）")
    ap.add_argument("--mock", action="store_true", help="LLM 用 Mock（默认）")
    ap.add_argument("--with-baselines", action="store_true",
                    help="附带可用外部基线（cppcheck/clang-tidy）")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"语料不存在：{corpus}", file=sys.stderr)
        return 2

    if args.gt:
        gt = load_ground_truth(args.gt)
    elif args.vuln_funcs:
        vuln = {s.strip() for s in args.vuln_funcs.split(",") if s.strip()}
        gt = gt_from_corpus(corpus, vuln)
    else:
        ap.error("需要 --gt 或 --vuln-funcs")
        return 2

    svd = Path(args.svd) if args.svd else None
    wanted = {s.strip() for s in args.configs.split(",") if s.strip()}
    runs: list = []
    for cfg in DEFAULT_ABLATIONS:
        key = cfg.name.split()[0]          # A0/A1/...
        if key not in wanted:
            continue
        print(f"运行 {cfg.name} …")
        run = run_ecdet_config(corpus, cfg, svd_path=svd)
        runs.append((run, compute_metrics(run.alerts, gt)))

    if args.with_baselines:
        for eng in DEFAULT_ENGINES:
            if eng.name == "builtin":
                continue
            print(f"运行基线 {eng.name} …")
            br = run_baseline(corpus, eng)
            runs.append((br, compute_metrics(br.alerts, gt) if br.available
                         else {}))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = []
    for run, m in runs:
        payload.append({
            "name": run.name, "note": run.note, "available": run.available,
            "seconds": round(run.seconds, 3), "kloc": run.kloc,
            "provenance_ratio": round(run.provenance_ratio, 4),
            "triage_counts": run.triage_counts,
            "n_alerts": len(run.alerts),
            "metrics": m,
        })
    (out / "eval_results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    report = render_markdown(runs)
    (out / "eval_report.md").write_text(report, encoding="utf-8")
    print("\n" + report)
    print(f"\n结果：{out / 'eval_results.json'}\n报告：{out / 'eval_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
