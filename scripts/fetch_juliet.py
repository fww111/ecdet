# -*- coding: utf-8 -*-
"""Juliet C/C++ 测试集接入脚本（阶段一里程碑：Juliet 接入）。

用途：下载/定位 NIST SARD Juliet 测试集（1.3 版，约 6 万 C/C++ 用例），
按 CWE 家族抽样，用 ecdet 内置引擎扫描，对照 good/bad 标注产出检出率，
作为规则引擎覆盖广度的评测输入（方案 3.4.1）。

用法：
  # 从 SARD 下载（约 100MB，需外网）
  uv run python scripts/fetch_juliet.py --download --dest data/juliet --limit 300

  # 使用已下载的 zip 离线评测
  uv run python scripts/fetch_juliet.py --zip path/to/juliet.zip --limit 300

  # 自检（不依赖 Juliet，验证评测管线本身）
  uv run python scripts/fetch_juliet.py --selftest

输出：data/juliet_report.json + 控制台摘要。
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

SARD_URL = "https://samate.nist.gov/SARD/test-suites/112/download/zips/Juliet_C_Cpp.zip"

# Juliet 家族目录名前缀 → ecdet 规则可对应的 CWE 口径
FAMILY_CWE = {
    "CWE121": ["CWE-787", "CWE-120"],       # 栈缓冲区越界写
    "CWE122": ["CWE-787", "CWE-120"],       # 堆缓冲区越界写
    "CWE124": ["CWE-125"],                  # 缓冲区越界读
    "CWE126": ["CWE-125"],                  # 越界读
    "CWE127": ["CWE-125"],                  # 越界读
    "CWE134": ["CWE-134"],                  # 格式串可控
    "CWE190": ["CWE-190", "CWE-197"],       # 整数溢出/截断
    "CWE191": ["CWE-190"],                  # 整数下溢
    "CWE197": ["CWE-197"],                  # 数值截断
    "CWE242": ["CWE-242"],                  # 无效继承函数（gets）
    "CWE676": ["CWE-676"],                  # 危险函数
    "CWE680": ["CWE-120"],                  # 缓冲区拷贝长度校验
    "CWE1284": ["CWE-1284"],                # 无界读取
}

BAD_FUNC_RE = re.compile(r"\b(\w+_bad)\s*\(")


def iter_juliet_c_files(zip_path: Path):
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            norm = "/" + name.replace("\\", "/")
            if norm.endswith(".c") and "/testcases/" in norm:
                yield name, zf.read(name).decode("utf-8", errors="replace")


def family_of(name: str) -> str | None:
    m = re.search(r"(CWE\d+)(?:[_/]|$)", name.replace("\\", "/"))
    return m.group(1) if m else None


def extract_bad_functions(src: str) -> list[str]:
    """抽取 Juliet 的 *_bad 函数（含签名，从上一语句边界到配对右花括号）。"""
    out = []
    for m in BAD_FUNC_RE.finditer(src):
        sig_start = max(src.rfind(";", 0, m.start()),
                        src.rfind("}", 0, m.start()), 0) + 1
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        depth, i = 0, brace
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    out.append(src[sig_start:i + 1])
                    break
            i += 1
    return out


def evaluate(juliet_zip: Path, limit: int, dest: Path) -> dict:
    from ecdet.l2_ir.model import Severity
    from ecdet.l3_analysis.builtin_rules.checks import (
        FILE_RULES, PROJECT_RULES, build_file_facts, finalize_facts,
    )
    from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES

    all_ids = {r.rule_id for r in BUILTIN_RULES}
    per_family: dict[str, dict] = defaultdict(lambda: {"cases": 0, "detected": 0})
    done = 0

    for name, src in iter_juliet_c_files(juliet_zip):
        if done >= limit:
            break
        fam = family_of(name)
        if fam not in FAMILY_CWE:
            continue
        bads = extract_bad_functions(src)
        if not bads:
            continue
        done += 1
        cwes = set(FAMILY_CWE[fam])
        detected = False
        for i, bad_body in enumerate(bads, 1):
            facts = [build_file_facts(f"juliet_{i}.c", bad_body)]
            ctx = finalize_facts(facts)
            seen: dict = {}
            for rid, fn in FILE_RULES.items():
                if rid in all_ids:
                    seen.setdefault(fn, set()).add(rid)
            alerts = []
            for fn, rids in seen.items():
                alerts.extend(fn(facts[0], ctx, rids))
            hit_cwes = {a.cwe for a in alerts if a.cwe} | {
                c for a in alerts if a.rule_id.startswith("ECDET-")
                for c in a.rule_id.replace("ECDET-", "").split()
            }
            hit_cwes = {c if c.startswith("CWE-") else f"CWE-{c.split('-')[-1]}"
                        for c in hit_cwes if c}
            if hit_cwes & cwes:
                detected = True
                break
        per_family[fam]["cases"] += 1
        per_family[fam]["detected"] += int(detected)
        if done % 100 == 0:
            print(f"  已评测 {done}/{limit} …")

    report = {
        "zip": str(juliet_zip),
        "limit": limit,
        "families": {
            fam: {
                "cases": v["cases"],
                "detected": v["detected"],
                "recall": round(v["detected"] / v["cases"], 4) if v["cases"] else 0.0,
                "expect_cwes": FAMILY_CWE[fam],
            }
            for fam, v in sorted(per_family.items())
        },
    }
    total_c = sum(v["cases"] for v in per_family.values())
    total_d = sum(v["detected"] for v in per_family.values())
    report["overall"] = {
        "cases": total_c,
        "detected": total_d,
        "recall": round(total_d / total_c, 4) if total_c else 0.0,
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def selftest() -> int:
    """不依赖 Juliet 包：用本地样例验证评测管线端到端可用。"""
    import tempfile

    sample_c = r"""
#include <stdio.h>
void CWE242_bad(void) { char b[8]; gets(b); }
void CWE190_bad(void) { uint8_t x = 300; (void)x; }
"""
    with tempfile.TemporaryDirectory() as td:
        zf = Path(td) / "mini.zip"
        with zipfile.ZipFile(zf, "w") as z:
            z.writestr("testcases/CWE242/x.c", sample_c)
            z.writestr("testcases/CWE190/y.c", sample_c)
        rep = evaluate(zf, limit=10, dest=Path(td) / "r.json")
        fams = rep["families"]
        assert "CWE242" in fams and fams["CWE242"]["detected"] >= 1, rep
        assert "CWE190" in fams and fams["CWE190"]["detected"] >= 1, rep
    print("selftest 通过：Juliet 评测管线（抽包→bad 提取→扫描→CWE 对照）端到端可用")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Juliet 测试集接入与检出率评测")
    ap.add_argument("--download", action="store_true", help="从 NIST SARD 下载测试集")
    ap.add_argument("--zip", type=Path, help="本地 Juliet zip 路径")
    ap.add_argument("--dest", type=Path, default=Path("data/juliet"),
                    help="下载/解包目录")
    ap.add_argument("--limit", type=int, default=300, help="评测用例数上限")
    ap.add_argument("--selftest", action="store_true", help="离线自检评测管线")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.zip:
        zip_path = args.zip
    elif args.download:
        args.dest.mkdir(parents=True, exist_ok=True)
        zip_path = args.dest / "Juliet_C_Cpp.zip"
        if not zip_path.exists():
            print(f"下载 {SARD_URL} → {zip_path}（约 100MB）…")
            req = urllib.request.Request(SARD_URL, headers={"User-Agent": "ecdet/0.1"})
            with urllib.request.urlopen(req, timeout=300) as resp, open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
    else:
        ap.error("需要 --zip <path> 或 --download（或 --selftest）")

    report = evaluate(zip_path, args.limit, args.dest / "juliet_report.json")
    print("\n=== Juliet 检出率（内置引擎，函数级简化口径） ===")
    for fam, v in report["families"].items():
        print(f"  {fam:<10} {v['detected']}/{v['cases']}  recall={v['recall']:.1%}")
    o = report["overall"]
    print(f"  合计       {o['detected']}/{o['cases']}  recall={o['recall']:.1%}")
    print(f"\n报告：{args.dest / 'juliet_report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
