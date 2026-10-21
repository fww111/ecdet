# -*- coding: utf-8 -*-
"""自建嵌入式漏洞数据集采集管线（方案 3.4.3，对应 P6）。

实现方案六步流程的工程化（可离线测试）：
  1. 安全通告条目由清单（manifest）给出：CVE/CWE/修复提交/严重级/嵌入式上下文标记；
  2. 修复提交定位：git log 检索（CVE/GHSA/security 关键词）辅助清单校验；
  3. 漏洞/修复函数切片：复用 ecdet 词法与结构解析器，取修复提交
     parent 版本中"文本发生变化的函数"为漏洞样本，同名修复后版本为配对样本；
  4. 标注：清单字段 + ISR 命名自动识别（人工双标注环节在标注平台完成，
     本脚本产出预标注）；
  5. 清洗与去重：函数规范化文本指纹（去注释/空白，PrimeVul 方法），全库唯一；
  6. 按修复时间划分 train/val/test（6:2:2），杜绝时间泄漏。

用法：
  uv run python scripts/build_dataset.py --manifest data/manifest.json --out data/dataset

清单格式见 tests/test_dataset.py 的 fixture。GitHub Advisory 在线抓取
（--fetch-ghsa）为最佳努力路径，需 GITHUB_TOKEN，离线环境跳过。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ecdet.l3_analysis.builtin_rules.ctokens import lex_c
from ecdet.l3_analysis.builtin_rules.cstruct import parse_functions

FIX_PATTERNS = ("CVE-", "GHSA-", "security", "vulnerab", "overflow", "out-of-bound")
SPLIT_RATIOS = (0.6, 0.2, 0.2)

# GitHub Security Advisory 抓取（方案 3.4.3 之 1 的在线通道）
GHSA_API = "https://api.github.com/repos/{slug}/security-advisories"
GHSA_SEV_MAP = {"critical": "超危", "high": "高危", "medium": "中危", "low": "低危"}


def fetch_ghsa_advisories(repo_slug: str, token: str | None = None,
                          per_page: int = 100,
                          _opener=None) -> list[dict]:
    """抓取仓库的 GHSA 安全通告（最佳努力，需外网；_opener 供测试注入）。

    返回精简条目：ghsa / cve / severity（GB/T 口径）/ summary / published /
    cwes。REST 通告对象缺 CWE 时回填 CWE-OTHER，人工标注环节补齐。
    """
    opener = _opener or urllib.request.urlopen
    url = f"{GHSA_API.format(slug=repo_slug)}?per_page={per_page}"
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "ecdet-dataset/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with opener(req, timeout=60) as resp:
        items = json.loads(resp.read().decode("utf-8"))
    out = []
    for it in items:
        cwes = [c.get("cwe_id") for c in (it.get("cwes") or [])
                if c.get("cwe_id")] or ["CWE-OTHER"]
        out.append({
            "ghsa": it.get("ghsa_id", ""),
            "cve": it.get("cve_id") or "",
            "severity": GHSA_SEV_MAP.get((it.get("severity") or "").lower(), "中危"),
            "summary": (it.get("summary") or "")[:200],
            "published": (it.get("published_at") or "")[:10],
            "cwes": cwes,
        })
    return out


def ghsa_to_advisories(repo_path: Path, items: list[dict]) -> list[Advisory]:
    """GHSA 条目 → 数据集 Advisory：以 CVE 号在 git log 中定位修复提交。"""
    advisories: list[Advisory] = []
    for it in items:
        if not it.get("cve"):
            continue
        try:
            sha = _git(Path(repo_path), "log", f"--grep={it['cve']}", "-i",
                       "--format=%H", "-n", "1").strip()
        except RuntimeError:
            sha = ""
        if not sha:
            print(f"  [跳过] {it['cve']} 未在 git log 中定位到修复提交")
            continue
        advisories.append(Advisory(
            cve=it["cve"],
            cwe=it["cwes"][0],
            fix_commit=sha,
            date=it.get("published") or "1970-01-01",
            severity_gb=it.get("severity", "中危"),
            summary=it.get("summary", ""),
        ))
    return advisories


@dataclass
class Advisory:
    cve: str
    cwe: str
    fix_commit: str
    date: str                      # YYYY-MM-DD，时间划分键
    severity_gb: str = "中危"      # GB/T 30279-2020 口径
    is_isr: bool = False
    is_mmio: bool = False
    is_rtos: bool = False
    summary: str = ""


@dataclass
class Manifest:
    repo: str
    license: str
    advisories: list[Advisory] = field(default_factory=list)


@dataclass
class Sample:
    sample_id: str
    repo: str
    license: str
    cve: str
    cwe: str
    label: str                     # vulnerable / fixed / normal
    func_name: str
    path: str
    start_line: int
    end_line: int
    code: str
    fingerprint: str
    fix_commit: str
    fix_date: str
    is_isr: bool
    is_mmio: bool
    is_rtos: bool
    severity_gb: str
    split: str


# ---------------------------------------------------------------------------
# 基础设施：git 操作与函数切片
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])}… 失败：{r.stderr[:200]}")
    return r.stdout


def find_fix_commits(repo: Path, max_count: int = 200) -> list[dict]:
    """方案 3.4.3 之 2：git log 关键词检索修复提交（供清单校验/发现）。"""
    out: list[dict] = []
    seen: set[str] = set()
    for pat in FIX_PATTERNS:
        try:
            log = _git(repo, "log", f"--grep={pat}", "-i",
                       "--format=%H %ad %s", "--date=short", f"-n{max_count}")
        except RuntimeError:
            continue
        for line in log.splitlines():
            parts = line.split(" ", 2)
            if len(parts) == 3 and parts[0] not in seen:
                seen.add(parts[0])
                out.append({"sha": parts[0], "date": parts[1], "subject": parts[2]})
    out.sort(key=lambda x: x["date"])
    return out


def commit_touched_c_files(repo: Path, sha: str) -> list[str]:
    """修复提交触及的 .c 文件（相对路径）。"""
    out = _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
    return [l.strip() for l in out.splitlines() if l.strip().endswith(".c")]


def git_show(repo: Path, rev: str, path: str) -> str | None:
    try:
        return _git(repo, "show", f"{rev}:{path}")
    except RuntimeError:
        return None


def extract_functions(source: str) -> list[dict]:
    """方案 3.4.3 之 3：函数切片（复用 ecdet 解析器）。"""
    lex = lex_c(source)
    out = []
    for func in parse_functions(lex):
        text = "\n".join(lex.source_lines[func.def_line - 1:func.body_close_line])
        out.append({
            "name": func.name,
            "start_line": func.def_line,
            "end_line": func.body_close_line,
            "code": text,
            "fingerprint": fingerprint_text(text),
        })
    return out


def fingerprint_text(code: str) -> str:
    """规范化指纹：注释/字符串内容遮蔽 + 空白折叠（PrimeVul 近重复删除方法）。"""
    lex = lex_c(code)
    joined = "\n".join(lex.clean_lines)
    normalized = re.sub(r"\s+", " ", joined).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 样本构建
# ---------------------------------------------------------------------------


def build_samples(manifest: Manifest, pair_ratio: int = 10,
                  seed: int = 42) -> tuple[list[Sample], dict]:
    repo = Path(manifest.repo)
    if not repo.exists():
        raise SystemExit(f"仓库不存在：{repo}")
    rng = random.Random(seed)
    global_fps: set[str] = set()
    samples: list[Sample] = []

    for adv in manifest.advisories:
        touched = commit_touched_c_files(repo, adv.fix_commit)
        for rel in touched:
            old_src = git_show(repo, f"{adv.fix_commit}^", rel)
            new_src = git_show(repo, adv.fix_commit, rel)
            if not old_src or not new_src:
                continue
            old_funcs = {f["name"]: f for f in extract_functions(old_src)}
            new_funcs = {f["name"]: f for f in extract_functions(new_src)}

            # 漏洞样本：parent 版本中文本发生变化的函数
            vuln_names = [n for n, f in old_funcs.items()
                          if n in new_funcs and new_funcs[n]["fingerprint"] != f["fingerprint"]]
            # 修复版本中消失的函数也算漏洞函数（被删除/重构）
            vuln_names += [n for n in old_funcs if n not in new_funcs]

            for name in vuln_names:
                f = old_funcs[name]
                samples.append(_mk_sample(manifest, adv, rel, f, "vulnerable",
                                          global_fps))
                # 配对修复样本
                fixed = new_funcs.get(name)
                if fixed:
                    samples.append(_mk_sample(manifest, adv, rel, fixed, "fixed",
                                              global_fps))

            # 正常配对样本：修复版本中未变化的函数，按 1:N 采样
            normals = [f for n, f in new_funcs.items()
                       if n not in vuln_names and n in old_funcs
                       and new_funcs[n]["fingerprint"] == old_funcs[n]["fingerprint"]]
            rng.shuffle(normals)
            quota = max(1, pair_ratio * max(1, len(vuln_names)))
            for f in normals[:quota]:
                samples.append(_mk_sample(manifest, adv, rel, f, "normal",
                                          global_fps))

    _assign_time_split(samples, manifest.advisories)
    stats = _stats(samples, len(manifest.advisories))
    return samples, stats


def _mk_sample(manifest: Manifest, adv: Advisory, rel: str, f: dict,
               label: str, global_fps: set[str]) -> Sample | None:
    if f["fingerprint"] in global_fps:
        return None                     # 近重复删除（PrimeVul 方法）
    global_fps.add(f["fingerprint"])
    return Sample(
        sample_id=f"{adv.cve}-{label}-{f['fingerprint']}",
        repo=Path(manifest.repo).name,
        license=manifest.license,
        cve=adv.cve,
        cwe=adv.cwe,
        label=label,
        func_name=f["name"],
        path=rel.replace("\\", "/"),
        start_line=f["start_line"],
        end_line=f["end_line"],
        code=f["code"],
        fingerprint=f["fingerprint"],
        fix_commit=adv.fix_commit,
        fix_date=adv.date,
        is_isr=bool(re.search(r"(_IRQHandler|_Handler|_ISR|_isr)$", f["name"], re.I))
        or adv.is_isr,
        is_mmio=adv.is_mmio,
        is_rtos=adv.is_rtos,
        severity_gb=adv.severity_gb,
        split="",
    )


def _assign_time_split(samples: list[Sample], advisories: list[Advisory]) -> None:
    """方案 3.4.3 之 6：按修复时间划分（6:2:2），同通告样本不跨集合。"""
    ordered = sorted({a.date for a in advisories})
    n = len(ordered)
    if n == 0:
        return
    n_train = max(1, round(n * SPLIT_RATIOS[0]))
    n_val = round(n * SPLIT_RATIOS[1]) if n >= 3 else 0
    date_split: dict[str, str] = {}
    for i, d in enumerate(ordered):
        if i < n_train:
            date_split[d] = "train"
        elif i < n_train + n_val:
            date_split[d] = "val"
        else:
            date_split[d] = "test"
    for s in samples:
        s.split = date_split.get(s.fix_date, "train")


def _stats(samples: list[Sample], n_advisories: int) -> dict:
    by_label: dict[str, int] = {}
    by_split: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    for s in samples:
        by_label[s.label] = by_label.get(s.label, 0) + 1
        by_split[s.split] = by_split.get(s.split, 0) + 1
        by_cwe[s.cwe] = by_cwe.get(s.cwe, 0) + 1
    emb = sum(1 for s in samples if s.is_isr or s.is_mmio or s.is_rtos)
    return {
        "advisories": n_advisories,
        "total_samples": len(samples),
        "by_label": by_label,
        "by_split": by_split,
        "by_cwe": by_cwe,
        "embedded_context_samples": emb,
        "compile_filter": "skipped（编译过滤需目标工具链，接入 L1 后启用）",
        "dual_annotation": "预标注产出；双标注+仲裁在标注平台完成（方案 3.4.3 之 4）",
    }


# ---------------------------------------------------------------------------
# 清单读写与输出
# ---------------------------------------------------------------------------


def load_manifest(path: Path) -> Manifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Manifest(
        repo=data["repo"],
        license=data.get("license", "UNKNOWN"),
        advisories=[Advisory(**a) for a in data.get("advisories", [])],
    )


def write_dataset(samples: list[Sample], stats: dict, manifest: Manifest,
                  out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "samples.jsonl", "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(asdict(s), ensure_ascii=False) + "\n")
    (out_dir / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "LICENSES.md").write_text(
        f"# 数据集许可登记\n\n- 仓库：{manifest.repo}\n"
        f"- 许可证：{manifest.license}\n"
        f"- 本数据集仅发布函数级切片与标注，不整仓再分发（方案 3.4.3 之 7）。\n",
        encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="自建嵌入式漏洞数据集采集管线")
    ap.add_argument("--manifest", help="清单 JSON（仓库/许可/通告）")
    ap.add_argument("--fetch-ghsa", metavar="OWNER/REPO",
                    help="在线抓取仓库 GHSA 通告并与 git log 对齐后写清单")
    ap.add_argument("--repo", help="本地仓库路径（与 --fetch-ghsa 搭配）")
    ap.add_argument("--token", help="GitHub Token（缺省 env GITHUB_TOKEN）")
    ap.add_argument("--license", default="UNKNOWN", help="仓库许可证登记")
    ap.add_argument("--out", default="data/dataset", help="输出目录")
    ap.add_argument("--pair-ratio", type=int, default=10, help="正常:漏洞配对比（默认 10）")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    import os
    if args.fetch_ghsa:
        if not args.repo:
            ap.error("--fetch-ghsa 需要 --repo 指向本地克隆")
            return 2
        print(f"抓取 {args.fetch_ghsa} 的 GHSA 通告 …")
        items = fetch_ghsa_advisories(
            args.fetch_ghsa, token=args.token or os.environ.get("GITHUB_TOKEN"))
        advisories = ghsa_to_advisories(Path(args.repo), items)
        manifest = Manifest(repo=args.repo, license=args.license,
                            advisories=advisories)
        manifest_path = Path(args.out) / "manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(
            {"repo": manifest.repo, "license": manifest.license,
             "advisories": [asdict(a) for a in advisories]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"清单已写入 {manifest_path}（通告 {len(advisories)} 条）")
    elif args.manifest:
        manifest_path = Path(args.manifest)
    else:
        ap.error("需要 --manifest 或 --fetch-ghsa")
        return 2

    manifest = load_manifest(manifest_path)
    samples, stats = build_samples(manifest, args.pair_ratio, args.seed)
    write_dataset(samples, stats, manifest, Path(args.out))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    print(f"\n样本：{Path(args.out) / 'samples.jsonl'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
