"""运行级源码快照：每次扫描完成定格一份源文件副本。

代码浏览（整文件 + 告警行标注）与版本对比（文件 diff + 告警差分）的
数据基座。快照按 run 存放于 <data_dir>/snapshots/<run_id>/，附
manifest.json（相对路径 → sha256/字节/行数），path 直引工程同样快照，
保证 apply 修复改写工作区后历史运行仍可回看。

告警的 path 为 posix 相对路径（如 src/comm.c），manifest 键与之同形态，
双方按该键直连匹配。
"""

from __future__ import annotations

import difflib
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

SNAPSHOT_EXTS = {".c", ".cc", ".cpp", ".h", ".hpp"}
SKIP_DIRS = {".git", "build", "ecdet_build", "ecdet_reports", ".venv",
             "__pycache__", "node_modules", "out", ".vs", ".vscode"}
MAX_FILE_BYTES = 1_000_000      # 单文件上限 1MB
MAX_FILES = 5000                # 单 run 文件数上限
MAX_DIFF_LINES = 5000           # 行级 diff 的单文件行数上限


def snapshot_dir(data_dir: str | Path, run_id: int) -> Path:
    return Path(data_dir) / "snapshots" / str(run_id)


def load_manifest(data_dir: str | Path, run_id: int) -> dict | None:
    p = snapshot_dir(data_dir, run_id) / "manifest.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def detect_git_commit(workspace: str | Path) -> str:
    """工作区为 git 克隆时返回 HEAD SHA，否则空串。"""
    if not (Path(workspace) / ".git").exists():
        return ""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(workspace),
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace")
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def create_snapshot(data_dir: str | Path, run_id: int,
                    workspace: str | Path) -> dict:
    """拷贝源文件到快照目录并写 manifest，返回摘要（入 runs.stats）。"""
    workspace = Path(workspace)
    dest_root = snapshot_dir(data_dir, run_id)
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    entries: dict[str, dict] = {}
    skipped = 0
    total_bytes = 0
    for p in sorted(workspace.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in SNAPSHOT_EXTS:
            continue
        if any(s in p.parts for s in SKIP_DIRS):
            continue
        if len(entries) >= MAX_FILES or p.stat().st_size > MAX_FILE_BYTES:
            skipped += 1
            continue
        rel = p.relative_to(workspace).as_posix()
        dst = dest_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
        data = dst.read_bytes()
        lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n")
                                     else 0)
        entries[rel] = {"sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data), "lines": lines}
        total_bytes += len(data)

    manifest = {"run_id": run_id, "workspace": str(workspace),
                "files": entries, "skipped": skipped,
                "total_files": len(entries), "total_bytes": total_bytes}
    (dest_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return {"files": len(entries), "skipped": skipped,
            "bytes": total_bytes}


def read_snapshot_file(data_dir: str | Path, run_id: int,
                       rel: str) -> str | None:
    """读快照文件文本。rel 必须命中 manifest 白名单（防路径穿越）。"""
    m = load_manifest(data_dir, run_id)
    if not m or rel not in m["files"]:
        return None
    root = snapshot_dir(data_dir, run_id).resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def file_alerts(store, run_id: int, rel: str) -> list[dict]:
    """某 run 中落在 rel 文件上的告警（折叠 path 形态差异后匹配）。"""
    out = []
    for a in store.list_alerts(run_id, limit=5000):
        if a["path"].replace("\\", "/").lstrip("./") == rel:
            out.append(a)
    return out


def diff_runs(data_dir: str | Path, store, base_id: int,
              target_id: int) -> dict | None:
    """两 run 的文件级变更（manifest 哈希）+ 告警差分（fingerprint）。"""
    mb = load_manifest(data_dir, base_id)
    mt = load_manifest(data_dir, target_id)
    if not mb or not mt:
        return None
    files = []
    for rel, meta in sorted(mt["files"].items()):
        old = mb["files"].get(rel)
        if old is None:
            status = "added"
        elif old["sha256"] != meta["sha256"]:
            status = "modified"
        else:
            continue
        files.append({"path": rel, "status": status,
                      "old_lines": old["lines"] if old else 0,
                      "new_lines": meta["lines"]})
    for rel, meta in sorted(mb["files"].items()):
        if rel not in mt["files"]:
            files.append({"path": rel, "status": "deleted",
                          "old_lines": meta["lines"], "new_lines": 0})

    base_fp = {a["fingerprint"]: a
               for a in store.list_alerts(base_id, limit=5000)
               if a["fingerprint"]}
    target_fp = {a["fingerprint"]: a
                 for a in store.list_alerts(target_id, limit=5000)
                 if a["fingerprint"]}
    new = [a for fp, a in target_fp.items() if fp not in base_fp]
    resolved = [a for fp, a in base_fp.items() if fp not in target_fp]
    new.sort(key=lambda a: (a["path"], a["line"]))
    resolved.sort(key=lambda a: (a["path"], a["line"]))
    return {
        "base_run": base_id, "target_run": target_id,
        "files": files,
        "summary": {
            "added": sum(1 for f in files if f["status"] == "added"),
            "modified": sum(1 for f in files if f["status"] == "modified"),
            "deleted": sum(1 for f in files if f["status"] == "deleted"),
            "alerts_new": len(new),
            "alerts_resolved": len(resolved),
            "alerts_unresolved": len(target_fp) - len(new),
        },
        "alerts_new": new,
        "alerts_resolved": resolved,
    }


def aligned_rows(old_lines: list[str],
                 new_lines: list[str]) -> list[dict]:
    """difflib 行对齐 → 结构化行序列（并排/统一两种渲染共用一份数据）。

    每行 {t, a, b, old, new}：t ∈ ctx/add/del/mod；a/b 为旧/新侧行号
    （1 基，无侧为 None）；mod = 行内替换，并排视图左右同排。
    """
    sm = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    rows: list[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({"t": "ctx", "a": i1 + k + 1, "b": j1 + k + 1,
                             "old": old_lines[i1 + k],
                             "new": new_lines[j1 + k]})
        elif tag == "delete":
            for k in range(i1, i2):
                rows.append({"t": "del", "a": k + 1, "b": None,
                             "old": old_lines[k], "new": None})
        elif tag == "insert":
            for k in range(j1, j2):
                rows.append({"t": "add", "a": None, "b": k + 1,
                             "old": None, "new": new_lines[k]})
        else:   # replace：少的一侧配对为 mod，多出部分单侧
            n = min(i2 - i1, j2 - j1)
            for k in range(n):
                rows.append({"t": "mod", "a": i1 + k + 1, "b": j1 + k + 1,
                             "old": old_lines[i1 + k],
                             "new": new_lines[j1 + k]})
            for k in range(i1 + n, i2):
                rows.append({"t": "del", "a": k + 1, "b": None,
                             "old": old_lines[k], "new": None})
            for k in range(j1 + n, j2):
                rows.append({"t": "add", "a": None, "b": k + 1,
                             "old": None, "new": new_lines[k]})
    return rows


def diff_file(data_dir: str | Path, store, base_id: int, target_id: int,
              rel: str) -> dict | None:
    """单文件行级对比 + 两侧告警标注（前端按 a/b 行号放 gutter 标记）。"""
    mb = load_manifest(data_dir, base_id)
    mt = load_manifest(data_dir, target_id)
    if not mb or not mt:
        return None
    in_base = rel in mb["files"]
    in_target = rel in mt["files"]
    if not in_base and not in_target:
        return None

    old_text = read_snapshot_file(data_dir, base_id, rel) if in_base else ""
    new_text = read_snapshot_file(data_dir, target_id, rel) if in_target else ""
    old_lines = old_text.splitlines() if in_base else []
    new_lines = new_text.splitlines() if in_target else []

    status = ("added" if not in_base
              else "deleted" if not in_target
              else "modified" if mb["files"][rel]["sha256"]
              != mt["files"][rel]["sha256"] else "unchanged")
    if len(old_lines) > MAX_DIFF_LINES or len(new_lines) > MAX_DIFF_LINES:
        rows = None          # 超限降级：不给行级对比
    else:
        rows = aligned_rows(old_lines, new_lines)
    return {
        "path": rel, "status": status,
        "base_run": base_id, "target_run": target_id,
        "old_lines": old_lines,
        "new_lines": new_lines,
        "rows": rows,
        "old_alerts": file_alerts(store, base_id, rel) if in_base else [],
        "new_alerts": file_alerts(store, target_id, rel) if in_target else [],
    }
