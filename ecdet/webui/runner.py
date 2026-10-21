"""扫描任务执行器 —— 后台队列串行执行，复用 L1→L5 流水线。"""

from __future__ import annotations

import queue
import shutil
import subprocess
import tarfile
import threading
import zipfile
from pathlib import Path

from ecdet.l1_build import reconstruct
from ecdet.l2_ir import save_sarif
from ecdet.l3_analysis.engine import (
    AnalysisTarget,
    collect_sources,
    run_all_engines,
)
from ecdet.l4_llm.client import MockLlmClient, OpenAICompatClient
from ecdet.l4_llm.triage import triage_alerts
from ecdet.l5_report import aggregate, build_compliance_records, render_html_report
from ecdet.webui.store import Store

_SKIP_DIRS = {".git", "build", "ecdet_build", "ecdet_reports", ".venv",
              "__pycache__", "node_modules"}


def register_project(store: Store, data_dir: Path, name: str,
                     source_type: str, source_ref: str,
                     archive_bytes: bytes | None = None) -> tuple[int, str]:
    """三源注册归一：全部落到服务端可访问目录，返回 (project_id, workspace)。

    - path：零拷贝直引（须已存在且含 C 源文件）
    - upload：archive_bytes 解压到工作区（zip 或 .tar.gz）
    - git：浅克隆（须本机 git 可用）
    """
    base = Path(data_dir) / "projects"
    base.mkdir(parents=True, exist_ok=True)
    workspace = None

    if source_type == "path":
        p = Path(source_ref)
        if not p.exists():
            raise ValueError(f"路径不存在：{p}")
        workspace = str(p.resolve())
        _require_sources(workspace)

    elif source_type == "upload":
        import uuid
        workspace_root = base / f"upload_{uuid.uuid4().hex[:10]}_{name}"
        workspace_root.mkdir(parents=True, exist_ok=True)
        _extract_archive(archive_bytes or b"", workspace_root)
        _require_sources(str(workspace_root))
        workspace = str(workspace_root)

    elif source_type == "git":
        if shutil.which("git") is None:
            raise ValueError("本机无 git，无法克隆仓库")
        target = base / f"git_{abs(hash(source_ref)) % 10**10}"
        target.mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1"]
        branch = source_ref.split("@", 1)   # url@branch 形式
        if len(branch) == 2:
            cmd += ["--branch", branch[1]]
        cmd.append(branch[0] if len(branch) == 2 else source_ref)
        cmd.append(".")
        proc = subprocess.run(cmd, cwd=str(target), capture_output=True,
                              text=True, timeout=600, encoding="utf-8",
                              errors="replace")
        if proc.returncode != 0:
            raise ValueError(f"git clone 失败：{(proc.stderr or '')[-300:]}")
        _require_sources(str(target))
        workspace = str(target)

    else:
        raise ValueError(f"未知来源类型：{source_type}")

    pid = store.add_project(name=name, source_type=source_type,
                            source_ref=source_ref, workspace=workspace)
    return pid, workspace


def _require_sources(workspace: str) -> None:
    files = [p for p in Path(workspace).rglob("*")
             if p.suffix.lower() in (".c", ".h")
             and not any(s in p.parts for s in _SKIP_DIRS)]
    if not files:
        raise ValueError("工程中未发现 C/H 源文件")


def _extract_archive(data: bytes, dest: Path) -> None:
    if not data:
        raise ValueError("上传内容为空")
    marker = dest / ".archive.bin"
    marker.write_bytes(data)
    try:
        if zipfile.is_zipfile(marker):
            with zipfile.ZipFile(marker) as zf:
                for info in zf.infolist():
                    name = info.filename.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/"):
                        continue          # 防路径逃逸
                    zf.extract(info, dest)
        elif tarfile.is_tarfile(marker):
            with tarfile.open(marker) as tf:
                safe = [m for m in tf.getmembers()
                        if not m.name.startswith("/")
                        and ".." not in Path(m.name).parts]
                tf.extractall(dest, members=safe)
        else:
            raise ValueError("仅支持 zip / tar.gz 归档")
    finally:
        marker.unlink(missing_ok=True)


class ScanRunner:
    """后台单工人队列：Run 依次执行，状态经 Store 流转。"""

    def __init__(self, store: Store, data_dir: Path):
        self.store = store
        self.data_dir = Path(data_dir)
        self._queue: queue.Queue[int] = queue.Queue()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def submit(self, project_id: int, params: dict) -> int:
        run_id = self.store.add_run(project_id, params)
        self._queue.put(run_id)
        return run_id

    def _worker(self) -> None:
        while True:
            run_id = self._queue.get()
            try:
                self._execute(run_id)
            except Exception as e:  # noqa: BLE001 —— 任务隔离，失败入状态
                self.store.set_run_status(run_id, "failed", error=str(e))

    def _execute(self, run_id: int) -> None:
        store = self.store
        run = store.get_run(run_id)
        project = store.get_project(run["project_id"])
        params = run["params"]
        workspace = Path(project["workspace"])
        out_dir = self.data_dir / "runs" / str(run_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        store.set_run_status(run_id, "running", out_dir=str(out_dir))

        # L1 构建复现（可选跳过）
        if params.get("no_build"):
            method = "skipped"
            warnings: list[str] = []
        else:
            res = reconstruct(workspace)
            method = res.method
            warnings = res.warnings

        # L3 静态扫描
        files = collect_sources(workspace, extra_skip=set())
        if not files:
            store.set_run_status(run_id, "failed", error="未发现 C/H 源文件")
            return
        svd = params.get("svd")
        svd_path = Path(svd) if svd else None
        if svd_path and not svd_path.is_absolute():
            svd_path = workspace / svd_path
        target = AnalysisTarget(root=workspace, files=files, svd_path=svd_path)
        enabled_disable = params.get("disable") or []
        alerts, metas = run_all_engines(
            target, profile=params.get("profile") or None,
            disable=list(enabled_disable))

        # L3 动态通道（可选）
        if params.get("dynamic"):
            from ecdet.l3_analysis.dynamic import DynamicEngine
            from ecdet.l3_analysis.builtin_rules.checks import build_file_facts
            engine = DynamicEngine(max_functions=6, max_seeds=17)
            if engine.available:
                facts = [build_file_facts(rel.as_posix(),
                                          (workspace / rel).read_text(
                                              encoding="utf-8",
                                              errors="replace"))
                         for rel in files if rel.as_posix().endswith(".c")]
                for f_ in engine.run(workspace, facts):
                    alerts.append(f_.to_alert())

        # L4 分诊（可选）
        triage_mode = params.get("triage", "off")
        if triage_mode != "off" and alerts:
            if triage_mode == "mock":
                client = MockLlmClient()
            else:
                import os
                client = OpenAICompatClient()
                _ = os
            triage_alerts(alerts, workspace, client=client)

        # L5 聚合输出
        result = aggregate(alerts, metas)
        records = build_compliance_records(result)
        save_sarif(alerts, metas, out_dir / "results.sarif")
        render_html_report(result, records, project_name=project["name"],
                           out_path=out_dir / "report.html")

        # 告警入库（聚合簇主告警）
        rows = []
        for c in result.clusters:
            a = c.primary
            rows.append({
                "rule_id": a.rule_id, "engine": a.engine,
                "severity": a.severity.value,
                "path": a.location.path, "line": a.location.line,
                "message": a.message, "cwe": a.cwe,
                "provenance": c.provenance.value,
                "triage": a.triage, "fingerprint": a.ensure_fingerprint(),
            })
        store.put_alerts(run_id, rows)

        stats = dict(result.stats)
        stats["build_method"] = method
        stats["warnings"] = warnings
        stats["files"] = len(files)
        stats["out_dir"] = str(out_dir)
        store.set_run_status(run_id, "done", stats=stats, out_dir=str(out_dir))
