"""扫描任务执行器 —— 后台队列串行执行，复用 L1→L5 流水线。"""

from __future__ import annotations

import json
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
from ecdet.l4_llm.fixer import apply_patch
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
    """后台单工人队列：扫描与修复任务依次执行，状态经 Store 流转。"""

    def __init__(self, store: Store, data_dir: Path):
        self.store = store
        self.data_dir = Path(data_dir)
        self._queue: queue.Queue[dict] = queue.Queue()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def submit(self, project_id: int, params: dict) -> int:
        run_id = self.store.add_run(project_id, params)
        self._queue.put({"kind": "scan", "id": run_id})
        return run_id

    def submit_analysis(self, project_id: int, params: dict) -> int:
        from ecdet.webui.analysis import normalize_request
        project = self.store.get_project(project_id)
        if not project:
            raise ValueError('工程不存在')
        options = normalize_request(Path(project['workspace']), params)
        return self.submit(project_id, {'analysis': options})

    def submit_fix(self, run_id: int, alert_ids: list[int] | None = None,
                   mode: str = "suggest") -> int:
        job_id = self.store.add_fix_job(run_id, alert_ids)
        self.store.set_fix_job(job_id, "pending", mode=mode)
        self._queue.put({"kind": "fix", "id": job_id, "run_id": run_id,
                         "alert_ids": alert_ids, "mode": mode})
        return job_id

    def _worker(self) -> None:
        while True:
            task = self._queue.get()
            try:
                if task["kind"] == "scan":
                    self._execute(task["id"])
                else:
                    self._execute_fixes(task["id"], task["run_id"],
                                        alert_ids=task.get("alert_ids"),
                                        mode=task.get("mode", "suggest"))
            except Exception as e:  # noqa: BLE001 —— 任务隔离，失败入状态
                if task["kind"] == "scan":
                    self.store.set_run_status(task["id"], "failed",
                                              error=str(e))
                else:
                    self.store.set_fix_job(task["id"], "failed", error=str(e))

    def _execute(self, run_id: int) -> None:
        store = self.store
        run = store.get_run(run_id)
        project = store.get_project(run["project_id"])
        params = run["params"]
        if params.get('analysis'):
            from ecdet.webui.analysis import execute_analysis
            execute_analysis(store, self.data_dir, run_id)
            return
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
        if svd_path is None:
            svd_path = next(iter(sorted(workspace.rglob('*.svd'))), None)
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

        # L4 分诊（可选）：mock 或设置页配置的真实端点
        triage_mode = params.get("triage", "off")
        if triage_mode != "off" and alerts:
            if triage_mode == "mock":
                client = MockLlmClient()
            else:
                client = llm_client_from_settings(store)
            from ecdet.l4_llm.budget import BudgetedClient, LlmCallBudget
            call_budget = LlmCallBudget(int(params.get('max_llm_calls', 64)))
            triage_alerts(alerts, workspace, client=BudgetedClient(client, call_budget, 'triage'))
            warnings.append(f"LLM calls: {call_budget.calls}/{call_budget.max_calls}")
            (out_dir/'llm_budget.json').write_text(json.dumps(call_budget.snapshot(), ensure_ascii=False, indent=2), encoding='utf-8')

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
                "evidence": [{"kind": e.kind, "message": e.message,
                              "path": e.location.path if e.location else "",
                              "line": e.location.line if e.location else None}
                             for e in a.evidence],
            })
        store.put_alerts(run_id, rows)

        # 源码快照：定格本 run 的源文件副本（代码浏览 / 版本对比的数据基座）
        from ecdet.webui.snapshot import create_snapshot, detect_git_commit
        snapshot = create_snapshot(self.data_dir, run_id, workspace)

        stats = dict(result.stats)
        stats["build_method"] = method
        stats["warnings"] = warnings
        stats["files"] = len(files)
        stats["out_dir"] = str(out_dir)
        stats["snapshot"] = snapshot
        commit = detect_git_commit(workspace)
        if commit:
            stats["commit"] = commit
        store.set_run_status(run_id, "done", stats=stats, out_dir=str(out_dir))

    # ---- 一键修复（L4 修复闭环：建议生成 + ToolLoopVerify） ----

    def _execute_fixes(self, job_id: int, run_id: int,
                       alert_ids: list[int] | None = None,
                       mode: str = "suggest",
                       max_targets: int = 8, max_rounds: int = 3) -> None:
        """修复闭环，两种模式：

        suggest（默认）：仅生成并验证补丁，不落盘，原文件字节级不变；
        apply（自动修复）：验证通过的补丁写入源文件，随后全工程重扫，
          剩余相关告警进入下一轮继续修，直至收敛/无进展/轮次上限；
          首次写入前自动备份全部 C/H 文件。
        """
        from ecdet.l2_ir.model import Alert, Location, Severity, Provenance
        from ecdet.l3_analysis.builtin_rules.checks import (
            build_file_facts, finalize_facts)
        from ecdet.l3_analysis.builtin_rules.rules_meta import BUILTIN_RULES
        from ecdet.l4_llm.fixer import FixProposer, FixVerifier, MockFixClient, fix_candidate_allowed
        from ecdet.l3_analysis.engine import BuiltinEngine
        from ecdet.l4_llm.budget import BudgetedClient, LlmCallBudget

        store = self.store
        store.set_fix_job(job_id, "running", mode=mode)
        run = store.get_run(run_id)
        project = store.get_project(run["project_id"])
        workspace = Path(project["workspace"])

        cfg = store.get_settings()
        if cfg.get("llm_mode") == "real":
            fix_client = llm_client_from_settings(store)
        else:
            fix_client = MockFixClient()
        budget = LlmCallBudget(int(cfg.get('max_llm_calls', 64)))
        proposer = FixProposer(BudgetedClient(fix_client, budget, 'patch'))
        svd = (run.get('params') or {}).get('svd')
        svd_path = Path(svd) if svd else next(iter(sorted(workspace.rglob('*.svd'))), None)
        verifier = FixVerifier(workspace, use_compiler=True, svd_path=svd_path)
        all_rule_ids = {r.rule_id for r in BUILTIN_RULES}

        def rescan_facts():
            files = collect_sources(workspace, extra_skip=set())
            facts = [build_file_facts(
                rel.as_posix(),
                (workspace / rel).read_text(encoding="utf-8",
                                            errors="replace"))
                for rel in files if rel.as_posix().endswith((".c", ".h"))]
            return facts, finalize_facts(facts)

        def scan_alerts(facts, ctx):
            """按当前生效规则重扫，返回 fresh 告警（L2 模型）。"""
            return BuiltinEngine().run(AnalysisTarget(workspace,
                [Path(f.path) for f in facts], verifier.svd_path or svd_path), all_rule_ids)

        verification = {}
        def record(proposal, alert, db_aid, applied=False):
            fix_id = store.add_fix(run_id=run_id, alert_id=db_aid,
                rule_id=alert.rule_id, path=alert.location.path, line=alert.location.line,
                func=proposal.func_name, verified=proposal.verified,
                fail_reason=proposal.fail_reason, explanation=proposal.explanation,
                diff=proposal.diff, job_id=job_id, applied=applied)
            verification[str(fix_id)] = proposal.to_props()
            store.set_fix_job(job_id, 'running', final_stats={'verification': verification,
                               'llm_budget': budget.snapshot()})

        backup_dir = ""
        if mode == "apply":
            backup_dir = self._backup_sources(workspace, job_id)
            store.set_fix_job(job_id, "running", backup_dir=backup_dir)

        total_accepted = total_rejected = total_applied = 0
        rounds_done = 0
        # 用户勾选按 (规则, 文件) 记录——行号随修复漂移，不按行匹配。
        # alert_ids 为告警库主键，先映射为 (rule_id, path)。
        selected: set[tuple[str, str]] = set()
        if alert_ids is not None:
            wanted = set(alert_ids)
            for a in store.list_alerts(run_id, limit=1000):
                if a["id"] in wanted:
                    selected.add((a["rule_id"], a["path"].replace("\\", "/")))
        if alert_ids is not None and not selected:
            store.set_fix_job(job_id, 'done', accepted=0, rejected=0, applied=0,
                              rounds=0, final_stats={'reason':'No selected alert IDs matched',
                                                     'llm_budget':budget.snapshot()})
            return
        # 告警库主键映射：补丁记录回填 alert_id，供告警抽屉按 id 匹配展示
        db_alert_id: dict[tuple[str, str], int] = {}
        stored_alerts = store.list_alerts(run_id, limit=2000)
        # Preserve review decisions when current sources are rescanned.
        protected = {(a['rule_id'],a['path'].replace('\\','/')) for a in stored_alerts
                     if a.get('triage') and (a['triage'].get('verdict') != 'TRUE_POSITIVE'
                         or not a['triage'].get('verified') or a['triage'].get('review_pending'))}
        for a in stored_alerts:
            db_alert_id.setdefault(
                (a["rule_id"], a["path"].replace("\\", "/")), a["id"])

        for round_no in range(1, max_rounds + 1):
            facts, ctx = rescan_facts()
            verifier._prepare(ctx)          # 每轮刷新 include 目录
            fresh = scan_alerts(facts, ctx)

            candidates = []
            if selected:
                for a in fresh:
                    key = (a.rule_id, a.location.path.replace("\\", "/"))
                    if key in selected:
                        if key not in protected and fix_candidate_allowed(a):
                            candidates.append(a)
            else:
                for a in fresh:
                    if a.severity == Severity.ERROR and (
                            a.provenance == Provenance.DETECTED
                            or a.engine == "dynamic") and (
                            a.rule_id in AUTO_FIXABLE):
                        key = (a.rule_id, a.location.path.replace('\\','/'))
                        if key not in protected and fix_candidate_allowed(a):
                            candidates.append(a)
            candidates = candidates[:max_targets]
            if not candidates:
                break

            # 同文件按行降序处理，避免前面补丁使后面行号漂移
            candidates.sort(key=lambda a: (a.location.path, -a.location.line))
            applied_this_round = 0

            for a in candidates:
                # Previous accepted patches may have changed another file.
                facts, ctx = rescan_facts()
                db_aid = db_alert_id.get(
                    (a.rule_id, a.location.path.replace("\\", "/")))
                proposal = proposer.propose(a, ctx)
                if proposal.fail_reason:
                    total_rejected += 1
                    record(proposal, a, db_aid)
                    continue
                rel = a.location.path.replace("\\", "/")
                src_path = workspace / rel
                current = src_path.read_text(encoding="utf-8",
                                             errors="replace")
                proposal = verifier.verify(proposal, ctx, current)
                if not proposal.verified:
                    total_rejected += 1
                    record(proposal, a, db_aid)
                    continue

                total_accepted += 1
                was_applied = False
                if mode == "apply":
                    modified = apply_patch(current, proposal.func_start, proposal.func_end, proposal.patched_code)
                    src_path.write_text(modified, encoding="utf-8")
                    total_applied += 1
                    applied_this_round += 1
                    was_applied = True
                record(proposal, a, db_aid, was_applied)

            rounds_done = round_no
            store.set_fix_job(job_id, "running", rounds=rounds_done,
                              applied=total_applied)
            if mode != "apply" or applied_this_round == 0:
                break           # 建议模式单轮；apply 无进展即收敛

        # 验收扫描：修复后的全工程残留告警
        final_files = collect_sources(workspace, extra_skip=set())
        target = AnalysisTarget(root=workspace, files=final_files, svd_path=verifier.svd_path or svd_path)
        final_alerts, _ = run_all_engines(target)
        final_stats = {
            "remaining_total": len(final_alerts),
            "remaining_error": sum(1 for a in final_alerts
                                   if a.severity == Severity.ERROR),
            "remaining_warning": sum(1 for a in final_alerts
                                     if a.severity == Severity.WARNING),
            "rounds": rounds_done,
            "applied_total": total_applied,
            "verification": verification,
            "llm_budget": budget.snapshot(),
        }
        store.set_fix_job(job_id, "done", accepted=total_accepted,
                          rejected=total_rejected, rounds=rounds_done,
                          applied=total_applied, final_stats=final_stats,
                          backup_dir=backup_dir)

    def _backup_sources(self, workspace: Path, job_id: int) -> str:
        """首写前备份全部 C/H 文件（保留相对结构），返回备份目录。"""
        backup = self.data_dir / "backups" / f"job_{job_id}"
        if backup.exists():
            return str(backup)
        for p in workspace.rglob("*"):
            if p.suffix.lower() in (".c", ".h") and not any(
                    s in p.parts for s in
                    {".git", "build", "ecdet_build", "ecdet_reports"}):
                rel = p.relative_to(workspace)
                dst = backup / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dst)
        return str(backup)


AUTO_FIXABLE = {
    "CERT C STR31-C", "CERT C ARR30-C", "ECDET-CWE-197",
    "ECDET-CWE-1284", "ECDET-CWE-242", "CERT C FIO30-C",
}


def _run_file_rules(facts, ctx, active):
    out = []
    seen = {}
    for rid, fn in FILE_RULES.items():
        if rid in active:
            seen.setdefault(fn, set()).add(rid)
    for fn, rids in seen.items():
        out.extend(fn(facts, ctx, rids))
    return out


def llm_client_from_settings(store: Store):
    """按设置页配置构建 LLM 客户端（mode=mock 或 OpenAI 兼容端点）。"""
    cfg = store.get_settings()
    if cfg.get("llm_mode", "mock") == "real":
        import os
        api_key = cfg.get("llm_api_key") or os.environ.get("ECODET_LLM_API_KEY")
        return OpenAICompatClient(
            base_url=cfg.get("llm_base_url") or None,
            model=cfg.get("llm_model") or None, api_key=api_key or None)
    return MockLlmClient()
