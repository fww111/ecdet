"""SQLite 存储：项目 / 扫描运行 / 告警（含人工复核状态流转）。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,          -- path / upload / git
    source_ref TEXT NOT NULL,           -- 路径 / git url
    workspace TEXT NOT NULL,            -- 服务端工作目录
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    status TEXT NOT NULL,               -- pending / running / done / failed
    params TEXT NOT NULL,               -- JSON
    stats TEXT,                         -- JSON（聚合统计）
    error TEXT,
    started_at REAL,
    finished_at REAL,
    out_dir TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    rule_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    severity TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER NOT NULL,
    message TEXT NOT NULL,
    cwe TEXT,
    provenance TEXT NOT NULL,
    triage TEXT,                        -- JSON（L4 分诊结论）
    status TEXT NOT NULL DEFAULT 'pending',   -- pending / confirmed / dismissed
    fingerprint TEXT,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_run ON alerts(run_id);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    alert_id INTEGER,
    rule_id TEXT, path TEXT, line INTEGER, func TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    fail_reason TEXT, explanation TEXT, diff TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS fix_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    status TEXT NOT NULL DEFAULT 'pending',   -- pending/running/done/failed
    param TEXT,                               -- JSON：指定修复的 alert_ids
    error TEXT, accepted INTEGER, rejected INTEGER,
    created_at REAL, finished_at REAL
);
"""


def _now() -> float:
    return time.time()


class Store:
    """线程安全 SQLite 封装（单写锁 + check_same_thread=False）。"""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            for alter in (  # 旧库迁移：逐列补齐（已存在则忽略）
                "ALTER TABLE alerts ADD COLUMN evidence TEXT",
                "ALTER TABLE fix_jobs ADD COLUMN param TEXT",
                "ALTER TABLE fixes ADD COLUMN job_id INTEGER",
                "ALTER TABLE fix_jobs ADD COLUMN mode TEXT",
                "ALTER TABLE fix_jobs ADD COLUMN rounds INTEGER",
                "ALTER TABLE fix_jobs ADD COLUMN applied INTEGER",
                "ALTER TABLE fix_jobs ADD COLUMN final_stats TEXT",
                "ALTER TABLE fix_jobs ADD COLUMN backup_dir TEXT",
                "ALTER TABLE fixes ADD COLUMN applied INTEGER",
            ):
                try:
                    self._conn.execute(alter)
                except sqlite3.OperationalError:
                    pass
            self._conn.commit()

    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    # ---- 项目 ----

    def add_project(self, name: str, source_type: str, source_ref: str,
                    workspace: str) -> int:
        cur = self._exec(
            "INSERT INTO projects(name, source_type, source_ref, workspace, "
            "created_at) VALUES (?,?,?,?,?)",
            (name, source_type, source_ref, workspace, _now()))
        return int(cur.lastrowid)

    def get_project(self, project_id: int) -> dict | None:
        row = self._exec("SELECT * FROM projects WHERE id=?",
                         (project_id,)).fetchone()
        return dict(row) if row else None

    def list_projects(self) -> list[dict]:
        rows = self._exec(
            "SELECT p.*, (SELECT MAX(id) FROM runs WHERE project_id=p.id) "
            "AS last_run_id FROM projects p ORDER BY p.id DESC").fetchall()
        return [dict(r) for r in rows]

    # ---- 运行 ----

    def add_run(self, project_id: int, params: dict) -> int:
        cur = self._exec(
            "INSERT INTO runs(project_id, status, params) VALUES (?,?,?)",
            (project_id, "pending", json.dumps(params, ensure_ascii=False)))
        return int(cur.lastrowid)

    def set_run_status(self, run_id: int, status: str,
                       stats: dict | None = None, error: str | None = None,
                       out_dir: str | None = None) -> None:
        finished = status in ("done", "failed")
        self._exec(
            "UPDATE runs SET status=?, stats=?, error=?, out_dir=?, "
            "started_at=COALESCE(started_at,?), finished_at=? WHERE id=?",
            (status,
             json.dumps(stats, ensure_ascii=False) if stats else None,
             error, out_dir,
             _now() if status == "running" else None,
             _now() if finished else None,
             run_id))

    def get_run(self, run_id: int) -> dict | None:
        row = self._exec("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["params"] = json.loads(d["params"] or "{}")
        d["stats"] = json.loads(d["stats"]) if d["stats"] else None
        return d

    def list_runs(self, project_id: int | None = None) -> list[dict]:
        if project_id:
            rows = self._exec(
                "SELECT * FROM runs WHERE project_id=? ORDER BY id DESC",
                (project_id,)).fetchall()
        else:
            rows = self._exec(
                "SELECT * FROM runs ORDER BY id DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d["params"] or "{}")
            d["stats"] = json.loads(d["stats"]) if d["stats"] else None
            out.append(d)
        return out

    # ---- 告警 ----

    def put_alerts(self, run_id: int, alerts: list[dict]) -> None:
        with self._lock:
            self._conn.executemany(
                "INSERT INTO alerts(run_id, rule_id, engine, severity, path, "
                "line, message, cwe, provenance, triage, status, fingerprint, "
                "evidence) VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?,?)",
                [(run_id, a["rule_id"], a["engine"], a["severity"], a["path"],
                  a["line"], a["message"], a.get("cwe"),
                  a["provenance"],
                  json.dumps(a["triage"], ensure_ascii=False)
                  if a.get("triage") else None,
                  a.get("fingerprint", ""),
                  json.dumps(a.get("evidence") or [], ensure_ascii=False))
                 for a in alerts])
            self._conn.commit()

    def list_alerts(self, run_id: int, severity: str | None = None,
                    rule_id: str | None = None, engine: str | None = None,
                    status: str | None = None, q: str | None = None,
                    limit: int = 500) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE run_id=?"
        params: list = [run_id]
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if rule_id:
            sql += " AND rule_id LIKE ?"
            params.append(f"%{rule_id}%")
        if engine:
            sql += " AND engine=?"
            params.append(engine)
        if status:
            sql += " AND status=?"
            params.append(status)
        if q:
            sql += " AND (message LIKE ? OR path LIKE ?)"
            params += [f"%{q}%", f"%{q}%"]
        sql += " ORDER BY CASE severity WHEN 'error' THEN 0 WHEN 'warning' " \
               "THEN 1 ELSE 2 END, path, line LIMIT ?"
        params.append(limit)
        rows = self._exec(sql, tuple(params)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["triage"] = json.loads(d["triage"]) if d["triage"] else None
            d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else []
            out.append(d)
        return out

    def get_alert(self, alert_id: int) -> dict | None:
        row = self._exec("SELECT * FROM alerts WHERE id=?",
                         (alert_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["triage"] = json.loads(d["triage"]) if d["triage"] else None
        d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else []
        return d

    def summary(self) -> dict:
        """总览聚合：工程/运行/告警总量与分布（仪表盘数据源）。"""
        n_projects = self._exec(
            "SELECT COUNT(*) AS n FROM projects").fetchone()["n"]
        n_runs = self._exec(
            "SELECT COUNT(*) AS n FROM runs WHERE status='done'").fetchone()["n"]
        n_alerts = self._exec(
            "SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        by_sev = {r["severity"]: r["n"] for r in self._exec(
            "SELECT severity, COUNT(*) AS n FROM alerts "
            "GROUP BY severity").fetchall()}
        by_prov = {r["provenance"]: r["n"] for r in self._exec(
            "SELECT provenance, COUNT(*) AS n FROM alerts "
            "GROUP BY provenance").fetchall()}
        by_triage = {r["v"]: r["n"] for r in self._exec(
            "SELECT JSON_EXTRACT(triage,'$.verdict') AS v, COUNT(*) AS n "
            "FROM alerts WHERE triage IS NOT NULL GROUP BY v").fetchall()}
        recent = []
        for r in self._exec(
                "SELECT id, project_id, status, stats, finished_at FROM runs "
                "ORDER BY id DESC LIMIT 5").fetchall():
            d = dict(r)
            d["stats"] = json.loads(d["stats"]) if d["stats"] else {}
            recent.append(d)
        pending = self._exec(
            "SELECT COUNT(*) AS n FROM alerts WHERE status='pending'"
        ).fetchone()["n"]
        return {"projects": n_projects, "runs_done": n_runs,
                "alerts_total": n_alerts, "pending_review": pending,
                "by_severity": by_sev, "by_provenance": by_prov,
                "by_triage": by_triage, "recent_runs": recent}

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        if status not in ("pending", "confirmed", "dismissed"):
            return False
        cur = self._exec("UPDATE alerts SET status=? WHERE id=?",
                         (status, alert_id))
        return cur.rowcount > 0

    def alert_counts(self, run_id: int) -> dict:
        rows = self._exec(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE run_id=? "
            "GROUP BY severity", (run_id,)).fetchall()
        by_sev = {r["severity"]: r["n"] for r in rows}
        rows = self._exec(
            "SELECT status, COUNT(*) AS n FROM alerts WHERE run_id=? "
            "GROUP BY status", (run_id,)).fetchall()
        by_status = {r["status"]: r["n"] for r in rows}
        return {"by_severity": by_sev, "by_status": by_status}

    # ---- 设置（LLM 接入） ----

    def set_setting(self, key: str, value: str) -> None:
        self._exec(
            "INSERT INTO settings(key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))

    def get_settings(self) -> dict:
        rows = self._exec("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # ---- 修复建议 ----

    def add_fix(self, run_id: int, alert_id: int | None, rule_id: str,
                path: str, line: int, func: str, verified: bool,
                fail_reason: str, explanation: str, diff: str,
                job_id: int | None = None, applied: bool = False) -> int:
        cur = self._exec(
            "INSERT INTO fixes(run_id, alert_id, rule_id, path, line, func, "
            "verified, fail_reason, explanation, diff, created_at, job_id, "
            "applied) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, alert_id, rule_id, path, line, func,
             int(verified), fail_reason, explanation, diff, _now(), job_id,
             int(applied)))
        return int(cur.lastrowid)

    def list_fixes(self, run_id: int,
                   job_id: int | None = None) -> list[dict]:
        sql = "SELECT * FROM fixes WHERE run_id=?"
        params: list = [run_id]
        if job_id:
            sql += " AND job_id=?"
            params.append(job_id)
        sql += " ORDER BY verified DESC, id"
        rows = self._exec(sql, tuple(params)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["verified"] = bool(d["verified"])
            out.append(d)
        return out

    def fixes_for_alerts(self, run_id: int,
                         alert_ids: list[int]) -> dict[int, dict]:
        if not alert_ids:
            return {}
        marks = ",".join("?" * len(alert_ids))
        rows = self._exec(
            f"SELECT * FROM fixes WHERE run_id=? AND alert_id IN ({marks}) "
            f"AND verified=1", (run_id, *alert_ids)).fetchall()
        return {r["alert_id"]: dict(r) for r in rows}

    def add_fix_job(self, run_id: int, alert_ids: list[int] | None = None) -> int:
        cur = self._exec(
            "INSERT INTO fix_jobs(run_id, status, param, created_at) "
            "VALUES (?,'pending',?,?)",
            (run_id,
             json.dumps(alert_ids) if alert_ids else None, _now()))
        return int(cur.lastrowid)

    def set_fix_job(self, job_id: int, status: str, error: str | None = None,
                    accepted: int | None = None, rejected: int | None = None,
                    mode: str | None = None, rounds: int | None = None,
                    applied: int | None = None, final_stats: dict | None = None,
                    backup_dir: str | None = None) -> None:
        finished = status in ("done", "failed")
        self._exec(
            "UPDATE fix_jobs SET status=?, error=?, accepted=?, rejected=?, "
            "mode=COALESCE(?,mode), rounds=COALESCE(?,rounds), "
            "applied=COALESCE(?,applied), "
            "final_stats=COALESCE(?,final_stats), "
            "backup_dir=COALESCE(?,backup_dir), "
            "finished_at=CASE WHEN ? THEN ? ELSE finished_at END WHERE id=?",
            (status, error, accepted, rejected, mode, rounds, applied,
             json.dumps(final_stats, ensure_ascii=False) if final_stats
             else None, backup_dir, finished, _now() if finished else None,
             job_id))

    def latest_fix_job(self, run_id: int) -> dict | None:
        row = self._exec(
            "SELECT * FROM fix_jobs WHERE run_id=? "
            "ORDER BY id DESC LIMIT 1", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["param"] = json.loads(d["param"]) if d.get("param") else None
        d["final_stats"] = (json.loads(d["final_stats"])
                            if d.get("final_stats") else None)
        return d
