"""零依赖 HTTP 服务：stdlib ThreadingHTTPServer + REST API + 单页前端。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ecdet.webui.runner import ScanRunner, register_project
from ecdet.webui.store import Store

_STATIC = Path(__file__).parent / "static"


class WebUI:
    """控制台服务。serve() 阻塞运行；测试可用 make_server 取得实例。"""

    def __init__(self, data_dir: str | Path, port: int = 8600):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "ecdet_web.db")
        self.runner = ScanRunner(self.store, self.data_dir)
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None

    def make_server(self) -> ThreadingHTTPServer:
        ui = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # 静默默认访问日志
                pass

            def _json(self, code: int, payload) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _file(self, path: Path, ctype: str) -> None:
                if not path.exists():
                    self._json(404, {"error": "not found"})
                    return
                body = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def do_GET(self):  # noqa: N802
                ui.handle_get(self)

            def do_POST(self):  # noqa: N802
                ui.handle_post(self)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        return self._httpd

    def serve(self) -> None:
        httpd = self.make_server()
        print(f"ecdet 控制台：http://127.0.0.1:{self.port} "
              f"（数据目录 {self.data_dir}）")
        httpd.serve_forever()

    # ---- 路由 ----

    def handle_get(self, h: BaseHTTPRequestHandler) -> None:
        url = urlparse(h.path)
        parts = [p for p in url.path.split("/") if p]
        q = {k: v[0] for k, v in parse_qs(url.query).items()}

        if not parts:
            return h._file(_STATIC / "index.html", "text/html; charset=utf-8")
        if parts[:2] == ["api", "projects"]:
            return h._json(200, {"projects": self.store.list_projects()})
        if parts[:2] == ["api", "runs"] and len(parts) == 2:
            return h._json(200, {"runs": self.store.list_runs(
                int(q["project_id"]) if q.get("project_id") else None)})
        if parts[:2] == ["api", "runs"] and len(parts) >= 3:
            run_id = int(parts[2])
            run = self.store.get_run(run_id)
            if not run:
                return h._json(404, {"error": "run not found"})
            if len(parts) == 3:
                run["alert_counts"] = self.store.alert_counts(run_id)
                return h._json(200, run)
            if parts[3] == "alerts":
                return h._json(200, {"alerts": self.store.list_alerts(
                    run_id, severity=q.get("severity"),
                    rule_id=q.get("rule_id"), engine=q.get("engine"),
                    status=q.get("status"), q=q.get("q"),
                    limit=int(q.get("limit", 500)))})
            if parts[3] == "report":
                out = Path(run.get("out_dir") or "")
                return h._file(out / "report.html", "text/html; charset=utf-8")
            if parts[3] == "sarif":
                out = Path(run.get("out_dir") or "")
                return h._file(out / "results.sarif",
                               "application/json; charset=utf-8")
        if parts[:2] == ["api", "carriers"]:
            from ecdet.l3_analysis.dynamic.carriers import probe_carriers
            return h._json(200, {"carriers": [
                {"name": c.name, "tier": c.tier, "available": c.available,
                 "note": c.note} for c in probe_carriers()]})
        return h._json(404, {"error": "not found"})

    def handle_post(self, h: BaseHTTPRequestHandler) -> None:
        url = urlparse(h.path)
        parts = [p for p in url.path.split("/") if p]
        body = h._body()

        if parts[:2] == ["api", "projects"] and len(parts) == 2:
            ctype = h.headers.get("Content-Type", "")
            try:
                if ctype.startswith("application/zip") or \
                        ctype.startswith("application/x-tar"):
                    name = parse_qs(url.query).get("name", ["uploaded"])[0]
                    pid, ws = register_project(
                        self.store, self.data_dir, name, "upload",
                        source_ref="", archive_bytes=body)
                else:
                    data = json.loads(body.decode("utf-8") or "{}")
                    stype = data.get("source_type", "path")
                    if stype == "path":
                        pid, ws = register_project(
                            self.store, self.data_dir, data.get("name")
                            or Path(data["path"]).name, "path", data["path"])
                    elif stype == "git":
                        pid, ws = register_project(
                            self.store, self.data_dir,
                            data.get("name") or "git_repo", "git",
                            data["git_url"])
                    else:
                        return h._json(400, {"error": f"未知来源 {stype}"})
            except (ValueError, KeyError) as e:
                return h._json(400, {"error": str(e)})
            return h._json(200, {"project_id": pid, "workspace": ws})

        if parts[:2] == ["api", "runs"] and len(parts) == 2:
            data = json.loads(body.decode("utf-8") or "{}")
            project = self.store.get_project(int(data.get("project_id", 0)))
            if not project:
                return h._json(404, {"error": "project not found"})
            params = {
                "profile": data.get("profile") or None,
                "svd": data.get("svd") or None,
                "triage": data.get("triage", "off"),
                "dynamic": bool(data.get("dynamic", False)),
                "no_build": bool(data.get("no_build", False)),
                "disable": data.get("disable") or [],
            }
            run_id = self.runner.submit(project["id"], params)
            return h._json(200, {"run_id": run_id})

        if parts[:2] == ["api", "alerts"] and len(parts) == 4 \
                and parts[3] == "status":
            data = json.loads(body.decode("utf-8") or "{}")
            ok = self.store.set_alert_status(int(parts[2]),
                                             data.get("status", ""))
            return h._json(200 if ok else 400,
                           {"ok": ok} if ok else {"error": "非法状态"})
        return h._json(404, {"error": "not found"})


def serve(data_dir: str | Path, port: int = 8600) -> None:
    WebUI(data_dir, port).serve()
