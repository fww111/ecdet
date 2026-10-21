# -*- coding: utf-8 -*-
"""Web 控制台测试：三源注册 / 后台扫描 / API 全流程。"""

import io
import json
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

from ecdet.webui import Store, WebUI

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture()
def ui(tmp_path):
    ui = WebUI(tmp_path / "data", port=0)
    httpd = ui.make_server()
    thread = threading_start(httpd)
    # 端口 0 → 实际端口取回
    port = httpd.server_address[1]
    yield ui, f"http://127.0.0.1:{port}"
    httpd.shutdown()


def threading_start(httpd):
    t = __import__("threading").Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return t


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(base, path, payload=None, raw=None, ctype="application/json"):
    if raw is not None:
        body = raw
    else:
        body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(base + path, data=body, method="POST",
                                 headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _wait_run(base, run_id, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = _get(base, f"/api/runs/{run_id}")
        if run["status"] in ("done", "failed"):
            return run
        time.sleep(0.5)
    raise TimeoutError("scan run timeout")


# ---------------- Store 单元 ----------------


def test_store_roundtrip(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    pid = store.add_project("p1", "path", "ref", "ws")
    run_id = store.add_run(pid, {"triage": "off"})
    store.set_run_status(run_id, "running")
    store.put_alerts(run_id, [
        {"rule_id": "R1", "engine": "builtin", "severity": "error",
         "path": "a.c", "line": 3, "message": "m1", "cwe": "CWE-1",
         "provenance": "detected", "fingerprint": "fp1"},
        {"rule_id": "R2", "engine": "dynamic", "severity": "warning",
         "path": "b.c", "line": 9, "message": "m2", "cwe": None,
         "provenance": "suspected", "fingerprint": "fp2",
         "triage": {"verdict": "TRUE_POSITIVE"}},
    ])
    alerts = store.list_alerts(run_id)
    assert len(alerts) == 2
    assert alerts[0]["rule_id"] == "R1"          # error 排前
    assert store.list_alerts(run_id, severity="warning")[0]["rule_id"] == "R2"
    assert store.list_alerts(run_id, q="m1")[0]["rule_id"] == "R1"
    assert store.set_alert_status(alerts[0]["id"], "confirmed")
    assert store.list_alerts(run_id, status="confirmed")[0]["rule_id"] == "R1"
    assert not store.set_alert_status(alerts[0]["id"], "bogus")
    counts = store.alert_counts(run_id)
    assert counts["by_severity"]["error"] == 1
    assert counts["by_status"]["confirmed"] == 1


def test_store_local_overrides_global(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.put_alerts(1, [
        {"rule_id": "R", "engine": "e", "severity": "note", "path": "a.c",
         "line": 1, "message": "x", "cwe": None, "provenance": "detected",
         "fingerprint": ""}])
    assert store.list_alerts(1)[0]["status"] == "pending"


# ---------------- 注册归一 ----------------


def test_register_path_source(ui):
    ui_obj, base = ui
    resp = _post(base, "/api/projects",
                 {"name": "demo", "source_type": "path",
                  "path": str(EXAMPLES / "demo_rtos")})
    assert resp["project_id"] >= 1
    projects = _get(base, "/api/projects")["projects"]
    assert any(p["name"] == "demo" for p in projects)


def test_register_path_missing(ui):
    _, base = ui
    req = urllib.request.Request(
        base + "/api/projects",
        data=json.dumps({"name": "x", "source_type": "path",
                         "path": "Z:/no/such/dir"}).encode(),
        method="POST", headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("应返回 400")
    except urllib.error.HTTPError as e:
        assert e.code == 400


def test_register_upload_zip(ui):
    ui_obj, base = ui
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pkg/src/main.c", "int main(void) { return 0; }\n")
        zf.writestr("pkg/src/../evil.c", "bad")   # 路径逃逸应被过滤
    resp = _post(base, "/api/projects?name=zipped", raw=buf.getvalue(),
                 ctype="application/zip")
    ws = Path(resp["workspace"])
    assert (ws / "pkg" / "src" / "main.c").exists()
    assert not (ws / "evil.c").exists() and not (ws / "pkg" / "evil.c").exists()


def test_register_upload_no_sources(ui):
    _, base = ui
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "no code here")
    req = urllib.request.Request(
        base + "/api/projects?name=empty", data=buf.getvalue(), method="POST",
        headers={"Content-Type": "application/zip"})
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("应返回 400")
    except urllib.error.HTTPError as e:
        assert e.code == 400


# ---------------- 扫描全流程（API） ----------------


def test_full_scan_flow(ui):
    ui_obj, base = ui
    reg = _post(base, "/api/projects",
                {"name": "demo", "source_type": "path",
                 "path": str(EXAMPLES / "demo_rtos")})
    run = _post(base, "/api/runs", {"project_id": reg["project_id"],
                                    "triage": "off"})
    done = _wait_run(base, run["run_id"])
    assert done["status"] == "done", done.get("error")
    assert done["stats"]["total"] > 0
    assert done["alert_counts"]["by_severity"].get("error", 0) >= 1

    alerts = _get(base, f"/api/runs/{run['run_id']}/alerts")["alerts"]
    assert len(alerts) == done["stats"]["total"]
    assert any(a["rule_id"] == "CERT C STR31-C" for a in alerts)

    # 筛选
    only_err = _get(base,
                    f"/api/runs/{run['run_id']}/alerts?severity=error")["alerts"]
    assert all(a["severity"] == "error" for a in only_err)

    # 状态流转
    aid = alerts[0]["id"]
    _post(base, f"/api/alerts/{aid}/status", {"status": "confirmed"})
    got = _get(base, f"/api/runs/{run['run_id']}/alerts?status=confirmed")["alerts"]
    assert any(a["id"] == aid for a in got)

    # 报告产物可访问
    with urllib.request.urlopen(
            base + f"/api/runs/{run['run_id']}/report", timeout=10) as r:
        html = r.read().decode("utf-8")
        assert "嵌入式代码检测报告" in html
    with urllib.request.urlopen(
            base + f"/api/runs/{run['run_id']}/sarif", timeout=10) as r:
        sarif = json.loads(r.read().decode("utf-8"))
        assert sarif["version"] == "2.1.0"

    # 运行列表
    runs = _get(base, f"/api/runs?project_id={reg['project_id']}")["runs"]
    assert runs and runs[0]["id"] == run["run_id"]


def test_full_scan_with_mock_triage(ui):
    ui_obj, base = ui
    reg = _post(base, "/api/projects",
                {"name": "demo2", "source_type": "path",
                 "path": str(EXAMPLES / "demo_rtos")})
    run = _post(base, "/api/runs", {"project_id": reg["project_id"],
                                    "triage": "mock"})
    done = _wait_run(base, run["run_id"])
    assert done["status"] == "done"
    alerts = _get(base, f"/api/runs/{run['run_id']}/alerts?severity=error")["alerts"]
    triaged = [a for a in alerts if a["triage"]]
    assert triaged, "Mock 分诊后 error 级告警应携带 triage 结论"


def test_carriers_endpoint(ui):
    _, base = ui
    data = _get(base, "/api/carriers")
    names = {c["name"] for c in data["carriers"]}
    assert names == {"host", "unicorn", "renode"}


def test_index_page(ui):
    _, base = ui
    with urllib.request.urlopen(base + "/", timeout=10) as r:
        html = r.read().decode("utf-8")
        assert "ecdet 控制台" in html


# ---------------- V0.9：总览聚合 / 告警详情（证据链） / 静态资源 ----------------


def test_summary_and_alert_detail(ui):
    ui_obj, base = ui
    reg = _post(base, "/api/projects",
                {"name": "demo", "source_type": "path",
                 "path": str(EXAMPLES / "demo_rtos")})
    run = _post(base, "/api/runs", {"project_id": reg["project_id"],
                                    "triage": "mock"})
    done = _wait_run(base, run["run_id"])
    assert done["status"] == "done"

    s = _get(base, "/api/summary")
    assert s["projects"] >= 1 and s["runs_done"] >= 1
    assert s["alerts_total"] == done["stats"]["total"]
    assert set(s["by_severity"]) <= {"error", "warning", "note"}
    assert len(s["recent_runs"]) >= 1

    alerts = _get(base, f"/api/runs/{run['run_id']}/alerts?severity=error")["alerts"]
    detail = _get(base, f"/api/alerts/{alerts[0]['id']}")
    assert detail["rule_id"] == alerts[0]["rule_id"]
    assert isinstance(detail["evidence"], list)
    assert any("证据" in e["message"] or e["message"] for e in detail["evidence"])


def test_static_assets_served(ui):
    _, base = ui
    for path, marker in (("/static/style.css", "--sidebar"),
                         ("/static/app.js", "ecdet")):
        with urllib.request.urlopen(base + path, timeout=10) as r:
            body = r.read().decode("utf-8")
            assert marker in body
    try:
        urllib.request.urlopen(base + "/static/../secrets", timeout=10)
    except urllib.error.HTTPError as e:
        assert e.code in (400, 404)


# ---------------- V1.0：设置 / 一键修复 ----------------


def test_settings_roundtrip_mask(ui):
    _, base = ui
    _post(base, "/api/settings", {"llm_mode": "real",
                                  "llm_base_url": "http://127.0.0.1:9/v1",
                                  "llm_api_key": "sk-test-1234",
                                  "llm_model": "test-model"})
    s = _get(base, "/api/settings")
    assert s["llm_mode"] == "real"
    assert s["llm_base_url"] == "http://127.0.0.1:9/v1"
    assert s["llm_model"] == "test-model"
    assert s["api_key_set"] is True
    assert "1234" in s["api_key_masked"] and "sk-test" not in s["api_key_masked"]
    # 空 key 不覆盖旧值
    _post(base, "/api/settings", {"llm_model": "model-2"})
    s2 = _get(base, "/api/settings")
    assert s2["llm_model"] == "model-2" and s2["api_key_set"] is True


def test_settings_test_endpoint(ui):
    """测试连接：起一个 OpenAI 格式的假端点验证探针回路。"""
    ui_obj, base = ui
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class FakeOpenAI(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = b'{"choices":[{"message":{"content":"pong"}}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        _post(base, "/api/settings", {"llm_mode": "real",
                                      "llm_base_url": f"http://127.0.0.1:{port}/v1",
                                      "llm_api_key": "sk-x",
                                      "llm_model": "fake"})
        r = _post(base, "/api/settings/test")
        assert r["ok"] is True and "pong" in r["message"]
    finally:
        httpd.shutdown()


def test_one_click_fix_flow(ui):
    """扫描（Mock 分诊）→ 一键修复 → 采纳补丁含 diff（STR31→strncpy）。"""
    _, base = ui
    reg = _post(base, "/api/projects",
                {"name": "fixdemo", "source_type": "path",
                 "path": str(EXAMPLES / "demo_rtos")})
    run = _post(base, "/api/runs", {"project_id": reg["project_id"],
                                    "triage": "mock"})
    done = _wait_run(base, run["run_id"])
    assert done["status"] == "done"

    job = _post(base, f"/api/runs/{run['run_id']}/fix")
    assert job["job_id"] >= 1
    deadline = time.time() + 120
    while time.time() < deadline:
        data = _get(base, f"/api/runs/{run['run_id']}/fixes")
        j = data["job"]
        if j and j["status"] in ("done", "failed"):
            break
        time.sleep(0.5)
    assert j["status"] == "done", j.get("error")
    assert j["accepted"] >= 1
    str31 = [p for p in data["proposals"]
             if p["rule_id"] == "CERT C STR31-C" and p["verified"]]
    assert str31, "STR31 正确补丁应被验证采纳"
    assert "strncpy" in str31[0]["diff"]

    # 告警详情接口携带 run_id（抽屉按 alert_id 匹配补丁）
    alerts = _get(base, f"/api/runs/{run['run_id']}/alerts")["alerts"]
    target = next(a for a in alerts if a["rule_id"] == "CERT C STR31-C")
    detail = _get(base, f"/api/alerts/{target['id']}")
    assert detail["run_id"] == run["run_id"]


def test_targeted_fix_by_alert_ids(ui):
    """勾选定向修复：只修选中的告警，且原文件内容保持不变。"""
    _, base = ui
    reg = _post(base, "/api/projects",
                {"name": "tf", "source_type": "path",
                 "path": str(EXAMPLES / "demo_rtos")})
    run = _post(base, "/api/runs", {"project_id": reg["project_id"],
                                    "triage": "mock"})
    done = _wait_run(base, run["run_id"])
    assert done["status"] == "done"

    alerts = _get(base, f"/api/runs/{run['run_id']}/alerts")["alerts"]
    str31 = next(a for a in alerts if a["rule_id"] == "CERT C STR31-C")
    target_file = EXAMPLES / "demo_rtos" / "src" / "sensor.c"
    before = target_file.read_bytes()

    # 只勾 STR31 与 ARR30 两条
    arr30 = next(a for a in alerts if a["rule_id"] == "CERT C ARR30-C")
    job = _post(base, f"/api/runs/{run['run_id']}/fix",
                {"alert_ids": [str31["id"], arr30["id"]]})
    deadline = time.time() + 120
    data = {}
    while time.time() < deadline:
        data = _get(base, f"/api/runs/{run['run_id']}/fixes")
        if data["job"] and data["job"]["status"] in ("done", "failed"):
            break
        time.sleep(0.5)
    assert data["job"]["status"] == "done", data["job"].get("error")
    assert len(data["proposals"]) == 2, "只应生成勾选的 2 条建议"
    assert {p["rule_id"] for p in data["proposals"]} ==         {"CERT C STR31-C", "CERT C ARR30-C"}

    # 原文件一个字节都不能变（修复只生成补丁不落盘）
    assert target_file.read_bytes() == before
