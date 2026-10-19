"""HTML 检测报告生成 —— L5 输出物之一（零依赖，内嵌样式）。

报告结构：执行摘要（统计面板）→ 合规记录（MISRA Compliance 框架）→
告警明细（含证据链，按严重级排序）。
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from ecdet import __version__
from ecdet.l5_report.aggregator import AggregationResult, ComplianceRecord

_CSS = """
:root { --bg:#f5f7fa; --card:#fff; --ink:#1f2933; --muted:#616e7c;
        --blue:#1f6feb; --red:#d1242f; --orange:#bf8700; --green:#1a7f37;
        --border:#e1e4e8; }
* { box-sizing: border-box; margin:0; padding:0; }
body { font-family:"Microsoft YaHei","Segoe UI",sans-serif; background:var(--bg);
       color:var(--ink); font-size:14px; line-height:1.6; padding:24px; }
.wrap { max-width: 1080px; margin: 0 auto; }
h1 { font-size:22px; margin-bottom:4px; }
.meta { color:var(--muted); font-size:12px; margin-bottom:20px; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:16px 0; }
.card { background:var(--card); border:1px solid var(--border); border-radius:8px;
        padding:14px 16px; }
.card .num { font-size:26px; font-weight:700; }
.card .lbl { color:var(--muted); font-size:12px; }
.num.error { color:var(--red); } .num.warning { color:var(--orange); }
.num.note { color:var(--blue); } .num.total { color:var(--ink); }
section { background:var(--card); border:1px solid var(--border); border-radius:8px;
          padding:16px; margin:16px 0; }
h2 { font-size:16px; margin-bottom:10px; border-left:4px solid var(--blue);
     padding-left:8px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border);
        vertical-align:top; }
th { background:#f0f3f6; font-weight:600; white-space:nowrap; }
tr:hover td { background:#f8fafc; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px;
         white-space:nowrap; }
.badge.error { background:#ffebe9; color:var(--red); }
.badge.warning { background:#fff8c5; color:#9a6700; }
.badge.note { background:#ddf4ff; color:#0969da; }
.badge.prov-proven { background:#dafbe1; color:var(--green); }
.badge.prov-detected { background:#ddf4ff; color:#0969da; }
.badge.prov-suspected { background:#fff1e5; color:#bc4c00; }
.badge.rule { background:#f0f3f6; color:var(--ink); }
.path { font-family:Consolas,monospace; font-size:12px; }
.evidence { margin-top:4px; color:var(--muted); font-size:12px; }
.evidence li { margin-left:16px; }
.ok { color:var(--green); font-weight:600; }
footer { color:var(--muted); font-size:12px; text-align:center; margin-top:20px; }
"""


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def render_html_report(result: AggregationResult,
                       records: list[ComplianceRecord],
                       project_name: str = "",
                       out_path: str | Path | None = None,
                       source_root: Path | None = None) -> str | None:
    """渲染 HTML 报告。out_path 提供时写文件。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    s = result.stats

    parts: list[str] = []
    parts.append(f"<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>")
    parts.append(f"<title>ecdet 检测报告 - {_esc(project_name or '工程')}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")
    parts.append(
        f"<h1>嵌入式代码检测报告{_esc(' — ' + project_name if project_name else '')}</h1>"
        f"<div class='meta'>ecdet v{__version__} · 生成时间 {now} · "
        f"引擎：{_esc('、'.join(s.get('by_engine', {}).keys()) or 'builtin')} · "
        f"告警 {s['total']} 条（去重后）</div>"
    )

    # 统计面板
    parts.append("<div class='grid'>")
    for num, label, cls in [
        (s["total"], "告警总数", "total"),
        (s["error"], "高危 error", "error"),
        (s["warning"], "中危 warning", "warning"),
        (s["note"], "低危 note", "note"),
    ]:
        parts.append(f"<div class='card'><div class='num {cls}'>{num}</div>"
                     f"<div class='lbl'>{label}</div></div>")
    parts.append("</div>")

    # 可证明性 + CWE 分布
    prov = s.get("by_provenance", {})
    parts.append("<section><h2>结论可证明性分布</h2><table>"
                 "<tr><th>级别</th><th>含义</th><th>数量</th><th>占比</th></tr>")
    prov_desc = {
        "proven": ("Proven", "健全引擎数学证明（阶段二引入抽象解释/模型检查后生效）"),
        "detected": ("Detected", "引擎检出且证据核对确认"),
        "suspected": ("Suspected", "疑似告警，需 LLM/人工评审"),
    }
    for k in ("proven", "detected", "suspected"):
        n = prov.get(k, 0)
        pct = f"{n / s['total'] * 100:.1f}%" if s["total"] else "0%"
        name, desc = prov_desc[k]
        parts.append(f"<tr><td><span class='badge prov-{k}'>{name}</span></td>"
                     f"<td>{desc}</td><td>{n}</td><td>{pct}</td></tr>")
    parts.append("</table></section>")

    cwe_rows = "".join(
        f"<tr><td>{_esc(c)}</td><td>{n}</td></tr>"
        for c, n in sorted(s.get("by_cwe", {}).items(),
                           key=lambda x: -x[1])[:15])
    if cwe_rows:
        parts.append(f"<section><h2>CWE 漏洞口径分布（Top 15）</h2>"
                     f"<table><tr><th>CWE</th><th>数量</th></tr>{cwe_rows}</table></section>")

    # 合规记录
    comp_rows = "".join(
        f"<tr><td>{_esc(r.rule_id)}</td><td>{_esc(r.category)}</td>"
        f"<td>{_esc(r.title)}</td>"
        f"<td>{'<span class=ok>合规</span>' if r.status == 'compliant' else '偏离'}</td>"
        f"<td>{r.violation_count}</td></tr>"
        for r in records)
    parts.append(f"<section><h2>规范合规记录（MISRA/CERT/ECDET）</h2>"
                 f"<table><tr><th>规则</th><th>类别</th><th>描述</th>"
                 f"<th>状态</th><th>违例数</th></tr>{comp_rows}</table></section>")

    # 告警明细
    parts.append("<section><h2>告警明细</h2><table>"
                 "<tr><th>#</th><th>位置</th><th>级别</th><th>规则（规范口径）</th>"
                 "<th>漏洞口径</th><th>说明与证据链</th><th>引擎</th></tr>")
    for i, c in enumerate(result.clusters, 1):
        a = c.primary
        loc = f"<span class='path'>{_esc(a.location.path)}</span>:{a.location.line}"
        cwes = "<br>".join(f"<span class='badge rule'>{_esc(x)}</span>" for x in c.cwes) or "—"
        ev_lines = "".join(
            f"<li>[{_esc(e.kind)}] {_esc(e.message)}"
            + (f"（{_esc(e.location.path)}:{e.location.line}）" if e.location else "")
            + "</li>"
            for e in a.evidence)
        evidence_html = f"<div class='evidence'><ul>{ev_lines}</ul></div>" if ev_lines else ""
        parts.append(
            f"<tr><td>{i}</td><td>{loc}</td>"
            f"<td><span class='badge {a.severity.value}'>{a.severity.value}</span><br>"
            f"<span class='badge prov-{c.provenance.value}'>{c.provenance.value}</span></td>"
            f"<td><span class='badge rule'>{_esc(c.primary.rule_id)}</span></td>"
            f"<td>{cwes}</td>"
            f"<td>{_esc(a.message)}{evidence_html}</td>"
            f"<td>{_esc('、'.join(c.engines))}</td></tr>"
        )
    parts.append("</table></section>")

    parts.append(f"<footer>ecdet v{__version__} · 嵌入式软件代码缺陷与安全漏洞检测系统 · "
                 f"报告基于静态分析产出，Suspected 级结论需结合评审确认</footer>")
    parts.append("</div></body></html>")
    doc = "\n".join(parts)

    if out_path:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(doc, encoding="utf-8")
        return out
    return None
