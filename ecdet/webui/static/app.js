/* ecdet 控制台前端逻辑（零依赖 vanilla JS） */
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEV_COLOR = { error:"#dc2626", warning:"#d97706", note:"#2563eb" };
const PROV_LABEL = { proven:"已证明", detected:"已检出", suspected:"待研判" };
const TRI_LABEL = { TRUE_POSITIVE:"真缺陷", FALSE_POSITIVE:"误报",
                    NEEDS_REVIEW:"待复核" };

async function api(method, url, body, rawCt) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    if (rawCt) { opt.body = body; opt.headers["Content-Type"] = rawCt; }
    else { opt.body = JSON.stringify(body);
           opt.headers["Content-Type"] = "application/json"; }
  }
  const r = await fetch(url, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
  return data;
}

let toastTimer = null;
function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.className = "", 2600);
}

/* ================= 总览 ================= */

function donut(sev) {
  const total = (sev.error||0) + (sev.warning||0) + (sev.note||0);
  const R = 52, C = 2 * Math.PI * R;
  let off = 0, segs = "";
  for (const [k, color] of [["error", SEV_COLOR.error],
                            ["warning", SEV_COLOR.warning],
                            ["note", SEV_COLOR.note]]) {
    const frac = total ? (sev[k]||0)/total : 0;
    if (frac > 0) {
      segs += `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${color}"
        stroke-width="20" stroke-dasharray="${(frac*C).toFixed(1)} ${C.toFixed(1)}"
        stroke-dashoffset="${(-off*C).toFixed(1)}"
        transform="rotate(-90 70 70)"/>`;
      off += frac;
    }
  }
  return `<svg width="140" height="140" viewBox="0 0 140 140">
    <circle cx="70" cy="70" r="${R}" fill="none" stroke="#f1f5f9" stroke-width="20"/>
    ${segs}
    <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800"
      fill="#0f172a">${total}</text>
    <text x="70" y="86" text-anchor="middle" font-size="11" fill="#94a3b8">
      告警总数</text></svg>`;
}

async function renderOverview(el) {
  el.innerHTML = `<div style="padding:30px"><span class="spin"></span> 加载中…</div>`;
  const s = await api("GET", "/api/summary");
  const sev = s.by_severity || {};
  const cards = [
    ["工程", s.projects, "#eff6ff", "#2563eb",
      '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="none" stroke="currentColor" stroke-width="2"/>'],
    ["已完成运行", s.runs_done, "#f0fdf4", "#16a34a",
      '<path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="M22 4L12 14l-3-3" fill="none" stroke="currentColor" stroke-width="2"/>'],
    ["告警总数", s.alerts_total, "#fffbeb", "#d97706",
      '<path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" fill="none" stroke="currentColor" stroke-width="2"/>'],
    ["高危 error", sev.error||0, "#fef2f2", "#dc2626",
      '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 8v5M12 16h.01" stroke="currentColor" stroke-width="2"/>'],
    ["待人工复核", s.pending_review, "#f5f3ff", "#7c3aed",
      '<path d="M9 11l3 3 8-8" fill="none" stroke="currentColor" stroke-width="2"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" fill="none" stroke="currentColor" stroke-width="2"/>'],
  ];
  el.innerHTML = `
    <div class="page-head"><div><h1>总览</h1>
      <div class="desc">工程、检测与复核的全局态势</div></div>
      <a class="btn" href="#/projects">＋ 注册工程</a></div>
    <div class="statgrid">${cards.map(([lbl, n, bg, fg, icon]) => `
      <div class="stat">
        <div class="ico" style="background:${bg};color:${fg}">
          <svg viewBox="0 0 24 24" fill="none">${icon}</svg></div>
        <div><div class="num">${n}</div><div class="lbl">${lbl}</div></div>
      </div>`).join("")}</div>
    <div class="grid-2-1">
      <div class="card"><h2>最近运行</h2><div id="ov-runs"></div></div>
      <div class="card"><h2>结论分布</h2>
        <div style="display:flex;gap:18px;align-items:center;">
          ${donut(sev)}
          <div class="legend">
            <div class="item"><span class="dot" style="background:${SEV_COLOR.error}"></span>error 高危<span class="n">${sev.error||0}</span></div>
            <div class="item"><span class="dot" style="background:${SEV_COLOR.warning}"></span>warning 中危<span class="n">${sev.warning||0}</span></div>
            <div class="item"><span class="dot" style="background:${SEV_COLOR.note}"></span>note 低危<span class="n">${sev.note||0}</span></div>
            <hr style="border:0;border-top:1px solid var(--line);width:100%">
            <div class="item"><span class="dot" style="background:#16a34a"></span>已证明/已检出<span class="n">${(s.by_provenance||{}).proven||0} / ${(s.by_provenance||{}).detected||0}</span></div>
            <div class="item"><span class="dot" style="background:#d97706"></span>待研判<span class="n">${(s.by_provenance||{}).suspected||0}</span></div>
          </div>
        </div></div>
    </div>`;
  const runsEl = $("ov-runs");
  if (!s.recent_runs.length) {
    runsEl.innerHTML = emptyGuide();
    return;
  }
  const names = {};
  (await api("GET", "/api/projects")).projects.forEach(p => names[p.id] = p.name);
  runsEl.innerHTML = `<table><thead><tr>
      <th>#</th><th>工程</th><th>状态</th><th>告警</th><th></th></tr></thead>
      <tbody>${s.recent_runs.map(r => {
        const st = r.stats || {};
        return `<tr class="click" onclick="location.hash='#/alerts?run=${r.id}'">
          <td>${r.id}</td><td>${esc(names[r.project_id] || r.project_id)}</td>
          <td><span class="badge ${r.status}">${r.status}</span></td>
          <td>${st.total ?? "—"}</td>
          <td><a class="link muted" href="/api/runs/${r.id}/report" target="_blank"
            onclick="event.stopPropagation()">HTML 报告</a></td></tr>`;
      }).join("")}</tbody></table>`;
}

function emptyGuide() {
  return `<div class="empty">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
    <div>还没有扫描记录，三步开始：</div>
    <ol class="steps">
      <li>进入 <b>工程管理</b>，用本地路径 / 上传压缩包 / Git 地址注册工程；</li>
      <li>点 <b>新建扫描</b>，选择参数后提交（可用 <span class="kbd">examples/demo_rtos</span> 体验）；</li>
      <li>在 <b>告警中心</b> 逐条研判：确认真缺陷或豁免误报。</li>
    </ol></div>`;
}

/* ================= 工程管理 ================= */

let curSource = "path";

async function renderProjects(el) {
  el.innerHTML = `
    <div class="page-head"><div><h1>工程管理</h1>
      <div class="desc">输入的单位是工程目录——三种来源统一归一为服务端可访问目录</div></div></div>
    <div class="card"><h2>注册分析工程</h2>
      <div class="tabs">
        <button id="tb-path" class="on" onclick="switchSrc('path')">本地路径</button>
        <button id="tb-upload" onclick="switchSrc('upload')">上传压缩包</button>
        <button id="tb-git" onclick="switchSrc('git')">Git 仓库</button>
      </div>
      <label>工程名称</label>
      <input type="text" id="p-name" placeholder="如 demo_rtos" style="max-width:320px">
      <div id="pane-path">
        <label>服务端工程路径（须包含 C/H 源文件）</label>
        <input type="text" id="p-path" placeholder="如 examples/demo_rtos" style="max-width:520px">
      </div>
      <div id="pane-upload" style="display:none">
        <label>zip / tar.gz 归档</label>
        <input type="file" id="p-file" accept=".zip,.gz,.tgz">
      </div>
      <div id="pane-git" style="display:none">
        <label>仓库地址（私有库带 token；@分支名 指定分支）</label>
        <input type="text" id="p-git" placeholder="https://github.com/owner/repo.git@main" style="max-width:520px">
      </div>
      <div style="margin-top:12px"><button class="btn" onclick="registerProject()">注册工程</button>
        <span class="muted" id="reg-msg" style="margin-left:10px"></span></div>
    </div>
    <div class="card"><h2>已注册工程</h2><div id="proj-list"></div></div>`;
  switchSrc("path");
  await loadProjectTable();
}

function switchSrc(t) {
  curSource = t;
  for (const k of ["path", "upload", "git"]) {
    $("pane-" + k).style.display = k === t ? "" : "none";
    $("tb-" + k).classList.toggle("on", k === t);
  }
}

async function registerProject() {
  const name = $("p-name").value.trim() || "未命名工程";
  try {
    if (curSource === "path") {
      await api("POST", "/api/projects",
        { name, source_type: "path", path: $("p-path").value.trim() });
    } else if (curSource === "git") {
      await api("POST", "/api/projects",
        { name, source_type: "git", git_url: $("p-git").value.trim() });
    } else {
      const f = $("p-file").files[0];
      if (!f) throw new Error("请选择归档文件");
      const buf = await f.arrayBuffer();
      await api("POST", "/api/projects?name=" + encodeURIComponent(name),
        new Uint8Array(buf), f.type || "application/zip");
    }
    toast("✓ 工程注册成功");
    loadProjectTable();
  } catch (e) { toast("✗ " + e.message, true); }
}

async function loadProjectTable() {
  const data = await api("GET", "/api/projects");
  const el = $("proj-list");
  if (!data.projects.length) {
    el.innerHTML = `<div class="empty">尚无工程。可在本仓库用
      <span class="kbd">examples/demo_rtos</span> 快速体验。</div>`;
    return;
  }
  el.innerHTML = `<table><thead><tr>
      <th>#</th><th>名称</th><th>来源</th><th>工作区</th><th>操作</th>
    </tr></thead><tbody>${data.projects.map(p => `
      <tr><td>${p.id}</td><td><b>${esc(p.name)}</b></td>
        <td><span class="badge pending">${p.source_type}</span></td>
        <td class="path">${esc(p.workspace)}</td>
        <td><button class="btn sm" onclick="openScanModal(${p.id},'${esc(p.name)}')">新建扫描</button></td>
      </tr>`).join("")}</tbody></table>`;
}

function openScanModal(pid, name) {
  $("modal-title").textContent = `新建扫描 — ${name}`;
  $("modal-body").innerHTML = `
    <label>行业 profile</label><select id="m-profile">
      <option value="">默认（全规则）</option>
      <option value="automotive">automotive</option>
      <option value="industrial">industrial</option></select>
    <label>SVD 文件（相对工程根，留空自动发现 *.svd）</label>
    <input type="text" id="m-svd" placeholder="chip.svd">
    <label>LLM 分诊</label><select id="m-triage">
      <option value="off">关闭</option><option value="mock">Mock（离线演示）</option>
      <option value="real">真实端点（env 配置）</option></select>
    <label>动态通道（fuzzing + 运行时监控，耗时显著增加）</label>
    <select id="m-dynamic"><option value="">关闭</option>
      <option value="1">开启</option></select>`;
  $("modal-ok").onclick = async () => {
    await api("POST", "/api/runs", { project_id: pid,
      profile: $("m-profile").value || null,
      svd: $("m-svd").value.trim() || null,
      triage: $("m-triage").value,
      dynamic: !!$("m-dynamic").value });
    closeModal();
    toast("✓ 扫描任务已提交");
    location.hash = "#/runs";
  };
  $("modal-mask").classList.add("open");
}
function closeModal() { $("modal-mask").classList.remove("open"); }

/* ================= 运行历史 ================= */

async function renderRuns(el) {
  el.innerHTML = `<div class="page-head"><div><h1>扫描运行</h1>
    <div class="desc">后台队列串行执行 · 进行中的任务每 2 秒自动刷新</div></div></div>
    <div class="card"><div id="runs-table"><span class="spin"></span> 加载中…</div></div>`;
  await loadRunsTable();
}

async function loadRunsTable() {
  const [runsData, projData] = await Promise.all([
    api("GET", "/api/runs"), api("GET", "/api/projects")]);
  const names = {};
  projData.projects.forEach(p => names[p.id] = p.name);
  const el = $("runs-table");
  if (!runsData.runs.length) {
    el.innerHTML = `<div class="empty">暂无运行记录。到
      <a href="#/projects" class="link">工程管理</a> 新建扫描。</div>`;
    return;
  }
  el.innerHTML = `<table><thead><tr>
      <th>#</th><th>工程</th><th>状态</th><th>error</th><th>warning</th>
      <th>note</th><th>构建通道</th><th>耗时</th><th>产物</th>
    </tr></thead><tbody>${runsData.runs.map(r => {
      const s = r.stats || {};
      const dur = r.finished_at && r.started_at
        ? (r.finished_at - r.started_at).toFixed(1) + "s" : "—";
      const arts = r.status === "done"
        ? `<a class="link" href="#" onclick="location.hash='#/alerts?run=${r.id}';return false;">告警</a> ·
           <a class="link" href="/api/runs/${r.id}/report" target="_blank">HTML</a> ·
           <a class="link" href="/api/runs/${r.id}/sarif" target="_blank">SARIF</a>`
        : (r.error ? `<span class="muted" title="${esc(r.error)}">失败</span>` : "—");
      return `<tr class="click" onclick="location.hash='#/alerts?run=${r.id}'">
        <td>${r.id}</td><td>${esc(names[r.project_id] || r.project_id)}</td>
        <td><span class="badge ${r.status}">${r.status}</span></td>
        <td><b style="color:${SEV_COLOR.error}">${s.error ?? "—"}</b></td>
        <td>${s.warning ?? "—"}</td><td>${s.note ?? "—"}</td>
        <td class="muted">${esc(s.build_method || "")}</td>
        <td>${dur}</td><td>${arts}</td></tr>`;
    }).join("")}</tbody></table>`;
  const active = runsData.runs.some(r => ["pending","running"].includes(r.status));
  clearTimeout(loadRunsTable._t);
  if (active) loadRunsTable._t = setTimeout(loadRunsTable, 2000);
}

/* ================= 告警中心 ================= */

let alertsRun = null;

async function renderAlerts(el, query) {
  const runs = (await api("GET", "/api/runs")).runs.filter(r => r.status === "done");
  alertsRun = query.run ? Number(query.run) : (runs[0] ? runs[0].id : null);
  el.innerHTML = `
    <div class="page-head"><div><h1>告警中心</h1>
      <div class="desc">逐条研判：确认真缺陷或豁免误报，状态落库</div></div></div>
    ${runs.length ? "" : `<div class="card">${emptyGuide()}</div>`}
    <div class="card" ${runs.length ? "" : 'style="display:none"'}>
      <div class="filters" style="display:flex;gap:8px;margin-bottom:10px">
        <select id="a-run" onchange="alertsRun=Number(this.value);loadAlerts()"
          style="max-width:240px">
          ${runs.map(r => `<option value="${r.id}" ${r.id===alertsRun?"selected":""}>
            运行 #${r.id}</option>`).join("")}
        </select>
        <select id="a-sev" onchange="loadAlerts()" style="max-width:130px">
          <option value="">全部级别</option><option value="error">error</option>
          <option value="warning">warning</option><option value="note">note</option></select>
        <select id="a-status" onchange="loadAlerts()" style="max-width:130px">
          <option value="">全部状态</option><option value="pending">待处理</option>
          <option value="confirmed">已确认</option>
          <option value="dismissed">已豁免</option></select>
        <input type="text" id="a-q" placeholder="搜索说明 / 路径…"
          oninput="clearTimeout(this._t);this._t=setTimeout(loadAlerts,300)">
      </div>
      <div id="alert-stat" class="muted" style="margin-bottom:6px"></div>
      <div id="alert-table"></div>
    </div>`;
  if (alertsRun) loadAlerts();
}

async function loadAlerts() {
  const q = new URLSearchParams({ severity: $("a-sev").value,
    status: $("a-status").value, q: $("a-q").value });
  const data = await api("GET", `/api/runs/${alertsRun}/alerts?` + q);
  const el = $("alert-table");
  $("alert-stat").textContent = `筛选结果 ${data.alerts.length} 条`;
  if (!data.alerts.length) {
    el.innerHTML = `<div class="empty">当前筛选条件下没有告警。</div>`;
    return;
  }
  el.innerHTML = `<table><thead><tr>
      <th>位置</th><th>级别</th><th>规则</th><th>结论</th><th>复核</th>
    </tr></thead><tbody>${data.alerts.map(a => `
      <tr class="click" onclick="openAlert(${a.id})">
        <td><span class="path">${esc(a.path)}</span>:${a.line}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span>
            <span class="badge ${a.provenance}">${PROV_LABEL[a.provenance]||a.provenance}</span></td>
        <td>${esc(a.rule_id)}${a.cwe?`<br><span class="muted">${esc(a.cwe)}</span>`:""}</td>
        <td>${a.triage?`<span class="badge ${a.triage.verdict}">${TRI_LABEL[a.triage.verdict]||a.triage.verdict}</span>`:'<span class="muted">—</span>'}</td>
        <td><span class="badge ${a.status}">${
          {pending:"待处理",confirmed:"已确认",dismissed:"已豁免"}[a.status]}</span></td>
      </tr>`).join("")}</tbody></table>`;
}

async function openAlert(id) {
  const a = await api("GET", "/api/alerts/" + id);
  $("drawer-title").innerHTML =
    `<span class="badge ${a.severity}">${a.severity}</span>
     <span class="badge ${a.provenance}">${PROV_LABEL[a.provenance]||a.provenance}</span>
     <span class="path" style="margin-left:6px">${esc(a.path)}:${a.line}</span>`;
  const tri = a.triage ? `
    <div class="card" style="margin:12px 0;background:var(--orange-soft);border-color:transparent">
      <b style="font-size:12.5px">LLM 分诊：${TRI_LABEL[a.triage.verdict]||a.triage.verdict}
      （置信度 ${(a.triage.confidence??0).toFixed(2)}${a.triage.verified?"，证据已核对":""}
      ${a.triage.used_rag?"，RAG 重判":""}）</b>
      <div class="muted" style="margin-top:4px">${esc(a.triage.reason||"")}</div></div>` : "";
  const ev = (a.evidence||[]).map(e => `
    <div class="evi"><span class="k">${esc(e.kind)}</span>${esc(e.message)}
      ${e.path?`<div class="muted path">${esc(e.path)}:${e.line??""}</div>`:""}</div>`).join("")
    || '<div class="muted">无结构化证据</div>';
  $("drawer-body").innerHTML = `
    <div class="kv"><b>规则</b>${esc(a.rule_id)}</div>
    <div class="kv"><b>CWE</b>${esc(a.cwe||"未标注")}</div>
    <div class="kv"><b>引擎</b>${esc(a.engine)}</div>
    <div class="kv"><b>说明</b>${esc(a.message)}</div>
    ${tri}
    <h2 style="font-size:13px;margin:14px 0 4px">证据链</h2>${ev}
    <div style="display:flex;gap:8px;margin-top:16px" id="alert-actions">
      <button class="btn sm green" onclick="markAlert(${a.id},'confirmed')">✓ 确认真缺陷</button>
      <button class="btn sm gray" onclick="markAlert(${a.id},'dismissed')">豁免（误报/不适用）</button>
      <button class="btn sm ghost" onclick="markAlert(${a.id},'pending')">重置待处理</button>
    </div>
    <div class="muted" style="margin-top:10px">当前状态：
      <span class="badge ${a.status}">${{pending:"待处理",confirmed:"已确认",dismissed:"已豁免"}[a.status]}</span></div>`;
  $("drawer").classList.add("open");
  $("drawer-mask").classList.add("open");
}

function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer-mask").classList.remove("open");
}

async function markAlert(id, status) {
  await api("POST", `/api/alerts/${id}/status`, { status });
  toast(status === "confirmed" ? "已确认真缺陷" :
        status === "dismissed" ? "已豁免" : "已重置为待处理");
  closeDrawer();
  loadAlerts();
}

/* ================= 路由 ================= */

async function route() {
  const hash = location.hash || "#/overview";
  const [path, qs] = hash.slice(1).split("?");
  const name = path.replace(/^\//, "") || "overview";
  const query = Object.fromEntries(new URLSearchParams(qs || ""));
  document.querySelectorAll("nav a").forEach(a =>
    a.classList.toggle("on", a.dataset.route === name));
  const el = $("main");
  try {
    if (name === "projects") await renderProjects(el);
    else if (name === "runs") await renderRuns(el);
    else if (name === "alerts") await renderAlerts(el, query);
    else await renderOverview(el);
  } catch (e) {
    el.innerHTML = `<div class="card"><div class="empty">加载失败：${esc(e.message)}</div></div>`;
  }
}
window.addEventListener("hashchange", route);
route();
