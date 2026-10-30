/* ecdet 控制台前端逻辑（零依赖 vanilla JS）
 * v1.2：代码浏览（SonarQube Code 式）+ 版本对比（GitHub diff + 告警差分）
 *       + facet 筛选 + 抽屉代码上下文。无任何外链库，离线可用。 */
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEV_COLOR = { error:"#dc2626", warning:"#d97706", note:"#2563eb" };
const PROV_LABEL = { proven:"已证明", detected:"已检出", suspected:"待研判" };
const TRI_LABEL = { TRUE_POSITIVE:"真缺陷", FALSE_POSITIVE:"误报",
                    NEEDS_REVIEW:"待复核" };
const STATUS_LABEL = { pending:"待处理", confirmed:"已确认",
                       dismissed:"已豁免" };
const FMOD_LABEL = { added:"新增", modified:"修改", deleted:"删除" };

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

function pageHead(title, desc, rightHtml) {
  return `<div class="page-head"><div><h1>${title}</h1>
    <div class="desc">${desc}</div></div>${rightHtml || ""}</div>`;
}

async function loadDoneRuns() {
  const [runsD, projD] = await Promise.all([
    api("GET", "/api/runs"), api("GET", "/api/projects")]);
  const names = {};
  projD.projects.forEach(p => names[p.id] = p.name);
  const runs = runsD.runs.filter(r => r.status === "done");
  return { runs, names };
}

function runOptionLabel(r, names) {
  return `运行 #${r.id} · ${esc(names[r.project_id] || r.project_id)}`;
}

/* ============ C 语法高亮（自研逐行状态机，支持跨行块注释） ============ */

const C_KW = new Set(("if else for while do switch case default break "
  + "continue return goto sizeof static extern const volatile register "
  + "auto signed unsigned void int char float double short long struct "
  + "union enum typedef inline restrict _Bool").split(" "));
const C_TYP = new Set(("uint8_t uint16_t uint32_t uint64_t int8_t int16_t "
  + "int32_t int64_t size_t ssize_t ptrdiff_t bool FILE uintptr_t intptr_t "
  + "u8 u16 u32 u64 s8 s16 s32 s64").split(" "));

const _span = (cls, t) => `<span class="${cls}">${esc(t)}</span>`;

function highlightCLines(lines) {
  const out = [];
  let inBlock = false;
  for (const s of lines) {
    let html = "", i = 0;
    const n = s.length;
    while (i < n) {
      if (inBlock) {
        const end = s.indexOf("*/", i);
        if (end < 0) { html += _span("tk-com", s.slice(i)); i = n; }
        else { html += _span("tk-com", s.slice(i, end + 2));
               i = end + 2; inBlock = false; }
        continue;
      }
      const c = s[i];
      if (c === "/" && s[i + 1] === "/") {
        html += _span("tk-com", s.slice(i)); break;
      }
      if (c === "/" && s[i + 1] === "*") {
        inBlock = true; html += _span("tk-com", "/*"); i += 2; continue;
      }
      if (c === "#" ) {
        const rest = s.slice(i);
        const ci = rest.indexOf("//");
        html += ci < 0 ? _span("tk-pre", rest)
          : _span("tk-pre", rest.slice(0, ci)) + _span("tk-com",
                                                    rest.slice(ci));
        break;
      }
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < n && s[j] !== c) { if (s[j] === "\\") j++; j++; }
        html += _span("tk-str", s.slice(i, Math.min(j + 1, n)));
        i = j + 1; continue;
      }
      if (/[0-9]/.test(c) && !/[A-Za-z_]/.test(s[i - 1] || "")) {
        let j = i;
        while (j < n && /[0-9a-fA-FxXuUlL.]/.test(s[j])) j++;
        html += _span("tk-num", s.slice(i, j)); i = j; continue;
      }
      if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < n && /[A-Za-z0-9_]/.test(s[j])) j++;
        const word = s.slice(i, j);
        html += C_KW.has(word) ? _span("tk-kw", word)
          : C_TYP.has(word) ? _span("tk-typ", word) : esc(word);
        i = j; continue;
      }
      html += esc(c); i++;
    }
    out.push(html);
  }
  return out;
}

/* ============ diff 渲染（统一 / 并排共用一套结构化行） ============ */

function markOf(al) {
  if (!al || !al.length) return `<span class="df-mark"></span>`;
  return `<span class="df-mark ${al[0].severity}" title="${esc(al[0].rule_id)}"
    onclick="event.stopPropagation();openAlert(${al[0].id})">●</span>`;
}

/* mod 行词级差异：公共前后缀外的高亮 */
function wordMark(oldS, newS, side) {
  let s = 0;
  const lo = oldS.length, ln = newS.length;
  while (s < lo && s < ln && oldS[s] === newS[s]) s++;
  let e = 0;
  while (e < lo - s && e < ln - s && oldS[lo - 1 - e] === newS[ln - 1 - e]) e++;
  const head = side === "old" ? oldS.slice(0, s) : newS.slice(0, s);
  const mid = side === "old" ? oldS.slice(s, lo - e) : newS.slice(s, ln - e);
  const tail = side === "old" ? oldS.slice(lo - e) : newS.slice(ln - e);
  return esc(head) + `<mark>${esc(mid)}</mark>` + esc(tail);
}

function diffRowsHtml(d) {
  const mode = d.mode;
  const oldBy = {}, newBy = {};
  (d.old_alerts || []).forEach(a => (oldBy[a.line] = oldBy[a.line] || []).push(a));
  (d.new_alerts || []).forEach(a => (newBy[a.line] = newBy[a.line] || []).push(a));
  const hlOld = highlightCLines(d.old_lines || []);
  const hlNew = highlightCLines(d.new_lines || []);
  const code = (text, hl) => text == null ? "&nbsp;"
    : (hl || esc(text) || "&nbsp;");

  if (!d.rows) {
    return `<div class="df-skipped">文件超过行级对比上限（${
      (d.old_lines || []).length + (d.new_lines || []).length} 行），已降级展示。</div>`;
  }
  if (!d.rows.length) {
    return `<div class="df-skipped">行内容完全一致——本次修改只涉及行尾/编码差异。</div>`;
  }
  if (mode === "split") {
    return d.rows.map(r => {
      const left = r.old == null
        ? `<span class="df-no"></span><span class="df-mark"></span>
           <span class="df-code"></span>`
        : `<span class="df-no">${r.a ?? ""}</span>${markOf(oldBy[r.a])}
           <span class="df-code ${r.t === "mod" ? "old" : ""}">${
             r.t === "mod" ? wordMark(r.old, r.new, "old")
                           : code(r.old, hlOld[r.a - 1])}</span>`;
      const right = r.new == null
        ? `<span class="df-no"></span><span class="df-mark"></span>
           <span class="df-code"></span>`
        : `<span class="df-no">${r.b ?? ""}</span>${markOf(newBy[r.b])}
           <span class="df-code ${r.t === "mod" ? "new" : ""}">${
             r.t === "mod" ? wordMark(r.old, r.new, "new")
                           : code(r.new, hlNew[r.b - 1])}</span>`;
      return `<div class="df-row ${r.t === "mod" ? "r-mod" : "r-" + r.t}">
        ${left}${right}</div>`;
    }).join("");
  }
  // unified：mod 展开为 -old / +new 两行
  const rows = [];
  for (const r of d.rows) {
    if (r.t === "mod") {
      rows.push({ t: "del", no: r.a, text: r.old, hl: hlOld[r.a - 1],
                  al: oldBy[r.a], side: "old" });
      rows.push({ t: "add", no: r.b, text: r.new, hl: hlNew[r.b - 1],
                  al: newBy[r.b], side: "new" });
    } else if (r.t === "del") {
      rows.push({ t: "del", no: r.a, text: r.old, hl: hlOld[r.a - 1],
                  al: oldBy[r.a], side: "old" });
    } else if (r.t === "add") {
      rows.push({ t: "add", no: r.b, text: r.new, hl: hlNew[r.b - 1],
                  al: newBy[r.b], side: "new" });
    } else {
      rows.push({ t: "ctx", no: r.b, text: r.new, hl: hlNew[r.b - 1],
                  al: newBy[r.b], side: "new" });
    }
  }
  return rows.map(r => `
    <div class="df-row r-${r.t}"><span class="df-no">${r.no ?? ""}</span>${
      markOf(r.al)}<span class="df-code">${
      code(r.text, r.hl)}</span></div>`).join("");
}

function diffToolbar(d) {
  return `<div class="seg">
    <button class="${d.mode !== "split" ? "on" : ""}"
      onclick="setDiffMode('${d.path}','unified')">统一</button>
    <button class="${d.mode === "split" ? "on" : ""}"
      onclick="setDiffMode('${d.path}','split')">并排</button>
  </div>`;
}

/* ============ 代码浏览（SonarQube Code 式） ============ */

let codeState = { runId: null, path: null, alertIdx: 0 };

async function renderCode(el, query) {
  el.innerHTML = `<div style="padding:30px"><span class="spin"></span> 加载中…</div>`;
  const { runs, names } = await loadDoneRuns();
  if (!runs.length) {
    el.innerHTML = pageHead("代码浏览", "以文件为中心查看整文件源码与告警行标注") +
      `<div class="card">${emptyGuide()}</div>`;
    return;
  }
  const projIds = [...new Set(runs.map(r => r.project_id))];
  codeState.runId = query.run ? Number(query.run) : runs[0].id;
  const curRun = runs.find(r => r.id === codeState.runId) || runs[0];
  el.innerHTML = `
    ${pageHead("代码浏览", "以文件为中心：整文件源码 + 告警行标注（数据来自本运行的源码快照）")}
    <div class="card"><div class="ctx-bar">
      <select id="cd-proj" onchange="codePickProject()">
        ${projIds.map(p => `<option value="${p}" ${p === curRun.project_id ? "selected" : ""}>${esc(names[p])}</option>`).join("")}
      </select>
      <select id="cd-run" onchange="codePickRun(Number(this.value))">
        ${runs.filter(r => r.project_id === curRun.project_id)
          .map(r => `<option value="${r.id}" ${r.id === codeState.runId ? "selected" : ""}>${runOptionLabel(r, names)}</option>`).join("")}
      </select>
      <span class="grow"></span><span id="cd-snap" class="snap-info"></span>
    </div></div>
    <div id="cd-body"></div>`;
  await loadCodeBody(query);
}

function codePickProject() {
  const pid = Number($("cd-proj").value);
  codeState.runId = null;
  api("GET", "/api/runs?project_id=" + pid).then(d => {
    const done = d.runs.filter(r => r.status === "done");
    if (!done.length) { toast("该工程暂无已完成运行", true); return; }
    codeState.runId = done[0].id;
    codeState.path = null;
    $("cd-run").innerHTML = done.map(r =>
      `<option value="${r.id}">运行 #${r.id}</option>`).join("");
    loadCodeBody({});
  });
}

function codePickRun(runId) {
  codeState.runId = runId;
  codeState.path = null;
  loadCodeBody({});
}

async function loadCodeBody(query) {
  const body = $("cd-body");
  if (!body) return;
  const files = await api("GET", `/api/runs/${codeState.runId}/files`);
  if (!files.snapshot) {
    body.innerHTML = `<div class="card"><div class="empty">
      本运行没有源码快照（v1.2 之前的运行）。<br>重新扫描一次即可开启代码浏览与版本对比。</div></div>`;
    return;
  }
  $("cd-snap").innerHTML = `<b>${files.snapshot.files}</b> 个源文件 ·
    ${(files.snapshot.bytes / 1024).toFixed(0)} KB
    ${files.snapshot.skipped ? `· 跳过 ${files.snapshot.skipped}` : ""}`;
  const pick = query.path ||
    (files.files.slice().sort((a, b) => b.alerts - a.alerts)[0] || {}).path;
  const treeHtml = fileTreeHtml(files.files, pick);
  body.innerHTML = `<div class="code-layout">
    <div class="ftree" id="cd-tree">${treeHtml}</div>
    <div class="codepane" id="cd-pane"><div style="padding:26px">
      <span class="spin"></span> 加载文件…</div></div></div>`;
  if (pick) await openCodeFile(pick, query.line ? Number(query.line) : null);
}

function fileTreeHtml(files, curPath) {
  if (!files.length) return `<div class="ft-empty">快照中没有源文件</div>`;
  const root = {};
  for (const f of files) {
    const parts = f.path.split("/");
    let node = root;
    for (let i = 0; i < parts.length - 1; i++)
      node = node[parts[i]] || (node[parts[i]] = {});
    node[parts[parts.length - 1]] = f;
  }
  const render = (node, prefix) => {
    let html = "";
    const dirs = Object.keys(node).filter(k => !node[k].path).sort();
    const names = Object.keys(node).filter(k => node[k].path).sort();
    for (const d of dirs) {
      html += `<details open><summary><span class="arrow">▶</span>${esc(d)}</summary>
        ${render(node[d], prefix + d + "/")}</details>`;
    }
    for (const nm of names) {
      const f = node[nm];
      const cntCls = f.errors ? "has-err" : f.alerts ? "has-warn" : "";
      html += `<div class="ft-file ${f.path === curPath ? "on" : ""} ${f.errors ? "has-err" : ""}"
        data-path="${esc(f.path)}" onclick="openCodeFile('${encodeURIComponent(f.path)}')">${esc(nm)}
        ${f.alerts ? `<span class="ft-cnt ${cntCls}">${f.alerts}</span>` : ""}</div>`;
    }
    return html;
  };
  return render(root, "");
}

async function openCodeFile(pathEnc, focusLine) {
  const path = decodeURIComponent(pathEnc);
  codeState.path = path;
  document.querySelectorAll("#cd-tree .ft-file").forEach(n =>
    n.classList.toggle("on", n.dataset.path === path));
  const pane = $("cd-pane");
  let data;
  try {
    data = await api("GET", `/api/runs/${codeState.runId}/file?path=${encodeURIComponent(path)}`);
  } catch (e) {
    pane.innerHTML = `<div style="padding:26px" class="muted">${esc(e.message)}</div>`;
    return;
  }
  const hl = highlightCLines(data.lines);
  const byLine = {};
  data.alerts.forEach(a => (byLine[a.line] = byLine[a.line] || []).push(a));
  const alertLines = Object.keys(byLine).map(Number).sort((a, b) => a - b);
  codeState.alertIdx = 0;
  if (focusLine) codeState.alertIdx = Math.max(0, alertLines.indexOf(focusLine));
  const rows = data.lines.map((_, i) => {
    const no = i + 1;
    const as = byLine[no];
    const top = as && as[0];
    return `<div class="cv-row ${top ? `cv-hit-${top.severity}` : ""}"
        id="cv-${no}"><span class="cv-no">${no}</span><span class="cv-mark"
        ${top ? `title="${esc(top.rule_id)}" style="cursor:pointer"
        onclick="openAlert(${top.id})">●` : ""}</span>
      <span class="cv-code">${hl[i] || "&nbsp;"}</span></div>`;
  }).join("");
  const nav = alertLines.length ? `
    <span>告警 ${alertLines.length}</span>
    <button onclick="codeAlertNav(-1)">↑</button>
    <button onclick="codeAlertNav(1)">↓</button>
    <span id="cv-nav-pos">1/${alertLines.length}</span>` : "";
  pane.innerHTML = `
    <div class="codepane-head"><span class="fp">${esc(path)}</span>
      <span class="badge ${data.alerts.length ? "warning" : "confirmed"}">
        ${data.alerts.length} 条告警</span>
      <span class="alertnav">${nav}</span></div>
    <div class="codeview">${rows}</div>`;
  const target = focusLine || alertLines[0];
  if (target) codeScrollAlert(target);
}

function codeScrollAlert(line) {
  document.querySelectorAll(".cv-hit.cur").forEach(n => n.classList.remove("cur"));
  const row = $("cv-" + line);
  if (row) {
    row.classList.add("cur");
    row.scrollIntoView({ block: "center" });
  }
}

function codeAlertNav(dir) {
  // 从 DOM 重建告警行序（文件重载后自动失效）
  const lines = [...document.querySelectorAll(".cv-row[class*=cv-hit]")]
    .map(n => Number(n.id.slice(3))).sort((a, b) => a - b);
  if (!lines.length) return;
  codeState.alertIdx = (codeState.alertIdx + dir + lines.length) % lines.length;
  codeScrollAlert(lines[codeState.alertIdx]);
  const pos = $("cv-nav-pos");
  if (pos) pos.textContent = `${codeState.alertIdx + 1}/${lines.length}`;
}

/* ============ 版本对比（GitHub diff + CodeChecker 告警差分） ============ */

let cmpState = { base: null, target: null, path: null, mode: "unified" };

async function renderCompare(el, query) {
  el.innerHTML = `<div style="padding:30px"><span class="spin"></span> 加载中…</div>`;
  const { runs, names } = await loadDoneRuns();
  if (runs.length < 2) {
    el.innerHTML = pageHead("版本对比", "两次运行之间的文件变更与告警差分") +
      `<div class="card"><div class="empty">版本对比至少需要两次已完成的扫描。
        <br>同一工程连续扫描两次（或修复后重扫）即可看到差异。</div></div>`;
    return;
  }
  const projIds = [...new Set(runs.map(r => r.project_id))];
  cmpState.target = query.target ? Number(query.target) : runs[0].id;
  cmpState.base = query.base
    ? Number(query.base)
    : (runs.filter(r => r.project_id === runs[0].project_id
                      && r.id < cmpState.target)[0] || {}).id || runs[1].id;
  cmpState.names = names;
  const curRun = runs.find(r => r.id === cmpState.target) || runs[0];
  el.innerHTML = `
    ${pageHead("版本对比", "两次运行之间的代码 diff 与告警差分（New / Resolved / Unresolved）")}
    <div class="card"><div class="ctx-bar">
      <select id="cp-proj" onchange="cmpPickProject()">
        ${projIds.map(p => `<option value="${p}" ${p === curRun.project_id ? "selected" : ""}>${esc(names[p])}</option>`).join("")}
      </select>
      <select id="cp-base" onchange="cmpReload()"></select>
      <button class="btn sm ghost" title="交换基准与目标"
        onclick="cmpSwap()">⇄</button>
      <select id="cp-target" onchange="cmpReload()"></select>
    </div>
    <div id="cp-summary" class="diffstat"></div></div>
    <div id="cmp-alerts"></div>
    <div class="cmp-layout" id="cmp-body"></div>`;
  cmpFillRunOptions(runs, names);
  await cmpReload();
}

function cmpFillRunOptions(runs, names) {
  names = names || cmpState.names || {};
  const target = runs.find(r => r.id === cmpState.target);
  const pid = target ? target.project_id : runs[0].project_id;
  const same = runs.filter(r => r.project_id === pid);
  const opts = (sel) => same.map(r =>
    `<option value="${r.id}" ${r.id === sel ? "selected" : ""}>${runOptionLabel(r, names)}</option>`).join("");
  $("cp-target").innerHTML = opts(cmpState.target);
  $("cp-base").innerHTML = opts(cmpState.base);
}

function cmpPickProject() {
  api("GET", "/api/runs?project_id=" + Number($("cp-proj").value)).then(d => {
    const done = d.runs.filter(r => r.status === "done");
    if (done.length < 1) { toast("该工程暂无已完成运行", true); return; }
    cmpState.target = done[0].id;
    cmpState.base = done.length > 1 ? done[1].id : done[0].id;
    cmpState.path = null;
    cmpFillRunOptions(done, {});
    cmpReload();
  });
}

function cmpSwap() {
  [cmpState.base, cmpState.target] = [cmpState.target, cmpState.base];
  $("cp-base").value = cmpState.base;
  $("cp-target").value = cmpState.target;
  cmpReload();
}

function cmpReload() {
  cmpState.base = Number($("cp-base").value);
  cmpState.target = Number($("cp-target").value);
  cmpState.path = null;
  if (cmpState.base === cmpState.target) {
    $("cmp-body").innerHTML = `<div class="card"><div class="empty">
      基准与目标是同一次运行。</div></div>`;
    return;
  }
  loadCmpSummary();
}

async function loadCmpSummary() {
  const body = $("cmp-body"), sum = $("cp-summary");
  let d;
  try {
    d = await api("GET", `/api/runs/${cmpState.target}/diff?base=${cmpState.base}`);
  } catch (e) {
    sum.innerHTML = ""; body.innerHTML =
      `<div class="card"><div class="empty">${esc(e.message)}</div></div>`;
    $("cmp-alerts").innerHTML = "";
    return;
  }
  cmpState._diff = d;
  const s = d.summary;
  sum.innerHTML = `
    <span class="ds add">＋ 新增文件 ${s.added}</span>
    <span class="ds mod">～ 修改 ${s.modified}</span>
    <span class="ds del">－ 删除 ${s.deleted}</span>
    <span class="sep">·</span>
    <span class="ds new">告警新增 ${s.alerts_new}</span>
    <span class="ds res">告警消除 ${s.alerts_resolved}</span>
    <span class="ds unres">持续存在 ${s.alerts_unresolved}</span>`;
  $("cmp-alerts").innerHTML = cmpAlertDiffHtml(d);
  if (!d.files.length) {
    body.innerHTML = `<div class="card"><div class="empty">
      两次运行之间源码没有变化。</div></div>`;
    return;
  }
  const first = d.files.find(f => f.status !== "deleted") || d.files[0];
  body.innerHTML = `
    <div class="cmp-files" id="cp-files">${d.files.map(f => `
      <div class="cmp-file" id="cf-${esc(f.path).replace(/[^a-zA-Z0-9]/g, "_")}"
        onclick="loadDiffFile('${encodeURIComponent(f.path)}')">
        <span class="st ${f.status}">${f.status === "added" ? "A"
          : f.status === "deleted" ? "D" : "M"}</span>
        <span class="fp" title="${esc(f.path)}">${esc(f.path)}</span>
      </div>`).join("")}</div>
    <div class="codepane" id="cp-pane"><div style="padding:26px">
      <span class="spin"></span> 选择左侧文件查看 diff</div></div>`;
  await loadDiffFile(first.path);
}

function cmpAlertDiffHtml(d) {
  const item = (a) => `<div class="al-diff-item" onclick="openAlert(${a.id})">
    <span class="badge ${a.severity}">${a.severity}</span>
    <span class="path">${esc(a.path)}:${a.line}</span>
    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.rule_id)}</span></div>`;
  const block = (title, list, cls) => list.length ? `
    <div class="card"><h2>${title}（${list.length}）</h2>
      <div class="al-diff-list">${list.map(item).join("")}</div></div>` : "";
  return block("🆕 新增告警", d.alerts_new, "new")
    + block("✅ 已消除告警", d.alerts_resolved, "res");
}

async function loadDiffFile(pathEnc) {
  const path = decodeURIComponent(pathEnc);
  cmpState.path = path;
  document.querySelectorAll("#cp-files .cmp-file").forEach(n =>
    n.classList.toggle("on",
      n.getAttribute("id") === "cf-" + esc(path).replace(/[^a-zA-Z0-9]/g, "_")));
  const pane = $("cp-pane");
  if (!pane) return;
  let d;
  try {
    d = await api("GET", `/api/runs/${cmpState.target}/diff/file?base=${cmpState.base}&path=${encodeURIComponent(path)}`);
  } catch (e) {
    pane.innerHTML = `<div style="padding:26px" class="muted">${esc(e.message)}</div>`;
    return;
  }
  d.mode = cmpState.mode;
  const nNew = (d.new_alerts || []).length - (d.old_alerts || []).length;
  pane.innerHTML = `
    <div class="codepane-head"><span class="fp">${esc(path)}</span>
      <span class="badge ${d.status === "added" ? "confirmed" : d.status === "deleted" ? "failed" : "running"}">${FMOD_LABEL[d.status] || d.status}</span>
      ${nNew > 0 ? `<span class="badge error">新增告警 +${nNew}</span>`
        : nNew < 0 ? `<span class="badge confirmed">告警 ${nNew}</span>` : ""}
      <span class="alertnav">${diffToolbar(d)}</span></div>
    <div class="diffbox">${diffRowsHtml(d)}</div>`;
}

function setDiffMode(path, mode) {
  cmpState.mode = mode;
  loadDiffFile(path);
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
    ${pageHead("总览", "工程、检测与复核的全局态势", '<a class="btn" href="#/projects">＋ 注册工程</a>')}
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
      <li>在 <b>代码浏览</b> 查看文件级告警，到 <b>告警中心</b> 逐条研判。</li>
    </ol></div>`;
}

/* ================= 工程管理 ================= */

let curSource = "path";

async function renderProjects(el) {
  el.innerHTML = `
    ${pageHead("工程管理", "输入的单位是工程目录——三种来源统一归一为服务端可访问目录")}
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
  el.innerHTML = `${pageHead("扫描运行", "后台队列串行执行 · 进行中的任务每 2 秒自动刷新")}
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
           <a class="link" href="#" onclick="location.hash='#/code?run=${r.id}';return false;">代码</a> ·
           <a class="link" href="#" onclick="location.hash='#/compare?target=${r.id}';return false;">对比</a> ·
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

let fixSelection = new Set();      // 勾选待修复的告警 id

async function renderAlerts(el, query) {
  const { runs, names } = await loadDoneRuns();
  alertsRun = query.run ? Number(query.run) : (runs[0] ? runs[0].id : null);
  fixSelection = new Set();
  el.innerHTML = `
    ${pageHead("告警中心", "逐条研判：确认真缺陷或豁免误报；勾选后可定向一键修复（只生成并验证补丁，不改原文件）")}
    ${runs.length ? "" : `<div class="card">${emptyGuide()}</div>`}
    <div class="card" ${runs.length ? "" : 'style="display:none"'}>
      <div class="ctx-bar">
        <select id="a-run" onchange="alertsRun=Number(this.value);fixSelection.clear();loadAlertFacets();loadAlerts()"
          style="max-width:280px">
          ${runs.map(r => `<option value="${r.id}" ${r.id===alertsRun?"selected":""}>
            ${runOptionLabel(r, names)}</option>`).join("")}
        </select>
        <div class="chips" id="a-chips"></div>
        <span class="grow"></span>
        <select id="a-status" onchange="loadAlerts()" style="max-width:130px">
          <option value="">全部状态</option><option value="pending">待处理</option>
          <option value="confirmed">已确认</option>
          <option value="dismissed">已豁免</option></select>
        <input type="text" id="a-q" placeholder="搜索说明 / 路径…" style="max-width:220px"
          oninput="clearTimeout(this._t);this._t=setTimeout(loadAlerts,300)">
      </div>
      <div id="alert-stat" class="muted" style="margin-bottom:6px"></div>
      <div id="alert-table"></div>
    </div>
    <div id="fix-bar" class="hidden" style="position:sticky;bottom:14px;
        background:var(--ink);color:#fff;border-radius:10px;padding:10px 16px;
        display:flex;gap:12px;align-items:center;box-shadow:var(--shadow-lg);z-index:30">
      <span id="fix-bar-n"></span>
      <button class="btn sm green" onclick="fixSelected()">⚙ 修复选中</button>
      <button class="btn sm ghost" onclick="fixSelection.clear();renderAlertRows()">取消</button>
    </div>`;
  if (alertsRun) { loadAlertFacets(); loadAlerts(); }
}

async function loadAlertFacets() {
  const run = await api("GET", `/api/runs/${alertsRun}`);
  const by = (run.alert_counts || {}).by_severity || {};
  const total = (by.error || 0) + (by.warning || 0) + (by.note || 0);
  const chip = (val, label, n, color) => `
    <button class="chip ${$("a-sev")?.value === val ? "on " + (val || "") : ""}"
      onclick="facetPick('${val}')">
      ${color ? `<span class="cdot" style="background:${color}"></span>` : ""}
      ${label} <span class="n">${n}</span></button>`;
  $("a-chips").innerHTML =
    chip("", "全部", total, null) +
    chip("error", "error", by.error || 0, SEV_COLOR.error) +
    chip("warning", "warning", by.warning || 0, SEV_COLOR.warning) +
    chip("note", "note", by.note || 0, SEV_COLOR.note);
}

function facetPick(sev) {
  if (!$("a-sev")) {
    const sel = document.createElement("select");
    sel.id = "a-sev"; sel.style.display = "none";
    sel.innerHTML = `<option value="">全部级别</option><option value="error">error</option>
      <option value="warning">warning</option><option value="note">note</option>`;
    $("a-chips").parentElement.appendChild(sel);
  }
  $("a-sev").value = sev;
  loadAlertFacets();
  loadAlerts();
}

function renderAlertRows(alerts) {
  const el = $("alert-table");
  if (!alerts.length) {
    el.innerHTML = `<div class="empty">当前筛选条件下没有告警。</div>`;
    return;
  }
  el.innerHTML = `<table><thead><tr>
      <th style="width:30px"><input type="checkbox" id="a-all"
        onclick="toggleAllChecks(this.checked)"></th>
      <th>位置</th><th>级别</th><th>规则</th><th>结论</th><th>复核</th>
    </tr></thead><tbody>${alerts.map(a => `
      <tr class="click" onclick="openAlert(${a.id})">
        <td onclick="event.stopPropagation()">
          <input type="checkbox" ${fixSelection.has(a.id)?"checked":""}
            onchange="toggleCheck(${a.id}, this.checked)"></td>
        <td><span class="path clickable" onclick="event.stopPropagation();gotoCode('${encodeURIComponent(a.path)}',${a.line})">${esc(a.path)}</span>:${a.line}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span>
            <span class="badge ${a.provenance}">${PROV_LABEL[a.provenance]||a.provenance}</span></td>
        <td>${esc(a.rule_id)}${a.cwe?`<br><span class="muted">${esc(a.cwe)}</span>`:""}</td>
        <td>${a.triage?`<span class="badge ${a.triage.verdict}">${TRI_LABEL[a.triage.verdict]||a.triage.verdict}</span>`:'<span class="muted">—</span>'}</td>
        <td><span class="badge ${a.status}">${STATUS_LABEL[a.status]}</span></td>
      </tr>`).join("")}</tbody></table>`;
  updateFixBar();
}

function gotoCode(pathEnc, line) {
  location.hash = `#/code?run=${alertsRun}&path=${pathEnc}&line=${line}`;
}

function toggleCheck(id, on) {
  if (on) fixSelection.add(id); else fixSelection.delete(id);
  updateFixBar();
}
function toggleAllChecks(on) {
  document.querySelectorAll("#alert-table tbody input[type=checkbox]")
    .forEach(cb => {
      cb.checked = on;
      const id = Number(cb.getAttribute("onchange").match(/\d+/)[0]);
      if (on) fixSelection.add(id); else fixSelection.delete(id);
    });
  updateFixBar();
}
function updateFixBar() {
  const bar = $("fix-bar");
  if (!bar) return;
  bar.classList.toggle("hidden", fixSelection.size === 0);
  $("fix-bar-n").textContent = `已勾选 ${fixSelection.size} 条告警`;
}

async function fixSelected() {
  if (!fixSelection.size) return;
  try {
    await api("POST", `/api/runs/${alertsRun}/fix`,
              { alert_ids: [...fixSelection] });
    const n = fixSelection.size;
    fixSelection.clear();
    toast(`✓ 已提交 ${n} 条定向修复任务`);
    location.hash = "#/fixes";
  } catch (e) { toast("✗ " + e.message, true); }
}

async function loadAlerts() {
  const q = new URLSearchParams({ severity: $("a-sev")?.value || "",
    status: $("a-status").value, q: $("a-q").value });
  const data = await api("GET", `/api/runs/${alertsRun}/alerts?` + q);
  $("alert-stat").textContent = `筛选结果 ${data.alerts.length} 条`;
  renderAlertRows(data.alerts);
}

async function openAlert(id) {
  const a = await api("GET", "/api/alerts/" + id);
  const fixes = a.run_id
    ? await api("GET", `/api/runs/${a.run_id}/fixes`) : null;
  const myFix = fixes ? (fixes.proposals.find(p => p.alert_id === a.id)) : null;
  $("drawer-title").innerHTML =
    `<span class="badge ${a.severity}">${a.severity}</span>
     <span class="badge ${a.provenance}">${PROV_LABEL[a.provenance]||a.provenance}</span>
     <span class="path" style="margin-left:6px">${esc(a.path)}:${a.line}</span>`;
  // 代码上下文：从本运行快照取告警行 ±5 行
  let ctxHtml = "";
  if (a.run_id) {
    try {
      const f = await api("GET",
        `/api/runs/${a.run_id}/file?path=${encodeURIComponent(a.path)}`);
      ctxHtml = alertCodeContext(a, f);
    } catch (e) { /* 无快照：退化为纯证据链 */ }
  }
  const tri = a.triage ? `
    <div class="card" style="margin:12px 0;background:var(--orange-soft);border-color:transparent">
      <b style="font-size:12.5px">LLM 分诊：${TRI_LABEL[a.triage.verdict]||a.triage.verdict}
      （置信度 ${(a.triage.confidence??0).toFixed(2)}${a.triage.verified?"，证据已核对":""}
      ${a.triage.used_rag?"，RAG 重判":""}）</b>
      <div class="muted" style="margin-top:4px">${esc(a.triage.reason||"")}</div></div>` : "";
  const fixHtml = myFix ? `
    <h2 style="font-size:13px;margin:14px 0 4px">
      ${myFix.verified ? "✓ 已验证修复补丁" : "修复建议（未通过验证）"}</h2>
    ${myFix.verified ? "" : `<div class="muted">${esc(myFix.fail_reason||"")}</div>`}
    ${myFix.explanation ? `<div class="muted" style="margin-bottom:6px">${esc(myFix.explanation)}</div>` : ""}
    ${myFix.diff ? fixDiffHtml(myFix.diff) : '<div class="muted">无 diff</div>'}` : "";
  const ev = (a.evidence||[]).map(e => `
    <div class="evi"><span class="k">${esc(e.kind)}</span>${esc(e.message)}
      ${e.path?`<div class="muted path">${esc(e.path)}:${e.line??""}</div>`:""}</div>`).join("")
    || '<div class="muted">无结构化证据</div>';
  $("drawer-body").innerHTML = `
    <div class="kv"><b>规则</b>${esc(a.rule_id)}</div>
    <div class="kv"><b>CWE</b>${esc(a.cwe||"未标注")}</div>
    <div class="kv"><b>引擎</b>${esc(a.engine)}</div>
    <div class="kv"><b>说明</b>${esc(a.message)}</div>
    ${ctxHtml || ""}
    ${tri}
    <h2 style="font-size:13px;margin:14px 0 4px">证据链</h2>${ev}
    ${fixHtml}
    <div style="display:flex;gap:8px;margin-top:16px" id="alert-actions">
      <button class="btn sm green" onclick="markAlert(${a.id},'confirmed')">✓ 确认真缺陷</button>
      <button class="btn sm gray" onclick="markAlert(${a.id},'dismissed')">豁免（误报/不适用）</button>
      <button class="btn sm ghost" onclick="markAlert(${a.id},'pending')">重置待处理</button>
    </div>
    <div class="muted" style="margin-top:10px">当前状态：
      <span class="badge ${a.status}">${STATUS_LABEL[a.status]}</span></div>`;
  $("drawer").classList.add("open");
  $("drawer-mask").classList.add("open");
  const cur = document.querySelector(".drawer-body .cv-hit-cur");
  if (cur) cur.scrollIntoView({ block: "center" });
}

function alertCodeContext(a, f) {
  const lo = Math.max(0, a.line - 5), hi = Math.min(f.lines.length, a.line + 5);
  const hl = highlightCLines(f.lines.slice(lo, hi));
  const rows = [];
  for (let i = lo; i < hi; i++) {
    const no = i + 1;
    const isHit = no === a.line;
    rows.push(`<div class="cv-row ${isHit ? `cv-hit-${a.severity} cv-hit-cur` : ""}"
      style="${isHit ? "" : "opacity:.72"}">
      <span class="cv-no">${no}</span><span class="cv-mark">${isHit ? "●" : ""}</span>
      <span class="cv-code">${hl[i - lo] || "&nbsp;"}</span></div>`);
  }
  return `<h2 style="font-size:13px;margin:14px 0 4px">代码上下文（本运行快照）
    <a class="link" style="font-weight:400;margin-left:8px"
      href="#" onclick="closeDrawer();gotoCode('${encodeURIComponent(a.path)}',${a.line});return false;">在代码浏览中打开 →</a></h2>
    <div class="codeview" style="max-height:320px;border:1px solid var(--line);
      border-radius:8px">${rows.join("")}</div>`;
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

/* ================= 修复建议 ================= */

async function renderFixes(el) {
  const { runs, names } = await loadDoneRuns();
  el.innerHTML = `
    ${pageHead("修复建议", "LLM 生成补丁 → 静态重扫 + gcc 语法验证闭环，未通过验证的补丁不会出现在采纳列表")}
    ${runs.length ? "" : `<div class="card">${emptyGuide()}</div>`}
    <div class="card" ${runs.length ? "" : 'style="display:none"'}>
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:6px;flex-wrap:wrap">
        <select id="fx-run" onchange="loadFixes()" style="max-width:280px">
          ${runs.map(r => `<option value="${r.id}" ${r.id===alertsRun?"selected":""}>
            ${runOptionLabel(r, names)}</option>`).join("")}
        </select>
        <select id="fx-mode" style="max-width:260px">
          <option value="suggest">仅生成建议（不改文件）</option>
          <option value="apply">⚙ 自动修复（写入源文件并迭代）</option>
        </select>
        <button class="btn" id="fx-go" onclick="startFix()">⚙ 开始修复</button>
        <span class="muted" id="fx-job"></span>
      </div>
      <div class="muted" style="margin-bottom:10px">
        自动目标 = 高危可修复规则（确认/LLM 真缺陷/动态 PoC）；要指定条目请到
        <a class="link" href="#/alerts">告警中心</a> 勾选后「修复选中」。<br>
        <b id="fx-mode-note">当前模式：仅生成建议——补丁不落盘，原文件不变。</b>
        自动修复模式会<b style="color:var(--orange)">直接写入源文件</b>（先自动备份），
        每轮写入后全工程重扫，剩余相关告警进入下一轮直至收敛，并给出验收统计。
        提交后到 <a class="link" href="#/alerts">告警中心</a> 刷新查看最新结果。</div>
      <div id="fx-final"></div>
      <div id="fx-list"></div>
    </div>`;
  if (runs.length) { alertsRun = alertsRun || runs[0].id; loadFixes(); }
  $("fx-mode").addEventListener("change", () => {
    $("fx-mode-note").innerHTML = $("fx-mode").value === "apply"
      ? "当前模式：<b style='color:var(--orange)'>自动修复</b>——验证通过的补丁将直接写入源文件（已自动备份）。"
      : "当前模式：仅生成建议——补丁不落盘，原文件不变。";
  });
}

async function startFix() {
  const runId = $("fx-run").value;
  $("fx-go").disabled = true;
  try {
    await api("POST", `/api/runs/${runId}/fix`,
              { mode: $("fx-mode").value });
    toast("修复任务已提交，后台执行中…");
    pollFixJob(runId);
  } catch (e) { toast("✗ " + e.message, true); $("fx-go").disabled = false; }
}

/* unified diff 文本 → 带行号的结构化渲染（与版本对比页同一视觉语言） */
function fixDiffHtml(diff) {
  const rows = [];
  let a = 0, b = 0;
  for (const ln of diff.split("\n")) {
    const m = ln.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (m) { a = Number(m[1]); b = Number(m[2]);
             rows.push({ t: "hunk", text: ln }); continue; }
    if (ln.startsWith("---") || ln.startsWith("+++")) {
      rows.push({ t: "meta", text: ln }); continue; }
    if (ln.startsWith("+")) {
      rows.push({ t: "add", no: b, text: ln.slice(1) }); b++;
    } else if (ln.startsWith("-")) {
      rows.push({ t: "del", no: a, text: ln.slice(1) }); a++;
    } else {
      rows.push({ t: "ctx", no: b, text: ln.replace(/^ /, "") }); a++; b++;
    }
  }
  const body = rows.map(r => {
    if (r.t === "hunk" || r.t === "meta")
      return `<div class="df-hunk">${esc(r.text)}</div>`;
    return `<div class="df-row r-${r.t}"><span class="df-no">${r.no ?? ""}</span>
      <span class="df-mark"></span><span class="df-code">${esc(r.text) || "&nbsp;"}</span></div>`;
  }).join("");
  return `<div class="diffbox" style="max-height:420px">${body}</div>`;
}

async function loadFixes() {
  const runId = $("fx-run").value;
  alertsRun = Number(runId);
  const data = await api("GET", `/api/runs/${runId}/fixes`);
  renderFixPanel(runId, data);
}

function renderFixPanel(runId, data) {
  const job = data.job;
  const el = $("fx-list");
  const jobEl = $("fx-job");
  const finEl = $("fx-final");
  if (job && ["pending", "running"].includes(job.status)) {
    jobEl.innerHTML = `<span class="spin"></span> 修复执行中…（${
      job.mode === "apply" ? "自动修复模式，写入源文件" : "仅生成建议"}）`;
    $("fx-go").disabled = true;
    clearTimeout(renderFixPanel._t);
    renderFixPanel._t = setTimeout(() => loadFixes(), 2000);
  } else {
    $("fx-go").disabled = false;
    jobEl.textContent = job && job.status === "done"
      ? `上次：采纳 ${job.accepted} / 拒绝 ${job.rejected}`
      : (job && job.status === "failed" ? `上次失败：${job.error || ""}` : "");
  }
  if (finEl) {
    const fs = job && job.final_stats;
    finEl.innerHTML = (job && job.status === "done" && fs) ? `
      <div style="background:var(--green-soft);border:1px solid transparent;
           border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:13px">
        <b>验收扫描（修复后全工程）</b>：残留告警 ${fs.remaining_total}
        （error ${fs.remaining_error} / warning ${fs.remaining_warning}）·
        执行轮数 ${fs.rounds} · 累计写入 ${fs.applied_total} 处
        ${job.backup_dir ? `· 原文件备份：${esc(job.backup_dir)}` : ""}
      </div>` : "";
  }
  if (!data.proposals.length) {
    el.innerHTML = `<div class="empty">尚无修复建议。到
      <a class="link" href="#/alerts">告警中心</a> 勾选告警后「修复选中」，
      或点「开始修复」走自动目标。</div>`;
    return;
  }
  el.innerHTML = data.proposals.map(p => `
    <div style="border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin-bottom:10px">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap">
        ${p.applied ? '<span class="badge done">✓ 已写入源文件</span>'
          : p.verified ? '<span class="badge done">✓ 已采纳（验证通过）</span>'
          : '<span class="badge failed">✗ 已拒绝</span>'}
        <b>${esc(p.rule_id)}</b>
        <span class="path clickable" onclick="gotoCode('${encodeURIComponent(p.path)}',${p.line})">${esc(p.path)}:${p.line}</span>
        ${p.func ? `<span class="muted">函数 ${esc(p.func)}</span>` : ""}
      </div>
      ${p.verified ? "" : `<div class="muted">拒绝原因：${esc(p.fail_reason||"")}</div>`}
      ${p.explanation ? `<div class="muted">${esc(p.explanation)}</div>` : ""}
      ${p.diff ? fixDiffHtml(p.diff) : ""}
    </div>`).join("");
}

async function pollFixJob(runId) {
  const data = await api("GET", `/api/runs/${runId}/fixes`);
  if (data.job && ["pending", "running"].includes(data.job.status)) {
    renderFixPanel(runId, data);
    clearTimeout(pollFixJob._t);
    pollFixJob._t = setTimeout(() => pollFixJob(runId), 2000);
  } else {
    loadFixes();
    toast(data.job && data.job.status === "done"
      ? `✓ 修复完成：采纳 ${data.job.accepted} / 拒绝 ${data.job.rejected}`
      : "✗ 修复任务失败", data.job?.status !== "done");
  }
}

/* ================= 大模型设置 ================= */

async function renderSettings(el) {
  const s = await api("GET", "/api/settings");
  el.innerHTML = `
    ${pageHead("大模型设置", "配置后分诊与修复建议直接使用真实端点；凭据保存在本机 SQLite，数据不出域")}
    <div class="card" style="max-width:560px">
      <label>工作模式</label>
      <select id="s-mode">
        <option value="mock" ${s.llm_mode==="mock"?"selected":""}>Mock（离线演示，确定性判定）</option>
        <option value="real" ${s.llm_mode==="real"?"selected":""}>真实端点（OpenAI 兼容 / vLLM / Ollama）</option>
      </select>
      <label>Base URL</label>
      <input type="text" id="s-url" placeholder="http://127.0.0.1:8000/v1" value="${esc(s.llm_base_url)}">
      <label>API Key ${s.api_key_set ? `<span class="muted">（已保存 ${esc(s.api_key_masked)}，留空则不修改）</span>` : ""}</label>
      <input type="password" id="s-key" placeholder="${s.api_key_set ? "不修改请留空" : "sk-…"}">
      <label>模型名</label>
      <input type="text" id="s-model" placeholder="Qwen2.5-Coder-7B-Instruct" value="${esc(s.llm_model)}">
      <div style="display:flex;gap:10px;margin-top:14px">
        <button class="btn" onclick="saveSettings()">保存设置</button>
        <button class="btn ghost" onclick="testSettings()">测试连接</button>
        <span class="muted" id="s-msg" style="align-self:center"></span>
      </div>
    </div>
    <div class="card" style="max-width:560px"><h2>说明</h2>
      <div class="muted">
        · 兼容一切 OpenAI Chat Completions 形态的端点（vLLM、Ollama、LM Studio 等）；<br>
        · 扫描时「LLM 分诊=真实端点」与一键修复都会使用此配置；<br>
        · API Key 仅存本机数据库，回传时脱敏显示。
      </div></div>`;
}

async function saveSettings() {
  await api("POST", "/api/settings", {
    llm_mode: $("s-mode").value,
    llm_base_url: $("s-url").value.trim(),
    llm_api_key: $("s-key").value.trim(),
    llm_model: $("s-model").value.trim(),
  });
  toast("✓ 设置已保存");
  renderSettings($("main"));
}

async function testSettings() {
  const msg = $("s-msg");
  msg.innerHTML = '<span class="spin"></span> 连接中…';
  await api("POST", "/api/settings", {
    llm_mode: $("s-mode").value,
    llm_base_url: $("s-url").value.trim(),
    llm_api_key: $("s-key").value.trim(),
    llm_model: $("s-model").value.trim(),
  });
  const r = await api("POST", "/api/settings/test");
  msg.textContent = r.ok ? "✓ 连接成功：" + r.message : "✗ " + r.message;
  msg.style.color = r.ok ? "var(--green)" : "var(--red)";
}

/* ================= 路由 ================= */

async function route() {
  const hash = location.hash || "#/overview";
  const [path, qs] = hash.slice(1).split("?");
  const name = path.replace(/^\//, "") || "overview";
  const query = Object.fromEntries(new URLSearchParams(qs || ""));
  document.querySelectorAll("nav a, .side-settings a").forEach(a =>
    a.classList.toggle("on", a.dataset.route === name));
  const el = $("main");
  try {
    if (name === "projects") await renderProjects(el);
    else if (name === "runs") await renderRuns(el);
    else if (name === "code") await renderCode(el, query);
    else if (name === "compare") await renderCompare(el, query);
    else if (name === "alerts") await renderAlerts(el, query);
    else if (name === "fixes") await renderFixes(el);
    else if (name === "settings") await renderSettings(el);
    else await renderOverview(el);
  } catch (e) {
    el.innerHTML = `<div class="card"><div class="empty">加载失败：${esc(e.message)}</div></div>`;
  }
}
window.addEventListener("hashchange", route);
route();
