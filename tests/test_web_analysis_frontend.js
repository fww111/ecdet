"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appPath = path.join(__dirname, "../ecdet/webui/static/app.js");
const code = fs.readFileSync(appPath, "utf8").replace(/\nroute\(\);\s*$/, "\n");
let checks = 0;

function runtime() {
  const nodes = new Map();
  const timers = new Map();
  let serial = 0;
  function node(id, values = {}) {
    const element = { id, value: "", innerHTML: "", textContent: "", disabled: false,
      dataset: {}, addEventListener() {}, ...values };
    nodes.set(id, element);
    return element;
  }
  const context = vm.createContext({
    console, URLSearchParams, Date, Number, Object, String, Array, Promise,
    document: { getElementById: id => nodes.get(id) || null, querySelectorAll: () => [] },
    window: { addEventListener() {} }, location: { hash: "#/analysis" },
    history: { replaceState() {} },
    setTimeout: callback => { timers.set(++serial, callback); return serial; },
    clearTimeout: id => timers.delete(id),
    fetch: async () => { throw new Error("Unexpected HTTP request"); },
  });
  vm.runInContext(code, context, { filename: appPath });
  return { context, nodes, timers, node };
}

function check(name, action) {
  return Promise.resolve().then(action).then(() => { checks++; console.log("PASS " + name); });
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

async function main() {
  await check("Constraint form maps source, function and numeric budget", () => {
    const { context: c } = runtime();
    assert.deepEqual(plain(c.analysisRequest("constraints", { source:" src/test.c ", function:"f", timeout_ms:"1500" })),
      { kind:"constraints", source:"src/test.c", function:"f", timeout_ms:1500 });
  });
  await check("Fuzzer form preserves each source and seed entry", () => {
    const { context: c } = runtime();
    const result = plain(c.analysisRequest("fuzz", { harness:"driver.c", sources:"a.c\r\nb.c\n", corpus:" seeds \nseed.bin", runs:"5000", timeout:"20", max_len:"64" }));
    assert.deepEqual(result.sources, ["a.c", "b.c"]);
    assert.deepEqual(result.corpus, ["seeds", "seed.bin"]);
    assert.equal(result.runs, 5000);
  });
  await check("Firmware form maps independent UART predicates and bytes", () => {
    const { context: c } = runtime();
    const result = plain(c.analysisRequest("firmware", {firmware:"build/f.elf", platform:"m.repl", uart:"sysbus.usart2", input_hex:"73 0A", expected:"READY\nOK", failure_markers:"FAIL", sources:"main.c", seconds:"0.1", timeout:"30"}));
    assert.deepEqual(result.expected,["READY","OK"]);
    assert.deepEqual(result.failure_markers,["FAIL"]);
    assert.equal(result.input_hex,"730A");
    assert.equal(result.seconds,0.1);
  });
  await check("Invalid budgets are rejected before submission", () => {
    const { context: c } = runtime();
    for (const value of ["", "0", "-1", "nan", "Infinity", "1.5"])
      assert.throws(() => c.analysisRequest("constraints", { timeout_ms:value }));
  });
  await check("A firmware run requires output predicates and complete hex bytes", () => {
    const { context: c } = runtime();
    const values={firmware:"f.elf",platform:"p.repl",uart:"sysbus.uart",seconds:"1",timeout:"30"};
    assert.throws(() => c.analysisRequest("firmware", values));
    assert.throws(() => c.analysisRequest("firmware", {...values,expected:"READY",input_hex:"7"}));
    assert.throws(() => c.analysisRequest("firmware", {...values,expected:"READY",input_hex:"zz"}));
    assert.throws(() => c.analysisRequest("firmware", {...values,expected:"READY",input_hex:"aa".repeat(4097)}));
  });
  await check("Only supported advanced run kinds enter task history", () => {
    const { context: c } = runtime();
    assert.equal(c.analysisKind({params:{analysis:{kind:"constraints"}}}),"constraints");
    assert.equal(c.analysisKind({params:{kind:"firmware"}}),"firmware");
    assert.equal(c.analysisKind({params:{dynamic:true}}),null);
    assert.equal(c.analysisKind({params:{analysis:{kind:"toString"}}}),null);
  });
  await check("Unavailable and partial results cannot look like a clean pass", () => {
    const { context: c } = runtime();
    const run={id:1,status:"failed",params:{analysis:{kind:"firmware"}},error:"missing tool"};
    const html=c.analysisResultHtml(run,{kind:"firmware",status:"NOT_AVAILABLE",summary:{alerts:0},details:{}});
    assert.match(html,/工具不可用，未执行/);
    assert.doesNotMatch(html,/判据通过/);
    assert.match(c.analysisBadge("PARTIAL"),/部分检查未完成/);
    assert.match(c.analysisBadge("UNKNOWN"),/求解未确定/);
    assert.match(c.analysisBadge("__proto__"),/__proto__/);
  });
  await check("Z3 candidates stay distinct from reproduced runtime failures", () => {
    const { context: c } = runtime();
    const run={id:8,status:"done",params:{analysis:{kind:"constraints"}}};
    const html=c.analysisResultHtml(run,{kind:"constraints",status:"FINDING",summary:{alerts:1,status_counts:{SAT:1}},details:{}});
    assert.match(html,/存在待验证候选/);
    assert.doesNotMatch(html,/已复现错误/);
    assert.match(c.analysisBadge("FINDING","fuzz"),/已复现错误/);
  });
  await check("Backend text and artifact names are escaped without inline callbacks", () => {
    const { context: c } = runtime();
    const run={id:3,status:"failed",params:{analysis:{kind:"firmware"}},error:'<b>broken</b>'};
    const html=c.analysisResultHtml(run,{kind:"firmware",status:"FAIL",summary:{missing_expected:['<b>READY</b>']},
      artifacts:[{name:'<b>log</b>',path:'run/a b&c.log'}],details:{log:'<b>raw</b>'}});
    assert.doesNotMatch(html,/<b>broken<\/b>|<b>READY<\/b>|<b>log<\/b>|<b>raw<\/b>/);
    assert.match(html,/&lt;b&gt;broken/);
    assert.match(html,/path=run%2Fa%20b%26c.log/);
    assert.doesNotMatch(html,/onclick=/);
  });
  await check("SARIF and full-result downloads use attachment endpoints", () => {
    const { context: c } = runtime();
    const run={id:4,status:"done",params:{analysis:{kind:"fuzz"}}};
    const html=c.analysisResultHtml(run,{kind:"fuzz",status:"COMPLETED",summary:{alerts:0},details:{}});
    assert.match(html,/href="\/api\/runs\/4\/artifact\?path=results\.sarif" download>下载SARIF/);
    assert.match(html,/href="\/api\/runs\/4\/artifact\?path=analysis\.json" download>下载完整结果/);
    assert.doesNotMatch(html,/href="\/api\/runs\/4\/(?:sarif|analysis)" download/);
  });
  await check("Navigation cancels polling and ignores late responses", async () => {
    const r=runtime(), c=r.context;
    const result=r.node("analysis-result",{innerHTML:"old"});
    let resolve;
    c.fetch=() => new Promise(done => { resolve=done; });
    vm.runInContext("Object.assign(analysisState,{active:true,epoch:4,runId:null})",c);
    const refresh=c.analysisRefresh(4);
    c.analysisStop();
    resolve({ok:true,json:async()=>({runs:[{id:1,status:"running",params:{analysis:{kind:"fuzz"}}}]})});
    await refresh;
    assert.equal(result.innerHTML,"old");
    assert.equal(r.timers.size,0);
  });
  await check("Duplicate submit is blocked until request completes", async () => {
    const r=runtime(), c=r.context;
    r.node("an-project",{value:"2"});r.node("analysis-submit");r.node("analysis-submit-message");
    r.node("analysis-result");r.node("analysis-run-list");
    c.document.querySelectorAll=selector=>selector.includes("data-analysis-field") ? [
      {dataset:{analysisField:"timeout_ms"},value:"1000"}] : [];
    vm.runInContext("Object.assign(analysisState,{active:true,epoch:1,kind:'constraints',projects:[{id:2,name:'Project'}]})",c);
    let resolvePost, posts=0;
    const pending={id:7,status:"pending",project_id:2,params:{analysis:{kind:"constraints"}}};
    c.fetch=(url,opt)=>{
      if(opt.method==="POST") {posts++;return new Promise(done=>{resolvePost=done;});}
      return Promise.resolve({ok:true,json:async()=>url==="/api/runs"?{runs:[pending]}:pending});
    };
    const event={preventDefault(){}};
    const first=c.analysisSubmit(event), second=c.analysisSubmit(event);
    assert.equal(posts,1);
    assert.equal(r.nodes.get("analysis-submit").disabled,true);
    resolvePost({ok:true,json:async()=>({run_id:7})});
    await Promise.all([first,second]);
    assert.equal(posts,1);
    assert.equal(r.nodes.get("analysis-submit").disabled,false);
    assert.match(r.nodes.get("analysis-submit-message").textContent,/#7/);
    assert.equal(r.timers.size,1);
  });
  await check("Task submission errors stay visible and re-enable the button", async () => {
    const r=runtime(), c=r.context;
    r.node("an-project",{value:"2"});r.node("analysis-submit");r.node("analysis-submit-message");
    c.document.querySelectorAll=selector=>selector.includes("data-analysis-field") ? [
      {dataset:{analysisField:"timeout_ms"},value:"1000"}] : [];
    vm.runInContext("Object.assign(analysisState,{active:true,epoch:1,kind:'constraints',projects:[{id:2}]})",c);
    c.fetch=async()=>({ok:false,status:400,json:async()=>({error:"source file unavailable"})});
    await c.analysisSubmit({preventDefault(){}});
    assert.equal(r.nodes.get("analysis-submit").disabled,false);
    assert.equal(r.nodes.get("analysis-submit-message").textContent,"source file unavailable");
  });
  console.log(`Frontend checks passed: ${checks}`);
}

main().catch(error=>{console.error(error);process.exitCode=1;});
