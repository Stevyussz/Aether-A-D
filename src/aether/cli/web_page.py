"""The AETHER Web Console single-page UI (served by webserver.py).

Self-contained HTML+CSS+JS, no external/CDN dependencies (works offline at the competition).
``__TOKEN__`` is replaced with the per-session action token by the server before serving.
"""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AETHER Web Console</title>
<style>
  :root{
    --bg:#0a0e14; --panel:#111823; --panel2:#0d141d; --line:#1e2a3a;
    --fg:#cfe3f5; --dim:#6b8299; --cyan:#22d3ee; --green:#34d399; --red:#f87171;
    --yellow:#fbbf24; --magenta:#e879f9; --accent:#22d3ee;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{display:flex;align-items:center;gap:16px;padding:12px 20px;
    border-bottom:1px solid var(--line);background:linear-gradient(90deg,#0b111a,#0a0e14)}
  .brand{font-weight:800;letter-spacing:2px;color:var(--cyan);font-size:18px}
  .brand small{color:var(--dim);font-weight:400;letter-spacing:0}
  .hstat{color:var(--dim);font-size:12px}
  .hstat b{color:var(--fg)}
  nav{display:flex;gap:4px;padding:10px 16px;border-bottom:1px solid var(--line)}
  nav button{background:var(--panel);color:var(--dim);border:1px solid var(--line);
    padding:8px 16px;border-radius:8px 8px 0 0;cursor:pointer;font:inherit}
  nav button.active{color:var(--cyan);border-color:var(--cyan);background:var(--panel2)}
  main{padding:18px 20px;max-width:1200px;margin:0 auto}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
  .card h3{margin:0 0 10px;font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--dim)}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);font-size:13px}
  th{color:var(--dim);font-weight:600}
  .pill{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
  .up{color:var(--green)} .down{color:var(--red)} .mut{color:var(--dim)}
  .sev-CRITICAL{color:var(--red);font-weight:700}
  .sev-WARNING{color:var(--yellow)} .sev-INFO{color:var(--cyan)}
  .kpi{display:flex;gap:18px;flex-wrap:wrap}
  .kpi div{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
    padding:10px 14px;min-width:92px}
  .kpi .n{font-size:22px;font-weight:800;color:var(--cyan)}
  .kpi .l{font-size:11px;color:var(--dim)}
  button.act{background:var(--cyan);color:#04121a;border:0;padding:7px 14px;border-radius:8px;
    cursor:pointer;font:inherit;font-weight:700}
  button.act:hover{filter:brightness(1.1)} button.ghost{background:transparent;color:var(--fg);
    border:1px solid var(--line)} button.ghost:hover{border-color:var(--cyan)}
  textarea{width:100%;height:340px;background:#05090f;color:var(--fg);border:1px solid var(--line);
    border-radius:10px;padding:12px;font:13px ui-monospace,monospace;resize:vertical}
  .banner{padding:10px 14px;border-radius:10px;margin-bottom:12px;border:1px solid}
  .ok{border-color:var(--green);color:var(--green);background:#07140f}
  .bad{border-color:var(--red);color:var(--red);background:#160a0a}
  .warn{color:var(--yellow)} .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  .muted{color:var(--dim);font-size:12px} .mono{font-family:ui-monospace,monospace}
  .log{white-space:pre-wrap;color:var(--dim);font-size:12px;margin-top:8px}
  .tag{color:var(--magenta)} .hide{display:none}
  .guidelist{margin:4px 0;padding-left:20px} .guidelist li{margin:7px 0;color:var(--fg)}
  .builder-in{width:100%;background:#05090f;color:var(--fg);border:1px solid var(--line);
    border-radius:6px;padding:4px 6px;font:12px ui-monospace,monospace}
  .foot{color:var(--dim);font-size:11px;padding:14px 20px;border-top:1px solid var(--line);
    text-align:center}
</style>
</head>
<body>
<header>
  <div class="brand">AETHER<small> A&amp;D</small></div>
  <div class="hstat" id="hstat">connecting…</div>
  <div class="hstat" style="margin-left:auto" id="hres"></div>
</header>
<nav>
  <button data-tab="monitor" class="active">Monitor</button>
  <button data-tab="attack">Attack</button>
  <button data-tab="flags">Flags</button>
  <button data-tab="config">Config</button>
  <button data-tab="guide">Game plan</button>
</nav>
<main>
  <section id="monitor">
    <div class="kpi" id="kpi"></div>
    <div style="height:12px"></div>
    <div class="grid">
      <div class="card"><h3>services</h3><div id="services"></div></div>
      <div class="card"><h3>file integrity</h3><div id="integrity"></div></div>
    </div>
    <div style="height:14px"></div>
    <div class="card"><h3>incidents (latest sweep)</h3><div id="incidents"></div></div>
    <div style="height:14px"></div>
    <div class="card"><h3>web shells detected (our services)</h3><div id="webshells"></div>
      <div class="log" id="wsout"></div></div>
    <div style="height:14px"></div>
    <div class="grid">
      <div class="card"><h3>flag inbox</h3><div id="flagsum"></div></div>
      <div class="card"><h3>modification / patch log</h3><div id="mods"></div></div>
    </div>
  </section>

  <section id="attack" class="hide">
    <div class="card">
      <h3>attack control</h3>
      <p class="muted">Sweep runs the full validated arsenal (auto-recon + auto-login +
        read server flags). Scope-enforced. Flags land PENDING — you submit on the portal.</p>
      <div id="targets"></div>
      <div style="height:10px"></div>
      <button class="ghost" onclick="defenseSweep()">Run one defense sweep</button>
    </div>
    <div style="height:14px"></div>
    <div class="card" id="progcard">
      <h3>live sweep <span id="progphase" class="mut"></span></h3>
      <div id="progbarwrap" style="background:var(--panel2);border:1px solid var(--line);
        border-radius:999px;height:14px;overflow:hidden;margin:6px 0">
        <div id="progbar" style="height:100%;width:0;background:var(--cyan);
          transition:width .3s"></div></div>
      <div class="row" style="justify-content:space-between">
        <span class="muted" id="progcur">idle</span>
        <span class="muted" id="progstat"></span>
      </div>
      <div style="height:8px"></div>
      <div id="progconfirmed"></div>
      <div class="log" id="attackout" style="max-height:220px;overflow:auto"></div>
    </div>
  </section>

  <section id="flags" class="hide">
    <div class="card">
      <h3>flag inbox</h3>
      <div class="row">
        <label class="muted"><input type="checkbox" id="reveal" onchange="loadFlags()">
          reveal values</label>
        <span class="muted">AETHER never submits — "mark" only records what YOU did.</span>
      </div>
      <div style="height:8px"></div>
      <div id="flagtable"></div>
    </div>
  </section>

  <section id="config" class="hide">
    <div id="cfgbanner"></div>
    <div class="card">
      <h3>scope builder — set this at the briefing</h3>
      <p class="muted">Add every authorized target the organizer gives you. <b>owner=opponent</b>
        = you may attack it; <b>owner=self</b> = your own service to defend (put its web-root
        path in <i>notes</i> so defense can watch it for web shells). Saving is fail-closed:
        it refuses to disable scope or turn on auto-submit.</p>
      <div style="height:8px"></div>
      <div class="row">
        <label class="muted">flag pattern
          <input id="fpattern" class="mono" placeholder="IONIC\{[^}]+\}"
            style="width:220px;background:#05090f;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 8px"></label>
        <label class="muted">tick seconds
          <input id="ftick" type="number" placeholder="120"
            style="width:90px;background:#05090f;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 8px"></label>
        <label class="muted"><input type="checkbox" id="fenforce" checked> enforce scope
          (keep ON)</label>
      </div>
      <div style="height:10px"></div>
      <table id="builder"><tr><th>name</th><th>host</th><th>ports</th><th>kind</th>
        <th>owner</th><th>notes (self web-root)</th><th></th></tr></table>
      <div style="height:8px"></div>
      <div class="row">
        <button class="ghost" onclick="addRow()">+ add target</button>
        <button class="act" onclick="applyScope()">Save scope</button>
        <span class="muted" id="builderout"></span>
      </div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <h3>scope — currently authorized</h3>
      <div id="scopetable"></div>
    </div>
    <div style="height:14px"></div>
    <details>
      <summary class="muted" style="cursor:pointer;padding:6px 0">Advanced — edit raw YAML</summary>
    <div class="card" style="margin-top:8px">
      <h3>config (<span id="cfgpath" class="mono muted"></span>)</h3>
      <textarea id="cfgyaml" spellcheck="false"></textarea>
      <div style="height:10px"></div>
      <div class="row">
        <button class="act" onclick="saveConfig()">Save config</button>
        <button class="ghost" onclick="loadConfig()">Reload</button>
        <span class="muted">Save is fail-closed: it refuses to disable scope or empty
          targets, and auto-submit can never be enabled.</span>
      </div>
      <div class="log" id="cfgout"></div>
    </div>
    </details>
  </section>

  <section id="guide" class="hide">
    <div class="card">
      <h3>first 5 minutes (do this in order)</h3>
      <ol class="guidelist">
        <li><b>Defend first.</b> Everyone starts with the SAME vulnerable service. Whatever you
          can exploit on others, they can exploit on you — so patch yourself before you attack.</li>
        <li><b>Snapshot your service</b> and back up the flag store. Note what "normal" looks
          like (this dashboard's Monitor tab is your baseline).</li>
        <li><b>Fill the scope</b> (Config tab) with every target the organizer gives you:
          opponents to attack, your own service as <i>self</i>.</li>
        <li><b>Run one sweep</b> on an opponent (Attack tab) to confirm the toolchain works and
          see what the vuln is.</li>
        <li><b>Find the same bug on your own box and patch it</b> — carefully, keep the service
          working (the scoreboard checks it).</li>
      </ol>
    </div>
    <div class="grid">
      <div class="card"><h3>the loop (every tick)</h3>
        <ol class="guidelist">
          <li>Attack: re-sweep every opponent (flags rotate each tick) → submit from Flags tab.</li>
          <li>Defend: watch Monitor for web shells / integrity drift → quarantine, re-patch.</li>
          <li>Never take your service DOWN — downtime loses SLA points even if unhacked.</li>
        </ol>
      </div>
      <div class="card"><h3>role split (2 people)</h3>
        <ul class="guidelist">
          <li><b>You — Attack:</b> run sweeps, read flags, submit on the portal, mark submitted.</li>
          <li><b>Teammate — Defense:</b> watch Monitor, quarantine shells, patch & keep service up.</li>
          <li>Swap only if one side is quiet. Talk constantly.</li>
        </ul>
      </div>
    </div>
    <div class="card"><h3>golden rules</h3>
      <ul class="guidelist">
        <li>A patched bug you can still exploit on others = double points. Patch, don't just block your own IP.</li>
        <li>Don't delete the flag file or break the service to "fix" it — you lose SLA points.</li>
        <li>Keep a copy of every exploit that worked; flags rotate, the bug usually doesn't.</li>
        <li>AETHER reads flags but <b>never submits</b> — you paste them on the official portal.</li>
        <li>Full strategy + command cheatsheet: <span class="mono">docs/STRATEGY.md</span> and
          <span class="mono">docs/CHEATSHEET.md</span> in the repo.</li>
      </ul>
    </div>
  </section>
</main>
<div class="foot">AETHER A&amp;D · localhost console · no AI runtime · read-only probes ·
  remediation &amp; submission are operator-gated</div>

<script>
const TOKEN="__TOKEN__";
const $=s=>document.querySelector(s);
async function getJSON(u){const r=await fetch(u);return r.json();}
async function postJSON(u,b){const r=await fetch(u,{method:"POST",
  headers:{"Content-Type":"application/json","X-AETHER-Token":TOKEN},
  body:JSON.stringify(b||{})});return r.json();}
function esc(s){return String(s==null?"":s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

let tab="monitor";
document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>{
  tab=b.dataset.tab;
  document.querySelectorAll("nav button").forEach(x=>x.classList.toggle("active",x===b));
  ["monitor","attack","flags","config","guide"].forEach(t=>$("#"+t).classList.toggle("hide",t!==tab));
  if(tab==="flags")loadFlags(); if(tab==="config")loadConfig();
  if(tab==="attack"){loadTargets();pollProgress();}
});

function kpi(n,l,c){return `<div><div class="n" style="color:${c||'var(--cyan)'}">${n}</div><div class="l">${l}</div></div>`;}
async function tick(){
  let s; try{s=await getJSON("/api/state");}catch(e){$("#hstat").textContent="backend unreachable";return;}
  const t=s.tick?`tick <b>${s.tick.tick}</b> (next ${s.tick.next_in}s)`:"tick <b>n/a</b>";
  $("#hstat").innerHTML=`${t} · sweeps <b>${s.sweeps}</b> · uptime <b>${s.uptime}s</b> · incidents <b style="color:${s.incidents.length?'var(--red)':'var(--green)'}">${s.incidents.length}</b>`;
  const r=s.resources; $("#hres").innerHTML=`cpu <b>${r.cpu}%</b> · mem <b>${r.mem_percent}%</b> · rss <b>${r.rss_mib}MiB</b>`;
  const fv=s.flags.by_validation||{}, fs=s.flags.by_submission||{};
  $("#kpi").innerHTML=kpi(s.flags.total,"flags")+kpi(fv.VALIDATED||0,"validated","var(--green)")+
    kpi(fs.PENDING||0,"pending submit","var(--yellow)")+kpi(s.incidents.length,"incidents",s.incidents.length?"var(--red)":"var(--green)")+
    kpi(s.services.filter(x=>x.up).length+"/"+s.services.length,"services up");
  $("#services").innerHTML=s.services.length?`<table><tr><th>service</th><th>health</th><th>latency</th><th>functional</th></tr>`+
    s.services.map(h=>`<tr><td>${esc(h.service)}</td><td class="${h.up?'up':'down'}">${h.up?'● UP':'● DOWN'}</td><td class="mut">${h.latency_ms} ms</td><td>${h.functional==null?'<span class="mut">n/a</span>':(h.functional?'<span class="up">pass</span>':'<span class="down">FAIL</span>')}</td></tr>`).join("")+`</table>`:'<span class="mut">no probes</span>';
  $("#integrity").innerHTML=s.integrity.length?`<table><tr><th>path</th><th>baseline</th><th>status</th></tr>`+
    s.integrity.map(i=>`<tr><td>${esc(i.path)}</td><td class="mut">${i.baseline} files</td><td>${i.clean?'<span class="up">clean</span>':`<span class="down">+${i.added} ~${i.modified} -${i.removed}</span>`}</td></tr>`).join("")+`</table>`:'<span class="mut">no paths watched</span>';
  $("#incidents").innerHTML=s.incidents.length?`<table><tr><th>severity</th><th>kind</th><th>summary</th></tr>`+
    s.incidents.map(i=>`<tr><td class="sev-${i.severity}">${i.severity}</td><td>${esc(i.kind)}</td><td>${esc(i.summary)}</td></tr>`).join("")+`</table>`:'<span class="up">no incidents this sweep</span>';
  window._shells=s.webshells||[];
  $("#webshells").innerHTML=window._shells.length?`<table><tr><th>path</th><th>signatures</th><th>action</th></tr>`+
    window._shells.map((w,i)=>`<tr><td class="mono down">${esc(w.path)}</td><td class="mut">${esc((w.signatures||[]).join(", "))}</td><td><button class="act" onclick="quarantineIdx(${i})">Quarantine</button></td></tr>`).join("")+`</table>`:'<span class="up">none detected in watched roots</span>';
  $("#flagsum").innerHTML=`<table>
    <tr><td class="mut">total</td><td><b>${s.flags.total}</b></td></tr>
    <tr><td class="mut">VALIDATED</td><td class="up">${fv.VALIDATED||0}</td></tr>
    <tr><td class="mut">UNVERIFIED</td><td class="warn">${fv.UNVERIFIED||0}</td></tr>
    <tr><td class="mut">PENDING submit</td><td class="warn">${fs.PENDING||0}</td></tr>
    <tr><td class="mut">SUBMITTED / ACCEPTED</td><td>${fs.SUBMITTED||0} / ${fs.ACCEPTED||0}</td></tr></table>`;
  $("#mods").innerHTML=s.mods.length?`<table><tr><th>time</th><th>component</th><th>action</th><th>target</th></tr>`+
    s.mods.map(m=>`<tr><td class="mut">${esc(m.ts)}</td><td>${esc(m.component)}</td><td>${esc(m.action)}</td><td class="mut">${esc(m.target)}</td></tr>`).join("")+`</table>`:'<span class="mut">no changes logged</span>';
}

async function loadTargets(){
  const c=await getJSON("/api/config");
  $("#targets").innerHTML=`<table><tr><th>name</th><th>host:port</th><th>kind</th><th>owner</th><th></th></tr>`+
    c.targets.map(t=>{const hp=`${t.host}:${t.ports[0]||80}`;
      const btn=t.owner==="opponent"?`<button class="act" onclick="sweep('${esc(t.host)}',${t.ports[0]||80})">Sweep</button>`:'<span class="mut">self</span>';
      return `<tr><td>${esc(t.name)}</td><td class="mono">${esc(hp)}</td><td>${esc(t.kind)}</td><td class="${t.owner==='opponent'?'down':'up'}">${esc(t.owner)}</td><td>${btn}</td></tr>`;}).join("")+`</table>`;
}
let progTimer=null;
async function sweep(host,port){
  const r=await postJSON("/api/attack/sweep",{host,port});
  if(r.error){$("#attackout").textContent="✗ "+r.error;return;}
  $("#attackout").textContent=`▶ round ${r.round}: sweeping ${host}:${port} …`;
  startProgress();
}
function startProgress(){if(progTimer)clearInterval(progTimer);pollProgress();progTimer=setInterval(pollProgress,1200);}
async function pollProgress(){
  let p; try{p=await getJSON("/api/attack/progress");}catch(e){return;}
  if(!p||p.status==="idle"){$("#progcur").textContent="idle — pick a target above and hit Sweep";return;}
  const pct=p.total?Math.round(100*p.index/p.total):(p.status==="done"?100:5);
  $("#progbar").style.width=pct+"%";
  $("#progbar").style.background=p.status==="error"?"var(--red)":(p.status==="done"?"var(--green)":"var(--cyan)");
  $("#progphase").textContent="· "+(p.status==="running"?(p.phase||""):(p.status||""));
  $("#progcur").textContent=p.status==="running"
    ?(p.current?("running "+p.current+"  ("+p.index+"/"+p.total+")"):(p.phase||"working…"))
    :(p.summary||"");
  $("#progstat").innerHTML=`round <b>${p.round||"-"}</b> · confirmed <b>${(p.confirmed||[]).length}</b> · flags <b style="color:var(--green)">${p.flags||0}</b>`+
    (p.authenticated?` · <span class="up">logged in${p.login_as?(" as "+esc(p.login_as)):""}</span>`:"");
  $("#progconfirmed").innerHTML=(p.confirmed||[]).length
    ?'<div class="row">'+p.confirmed.map(m=>`<span class="pill" style="background:#07140f;color:var(--green);border:1px solid var(--green)">${esc(m)}</span>`).join(" ")+'</div>':"";
  $("#attackout").textContent=(p.log||[]).join("\n");
  $("#attackout").scrollTop=$("#attackout").scrollHeight;
  if(p.status!=="running"){if(progTimer){clearInterval(progTimer);progTimer=null;}}
}
async function defenseSweep(){const r=await postJSON("/api/defense/sweep",{});$("#attackout").textContent=`defense sweep: ${r.incidents} incident(s)`;}
async function quarantineIdx(i){
  const w=(window._shells||[])[i]; if(!w)return;
  if(!confirm("Quarantine (back up + move out of web root) "+w.path+" ?"))return;
  $("#wsout").textContent="quarantining "+w.path+" … (backup → move → functional test → verify)";
  const r=await postJSON("/api/defense/quarantine",{path:w.abs_path});
  if(r.error){$("#wsout").textContent="✗ "+r.error;return;}
  $("#wsout").textContent=`${r.outcome}${r.safe?" ✓ safe":""}: ${r.detail}\n`+(r.steps||[]).join("\n");
  tick();
}

async function loadFlags(){
  const show=$("#reveal").checked?1:0;
  const d=await getJSON("/api/flags?show="+show);
  $("#flagtable").innerHTML=d.flags.length?`<table><tr><th>key</th><th>value</th><th>target</th><th>module</th><th>validation</th><th>submission</th><th>actions</th></tr>`+
    d.flags.map(f=>`<tr><td class="mono mut">${esc(f.key_short)}</td><td class="mono">${esc(f.value)}</td><td>${esc(f.target)}</td><td class="mut">${esc(f.module)}</td><td class="${f.validation==='VALIDATED'?'up':'warn'}">${f.validation}</td><td>${f.submission}</td>
      <td class="row"><button class="ghost" onclick="mark('${f.key}','SUBMITTED')">submitted</button>
      <button class="ghost" onclick="mark('${f.key}','ACCEPTED')">accepted</button></td></tr>`).join("")+`</table>`:'<span class="mut">no flags yet — run a sweep from the Attack tab</span>';
}
async function mark(key,status){await postJSON("/api/flags/mark",{key,status});loadFlags();}

const KINDS=["web","redis","memcached","tcp","vault","note","linux"];
const OWNERS=["opponent","self"];
function _opt(sel,v){return sel.map(k=>`<option ${k===v?"selected":""}>${k}</option>`).join("");}
function builderRow(t){
  t=t||{name:"",host:"",ports:[],kind:"web",owner:"opponent",notes:""};
  const tr=document.createElement("tr");
  tr.innerHTML=`<td><input class="builder-in f-name" value="${esc(t.name)}"></td>
    <td><input class="builder-in f-host" value="${esc(t.host)}"></td>
    <td><input class="builder-in f-ports" value="${esc((t.ports||[]).join(","))}" placeholder="80,8080"></td>
    <td><select class="builder-in f-kind">${_opt(KINDS,t.kind||"web")}</select></td>
    <td><select class="builder-in f-owner">${_opt(OWNERS,t.owner||"opponent")}</select></td>
    <td><input class="builder-in f-notes" value="${esc(t.notes||"")}" placeholder="/var/www/html"></td>
    <td><button class="ghost" onclick="this.closest('tr').remove()">✕</button></td>`;
  return tr;
}
function addRow(t){$("#builder").appendChild(builderRow(t));}
function fillBuilder(c){
  document.querySelectorAll("#builder tr:not(:first-child)").forEach(r=>r.remove());
  (c.targets||[]).forEach(t=>addRow(t));
  if(!(c.targets||[]).length)addRow();
  $("#fpattern").value=c.pattern||"";
  $("#ftick").value=c.tick||"";
  $("#fenforce").checked=c.enforce!==false;
}
async function applyScope(){
  const rows=[...document.querySelectorAll("#builder tr:not(:first-child)")];
  const targets=rows.map(r=>({
    name:r.querySelector(".f-name").value.trim(),
    host:r.querySelector(".f-host").value.trim(),
    ports:r.querySelector(".f-ports").value.trim(),
    kind:r.querySelector(".f-kind").value,
    owner:r.querySelector(".f-owner").value,
    notes:r.querySelector(".f-notes").value.trim(),
  })).filter(t=>t.name||t.host);
  $("#builderout").textContent="saving…";
  const r=await postJSON("/api/config/apply",{
    pattern:$("#fpattern").value.trim(),tick:$("#ftick").value.trim(),
    enforce:$("#fenforce").checked,targets});
  if(r.error){$("#builderout").innerHTML='<span class="down">✗ '+esc(r.error)+'</span>';return;}
  $("#builderout").innerHTML=(r.ready?'<span class="up">✓ saved — READY</span>':'<span class="warn">✓ saved — not ready: '+esc((r.issues||[]).join("; "))+'</span>')+' <span class="muted">(restart the web console to re-arm the live engine)</span>';
  loadConfig();
}
async function loadConfig(){
  const c=await getJSON("/api/config");
  $("#cfgpath").textContent=c.path;
  $("#cfgyaml").value=c.yaml;
  fillBuilder(c);
  let b=c.ready?`<div class="banner ok">✓ READY — scope is armed and fail-closed</div>`
    :`<div class="banner bad">✗ NOT READY (fail closed):<br>`+c.issues.map(esc).join("<br>")+`</div>`;
  if(c.warnings&&c.warnings.length)b+=`<div class="banner" style="border-color:var(--yellow);color:var(--yellow)">⚠ `+c.warnings.map(esc).join("<br>⚠ ")+`</div>`;
  $("#cfgbanner").innerHTML=b;
  $("#scopetable").innerHTML=c.targets.length?`<table><tr><th>name</th><th>host:port</th><th>kind</th><th>owner</th></tr>`+
    c.targets.map(t=>`<tr><td>${esc(t.name)}</td><td class="mono">${esc(t.host)}:${t.ports[0]||80}</td><td>${esc(t.kind)}</td><td class="${t.owner==='opponent'?'down':'up'}">${esc(t.owner)}</td></tr>`).join("")+`</table>`:'<span class="mut">no targets</span>';
}
async function saveConfig(){
  $("#cfgout").textContent="saving…";
  const r=await postJSON("/api/config/save",{yaml:$("#cfgyaml").value});
  if(r.error){$("#cfgout").textContent="✗ "+r.error;return;}
  $("#cfgout").textContent="✓ "+(r.note||"saved")+(r.ready?"":"\n⚠ not ready: "+(r.issues||[]).join("; "));
  loadConfig();
}

tick(); setInterval(()=>{if(tab==="monitor")tick();},3000);
</script>
</body>
</html>
"""
