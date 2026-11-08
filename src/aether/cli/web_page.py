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
      <div class="log" id="attackout"></div>
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
      <h3>scope — authorized targets</h3>
      <div id="scopetable"></div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
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
  ["monitor","attack","flags","config"].forEach(t=>$("#"+t).classList.toggle("hide",t!==tab));
  if(tab==="flags")loadFlags(); if(tab==="config")loadConfig(); if(tab==="attack")loadTargets();
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
async function sweep(host,port){
  $("#attackout").textContent=`▶ sweeping ${host}:${port} … (recon + login + arsenal)`;
  const r=await postJSON("/api/attack/sweep",{host,port});
  if(r.error){$("#attackout").textContent="✗ "+r.error;return;}
  $("#attackout").textContent=`${r.authenticated?('✓ logged in as '+r.login_as+'\n'):''}${r.summary}\nconfirmed: ${(r.confirmed||[]).join(", ")||'—'}\n→ check the Flags tab (PENDING; you submit).`;
}
async function defenseSweep(){const r=await postJSON("/api/defense/sweep",{});$("#attackout").textContent=`defense sweep: ${r.incidents} incident(s)`;}

async function loadFlags(){
  const show=$("#reveal").checked?1:0;
  const d=await getJSON("/api/flags?show="+show);
  $("#flagtable").innerHTML=d.flags.length?`<table><tr><th>key</th><th>value</th><th>target</th><th>module</th><th>validation</th><th>submission</th><th>actions</th></tr>`+
    d.flags.map(f=>`<tr><td class="mono mut">${esc(f.key_short)}</td><td class="mono">${esc(f.value)}</td><td>${esc(f.target)}</td><td class="mut">${esc(f.module)}</td><td class="${f.validation==='VALIDATED'?'up':'warn'}">${f.validation}</td><td>${f.submission}</td>
      <td class="row"><button class="ghost" onclick="mark('${f.key}','SUBMITTED')">submitted</button>
      <button class="ghost" onclick="mark('${f.key}','ACCEPTED')">accepted</button></td></tr>`).join("")+`</table>`:'<span class="mut">no flags yet — run a sweep from the Attack tab</span>';
}
async function mark(key,status){await postJSON("/api/flags/mark",{key,status});loadFlags();}

async function loadConfig(){
  const c=await getJSON("/api/config");
  $("#cfgpath").textContent=c.path;
  $("#cfgyaml").value=c.yaml;
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
