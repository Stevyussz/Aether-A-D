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
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
  @media(max-width:820px){.grid,.grid3{grid-template-columns:1fr}}
  .chart{width:100%;height:120px;display:block}
  .chart text{fill:var(--dim);font-size:10px}
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
  <button data-tab="defense">Defense</button>
  <button data-tab="flags">Flags</button>
  <button data-tab="config">Config</button>
  <button data-tab="guide">Panduan</button>
</nav>
<main>
  <section id="monitor">
    <div class="kpi" id="kpi"></div>
    <div style="height:12px"></div>
    <div class="grid3">
      <div class="card"><h3>CPU &amp; memory (live)</h3><div id="chart-res"></div></div>
      <div class="card"><h3>service latency (ms)</h3><div id="chart-lat"></div></div>
      <div class="card"><h3>flags</h3><div id="chart-flags"></div></div>
    </div>
    <div style="height:14px"></div>
    <div class="grid">
      <div class="card"><h3>services</h3><div id="services"></div></div>
      <div class="card"><h3>file integrity</h3><div id="integrity"></div></div>
    </div>
    <div style="height:14px"></div>
    <div class="card"><h3>incidents (sweep terakhir)</h3><div id="incidents"></div></div>
    <div style="height:14px"></div>
    <div class="card"><h3>web shell terdeteksi (service kita)</h3><div id="webshells"></div>
      <div class="log" id="wsout"></div></div>
    <div style="height:14px"></div>
    <div class="grid">
      <div class="card"><h3>flag inbox</h3><div id="flagsum"></div></div>
      <div class="card"><h3>log modifikasi / patch</h3><div id="mods"></div></div>
    </div>
  </section>

  <section id="attack" class="hide">
    <div class="card">
      <h3>attack control</h3>
      <p class="muted">Sweep menjalankan seluruh arsenal (external tools + recon + auto-login +
        baca flag di server). Scope-enforced. Flag masuk inbox sebagai PENDING — kamu yang
        submit di portal.</p>
      <label class="muted"><input type="checkbox" id="usetools" checked>
        pakai external tools (nmap/rustscan/gobuster/ffuf/whatweb) — lebih lengkap, agak lebih lama</label>
      <label class="muted" style="margin-left:14px"><input type="checkbox" id="usenuclei">
        + nuclei (CVE checks — lebih lambat, hasil jadi lead)</label>
      <div style="height:10px"></div>
      <div class="row" style="margin-bottom:10px">
        <button class="act" onclick="sweep('*',null)">▶ Sweep SEMUA Lawan (All Targets &amp; Ports)</button>
        <button class="ghost" id="btn-atk-loop" onclick="toggleAttackLoop()">Switch Auto-Attack Loop: OFF</button>
      </div>
      <div id="targets"></div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <h3>farm control — auto multi-target (satset)</h3>
      <p class="muted">Tarik daftar lawan dari Targets API → auto-attack loop serang semua →
        auto-submit tiap ronde. Harvester ambil flag dari path yang kamu tau ke SEMUA target.</p>
      <div class="row" style="margin-bottom:8px">
        <button class="act" onclick="syncTargets()">⟳ Sync target dari API</button>
        <button class="ghost" id="btn-autosub" onclick="toggleAutoSubmit()">Auto-submit: OFF</button>
      </div>
      <div id="farmout" class="muted" style="font-size:12px"></div>
      <div style="height:8px"></div>
      <label class="muted">Harvest paths (satu per baris; {ip}/{port} boleh) — path yang membocorkan flag:</label>
      <textarea id="harvestpaths" class="builder-in" style="width:100%;height:68px;font-family:monospace"
        placeholder="/index.php?page=/home/mahasiswa/flag.txt"></textarea>
      <div class="row" style="margin-top:6px">
        <button class="act" onclick="saveHarvest()">Simpan harvest paths</button>
        <span id="harveststat" class="muted"></span>
      </div>
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
      <div id="progintel"></div>
      <div class="log" id="attackout" style="max-height:220px;overflow:auto"></div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <h3>OAST — out-of-band callback (konfirmasi blind SSRF/RCE/XXE)</h3>
      <p class="muted">Listener self-hosted (data callback mendarat di box kita, bukan server
        publik). Start listener, mint URL unik, suntik ke payload blind; kalau target ping balik
        = vuln terkonfirmasi (sering bawa data exfil di path/body).</p>
      <div class="row" style="margin-top:6px">
        <label class="muted">listen port <input id="oast-port" type="number" value="0" style="width:78px" class="builder-in"></label>
        <label class="muted">pub host (IP tim kita) <input id="oast-pub" type="text" placeholder="10.60.x.x" style="width:120px" class="builder-in"></label>
        <button class="act" onclick="oastStart()">Start</button>
        <button class="ghost" onclick="oastStop()">Stop</button>
        <button class="act" onclick="oastToken()">Mint URL</button>
        <button class="ghost" onclick="loadOast()">Refresh</button>
      </div>
      <div class="row" style="margin-top:6px"><span class="muted" id="oast-stat">listener: stopped</span></div>
      <div id="oast-url"></div>
      <div style="height:8px"></div>
      <div id="oast-list"><span class="mut">belum ada interaksi.</span></div>
    </div>
  </section>

  <section id="defense" class="hide">
    <div class="card">
      <h3>defense control — jaga service kita, jangan sampai kebobolan</h3>
      <p class="muted">Deteksi web shell & perubahan file di service sendiri, lalu bersihkan
        dengan aman (backup dulu, reversible). Service tetap harus UP (dicek juri/SLA).</p>
      <div class="row">
        <button class="act" onclick="defSweep()">Jalankan defense sweep</button>
        <button class="act" onclick="defAudit()">Self-audit source (patch diri dulu)</button>
        <button class="ghost" onclick="runGuardNow()">Jalankan AutoGuard 1x</button>
        <button class="ghost" onclick="tick()">Scan ulang web shell</button>
        <span class="muted" id="defout"></span>
      </div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <h3>defense remote — SSH ke box kita, audit + harden (satset)</h3>
      <p class="muted">AETHER masuk SSH ke vulnbox kita sendiri: audit source (sink + upload-blacklist),
        scan web shell, dan privesc (SUID non-standar). <b>--harden</b> (opsional, reversible) cabut
        SUID + karantina webshell — tidak menyentuh Apache/health/proof/flag (SLA aman).</p>
      <div class="row" style="margin-top:6px">
        <input id="rem-ssh" type="text" class="builder-in" style="flex:1;min-width:260px;font-family:monospace"
          placeholder="6@10.2.4.4 -p 2222 -i ~/.ssh/key">
        <input id="rem-webroot" type="text" class="builder-in" style="width:160px;font-family:monospace"
          value="/var/www/html">
      </div>
      <div class="row" style="margin-top:8px">
        <button class="act" onclick="defRemote(false)">Audit (read-only)</button>
        <button class="ghost" onclick="defRemote(true)">Audit + Harden (cabut SUID + karantina)</button>
        <span id="remstat" class="muted"></span>
      </div>
      <div id="remout" class="log" style="max-height:240px;overflow:auto;margin-top:8px"></div>
    </div>
    <div style="height:14px"></div>
    <div class="grid">
      <div class="card">
        <h3>perisai file (AutoGuard — self-healing &amp; karantina)</h3>
        <p class="muted">Otomatis karantina file asing &amp; pulihkan file inti dari snapshot setiap siklus.</p>
        <div class="row" style="margin-top:8px">
          <button class="act" id="btn-guard-toggle" onclick="toggleGuard()">Switch AutoGuard: OFF</button>
          <span class="muted" id="guard-stat">status: OFF</span>
        </div>
      </div>
      <div class="card">
        <h3>perisai jaringan (HTTP Shield Proxy — filter input)</h3>
        <p class="muted">Reverse-proxy di depan port web kita dengan saklar ON/OFF instan.</p>
        <div class="row" style="margin-top:6px">
          <label class="muted">listen port <input id="sh-listen" type="number" value="8080" style="width:78px" class="builder-in"></label>
          <label class="muted">backend port <input id="sh-backend" type="number" value="8000" style="width:78px" class="builder-in"></label>
          <button class="act" id="btn-sh-run" onclick="startShield()">Start Proxy</button>
          <button class="ghost" id="btn-sh-stop" onclick="stopShield()">Stop</button>
        </div>
        <div class="row" style="margin-top:6px">
          <label class="muted">SLA allow IP (checker juri, pisah koma)
            <input id="sh-allow-ip" type="text" placeholder="10.60.0.1" style="width:150px" class="builder-in"></label>
          <label class="muted">allow path <input id="sh-allow-path" type="text" placeholder="/healthz,/sla" style="width:140px" class="builder-in"></label>
          <button class="ghost" onclick="applyAllowlist()">Set allowlist</button>
        </div>
        <div class="row" style="margin-top:8px">
          <button class="act" id="btn-sh-toggle" onclick="toggleShieldFilter()">Filter Switch: ON (BLOCKING)</button>
          <span class="muted" id="sh-stat">proxy: stopped</span>
        </div>
        <p class="muted" style="margin-top:4px">SLA-safe: IP/path di allowlist tidak akan pernah
          diblok → service tetap lolos cek juri walau filter ON.</p>
      </div>
    </div>
    <div style="height:14px"></div>
    <div class="card">
      <h3>traffic capture — exploit musuh (curi &amp; replay ala Tulip)</h3>
      <p class="muted">Setiap request musuh yang masuk ke Shield kita direkam. Yang terdeteksi
        sebagai serangan bisa <b>di-replay ke semua tim lawan</b> (scope-enforced) — curi exploit
        mereka, balikin ke mereka. Flag hasil replay masuk inbox PENDING.</p>
      <div class="row" style="margin-top:6px">
        <button class="ghost" onclick="loadTraffic()">Refresh capture</button>
        <span class="muted" id="traf-stat"></span>
      </div>
      <div style="height:8px"></div>
      <div id="traf-list"><span class="mut">Shield harus running untuk menangkap trafik.</span></div>
    </div>
    <div style="height:14px"></div>
    <div class="card"><h3>self-audit — sink yang bisa di-exploit lawan (patch SEBELUM kebobolan)</h3>
      <p class="muted">Cerminan arsenal attack ke dalam: LFI/cmdi/SSTI/SQLi/upload/file ke-expose
        di source service kita, lengkap dengan saran patch. Read-only.</p>
      <div id="def-audit"><span class="mut">Klik "Self-audit source" untuk memindai.</span></div>
    </div>
    <div style="height:14px"></div>
    <div class="kpi" id="defkpi"></div>
    <div style="height:12px"></div>
    <div class="card"><h3>web shell terdeteksi — klik Quarantine untuk membersihkan</h3>
      <div id="def-webshells"></div><div class="log" id="def-wsout"></div></div>
    <div style="height:14px"></div>
    <div class="grid">
      <div class="card"><h3>incidents</h3><div id="def-incidents"></div></div>
      <div class="card"><h3>file integrity — service kita</h3><div id="def-integrity"></div></div>
    </div>
    <div style="height:14px"></div>
    <div class="card"><h3>services — status &amp; functional check (SLA)</h3>
      <div id="def-services"></div></div>
    <div style="height:14px"></div>
    <div class="card"><h3>log modifikasi / patch (semua reversible)</h3>
      <div id="def-mods"></div></div>
  </section>

  <section id="flags" class="hide">
    <div class="card">
      <h3>flag inbox</h3>
      <div class="row">
        <label class="muted"><input type="checkbox" id="reveal" onchange="loadFlags()">
          tampilkan nilai flag</label>
        <span class="muted">AETHER tidak pernah submit — tombol "mark" hanya mencatat tindakanmu.</span>
      </div>
      <div style="height:8px"></div>
      <div id="flagtable"></div>
    </div>
    <div class="card">
      <h3>submit ke panitia (organizer)</h3>
      <p class="muted">Kirim semua flag <b>VALIDATED</b> yang masih PENDING ke official game
        server (dari config <code>submission.*</code>). <b>Fail-closed</b>: tidak jalan kalau
        <code>submission.enabled=false</code> atau endpoint kosong. Tiap flag ditandai agar tidak
        terkirim dua kali. Ini satu-satunya jalur kirim otomatis, dan hanya ke endpoint panitia.</p>
      <div class="row">
        <button class="act" onclick="submitFlags()">Submit flag VALIDATED ke panitia</button>
        <span id="submitout" class="muted"></span>
      </div>
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
        <label class="muted">flag_id endpoint (optional)
          <input id="fflagid" class="mono" placeholder="http://10.60.0.1/flag_ids.json"
            style="width:260px;background:#05090f;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 8px"></label>
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
      <h3>PANDUAN LANGKAH DEMI LANGKAH (ikuti urut)</h3>
      <ol class="guidelist">
        <li><b>STEP 0 — Dapat info dari panitia (saat warmup/brief).</b> Catat: (a) <b>token API</b>
          kamu (<span class="mono">ad_...</span>), (b) <b>IP + akses SSH vulnbox KITA</b>
          (<span class="mono">ssh &lt;id&gt;@host -p 2222 -i key</span>, dari portal "SSH access"),
          (c) alamat <b>Game</b> (warmup=Game 4, final=Game 2).</li>
        <li><b>STEP 1 — Isi Config (tab Config).</b> Flag pattern <span class="mono">IONIC\{[^}]+\}</span>;
          scoring tick; <b>targets_endpoint</b> = <span class="mono">.../Ad/Targets</span>;
          submission: endpoint <span class="mono">.../Ad/Submit</span>, <b>batch=true</b>,
          token_header <span class="mono">Authorization</span>, token <span class="mono">"Bearer ad_..."</span>.
          Edit YAML via Advanced kalau perlu. Pastikan scope enforce ON.</li>
        <li><b>STEP 2 — DEFENDER amankan box KITA (tab Defense → "defense remote").</b> Isi SSH args
          box kita → <b>Audit (read-only)</b>. Patch tiap temuan CRITICAL/HIGH via SSH (whitelist
          upload, prepared statement, dll). Lalu <b>Audit + Harden</b> → cabut SUID + karantina
          webshell (reversible). JANGAN matikan Apache/health.php/proof.php (SLA).</li>
        <li><b>STEP 3 — ATTACKER ambil SEMUA target (tab Attack → "farm control").</b>
          Klik <b>⟳ Sync target dari API</b> → semua lawan (status Ok) masuk scope otomatis.
          Nyalakan <b>Auto-submit: ON</b>. Nyalakan <b>Auto-Attack Loop: ON</b> (atau klik Sweep SEMUA).</li>
        <li><b>STEP 4 — Kalau tau PATH flag, pakai Harvester.</b> Mis. nemu LFI
          <span class="mono">/index.php?page=/home/mahasiswa/flag.txt</span> → tempel di kotak
          <b>Harvest paths</b> → Simpan. Tiap tick ditembak ke SEMUA lawan + auto-submit.</li>
        <li><b>STEP 5 — Loop sampai habis.</b> Pantau tab Monitor (flag masuk, "accepted" naik) &
          box kita (webshell asing? SLA Ok?). Attacker lihat flag, Defender jaga box. Ngobrol terus.</li>
      </ol>
    </div>
    <div class="grid">
      <div class="card"><h3>ritme tiap tick</h3>
        <ol class="guidelist">
          <li><b>Attack:</b> Auto-Attack Loop + Auto-submit ON → serang semua lawan tiap tick,
            flag auto-submit. Cukup pantau "accepted" naik.</li>
          <li><b>Defend:</b> pantau Monitor (webshell / file berubah) → defense remote Harden,
            re-patch kalau ada bug baru.</li>
          <li>Service JANGAN down — downtime = SLA jatuh walau gak kebobolan.</li>
        </ol>
      </div>
      <div class="card"><h3>bagi peran (2 orang)</h3>
        <ul class="guidelist">
          <li><b>Attacker:</b> Sync target → Auto-Attack Loop + Auto-submit ON → isi Harvest path
            kalau ketemu → pantau flag.</li>
          <li><b>Defender:</b> defense remote Audit+Harden box kita, patch via SSH, jaga SLA Ok.</li>
          <li>Ngobrol terus. Tukeran peran kalau satu sisi sepi.</li>
        </ul>
      </div>
    </div>
    <div class="card"><h3>aturan emas</h3>
      <ul class="guidelist">
        <li>Bug yang kamu patch TAPI masih bisa exploit ke lawan = poin ganda. Patch bug-nya,
          jangan cuma blok IP-mu.</li>
        <li>Jangan hapus file flag / rusak service buat "benerin" — SLA jatuh.</li>
        <li>Simpan tiap exploit yang berhasil (Harvest path / custom script); flag ganti, bug biasanya tetap.</li>
        <li><b>Auto-submit</b> aktif = AETHER kirim flag VALIDATED ke panitia pakai token-mu (fail-closed:
          mati kalau submission belum diisi). Verifikasi "accepted" di log.</li>
        <li>⚠ <b>Aturan lomba: dilarang AI selama bertanding.</b> AETHER = automation (no-AI runtime),
          boleh. Jangan buka ChatGPT/Claude. Siapkan exploit SEBELUM lomba.</li>
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
  ["monitor","attack","defense","flags","config","guide"].forEach(t=>$("#"+t).classList.toggle("hide",t!==tab));
  if(tab==="flags")loadFlags(); if(tab==="config")loadConfig();
  if(tab==="attack"){loadTargets();pollProgress();}
  if(tab==="defense")tick();
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
    s.services.map(h=>`<tr><td>${esc(h.service)}</td><td class="${h.up?'up':'down'}">${h.up?'● UP':'● DOWN'}</td><td class="mut">${h.latency_ms} ms</td><td>${h.functional==null?'<span class="mut">n/a</span>':(h.functional?'<span class="up">pass</span>':'<span class="down">FAIL</span>')}</td></tr>`).join("")+`</table>`:'<span class="mut">belum ada service probe</span>';
  $("#integrity").innerHTML=s.integrity.length?`<table><tr><th>path</th><th>baseline</th><th>status</th></tr>`+
    s.integrity.map(i=>`<tr><td>${esc(i.path)}</td><td class="mut">${i.baseline} files</td><td>${i.clean?'<span class="up">clean</span>':`<span class="down">+${i.added} ~${i.modified} -${i.removed}</span>`}</td></tr>`).join("")+`</table>`:'<span class="mut">belum ada path dipantau</span>';
  $("#incidents").innerHTML=s.incidents.length?`<table><tr><th>severity</th><th>kind</th><th>summary</th></tr>`+
    s.incidents.map(i=>`<tr><td class="sev-${i.severity}">${i.severity}</td><td>${esc(i.kind)}</td><td>${esc(i.summary)}</td></tr>`).join("")+`</table>`:'<span class="up">tidak ada incident di sweep ini</span>';
  window._shells=s.webshells||[];
  $("#webshells").innerHTML=window._shells.length?`<table><tr><th>path</th><th>signatures</th><th>action</th></tr>`+
    window._shells.map((w,i)=>`<tr><td class="mono down">${esc(w.path)}</td><td class="mut">${esc((w.signatures||[]).join(", "))}</td><td><button class="act" onclick="quarantineIdx(${i})">Quarantine</button></td></tr>`).join("")+`</table>`:'<span class="up">bersih — tidak ada web shell di watched roots</span>';
  $("#flagsum").innerHTML=`<table>
    <tr><td class="mut">total</td><td><b>${s.flags.total}</b></td></tr>
    <tr><td class="mut">VALIDATED</td><td class="up">${fv.VALIDATED||0}</td></tr>
    <tr><td class="mut">UNVERIFIED</td><td class="warn">${fv.UNVERIFIED||0}</td></tr>
    <tr><td class="mut">PENDING submit</td><td class="warn">${fs.PENDING||0}</td></tr>
    <tr><td class="mut">SUBMITTED / ACCEPTED</td><td>${fs.SUBMITTED||0} / ${fs.ACCEPTED||0}</td></tr></table>`;
  $("#mods").innerHTML=s.mods.length?`<table><tr><th>time</th><th>component</th><th>action</th><th>target</th></tr>`+
    s.mods.map(m=>`<tr><td class="mut">${esc(m.ts)}</td><td>${esc(m.component)}</td><td>${esc(m.action)}</td><td class="mut">${esc(m.target)}</td></tr>`).join("")+`</table>`:'<span class="mut">belum ada perubahan tercatat</span>';
  window._laststate=s; pushHistory(s); drawCharts();
  if(tab==="defense")renderDefense(s);
}

// ---- charts (inline SVG, offline) --------------------------------------------------------
const HIST={cpu:[],mem:[],lat:{},flags:[]};
function pushHistory(s){
  const cap=40;
  HIST.cpu.push(s.resources.cpu); if(HIST.cpu.length>cap)HIST.cpu.shift();
  HIST.mem.push(s.resources.mem_percent); if(HIST.mem.length>cap)HIST.mem.shift();
  (s.services||[]).forEach(h=>{const k=h.service;(HIST.lat[k]=HIST.lat[k]||[]).push(h.up?h.latency_ms:0); if(HIST.lat[k].length>cap)HIST.lat[k].shift();});
  const fv=s.flags.by_validation||{}; HIST.flags.push(fv.VALIDATED||0); if(HIST.flags.length>cap)HIST.flags.shift();
}
function linePath(arr,w,h,max){
  if(!arr.length)return "";
  const mx=max||Math.max(1,...arr); const step=arr.length>1?w/(arr.length-1):w;
  return arr.map((v,i)=>`${i===0?'M':'L'}${(i*step).toFixed(1)},${(h-(v/mx)*h).toFixed(1)}`).join(" ");
}
function sparkSVG(series,max,unit){
  const w=300,h=100; let paths="",leg="",ci=0;
  const cols=["var(--cyan)","var(--green)","var(--magenta)","var(--yellow)","var(--red)"];
  for(const name in series){const c=cols[ci%cols.length];ci++;
    paths+=`<path d="${linePath(series[name],w,h,max)}" fill="none" stroke="${c}" stroke-width="1.5"/>`;
    const last=series[name].length?series[name][series[name].length-1]:0;
    leg+=`<tspan fill="${c}">■</tspan> ${esc(name)} ${last}${unit||""}  `;}
  return `<svg class="chart" viewBox="0 0 ${w} ${h+16}" preserveAspectRatio="none">${paths}<text x="0" y="${h+12}">${leg}</text></svg>`;
}
function barSVG(arr,col){
  const w=300,h=100,mx=Math.max(1,...arr),bw=arr.length?w/arr.length:w;
  const bars=arr.map((v,i)=>`<rect x="${(i*bw).toFixed(1)}" y="${(h-(v/mx)*h).toFixed(1)}" width="${(bw*0.8).toFixed(1)}" height="${((v/mx)*h).toFixed(1)}" fill="${col}"/>`).join("");
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${bars}</svg>`;
}
function drawCharts(){
  $("#chart-res").innerHTML=sparkSVG({cpu:HIST.cpu,mem:HIST.mem},100,"%");
  const latc=$("#chart-lat"); if(latc)latc.innerHTML=Object.keys(HIST.lat).length?sparkSVG(HIST.lat,null,"ms"):'<span class="mut">no services</span>';
  const fc=$("#chart-flags"); if(fc)fc.innerHTML=HIST.flags.some(x=>x)?barSVG(HIST.flags,"var(--green)"):'<span class="mut">belum ada flag VALIDATED</span>';
}

// ---- defense tab -------------------------------------------------------------------------
function renderDefense(s){
  const shells=s.webshells||[]; window._shells=shells;
  const down=(s.services||[]).filter(x=>!x.up).length;
  const crit=(s.incidents||[]).filter(i=>i.severity==="CRITICAL").length;
  $("#defkpi").innerHTML=kpi(shells.length,"web shell",shells.length?"var(--red)":"var(--green)")+
    kpi(crit,"incident CRITICAL",crit?"var(--red)":"var(--green)")+
    kpi((s.services.filter(x=>x.up).length)+"/"+s.services.length,"service UP",down?"var(--red)":"var(--green)")+
    kpi((s.integrity||[]).filter(i=>!i.clean).length,"file integrity drift","var(--yellow)");
  $("#def-webshells").innerHTML=shells.length?`<table><tr><th>path</th><th>signatures</th><th>action</th></tr>`+
    shells.map((w,i)=>`<tr><td class="mono down">${esc(w.path)}</td><td class="mut">${esc((w.signatures||[]).join(", "))}</td><td><button class="act" onclick="quarantineDef(${i})">Quarantine</button></td></tr>`).join("")+`</table>`:'<span class="up">bersih — tidak ada web shell di watched roots</span>';
  $("#def-incidents").innerHTML=(s.incidents||[]).length?`<table><tr><th>severity</th><th>kind</th><th>summary</th></tr>`+
    s.incidents.map(i=>`<tr><td class="sev-${i.severity}">${i.severity}</td><td>${esc(i.kind)}</td><td>${esc(i.summary)}</td></tr>`).join("")+`</table>`:'<span class="up">tidak ada incident</span>';
  $("#def-integrity").innerHTML=(s.integrity||[]).length?`<table><tr><th>path</th><th>baseline</th><th>status</th></tr>`+
    s.integrity.map(i=>`<tr><td>${esc(i.path)}</td><td class="mut">${i.baseline} files</td><td>${i.clean?'<span class="up">clean</span>':`<span class="down">+${i.added} ~${i.modified} -${i.removed}</span>`}</td></tr>`).join("")+`</table>`:'<span class="mut">belum ada path yang dipantau (set owner=self + notes di Config)</span>';
  $("#def-services").innerHTML=(s.services||[]).length?`<table><tr><th>service</th><th>health</th><th>latency</th><th>functional (SLA)</th></tr>`+
    s.services.map(h=>`<tr><td>${esc(h.service)}</td><td class="${h.up?'up':'down'}">${h.up?'● UP':'● DOWN'}</td><td class="mut">${h.latency_ms} ms</td><td>${h.functional==null?'<span class="mut">n/a</span>':(h.functional?'<span class="up">pass</span>':'<span class="down">FAIL</span>')}</td></tr>`).join("")+`</table>`:'<span class="mut">no service probes</span>';
  $("#def-mods").innerHTML=(s.mods||[]).length?`<table><tr><th>time</th><th>component</th><th>action</th><th>target</th></tr>`+
    s.mods.map(m=>`<tr><td class="mut">${esc(m.ts)}</td><td>${esc(m.component)}</td><td>${esc(m.action)}</td><td class="mut">${esc(m.target)}</td></tr>`).join("")+`</table>`:'<span class="mut">belum ada perubahan tercatat</span>';
  if(s.guard){
    window._guardEnabled=!!s.guard.enabled;
    const gb=$("#btn-guard-toggle");
    if(gb){gb.textContent=s.guard.enabled?"Switch AutoGuard: ON (AKTIF)":"Switch AutoGuard: OFF";
      gb.style.background=s.guard.enabled?"var(--green)":"var(--panel2)";
      gb.style.color=s.guard.enabled?"#04121a":"var(--fg)";}
    const gs=$("#guard-stat");
    if(gs)gs.innerHTML=`cycles: <b>${s.guard.cycles||0}</b> · quarantined: <b>${s.guard.total_quarantined||0}</b> · restored: <b>${s.guard.total_restored||0}</b>`;
  }
  if(s.shield){
    window._shieldEnabled=!!s.shield.enabled;
    const sb=$("#btn-sh-toggle");
    if(sb){sb.textContent=s.shield.enabled?"Filter Switch: ON (BLOCKING)":"Filter Switch: OFF (PASS-THROUGH)";
      sb.style.background=s.shield.enabled?"var(--green)":"var(--yellow)";
      sb.style.color="#04121a";}
    const ss=$("#sh-stat");
    if(ss)ss.innerHTML=(s.shield.running?`<span class="up">● RUNNING (:${s.shield.listen_port} → :${s.shield.backend_port})</span>`:`<span class="mut">● stopped</span>`)+
      ` · req: <b>${s.shield.total_requests||0}</b> · blocked: <b class="${s.shield.blocked_requests?'down':'up'}">${s.shield.blocked_requests||0}</b>`;
  }
}
async function toggleGuard(){
  const next=!window._guardEnabled;
  const r=await postJSON("/api/defense/guard",{enabled:next});
  $("#defout").textContent=`AutoGuard ${r.enabled?'ON':'OFF'} (quarantined=${(r.files_quarantined||[]).length}, restored=${(r.files_restored||[]).length})`;
  tick();
}
async function runGuardNow(){
  const r=await postJSON("/api/defense/guard",{});
  $("#defout").textContent=`AutoGuard pass selesai: quarantined=${(r.files_quarantined||[]).length}, restored=${(r.files_restored||[]).length}`;
  tick();
}
function _csv(id){return ($("#"+id).value||"").split(",").map(s=>s.trim()).filter(Boolean);}
async function startShield(){
  const lp=parseInt($("#sh-listen").value||"8080",10);
  const bp=parseInt($("#sh-backend").value||"8000",10);
  const r=await postJSON("/api/defense/shield",{action:"start",listen_port:lp,backend_port:bp,
    allow_ips:_csv("sh-allow-ip"),allow_paths:_csv("sh-allow-path")});
  $("#defout").textContent=r.error?("✗ "+r.error):`Shield proxy aktif di port ${r.listen_port} → backend ${bp}`;
  tick();
}
async function applyAllowlist(){
  const r=await postJSON("/api/defense/shield",{action:"allowlist",
    allow_ips:_csv("sh-allow-ip"),allow_paths:_csv("sh-allow-path")});
  $("#defout").textContent=r.error?("✗ "+r.error):("SLA allowlist di-set: "+JSON.stringify(r.allowlist));
}
async function stopShield(){
  await postJSON("/api/defense/shield",{action:"stop"});
  $("#defout").textContent="Shield proxy dihentikan";
  tick();
}
async function toggleShieldFilter(){
  const next=!window._shieldEnabled;
  const r=await postJSON("/api/defense/shield",{action:"toggle",enabled:next});
  $("#defout").textContent=`Shield filter: ${r.enabled?'ON (BLOCKING)':'OFF (PASS-THROUGH)'}`;
  tick();
}
async function defSweep(){
  $("#defout").textContent="menjalankan defense sweep…";
  const r=await postJSON("/api/defense/sweep",{});
  $("#defout").textContent=`defense sweep selesai: ${r.incidents} incident(s)`;
  tick();
}
async function defAudit(){
  $("#def-audit").innerHTML='<span class="mut">memindai source…</span>';
  const r=await postJSON("/api/defense/audit",{});
  if(r.error){$("#def-audit").innerHTML='<span class="down">✗ '+esc(r.error)+'</span>';return;}
  const fs=r.findings||[];
  if(!fs.length){$("#def-audit").innerHTML='<span class="up">✓ tidak ada sink mencolok. Tetap cek manual.</span>';return;}
  const sevcls=s=>({CRITICAL:"sev-CRITICAL",HIGH:"sev-CRITICAL",MEDIUM:"sev-WARNING",LOW:"sev-INFO"}[s]||"");
  $("#def-audit").innerHTML='<div class="muted" style="margin-bottom:6px">'+Object.entries(r.by_severity||{}).map(([k,v])=>k+": "+v).join(" · ")+'</div>'+
    '<table><tr><th>severity</th><th>category</th><th>location</th><th>fix</th></tr>'+
    fs.map(f=>`<tr><td class="${sevcls(f.severity)}">${esc(f.severity)}</td><td>${esc(f.category)}</td><td class="mono">${esc(f.path)}${f.line?(":"+f.line):""}</td><td class="muted">${esc(f.remediation)}</td></tr>`).join("")+'</table>';
}
async function quarantineDef(i){
  const w=(window._shells||[])[i]; if(!w)return;
  if(!confirm("Quarantine (backup + pindahkan keluar web root) "+w.path+" ?"))return;
  $("#def-wsout").textContent="quarantine "+w.path+" … (backup → move → functional test → verify)";
  const r=await postJSON("/api/defense/quarantine",{path:w.abs_path});
  if(r.error){$("#def-wsout").textContent="✗ "+r.error;return;}
  $("#def-wsout").textContent=`${r.outcome}${r.safe?" ✓ safe":""}: ${r.detail}\n`+(r.steps||[]).join("\n");
  tick();
}

async function loadTargets(){
  const c=await getJSON("/api/config");
  $("#targets").innerHTML=`<table><tr><th>name</th><th>host:ports</th><th>kind</th><th>owner</th><th>actions</th></tr>`+
    c.targets.map(t=>{
      const pts=(t.ports&&t.ports.length)?t.ports:[80];
      const hp=`${t.host}:${pts.join(",")}`;
      let btn='<span class="mut">self (defended)</span>';
      if(t.owner==="opponent"){
        btn=pts.map(p=>`<button class="act" style="margin-right:4px" onclick="sweep('${esc(t.host)}',${p})">Sweep :${p}</button>`).join("");
        if(pts.length>1) btn+=`<button class="ghost" onclick="sweep('${esc(t.host)}',null)">All Ports</button>`;
      }
      return `<tr><td>${esc(t.name)}</td><td class="mono">${esc(hp)}</td><td>${esc(t.kind)}</td><td class="${t.owner==='opponent'?'down':'up'}">${esc(t.owner)}</td><td>${btn}</td></tr>`;}).join("")+`</table>`;
}
let progTimer=null;
async function sweep(host,port){
  const tools=$("#usetools")?$("#usetools").checked:true;
  const nuclei=$("#usenuclei")?$("#usenuclei").checked:false;
  const r=await postJSON("/api/attack/sweep",{host,port,tools,nuclei});
  if(r.error){$("#attackout").textContent="✗ "+r.error;return;}
  $("#attackout").textContent=`▶ round ${r.round}: sweeping ${host==='*'?'ALL opponents':(host+(port?(":"+port):" (all ports)"))} …`;
  startProgress();
}
async function toggleAttackLoop(){
  const next=!window._atkLoop;
  const r=await postJSON("/api/attack/loop",{enabled:next});
  window._atkLoop=!!r.loop_enabled;
  const b=$("#btn-atk-loop");
  if(b){b.textContent=window._atkLoop?"Switch Auto-Attack Loop: ON (AKTIF)":"Switch Auto-Attack Loop: OFF";
    b.style.background=window._atkLoop?"var(--green)":"transparent";
    b.style.color=window._atkLoop?"#04121a":"var(--fg)";}
  startProgress();
}
async function syncTargets(){
  const o=$("#farmout"); if(o) o.textContent="⟳ sync…";
  const r=await postJSON("/api/attack/targets-sync",{});
  if(o){ o.textContent = r.error ? ("✗ "+r.error)
    : `✓ roster ${r.roster}, sehat ${r.healthy}, +${r.added} target ke scope: `+(r.targets||[]).join(", "); }
  if(!r.error) tick();
}
async function toggleAutoSubmit(){
  const r=await postJSON("/api/attack/auto-submit",{enabled:!window._autosub});
  window._autosub=!!r.auto_submit;
  const b=$("#btn-autosub");
  if(b){ b.textContent=window._autosub?"Auto-submit: ON (AKTIF)":"Auto-submit: OFF";
    b.style.background=window._autosub?"var(--green)":"transparent";
    b.style.color=window._autosub?"#04121a":"var(--fg)"; }
  if(window._autosub && r.armed===false) alert("Auto-submit nyala, tapi submission belum armed: "+(r.reason||"cek config submission"));
}
async function saveHarvest(){
  const paths=$("#harvestpaths")?$("#harvestpaths").value:"";
  const r=await postJSON("/api/attack/harvest",{paths:paths,enabled:true});
  const s=$("#harveststat");
  if(s) s.textContent = r.ok ? `✓ ${r.paths.length} path disimpan (dipakai tiap sweep/farm)` : ("✗ "+(r.error||"gagal"));
}
async function defRemote(harden){
  const ssh=$("#rem-ssh")?$("#rem-ssh").value.trim():"";
  const webroot=$("#rem-webroot")?$("#rem-webroot").value.trim():"/var/www/html";
  if(!ssh){ alert("Isi SSH args dulu, mis. 6@10.2.4.4 -p 2222 -i ~/.ssh/key"); return; }
  if(harden && !confirm("Harden box: cabut SUID non-standar + karantina webshell (reversible). Lanjut?")) return;
  const st=$("#remstat"); if(st) st.textContent="⟳ SSH + audit…";
  const out=$("#remout"); if(out) out.innerHTML="";
  const r=await postJSON("/api/defense/remote",{ssh:ssh,webroot:webroot,harden:harden});
  if(st) st.textContent = r.error ? ("✗ "+r.error) : ("✓ "+(r.whoami||"connected"));
  if(r.error || !out) return;
  let h="";
  (r.audit||[]).forEach(f=>{h+=`<div><span class="sev-${f.severity==='CRITICAL'||f.severity==='HIGH'?'CRITICAL':'WARNING'}">${esc(f.severity)}</span> ${esc(f.category)} @ ${esc(f.location)} — ${esc(f.fix)}</div>`;});
  if((r.webshells||[]).length) h+='<div style="color:var(--red);margin-top:6px">⚠ webshell: '+r.webshells.map(w=>esc(w.path)+" ("+w.sigs.join(",")+")").join("; ")+'</div>';
  else h+='<div style="color:var(--green)">✓ tidak ada webshell</div>';
  if((r.suspect_suid||[]).length) h+='<div style="color:var(--red)">⚠ SUID non-standar: '+r.suspect_suid.map(esc).join(", ")+' → cabut (chmod u-s)</div>';
  else h+='<div style="color:var(--green)">✓ tidak ada SUID non-standar</div>';
  if(r.sudo) h+='<div class="muted">sudo -l: '+esc(r.sudo.slice(0,200))+'</div>';
  if(r.hardened) h+='<div style="color:var(--green);margin-top:6px">✓ hardened: '+(r.hardened.length?r.hardened.map(esc).join("; "):"nihil")+' (reversible)</div>';
  out.innerHTML=h;
}
function renderIntel(p){
  let h="";
  if((p.open_ports||[]).length) h+='<div class="card" style="margin:8px 0"><h3>open ports &amp; services</h3><table><tr><th>port</th><th>service</th><th>product</th></tr>'+
    p.open_ports.map(s=>`<tr><td class="mono">${s.port}</td><td>${esc(s.service||"?")}</td><td class="mut">${esc(s.product||"")}</td></tr>`).join("")+'</table></div>';
  if((p.fingerprints||[]).length) h+='<div class="muted" style="margin:6px 0"><b>tech:</b> '+p.fingerprints.map(esc).join(", ")+'</div>';
  if((p.paths||[]).length) h+='<div class="muted" style="margin:6px 0"><b>paths ditemukan:</b> '+p.paths.slice(0,30).map(x=>esc(x.path)+" ("+x.status+")").join(", ")+'</div>';
  if((p.nuclei||[]).length) h+='<div class="card" style="margin:8px 0"><h3>nuclei findings (lead — belum di-exploit)</h3><table><tr><th>severity</th><th>template</th><th>matched</th></tr>'+
    p.nuclei.map(n=>`<tr><td class="sev-${(n.severity||"").toUpperCase()==="CRITICAL"?"CRITICAL":((n.severity||"").toUpperCase()==="HIGH"?"CRITICAL":"WARNING")}">${esc(n.severity||"?")}</td><td>${esc(n.template||"")}</td><td class="mut">${esc(n.matched||"")}</td></tr>`).join("")+'</table></div>';
  $("#progintel").innerHTML=h;
}
function startProgress(){if(progTimer)clearInterval(progTimer);pollProgress();progTimer=setInterval(pollProgress,1200);}
async function pollProgress(){
  let p; try{p=await getJSON("/api/attack/progress");}catch(e){return;}
  if(p&&typeof p.loop_enabled==="boolean"){
    window._atkLoop=p.loop_enabled;
    const b=$("#btn-atk-loop");
    if(b){b.textContent=window._atkLoop?"Switch Auto-Attack Loop: ON (AKTIF)":"Switch Auto-Attack Loop: OFF";
      b.style.background=window._atkLoop?"var(--green)":"transparent";
      b.style.color=window._atkLoop?"#04121a":"var(--fg)";}
  }
  if(!p||p.status==="idle"){$("#progcur").textContent="idle — pilih target di atas lalu klik Sweep";return;}
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
  renderIntel(p);
  $("#attackout").textContent=(p.log||[]).join("\n");
  $("#attackout").scrollTop=$("#attackout").scrollHeight;
  if(p.status!=="running"){if(progTimer){clearInterval(progTimer);progTimer=null;}}
}
async function defenseSweep(){const r=await postJSON("/api/defense/sweep",{});$("#attackout").textContent=`defense sweep: ${r.incidents} incident(s)`;}
async function loadTraffic(){
  const r=await getJSON("/api/defense/traffic");
  const st=r.stats||{};
  $("#traf-stat").textContent=`total: ${st.total||0} · serangan: ${st.attacks||0} · buffer: ${st.buffered||0}`;
  const caps=r.captures||[];
  if(!caps.length){$("#traf-list").innerHTML='<span class="mut">belum ada serangan tertangkap.</span>';return;}
  $("#traf-list").innerHTML=caps.map(c=>
    `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:5px 0">
      <div style="min-width:0;overflow:hidden"><span class="mut">${esc(c.ts)}</span> <b>${esc(c.method)}</b>
      <code>${esc((c.path||'').slice(0,90))}</code> <span class="mut">src ${esc(c.src_ip)}</span>
      ${c.blocked?'<span class="down">BLOCKED</span>':''} <span class="mut">${esc((c.rule_hits||[]).join(','))}</span></div>
      <button class="act" onclick="replayCapture(${c.id})">Replay ke musuh</button></div>`).join("");
}
async function replayCapture(id){
  if(!confirm("Replay request musuh ini ke SEMUA target opponent di scope? (scope-enforced)"))return;
  $("#traf-stat").textContent="replaying…";
  const r=await postJSON("/api/attack/replay",{id});
  $("#traf-stat").textContent = r.error?("⚠ "+r.error):(r.summary||"selesai");
  loadFlags&&loadFlags();
}
async function oastStart(){
  const lp=parseInt($("#oast-port").value||"0",10)||0;
  const pub=($("#oast-pub").value||"").trim();
  const r=await postJSON("/api/attack/oast",{action:"start",listen_port:lp,pub_host:pub});
  if(r.error){$("#oast-stat").textContent="⚠ "+r.error;return;}
  loadOast();
}
async function oastStop(){await postJSON("/api/attack/oast",{action:"stop"});loadOast();}
async function oastToken(){
  const r=await postJSON("/api/attack/oast",{action:"token"});
  if(r.error){$("#oast-url").innerHTML='<span class="down">⚠ '+esc(r.error)+'</span>';return;}
  $("#oast-url").innerHTML='<div class="muted">suntik URL ini ke payload blind:</div><code style="user-select:all">'+esc(r.url)+'</code>';
}
async function loadOast(){
  const r=await getJSON("/api/attack/oast");
  const st=r.stats||{};
  $("#oast-stat").textContent=(st.running?`listener: RUNNING (:${st.listen_port}, pub ${st.pub_host})`:"listener: stopped")+` · hits: ${st.total||0}`;
  const its=r.interactions||[];
  $("#oast-list").innerHTML = its.length? its.map(i=>
    `<div style="border-bottom:1px solid var(--line);padding:4px 0"><span class="mut">${esc(i.ts)}</span>
     <b>${esc(i.method)}</b> <code>${esc((i.path||'').slice(0,100))}</code>
     <span class="up">token ${esc(i.token)}</span> <span class="mut">src ${esc(i.src_ip)}</span></div>`).join("")
    : '<span class="mut">belum ada interaksi.</span>';
}
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
async function submitFlags(){
  if(!confirm("Kirim semua flag VALIDATED (PENDING) ke endpoint panitia yang di-set di config submission.*?"))return;
  const out=document.getElementById("submitout"); out.textContent="mengirim…";
  const r=await postJSON("/api/flags/submit",{});
  out.textContent = r.error ? ("⚠ "+r.error) : (r.summary||"selesai");
  loadFlags();
}

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
  if($("#fflagid"))$("#fflagid").value=c.flag_id_endpoint||"";
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
    flag_id_endpoint:$("#fflagid")?$("#fflagid").value.trim():"",
    enforce:$("#fenforce").checked,targets});
  if(r.error){$("#builderout").innerHTML='<span class="down">✗ '+esc(r.error)+'</span>';return;}
  $("#builderout").innerHTML=(r.ready?'<span class="up">✓ saved — READY</span>':'<span class="warn">✓ saved — not ready: '+esc((r.issues||[]).join("; "))+'</span>')+' <span class="muted">(live engine hot-reloaded automatically)</span>';
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
  $("#scopetable").innerHTML=c.targets.length?`<table><tr><th>name</th><th>host:ports</th><th>kind</th><th>owner</th><th>notes</th></tr>`+
    c.targets.map(t=>`<tr><td>${esc(t.name)}</td><td class="mono">${esc(t.host)}:${esc((t.ports||[]).join(",")||"80")}</td><td>${esc(t.kind)}</td><td class="${t.owner==='opponent'?'down':'up'}">${esc(t.owner)}</td><td class="mono mut">${esc(t.notes||"-")}</td></tr>`).join("")+`</table>`:'<span class="mut">no targets</span>';
}
async function saveConfig(){
  $("#cfgout").textContent="saving…";
  const r=await postJSON("/api/config/save",{yaml:$("#cfgyaml").value});
  if(r.error){$("#cfgout").textContent="✗ "+r.error;return;}
  $("#cfgout").textContent="✓ "+(r.note||"saved")+(r.ready?"":"\n⚠ not ready: "+(r.issues||[]).join("; "));
  loadConfig();
}

tick(); setInterval(()=>{if(tab==="monitor"||tab==="defense")tick();},3000);
</script>
</body>
</html>
"""
