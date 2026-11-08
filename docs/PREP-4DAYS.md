# AETHER A&D — Rencana Belajar 4 Hari (fokus, di dalam scope)

Dibuat dari bocoran panitia: **format Attack & Defense**, **initial access = web**, lalu
**nyerang server** (gaya HTB/THM/VulnHub), flag **`IONIC{...}`**. Jadi 95% yang keluar hampir
pasti: **web → RCE → baca flag di server Linux → priv-esc**, plus **defense/patching** service
sendiri. Rencana ini **sengaja membuang** yang kemungkinan besar TIDAK keluar biar hemat waktu.

> Prinsip hemat waktu: AETHER sudah otomatis **menemukan** bug web + **membaca** flag. Yang
> wajib kalian kuasai sebagai manusia = **(1) ubah pijakan jadi root (priv-esc), (2) baca
> aplikasi untuk bug logic, (3) patch service sendiri tanpa matiin.** Latih tiga itu.

---

## 0. Fokus scope — PELAJARI vs LEWATI

**PELAJARI (hampir pasti keluar):**
- Web → RCE: **command injection, file upload shell, SSTI, LFI/path traversal, SQLi, default/weak creds, deserialization.**
- **Linux privilege escalation** (SUID, sudo, cron, capabilities, PATH, writable files).
- **Baca flag di server** (`/root`, `/home/*`, env, web-root) — AETHER bantu, tapi paham manual.
- **Defense A&D**: patch bug tanpa matiin service, deteksi & buang web shell, jaga uptime.
- **Alur A&D**: tick, flag berputar, SLA, submit manual.

**LEWATI / nanti saja (kemungkinan kecil keluar, mahal dipelajari):**
- Active Directory / Windows priv-esc. ❌
- Binary pwn / exploit dev / ROP. ❌ (kecuali kalian memang sudah jago)
- Kripto berat, stego, forensic. ❌ (itu ranah Jeopardy)
- Cloud/k8s. ❌

Kalau ragu suatu topik masuk scope atau tidak: tanya **"apakah ini web→server Linux?"** Kalau
bukan, skip untuk sekarang.

---

## 1. Yang bikin MENANG (aturan 80/20)

Urut dari dampak terbesar:

1. **Patch cepat + service tetap UP.** Attack itu rata (semua tim punya exploit sama). Yang
   beda = siapa yang flag-nya tidak dicuri & service tidak pernah mati. **Ini kemenangan kalian.**
2. **Priv-esc cepat.** Pijakan web (www-data) → root = akses flag paling dalam. Latih sampai refleks.
3. **Konsistensi tiap tick.** Re-sweep + re-submit tiap ronde (AETHER `attack loop` + exploit farm).
4. **Baca aplikasi.** Bug logic/bespoke yang scanner lewatkan — di sinilah skill B2R kalian unggul.

---

## 2. Setup platform (hari ini, < 30 menit)

- **TryHackMe** (utama, paling ramah pemula & paling mirip scope): buat akun, `OpenVPN`/AttackBox.
- **VulnHub** (gratis, lokal via VirtualBox): download 2–3 VM gaya boot2root.
- **GTFOBins** & **PayloadsAllTheThings** & **HackTricks**: bookmark, ini "kamus" saat lomba.
- **AETHER lab lokal**: `aether lab test` harus hijau. Untuk **simulasi A&D penuh** (serang +
  patch) pakai `aether lab serve` — lihat **[DEFENSE-AND-LAB.md](DEFENSE-AND-LAB.md)** (juga:
  cara nge-patch walau belum jago koding).

---

## 3. Jadwal 4 hari (tim 2 orang)

Asumsi ~6–8 jam/hari. **A = kamu (Attack)**, **B = teammate (Defense)**. Hari 1–2 kalian
berdua belajar skill inti yang sama; hari 3–4 mulai spesialisasi + simulasi.

### HARI 1 — Web → RCE (fondasi attack)
Target: paham & praktek tiap jalur web jadi eksekusi kode.
- **THM rooms (urut):**
  - `OWASP Top 10` (refresh cepat semua kelas)
  - `Upload Vulnerabilities` (upload web shell → RCE) ← sering keluar
  - `Command Injection` (atau bagian injeksi di OWASP Top 10)
  - `SSTI` / baca bagian SSTI di HackTricks
  - `File Inclusion` (LFI→RCE via log poisoning / php filter)
- **Latihan RCE→flag:** `Pickle Rick` (THM) — web → shell → cari "ingredients"/flag. Wajib, cepat.
- **Trik hafalkan:** separator cmdi (`; | && \`\` $()`), `{{7*7}}` tes SSTI, `../../etc/passwd`,
  `php://filter/convert.base64-encode/resource=`, upload bypass (ekstensi ganda, magic bytes).

### HARI 2 — Linux Privilege Escalation (ini yang menang attack)
Target: dari user biasa → root dengan cepat, refleks.
- **THM rooms (urut):**
  - `Linux PrivEsc` (THM, oleh Tib3rius) — **wajib, ini inti.** SUID, sudo, cron, caps, PATH.
  - `Linux Privilege Escalation` (versi lanjut / Junior PenTester path kalau ada)
- **Tool:** jalankan **LinPEAS** di tiap box, baca output-nya (biasakan baca cepat).
- **Full chain (wajib latih):** `RootMe` (THM) & `Vulnversity` (THM) — upload shell → www-data
  → priv-esc → root → baca `/root`. Ini **persis pola lomba**.
- **Trik hafalkan:** `sudo -l` → GTFOBins; `find / -perm -4000` → GTFOBins SUID; cron writable;
  `getcap -r /`; PATH hijack; `python3 -c 'import pty;pty.spawn("/bin/bash")'` upgrade shell.

### HARI 3 — Full boot2root berulang + mulai DEFENSE
Pagi (A & B): kecepatan — selesaikan box web→root **tanpa** nyontek writeup, catat waktu.
- **THM:** `Simple CTF`, `GameZone` (SQLi→shell→priv-esc), `Daily Bugle` (Joomla→RCE→priv-esc),
  `Blog` atau `Internal` (lebih nyata).
- **VulnHub:** `Kioptrix 1`, `DC-1` (keduanya web→RCE→priv-esc klasik, pas scope).
Sore (B fokus, A bantu): **DEFENSE drill** (unik A&D, belum pernah kalian lakukan):
- Ambil salah satu box yang tadi kalian exploit. Sekarang **perbaiki bug-nya** supaya exploit
  kalian sendiri gagal, **tapi service tetap jalan**. (mis. upload: tolak .php; cmdi: hapus
  `system()`; SQLi: parameterize.)
- Latih di **AETHER lab**: plant web shell dummy → `aether defense webshells` → `aether defense
  quarantine` → pastikan service tetap UP. Ulang sampai refleks.

### HARI 4 — Simulasi A&D penuh + hafalan operasional
- **Simulasi loop (pakai AETHER + lab):**
  1. `aether web` → isi scope (lab sebagai "lawan" + service kalian sebagai "self").
  2. A: `aether attack loop --interval 120` → flag masuk inbox → submit (latih alurnya).
  3. B: `aether monitor dashboard` → plant shell → deteksi → quarantine → patch → service UP.
  4. Ulang beberapa "tick". Target: tangan hafal, gak panik.
- **Hafal cheatsheet** ([CHEATSHEET.md](CHEATSHEET.md)) sampai gak perlu lihat.
- **Baca ulang** [STRATEGY.md](STRATEGY.md) bagian "5 menit pertama" & "checklist Hari-H".
- **Siapkan arsenal pribadi:** folder berisi LinPEAS, reverse-shell one-liner, payload favorit,
  catatan tiap box yang kalian selesaikan (bug + cara patch).

---

## 4. Daftar room/box prioritas (kalau waktu mepet, ini saja)

**Wajib (pola lomba persis — web→shell→priv-esc→flag):**
1. `Pickle Rick` (THM) — tercepat, bangun percaya diri.
2. `Linux PrivEsc` (THM, Tib3rius) — inti priv-esc.
3. `RootMe` (THM) — upload → www-data → root.
4. `Vulnversity` (THM) — upload → priv-esc.
5. `DC-1` (VulnHub) — boot2root penuh offline.

**Bonus kalau sempat:** `GameZone` (SQLi), `Daily Bugle` (CMS→RCE), `Kioptrix 1`, `Simple CTF`.

---

## 5. Trik & akselerator (yang jarang dikasih tahu pemula)

**Attack:**
- Begitu dapat shell www-data, **langsung** `sudo -l` + `find / -perm -4000 2>/dev/null` + LinPEAS. 80% priv-esc ketemu di 3 perintah itu.
- Stabilkan shell dulu (`pty.spawn`) sebelum ngoprek — shell putus = buang waktu.
- Simpan setiap payload yang tembus; di lomba flag berputar tapi **bug-nya tetap** → re-use.
- Kalau upload difilter: coba `.phtml`, `.php5`, double-ext `shell.php.jpg`, magic byte `GIF89a;`.
- `grep -rsoaE 'IONIC\{[^}]+\}' / 2>/dev/null` = cara tercepat nemu flag kalau lupa lokasinya.

**Defense (yang paling nentuin juara, dan kalian belum terbiasa):**
- **Patch = perbaiki akar, bukan matikan fitur.** Fitur mati → functional test gagal → SLA hilang.
- Selalu **backup dulu** (AETHER otomatis). Tes service **sesudah** patch (`curl -w '%{http_code}'`).
- Pantau folder upload & web-root: `find /var/www -newermt '-5 min'` → file baru = kemungkinan shell.
- Ganti **default/weak creds** di menit pertama — ini pintu masuk termurah buat lawan.
- Jangan pernah `systemctl stop`. Jangan hapus flag store.

**Operasional A&D:**
- Bagi peran & **jangan tukeran keyboard**. Ngobrol terus.
- Submit flag **tiap tick**, jangan numpuk (flag kadaluarsa setelah beberapa tick).
- Kalau kena hack: tenang → Monitor → identifikasi → quarantine/patch → verify UP → catat.

---

## 6. Yang HARUS mahir di akhir hari-4 (checklist skill)

- [ ] Upload web shell & bypass filter → dapat RCE. (A & B)
- [ ] Command injection / SSTI / LFI → RCE. (A & B)
- [ ] Dari www-data → root via SUID/sudo/cron/caps (refleks, < 10 menit di box easy). (A & B)
- [ ] Stabilkan shell + baca LinPEAS cepat. (A & B)
- [ ] Baca aplikasi & temukan 1 bug logic tanpa scanner. (A)
- [ ] Patch bug (upload/cmdi/SQLi) **tanpa** mematikan service. (B)
- [ ] Deteksi + quarantine web shell via AETHER, service tetap UP. (B)
- [ ] Jalankan loop AETHER penuh (scope→sweep→inbox→submit→mark) tanpa lihat catatan. (A)
- [ ] Hafal "5 menit pertama" & pembagian peran. (A & B)

Kalau semua ter-centang, kalian siap. Sisa keunggulan = ketenangan + konsistensi tiap tick.

---

Rujukan: [STRATEGY.md](STRATEGY.md) (strategi tim), [CHEATSHEET.md](CHEATSHEET.md) (perintah),
[RUNBOOK.md](RUNBOOK.md) (operasional AETHER). Latihan defense: `aether lab test` + Web Console.
