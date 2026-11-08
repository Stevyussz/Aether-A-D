# AETHER A&D — Defense Tanpa Harus Jago Koding, & Tempat Latihan

Dua pertanyaan nyata, dua jawaban praktis:
1. **"Gimana nge-patch kalau nggak ngerti kode / bahasa pemrogramannya?"** → Kamu butuh
   **bisa MEMBACA pola bahaya**, bukan jago NULIS program. 80% patching A&D = kenali pola +
   hardening di layer config/edge + tool. Bagian 1.
2. **"Ada tempat buat simulasi A&D? Aku punya VM."** → Ada, dan kamu bisa bikin sendiri
   dengan VM-mu dalam 15 menit. Bagian 2.

---

# BAGIAN 1 — Defense walau nggak jago koding

## Kenyataannya
Di A&D kamu jarang perlu menulis program. Yang perlu:
- **Membaca** dan mengenali "baris berbahaya" (sink) — ini bisa dihafal, lihat tabel di bawah.
- **Hardening di layer non-kode** (config runtime, permission file, proxy depan) — **nol koding**.
- **Membandingkan** service kamu dengan salinan asli untuk menemukan sisipan lawan.
- Pakai **AETHER** (quarantine web shell, integrity diff).

Patch A&D yang paling sering = **mematikan satu baris berbahaya** atau **menambah satu
pengecekan** — copy-paste pola, bukan bikin fitur.

## 3 layer defense, dari yang PALING nggak butuh koding

### Layer 1 — File & sistem (0 koding) ← mulai dari sini
```bash
# 1) Web shell yang disisipkan lawan — buang (AETHER, reversible):
aether defense webshells
aether defense quarantine /var/www/html/uploads/evil.php

# 2) Bikin folder upload TIDAK bisa eksekusi skrip (mematikan banyak web shell sekaligus):
#    Apache: taruh .htaccess di folder upload:
printf 'php_flag engine off\nSetHandler none\n' > /var/www/html/uploads/.htaccess
#    atau cabut izin & pindah upload ke luar web-root.

# 3) Hapus file yang nggak seharusnya ke-expose:
rm -rf /var/www/html/.git /var/www/html/*.bak /var/www/html/backup*

# 4) Cari file baru mencurigakan (kemungkinan shell) tiap ronde:
find /var/www -newermt '-5 min' -type f 2>/dev/null
```

### Layer 2 — Config runtime (hampir 0 koding, cuma edit setting)
Mematikan fungsi berbahaya di level bahasa, tanpa menyentuh kode aplikasi:
```ini
; PHP — di php.ini (lalu restart service): matikan eksekusi perintah & include URL.
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec,eval
allow_url_include = Off
allow_url_fopen   = Off
file_uploads      = On      ; biarkan on jika service butuh, tapi folder non-exec (Layer 1)
```
> Efek: command injection & kebanyakan web shell PHP langsung mati, **tanpa** ngoding. Pastikan
> service masih jalan sesudahnya (fitur legit jangan ikut mati).

### Layer 3 — Edit kode minimal (baca pola, tempel perbaikan)
Kamu nggak perlu paham seluruh program — cukup temukan **sink**-nya dan netralkan.

**Tabel sink berbahaya (hafalkan bentuknya di bahasa apa pun):**

| Bahaya | Terlihat seperti (PHP / Python / Node) | Perbaikan termudah |
|---|---|---|
| Command exec | `system($_GET..)` / `os.system(req..)` / `exec(req..)`, `child_process.exec` | Hapus/komentari baris itu, atau ganti ke versi yang argumennya tetap (array), bukan string |
| Eval kode | `eval($_POST..)` / `eval(request..)` | Hapus `eval`; tidak ada alasan sah untuk eval input |
| Upload | `move_uploaded_file(...)` tanpa cek ekstensi | Tambah cek: tolak kalau bukan gambar/ekstensi aman |
| Path/LFI | `include($_GET..)` / `open(req_path)` | Pastikan path di dalam folder izin (basename/realpath) |
| SQL | string di-concat ke query (`"... ".$_GET["id"]`) | Pakai prepared statement/parameter |

**Pola perbaikan yang bisa di-copy (tanpa ngerti sisa program):**
```php
// SEBELUM (berbahaya):  system("ping " . $_GET["host"]);
// SESUDAH 1 (paling aman, matikan fitur berisiko):
//     // system("ping " . $_GET["host"]);   // dimatikan saat lomba
// SESUDAH 2 (whitelist — tempel pola ini):
$h = $_GET["host"];
if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $h)) { die("invalid"); }  // hanya huruf/angka/titik/strip
system("ping -c1 " . escapeshellarg($h));
```
```php
// Upload — tolak skrip:
$name = $_FILES["f"]["name"];
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (!in_array($ext, ["jpg","png","gif","pdf"])) { die("blocked"); }
```
Prinsipnya sama di Python/Node: cari sink → tambah 1 pengecekan input, atau matikan baris itu.

## Aturan emas defense (ulangi di kepala)
1. **Backup dulu** (AETHER otomatis saat patch/quarantine).
2. **Perbaiki akar, jangan matikan service.** Fitur mati → functional test gagal → SLA hilang.
3. **Tes sesudah patch:** `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/` harus 200.
4. **Diff lawan salinan asli** untuk temukan sisipan lawan (lihat Bagian 2, teknik pamungkas).
5. Yang lebih "ngerti kode" pegang Layer 3; yang lain pegang Layer 1 & 2 + AETHER. **Dua-duanya
   dibutuhkan, dan Layer 1–2 sudah cukup untuk menahan mayoritas serangan.**

---

# BAGIAN 2 — Tempat latihan A&D (pakai VM-mu)

## Opsi 1 (REKOMENDASI, paling mirip lomba) — A&D mini dengan AETHER di 2 VM/mesin
AETHER punya **target rentan bawaan** yang bisa dijalankan sebagai service hidup. Ini cara
tercepat merasakan loop attack **dan** defense sekaligus.

**Siapkan (di VM "korban"):**
```bash
# jalankan target rentan, bisa diakses dari mesin lain:
aether lab serve --host 0.0.0.0 --port 8080 --flag 'IONIC{latihan_ronde_1}'
# (⚠ hanya di jaringan lab terisolasi — JANGAN di jaringan publik/lomba)
```
**ATTACK (dari mesin/VM lain, mis. laptop kamu):**
```bash
aether web                      # isi scope: target = IP-VM-korban, owner opponent, kind web
aether attack sweep <ip-vm-korban> --cred admin:admin
aether flags inbox --show-values    # lihat IONIC{...} masuk → latih alur submit + mark
```
**DEFENSE (balik ke VM korban — ini latihan patch-mu):**
```bash
# 1) edit file service:  lab/web/vuln_service.py
#    matikan satu kelas, misal command injection: cari blok  if "command_injection" in enabled
#    dan hapus "command_injection" dari daftar yang kamu serve:
aether lab serve --host 0.0.0.0 --port 8080 --only sqli,ssti,exposed_files   # cmdi dimatikan
# 2) dari penyerang, sweep lagi → buktikan jalur itu sekarang GAGAL, tapi service tetap UP.
```
Ulangi: matikan/benahi satu kelas tiap kali, konfirmasi sweep gagal + service hidup. Ini
**persis** rasa defense A&D: tutup lubang tanpa mematikan layanan. Latih juga web shell:
```bash
# di VM korban, simulasikan lawan menanam shell lalu kamu quarantine:
mkdir -p /tmp/www/uploads && echo '<?php @eval($_POST["c"]); ?>' > /tmp/www/uploads/x.php
aether defense webshells --path /tmp/www
aether defense quarantine /tmp/www/uploads/x.php
```

## Opsi 2 — VulnHub box sebagai "service" (full server, offline)
Boot2root VM = server lengkap yang bisa kamu **serang lalu keraskan**. Pas banget untuk A&D:
1. Import ke VirtualBox (host-only / internal network, **jangan** bridged ke internet):
   - **DC-1**, **Kioptrix Level 1**, **Basic Pentesting 1** — web → RCE → priv-esc.
2. Serang dari host/Kali sampai dapat root & baca flag.
3. **Lalu masuk sebagai root dan patch** bug yang tadi kamu pakai (Layer 1–3 di atas), reboot
   service, coba exploit lagi → harus gagal, service tetap jalan. **Itu ronde defense-mu.**

## Opsi 3 — Web app latihan patch (lihat kode aman vs rentan)
Jalankan di VM (paling gampang via Docker):
- **DVWA** (`docker run -p 80:80 vulnerables/web-dvwa`) — tiap level ada tombol **"View Source"**
  yang menampilkan kode **rentan vs aman** berdampingan. **Ini guru patching terbaik** buat yang
  belum jago koding: kamu lihat persis "sebelum vs sesudah".
- **OWASP Juice Shop** / **bWAPP** — banyak kelas web untuk latihan attack.

## Platform/event A&D publik (referensi)
- **CTFtime.org** → filter format **"Attack-Defense"** untuk jadwal event (biasanya terjadwal,
  bukan 24/7).
- **FAUST CTF**, **RuCTF / RuCTFe**, **ENOWARS** — kompetisi A&D nyata, periodik; writeup-nya
  bagus untuk belajar pola service & patch.
- Untuk 4 hari ini: **Opsi 1 + Opsi 2/3 jauh lebih hemat waktu** daripada menunggu/menyetel
  event. Tidak perlu memasang scoreboard A&D penuh (iCTF/Root the Box) — overkill sekarang.

---

## Ringkas
- **Tidak jago koding bukan penghalang defense.** Mulai Layer 1 (buang shell, folder upload
  non-exec) + Layer 2 (disable_functions) — nol/again minim koding, sudah menahan mayoritas
  serangan. Layer 3 cukup "kenali sink → tempel 1 cek / matikan 1 baris".
- **Latihan:** `aether lab serve` (2 VM) untuk loop A&D penuh; VulnHub box untuk serang→keraskan;
  DVWA untuk belajar bentuk patch. Semua di jaringan lab terisolasi.

Lihat juga: [PREP-4DAYS.md](PREP-4DAYS.md) · [STRATEGY.md](STRATEGY.md) ·
[CHEATSHEET.md](CHEATSHEET.md) · [RUNBOOK.md](RUNBOOK.md).
