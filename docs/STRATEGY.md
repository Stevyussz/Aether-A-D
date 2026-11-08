# AETHER A&D — Strategi Tim (untuk tim yang belum pernah Attack & Defense)

Ditulis untuk tim 2 orang yang pengalamannya **Jeopardy** dan **boot2root (B2R)** — belum
pernah ikut **Attack & Defense (A&D)**. Tujuannya: begitu lomba mulai, kalian tahu persis
harus ngapain, menit per menit. Semua langkah "tool" di sini mengacu ke AETHER (`aether …`
atau Web Console `aether web`).

> Flag format kompetisi ini: **`IONIC{...}`**. Initial access via **web**, tapi flag ada di
> **server** (gaya HTB/THM/VulnHub). Jadi pola intinya: **web → RCE → baca flag di server**.

---

## 1. Apa bedanya A&D dengan yang kalian kenal

| | Jeopardy / B2R | Attack & Defense |
|---|---|---|
| Lawan | Soal statis | Tim lain, hidup, melawan balik |
| Flag | Sekali ambil, selesai | **Berputar tiap ronde (tick)** — ambil ulang terus |
| Menang | Siapa paling banyak solve | Skor = **Attack + Defense + SLA (uptime)** |
| Service | Punya panitia | **Kalian punya service sendiri yang harus dijaga** |
| Kunci | Pintar nge-solve | **Cepat + konsisten + service jangan mati** |

Insight terpenting yang bikin pemula kaget:

1. **Semua tim dapat service yang SAMA dan rentan.** Bug yang bisa kalian exploit ke lawan,
   bisa dipakai lawan ke kalian. → **Patch diri sendiri dulu, baru serang.**
2. **Flag berputar tiap tick** (misal tiap 1–5 menit). Sekali ambil tidak cukup — harus
   **ambil ulang tiap ronde**. Ini kenapa AETHER punya `attack loop` + "exploit farm".
3. **Service mati = kehilangan poin SLA**, walau tidak di-hack. Jangan pernah matikan service
   untuk "mengamankan". Patch sambil service tetap jalan.

---

## 2. Model skor (mental model)

Skor total ≈ **FLAG dicuri dari lawan** + **FLAG kalian TIDAK dicuri** + **SLA/uptime**.

Artinya ada 3 pekerjaan paralel, bukan 1:
- **ATTACK** — curi flag lawan tiap tick.
- **DEFENSE** — tutup bug supaya flag kalian tidak dicuri.
- **AVAILABILITY** — service kalian harus tetap lolos cek fungsional panitia.

Pemula sering lupa #2 dan #3 dan cuma fokus nyerang. Juara biasanya yang **defense + uptime**-nya
rapi, karena attack itu "sama rata" (semua orang punya exploit yang sama cepat atau lambat).

---

## 3. Pembagian peran (2 orang)

Tetapkan dari awal, jangan rebutan keyboard:

- **Operator A — ATTACK (kamu, Stev):**
  - Isi scope, jalankan `aether attack sweep`/`loop`, pantau **Flags inbox**.
  - Submit flag di portal resmi (AETHER tidak submit otomatis), lalu `mark-submitted`.
  - Simpan tiap exploit yang berhasil (AETHER otomatis ingat lewat exploit farm).
- **Operator B — DEFENSE (teammate):**
  - Jalankan `aether monitor dashboard` / Web Console tab Monitor.
  - Begitu ada **web shell** / integrity drift → **quarantine** + patch.
  - Pastikan service tetap UP & lolos functional test.

Aturan komunikasi: **ngobrol terus-terusan.** "Aku nemu SQLi di :8080", "service kita abis
dibikin drop file di /uploads", dst. A&D itu game komunikasi.

---

## 4. 5 menit pertama (urut, jangan loncat)

Begitu briefing + akses diberikan:

1. **BERTAHAN DULU.** Jangan langsung nyerang. Backup service + flag store kalian.
   ```bash
   aether web                       # buka dashboard — ini "mata" kalian sepanjang lomba
   ```
2. **Isi scope di tab Config → Scope builder** (atau `aether init` + edit YAML): masukkan
   semua target lawan (`owner: opponent`) dan service kalian sendiri (`owner: self`, isi
   `notes` dengan path web-root supaya defense bisa memindai web shell).
3. **Validasi**: `aether config validate` harus **READY**. Kalau belum, scope fail-closed
   (tidak akan jalan — itu sengaja).
4. **Satu sweep uji** ke satu lawan untuk memastikan toolchain jalan & lihat bug-nya apa:
   ```bash
   aether attack sweep <ip-lawan>
   ```
5. **Temukan bug yang sama di service SENDIRI, lalu patch** — hati-hati, service harus tetap
   jalan. Verifikasi di tab Monitor service masih UP.

Target 5 menit pertama: **kalian sudah ter-patch + tahu bug-nya + scope terisi.**

---

## 5. Loop sepanjang lomba (ulang tiap tick)

**ATTACK (Operator A):**
```bash
aether attack loop --interval <detik-tick>    # sweep tiap ronde; flag baru otomatis ditarik
aether flags inbox                            # pantau; nilai ter-mask sampai kamu reveal
aether flags inbox --show-values              # saat mau submit
aether flags copy <prefix> | xclip -selection clipboard
# submit di PORTAL resmi → lalu:
aether flags mark-submitted <prefix> --status SUBMITTED
```
AETHER mengingat modul yang berhasil per target (**exploit farm**) dan menjalankannya **duluan**
tiap ronde → flag baru langsung ketarik.

**DEFENSE (Operator B):**
```bash
aether monitor dashboard --interval 5         # health, integrity, incidents, web shell
aether defense webshells                      # scan web-root sendiri (read-only)
aether defense quarantine <path-shell>        # backup → pindah → tes → verify (reversible)
```
Tiap incident CRITICAL (web shell / file berubah di protected path) → tangani segera.

**Aturan availability:** jangan matikan service. Patch itu: backup → ubah minimal → tes
service masih jalan → commit. AETHER `patch`/`quarantine` otomatis rollback kalau functional
test gagal.

---

## 6. "Web masuk, flag di server" — cara AETHER kerja

Pola kompetisi ini: dapat pijakan lewat **web**, tapi flag `IONIC{...}` ada di **filesystem
server** (`/root/root.txt`, `/home/*/user.txt`, `proof.txt`, web-root `flag*`, atau env).

Modul AETHER yang mencapai eksekusi kode (command injection, SSTI, deserialization, LFI)
otomatis:
- `cat` file flag konvensional, **dan**
- `grep` seluruh filesystem (terbatas, read-only) untuk prefix `IONIC{` → ketemu di mana pun
  ia disembunyikan.

AETHER juga **auto-login** (CSRF-aware: baca token tersembunyi di form) sehingga exploit
menyerang **di balik login**, dan bisa **enumerasi priv-esc** read-only (`id`, `sudo -l`,
SUID, capabilities, cron) setelah pijakan.

**Yang TETAP manual (bagian otak manusia kalian — justru kekuatan tim B2R):**
- **Eksekusi** priv-esc (jalankan SUID/sudo/cron/capability yang sudah dienumerasi).
- **Pwn biner**, **logic bug unik**, login multi-step aneh (OTP/captcha).
- Lihat **[CHEATSHEET.md](CHEATSHEET.md)** untuk perintah manualnya.

---

## 7. Prioritas serangan (yield tertinggi dulu)

AETHER sudah mengurutkan arsenalnya, tapi ini mental model kalian:

1. **File ke-expose** (backup, `.git`, `flag.txt` di web-root) — gratisan, cek dulu.
2. **Path traversal / LFI** → baca `/etc/passwd`, lalu file flag.
3. **SQLi** → sering bocor kredensial / data flag.
4. **Command injection & SSTI** → **RCE langsung** → baca flag server (yield tertinggi).
5. **Default/weak creds** → login → serang area dalam.
6. **Deserialization / JWT lemah / SSRF / XXE** → tergantung service.

Kalau sweep nemu nol: target belum tentu aman — mungkin bug-nya **logic/bespoke**. Di situ
pengalaman B2R kalian jalan: baca aplikasinya, cari yang "aneh".

---

## 8. Kesalahan pemula A&D (hindari)

- ❌ Fokus nyerang, lupa patch diri → flag sendiri dipanen lawan tiap tick.
- ❌ Matikan/putus service biar "aman" → kehilangan SLA, kalah pelan-pelan.
- ❌ Patch sampai service rusak → functional test gagal → SLA hilang. (AETHER rollback otomatis,
  tapi tetap buang waktu.)
- ❌ Ambil flag sekali lalu santai → flag berputar, skor berhenti nambah.
- ❌ Patch dengan cara "blokir IP-ku sendiri dari fitur X" → kalian ikut rusak, dan kadang
  lawan tetap tembus. **Perbaiki bug-nya, bukan sembunyikan.**
- ❌ Lupa simpan exploit yang berhasil → tiap ronde mulai dari nol. (AETHER ingat otomatis.)
- ❌ Hardcode satu flag ke submit script → **AETHER sengaja tidak auto-submit**; kalian submit
  manual supaya tidak kirim flag palsu/aneh.

---

## 9. Checklist Hari-H (print / tempel)

**Sebelum ronde:**
- [ ] `aether web` terbuka di dua laptop (A & B).
- [ ] Scope terisi: semua lawan (`opponent`) + service sendiri (`self` + notes web-root).
- [ ] `aether config validate` → **READY**.
- [ ] Backup service + flag store diambil; baseline integrity ter-set (otomatis saat watch).
- [ ] `flags.pattern` = `IONIC\{[^}]+\}`, `tick_seconds` sesuai pengumuman.

**Tiap tick:**
- [ ] A: `attack loop` jalan, inbox dipantau, flag baru disubmit + mark.
- [ ] B: Monitor dipantau, web shell/drift ditangani, service UP & lolos functional.
- [ ] Komunikasi: siapa nyerang siapa, apa yang ketemu, apa yang di-patch.

**Kalau kena serang:**
- [ ] Tab Monitor → identifikasi (web shell? file berubah?).
- [ ] `defense quarantine <path>` untuk web shell (reversible).
- [ ] Cari & patch bug akarnya; verifikasi service tetap jalan.
- [ ] Simpan catatan: bug apa, patch apa (buat ronde berikutnya & lawan lain).

---

## 10. Satu kalimat yang harus diingat

> **Patch dirimu dulu, jaga service tetap hidup, lalu curi flag lawan tiap tick — konsisten
> mengalahkan heroik.**

Untuk perintah spesifik (AETHER + manual), buka **[CHEATSHEET.md](CHEATSHEET.md)**.
Untuk alur operasional lengkap, **[RUNBOOK.md](RUNBOOK.md)**.
