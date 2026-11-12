# AETHER A&D — RUNBOOK HARI-H (Bahasa Indonesia)

Checklist tempur untuk **tim 2 orang**. Istilah cyber tetap English (files/service/flag/scope).
Semua langkah di sini sudah **terbukti live** (rehearsal multi-box: sweep → submit → capture →
replay). Yang kamu tambah di lomba cuma **scope + flag format + timing + submission** resmi dari
panitia ke `config/aether.yaml`.

> Baca juga: [STRATEGY.md](STRATEGY.md) (konsep A&D), [CHEATSHEET.md](CHEATSHEET.md) (perintah
> cepat), [DEFENSE-AND-LAB.md](DEFENSE-AND-LAB.md) (defense tanpa ngoding).

---

## 0. SETUP DARI NOL → SIAP TEMPUR (lakukan di KEDUA laptop, kamu + timmu, H-1)

Internet di arena bisa diputus panitia, jadi **semua ini WAJIB beres di rumah.**

### 0a. Prasyarat (sekali per laptop)

```bash
# 1) Git + Docker (lab latihan) + qemu (opsional, image multi-arch)
sudo apt update && sudo apt install -y git docker.io docker-compose-plugin
sudo usermod -aG docker $USER      # lalu logout/login sekali biar `docker` tanpa sudo

# 2) uv (Python toolchain — installer resmi)
curl -LsSf https://astral.sh/uv/install.sh | sh
#   buka terminal baru supaya `uv` ada di PATH

# 3) Tools pentest eksternal (AETHER mengintegrasikannya)
sudo apt install -y nmap gobuster whatweb        # dasar
#   rustscan / ffuf / nuclei (kalau belum ada):
cargo install rustscan 2>/dev/null || sudo apt install -y rustscan
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || sudo apt install -y ffuf
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || sudo apt install -y nuclei
```

### 0b. Pasang AETHER (dari repo)

```bash
git clone https://github.com/Stevyussz/Aether-A-D.git
cd Aether-A-D
uv venv --python 3.12 .venv
uv pip install -e ".[dev]" --python .venv/bin/python
uv tool install --editable .          # perintah global `aether` (tanpa prefix .venv/bin)
```

### 0c. Verifikasi + cache offline (WAJIB)

```bash
aether system health                  # semua hijau, "No-AI runtime: clean"
.venv/bin/pytest -q                   # semua test lulus = arsenal sehat
aether lab serve &                    # self-test lab: pastikan ambil flag jalan
nuclei -update-templates              # cache templates nuclei LOKAL (biar offline)
docker pull vulhub/flask:1.1.1        # (opsional) image lab latihan, biar offline
```

### Checklist "siap tempur" (centang di kedua laptop)
- [ ] `aether` jalan tanpa error, `aether system health` hijau.
- [ ] `pytest` hijau (arsenal + defense teruji).
- [ ] Tools eksternal ada: `nmap`, `rustscan`, `ffuf`/`gobuster`, `whatweb`, `nuclei`.
- [ ] nuclei templates sudah ke-cache (`~/nuclei-templates` ada isinya).
- [ ] `docker ps` jalan tanpa sudo.
- [ ] Repo ke-clone & AETHER terpasang di **kedua** laptop (kamu + timmu).
- [ ] Sudah coba `aether web` → dashboard kebuka di browser.

> **Update dari repo** (kalau ada perubahan): `git pull && uv tool install --editable . --force`

---

## 1. T-0 — saat briefing panitia (isi config, 5 menit pertama)

Buka dashboard: `aether web` → buka URL+token yang tercetak. Tab **Config** → scope builder.
Atau edit `config/aether.yaml` langsung. Yang WAJIB diisi:

| Field | Isi dari panitia |
|---|---|
| `scope.targets` owner=`opponent` | IP semua tim lawan (yang boleh diserang) |
| `scope.targets` owner=`self` | IP vulnbox kita + `notes:` = path source service kita |
| `flags.pattern` | format flag resmi (contoh `IONIC\{[^}]+\}`) |
| `scoring.tick_seconds` | panjang 1 tick (contoh 120) |
| `scoring.flag_id_endpoint` | URL/file flag_ids per tick (kalau ada) |
| `submission.*` | endpoint + protokol submit flag ke panitia (lihat §5) |

```bash
aether config validate -c config/aether.yaml   # harus "READY", scope enforce=true
```

> ⚠️ `scope.enforce` **SELALU true**. `flags.auto_submit` **SELALU false**. Jangan diubah.

**Bagi peran (2 orang):**
- **Orang A — DEFENDER** (box kita, paling penting biar ga kebobolan & lolos cek juri).
- **Orang B — ATTACKER** (serang musuh, kumpulkan + submit flag).

---

## 2. DEFENDER — 5 menit pertama di vulnbox kita (PATCH DIRI DULU)

Golden rule: **amankan diri sebelum nyerang.** Satu flag kebobolan = minus terus tiap tick.

```bash
# 1) audit source service kita — cari sink yang bisa di-exploit lawan
aether defense audit --path /path/ke/webroot-kita
```
- [ ] Baca temuan CRITICAL/HIGH (LFI/cmdi/SSTI/SQLi/upload/file ke-expose) → **patch** satu per satu.
- [ ] Simpan copy source asli (git lokal) sebelum patch, biar bisa rollback.

**Pasang perisai (lewat dashboard tab Defense, atau CLI):**
```bash
# 2) WAF di depan service kita: pindah service asli ke port lokal (mis. 9000),
#    ShieldProxy dengar di port publik. Blokir SQLi/LFI/cmdi/SSTI + rekam exploit musuh.
#    --allow-ip = IP SLA-checker juri JANGAN pernah diblok (biar MENANG SLA!).
aether defense shield --listen 80 --backend 9000 --allow-ip <IP-checker-juri> --allow-path /healthz

# 3) AutoGuard: auto-karantina webshell + auto-restore file yang diubah musuh,
#    lindungi file flag yang di-update juri. --interval 5 = loop tiap 5 detik.
aether defense guard --path /path/ke/webroot-kita --interval 5
```
- [ ] ShieldProxy **RUNNING**, filter **ON (BLOCKING)**.
- [ ] AutoGuard **ON**.
- [ ] Cek service masih normal (SLA checker hijau) setelah shield + patch.

> Dashboard tab **Defense**: tombol ON/OFF ShieldProxy & AutoGuard, counter blocked, panel
> **traffic capture** (exploit musuh yang masuk), dan **self-audit**.

---

## 3. ATTACKER — loop per tick (ulang tiap tick sampai lomba selesai)

```bash
# Serang SEMUA target opponent sekaligus, tiap ronde, pakai tools recon:
aether attack loop --tools
```
Atau manual per target lewat dashboard tab **Attack** (tombol Sweep), atau:
```bash
aether attack sweep <IP-musuh> --tools --show-values
```
- [ ] Flag masuk **Flag Inbox** (tab Flags) sebagai **VALIDATED / PENDING**.
- [ ] AETHER **tidak pernah auto-submit** — kamu yang submit (§5).

**Urutan prioritas serangan** (yang cepat & mahal dulu): exposed files → LFI/path-traversal →
SQLi → command injection → SSTI → file upload → shellshock → XXE → sisanya. Arsenal jalan
otomatis; `--tools` (ffuf/gobuster) penting buat nemu endpoint custom service lomba.

---

## 4. "CURI EXPLOIT MUSUH" — capture → replay (senjata pamungkas)

Setiap serangan musuh ke box kita direkam ShieldProxy. Ambil exploit mereka, balikin ke semua tim.

Dashboard tab **Defense** → panel **traffic capture**:
- [ ] Lihat request musuh yang terdeteksi serangan (ditandai BLOCKED + rule).
- [ ] Klik **Replay ke musuh** pada baris exploit → AETHER refire ke SEMUA target opponent
      (scope-enforced), flag hasil replay masuk inbox.

> Ini cara tercepat dapat flag kalau musuh punya exploit yang kita belum punya.

---

## 5. SUBMIT flag ke panitia (jangan sampai flag expire!)

Flag ganti tiap tick — **submit cepat tiap ronde**. Sudah di-set di `submission.*` (§1):

```bash
aether flags submit            # kirim semua VALIDATED+PENDING ke endpoint panitia
# atau: dashboard tab Flags → tombol "Submit flag VALIDATED ke panitia"
```
- [ ] Hasil: `X accepted`. Flag yang terkirim ditandai (tidak akan dikirim dua kali).
- **Fail-closed**: kalau `submission.enabled=false` atau endpoint kosong → tidak mengirim apa-apa
  (aman). Isi dulu protokol resmi dari panitia.

Protokol didukung: `http` (POST JSON/form, bisa pakai token header) atau `tcp` (`<flag>\n`).
Kalau respons panitia beda, sesuaikan `accepted_patterns`/`rejected_patterns` di config.

---

## 6. Blind vuln (SSRF/RCE/XXE tanpa output) → OAST

```bash
aether attack oast --pub-host <IP-tim-kita>    # listener callback self-hosted
```
- [ ] Copy callback URL yang tercetak → suntik ke payload blind (`http://<IP-kita>/<token>`).
- [ ] Kalau target ping balik = vuln terkonfirmasi (sering bawa data exfil). Lihat juga di
      dashboard tab **Attack** → panel OAST.

---

## 7. Kalau ada masalah (panic / rollback)

| Gejala | Tindakan |
|---|---|
| Service kita DOWN (SLA merah) setelah patch | `aether defense guard` auto-restore, atau rollback git lokal manual |
| Ragu kebobolan / ada webshell | tab Defense → scan webshells → **quarantine**; AutoGuard auto |
| Shield blokir SLA checker (false positive) | Tambah IP checker ke **allowlist** (`--allow-ip` / tombol "Set allowlist") — permanen & tetap blokir musuh. Darurat: Filter Switch → **OFF** sementara (tetap merekam) |
| SLA turun walau service normal | Pastikan IP SLA-checker ada di shield allowlist; cek counter `allowlisted` di dashboard naik tiap tick |
| Sweep "already running" | tunggu selesai (1 sweep sekaligus), atau `aether attack stop` |
| Flag ke-reject panitia | cek flag_id/tick benar; flag mungkin sudah expired ronde lalu |
| Internet mati | semua tetap jalan (tools + nuclei templates sudah lokal) |

---

## 8. Ritme tiap tick (hafalkan)

```
DEFENDER: cek dashboard — ada incident? webshell? file berubah? → AutoGuard handle, pastikan SLA hijau
ATTACKER: aether attack loop --tools  →  flag masuk inbox  →  aether flags submit  →  cek traffic capture → replay
```

Ulang. Konsisten tiap tick menang lomba. **Defense rapi + submit cepat tiap ronde = juara.**
