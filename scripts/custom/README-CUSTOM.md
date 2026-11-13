# Custom Script — BACA INI DULU (buat yang "gak bisa ngoding")

## Kabar baik: kamu KEMUNGKINAN BESAR gak akan butuh folder ini.
AETHER udah otomatis nyerang web (SQLi/LFI/SSTI/upload/XXE/IDOR/dll), SSH, redis,
dan TCP umum (`tcp_vault`). Kamu cukup jalanin `aether attack loop --tools`. **Nol ngoding.**

Folder ini **cuma pelampung darurat** kalau ada service dengan protokol aneh yang
belum ketangkap. Itu jarang.

## Kalau sampai butuh — kamu TETAP gak nulis kode dari nol.
Sudah disediakan 3 template "ganti-1-baris". Yang prefix `example_` **tidak jalan**
otomatis (aman). Cara aktifin: **copy** ke nama baru tanpa `example_`, ganti baris
bertanda `# GANTI INI`, selesai.

| Template | Dipakai kalau… | Yang diganti |
|---|---|---|
| `example_tcp_commands.py` | service nc/TCP butuh urutan perintah khusus | daftar `COMMANDS` |
| `example_http_login.py` | flag di balik login web | URL login + halaman + user/pass |
| `example_template.py` | alur web multi-langkah lain | isi fungsi sesuai contoh |

Contoh aktifin (TCP):
```bash
cp scripts/custom/example_tcp_commands.py scripts/custom/serang_tcp.py
# buka serang_tcp.py, ganti COMMANDS, simpan. Udah. AETHER jalanin otomatis.
```

## Macet? Jangan panik.
1. **Lewati aja.** Fokus ke service lain yang modul bawaan udah bisa — biasanya cukup buat menang.
2. Service custom itu **bonus**, bukan syarat juara. Defense rapi + submit cepat tiap tick yang bikin juara.

Script aktif otomatis dapat: ScopeGuard (gak nyerang di luar izin), ekstraksi flag,
dedup ke inbox. Kamu cukup mikirin "kirim apa", bukan "gimana amannya".
