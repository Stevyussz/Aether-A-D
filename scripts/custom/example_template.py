"""Template skrip kustom kompetisi untuk logika layanan spesifik (multi-step).

Cara pakai saat lomba:
1. Salin file ini ke nama baru di folder yang sama, misalnya:
   cp scripts/custom/example_template.py scripts/custom/service_notes.py
2. Isi fungsi `check_target` di bawah sesuai alur aplikasi target.
3. Semua file `scripts/custom/*.py` (yang tidak diawali `example_` atau `_`)
   otomatis dieksekusi dengan penjagaan ScopeGuard, ekstraksi regex flag,
   dan deduplikasi ke FlagInbox.
"""

from __future__ import annotations

import httpx


async def check_target(
    host: str,
    port: int,
    flag_ids: list[str],
    client: httpx.AsyncClient,
) -> list[str]:
    base = f"http://{host}:{port}"
    outputs: list[str] = []

    # Jika juri menyediakan flag_id per tick, iterasi setiap flag_id:
    targets = flag_ids or [""]
    for fid in targets:
        url = f"{base}/profile?id={fid}" if fid else f"{base}/"
        resp = await client.get(url)
        outputs.append(resp.text)

    return outputs
