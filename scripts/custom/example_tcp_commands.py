"""TEMPLATE: service TCP/nc custom — kirim daftar perintah, baca balasannya.

KAPAN DIPAKAI: ada service non-web (nc/tcp) yang butuh urutan perintah khusus
(mis. "HELP", "MENU 1", "GET flag") yang belum ketangkap modul bawaan `tcp_vault`.

CARA PAKAI (TANPA NGODING — ganti 1 baris saja):
1. Aktifkan:  cp scripts/custom/example_tcp_commands.py scripts/custom/serang_tcp.py
2. Buka file barunya, ganti HANYA baris bertanda `# GANTI INI`.
3. Selesai. AETHER jalanin otomatis tiap sweep (scope-enforced, flag auto-masuk inbox).
"""

from __future__ import annotations

import asyncio

import httpx  # noqa: F401  (disediakan AETHER; tak dipakai untuk TCP murni)

# ── GANTI INI ─────────────────────────────────────────────────────────────────
# Daftar perintah yang dikirim ke service, berurutan. Satu string = satu baris.
# Contoh umum A&D: minta menu/help dulu, lalu ambil flag.
COMMANDS: list[str] = [
    "HELP",
    "LIST",
    "GET flag",
]
# ────────────────────────────────────────────────────────────────────────────


async def check_target(host: str, port: int, flag_ids: list[str], client: httpx.AsyncClient) -> list[str]:
    outputs: list[str] = []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=6)
    except Exception as exc:  # noqa: BLE001
        return [f"(connect gagal: {exc})"]

    # Baca banner awal kalau ada.
    try:
        banner = await asyncio.wait_for(reader.read(4096), timeout=2)
        outputs.append(banner.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        pass

    # Kirim tiap perintah, baca balasan. Kalau juri kasih flag_id, coba juga per-id.
    cmds = list(COMMANDS)
    for fid in (flag_ids or []):
        cmds.append(f"GET {fid}")

    for cmd in cmds:
        try:
            writer.write((cmd + "\n").encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=2)
            outputs.append(data.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            outputs.append(f"(error '{cmd}': {exc})")

    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
    return outputs
