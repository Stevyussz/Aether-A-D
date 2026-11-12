"""Simulated Community A&D Vulnbox Services for IONIC Final Training.

Provides realistic, isolated HTTP and TCP challenge archetypes frequently seen in
collegiate and community Attack & Defense finals:
1. `paste_note_idor`       — UUID/hash `flag_id` note store (`/api/notes/<flag_id>`).
2. `gateway_header_bypass` — Internal microservice trusting `X-Forwarded-For: 127.0.0.1` / `X-Original-URL`.
3. `portal_cookie_forge`   — Stateless Base64-JSON session cookie (`role: admin` / `is_admin: true`).
4. `config_proto_pollution`— JSON settings merger (`/api/merge`) susceptible to `__proto__` / mass assignment.
5. `export_backup_leak`    — Unprotected `/api/export?all=1` business data export endpoint.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class CommunityVulnboxService:
    """Configurable local HTTP server emulating one community A&D vulnbox challenge."""

    def __init__(self, mode: str, flag: str, *, flag_id: str = "item-9001") -> None:
        self.mode = mode
        self.flag = flag
        self.flag_id = flag_id
        self.polluted_admin = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> CommunityVulnboxService:
        svc = self

        class _H(BaseHTTPRequestHandler):
            def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
                raw = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                path = parsed.path
                qs = parse_qs(parsed.query)

                # Archetype 1: UUID/string flag_id IDOR note store
                if svc.mode == "paste_note_idor":
                    if path == f"/api/notes/{svc.flag_id}" or path == f"/notes/{svc.flag_id}":
                        self._send(200, json.dumps({"id": svc.flag_id, "note": svc.flag}))
                        return
                    if path in ("/note", "/api/note", "/notes") and qs.get("id", [""])[0] == svc.flag_id:
                        self._send(200, json.dumps({"id": svc.flag_id, "note": svc.flag}))
                        return
                    self._send(404, json.dumps({"error": "note not found"}))
                    return

                # Archetype 2: Reverse-proxy / localhost header bypass
                if svc.mode == "gateway_header_bypass":
                    xff = self.headers.get("X-Forwarded-For", "")
                    xreal = self.headers.get("X-Real-IP", "")
                    xorig = self.headers.get("X-Original-URL", "")
                    if (path in ("/internal/flags", "/api/admin", "/admin") or xorig in ("/internal/flags", "/admin")) and (
                        "127.0.0.1" in xff or "127.0.0.1" in xreal
                    ):
                        self._send(200, json.dumps({"internal_flag": svc.flag}))
                        return
                    self._send(403, json.dumps({"error": "external access forbidden"}))
                    return

                # Archetype 3: Base64-JSON session cookie forgery
                if svc.mode == "portal_cookie_forge":
                    cookie_hdr = self.headers.get("Cookie", "")
                    is_admin = False
                    for part in cookie_hdr.split(";"):
                        part = part.strip()
                        if "=" not in part:
                            continue
                        k, v = part.split("=", 1)
                        if k.strip() in ("session", "auth", "user"):
                            try:
                                pad = v + "=" * (-len(v) % 4)
                                data = json.loads(base64.b64decode(pad).decode("utf-8"))
                                if data.get("role") == "admin" or data.get("is_admin") is True:
                                    is_admin = True
                            except Exception:  # noqa: BLE001
                                pass
                    if is_admin and path in ("/dashboard", "/admin", "/api/flag", "/flag"):
                        self._send(200, json.dumps({"dashboard_flag": svc.flag}))
                        return
                    self._send(401, json.dumps({"error": "admin session required"}))
                    return

                # Archetype 4: Prototype pollution / Mass assignment state read
                if svc.mode == "config_proto_pollution":
                    if svc.polluted_admin and path in ("/api/admin", "/api/flags", "/admin", "/flag"):
                        self._send(200, json.dumps({"polluted_flag": svc.flag}))
                        return
                    self._send(403, json.dumps({"error": "not admin"}))
                    return

                # Archetype 5: Business export endpoint leak
                if svc.mode == "export_backup_leak":
                    if path in ("/api/export", "/export", "/api/backup") and (
                        qs.get("export", [""])[0] == "1" or qs.get("all", [""])[0] == "1"
                    ):
                        self._send(200, json.dumps({"records": [{"id": svc.flag_id, "secret": svc.flag}]}))
                        return
                    self._send(200, json.dumps({"status": "ok"}))
                    return

                self._send(200, "OK", "text/plain")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
                if svc.mode == "config_proto_pollution" and self.path in (
                    "/api/merge", "/api/settings", "/api/profile", "/api/config"
                ):
                    try:
                        body = json.loads(raw)
                        proto = body.get("__proto__") or {}
                        if proto.get("isAdmin") or proto.get("admin") or body.get("is_admin"):
                            svc.polluted_admin = True
                            self._send(200, json.dumps({"updated": True}))
                            return
                    except Exception:  # noqa: BLE001
                        pass
                self._send(400, json.dumps({"error": "bad request"}))

            def log_message(self, *args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
