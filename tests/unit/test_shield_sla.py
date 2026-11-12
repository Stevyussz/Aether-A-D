"""ShieldProxy SLA safety: the organizer's SLA checker must never be blocked. An allowlist of
source IPs / path prefixes bypasses filtering so a false block can't cost an SLA tick, while
real attacks from everywhere else are still blocked.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from aether.defense.shield_proxy import ShieldProxy

# A query that trips the template_expr rule (would be blocked by default).
ATTACK = "name={{config.__class__}}"


def _backend():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = ("OK:" + self.path).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_allowlisted_path_is_never_blocked_but_others_are():
    backend = _backend()
    bport = backend.server_address[1]
    shield = ShieldProxy(backend_host="127.0.0.1", backend_port=bport,
                         allow_paths=("/sla", "/healthz"))
    lport = shield.start("127.0.0.1", 0)
    try:
        base = f"http://127.0.0.1:{lport}"
        # Attack content on an ALLOWLISTED path -> forwarded (SLA checker protected).
        r_sla = httpx.get(f"{base}/sla?{ATTACK}", timeout=5)
        assert r_sla.status_code == 200 and r_sla.text.startswith("OK:/sla")
        # Same attack content on a normal path -> blocked.
        r_app = httpx.get(f"{base}/app?{ATTACK}", timeout=5)
        assert r_app.status_code == 403
        # A perfectly benign SLA health check -> forwarded.
        assert httpx.get(f"{base}/healthz", timeout=5).status_code == 200
        st = shield.status()
        assert st.allowlisted_requests >= 1 and st.blocked_requests >= 1
        assert "/sla" in st.allow_paths
    finally:
        shield.stop()
        backend.shutdown()


def test_allowlisted_source_ip_bypasses_filter():
    backend = _backend()
    bport = backend.server_address[1]
    # Our test client is 127.0.0.1 — allowlist it and even an attack goes through.
    shield = ShieldProxy(backend_host="127.0.0.1", backend_port=bport,
                         allow_ips=("127.0.0.1",))
    lport = shield.start("127.0.0.1", 0)
    try:
        base = f"http://127.0.0.1:{lport}"
        assert httpx.get(f"{base}/anything?{ATTACK}", timeout=5).status_code == 200
        # Flip the allowlist to a different IP at runtime -> now the attack is blocked.
        shield.set_allowlist(ips=["10.11.12.13"])
        assert httpx.get(f"{base}/anything?{ATTACK}", timeout=5).status_code == 403
    finally:
        shield.stop()
        backend.shutdown()
