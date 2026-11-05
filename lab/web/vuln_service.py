"""Deliberately-vulnerable isolated LAB web service (127.0.0.1 only).

Models each vulnerability class the exploit arsenal targets, so the attack modules can be
proven to genuinely extract a flag from a REAL HTTP response (never fabricated). Each class
can be toggled via ``enabled`` so negative tests can confirm a module reports nothing when
the vuln is absent.

NOT part of the competition runtime. Never point at real infrastructure.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

ALL_VULNS = frozenset({
    "exposed_files", "path_traversal", "sqli", "command_injection", "ssti",
    "nosqli", "default_creds", "idor", "ssrf", "xxe", "graphql",
    "elasticsearch", "jwt", "deserialization",
})

# Secrets the JWT double will accept an HS256 token signed with (weak-secret bypass).
_JWT_WEAK_SECRETS = ("secret", "password", "key", "jwt", "admin", "changeme")
_JWT_ENDPOINTS = {"/flag", "/admin", "/admin/flag", "/api/flag", "/me", "/profile",
                  "/dashboard", "/api/admin", "/account", "/user"}


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _jwt_authorizes(token: str) -> bool:
    """Genuinely verify a forged JWT: alg:none with admin claims, or HS256 signed with a
    weak secret. Returns True only for a correctly-forged privileged token."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return False
    privileged = (payload.get("admin") is True or payload.get("is_admin") is True
                  or payload.get("isAdmin") is True
                  or str(payload.get("role", "")).lower() in ("admin", "administrator"))
    if not privileged:
        return False
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return True
    if alg == "hs256":
        signing = (parts[0] + "." + parts[1]).encode()
        for secret in _JWT_WEAK_SECRETS:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=").decode()
            if hmac.compare_digest(sig, parts[2]):
                return True
    return False


def _looks_like_deser_gadget(value: str) -> bool:
    """Detect a flag-reading deserialization gadget without ever executing it."""
    if any(tok in value for tok in ("FlagRead", "readFileSync", "_$$ND_FUNC$$_")):
        return True
    # base64-encoded pickle referencing the flag file
    try:
        decoded = base64.b64decode(value, validate=True)
        if b"flag" in decoded.lower() or b"/flag" in decoded:
            return True
    except (binascii.Error, ValueError):
        pass
    return False

_DEFAULT_PATHS = {"/flag", "/flag.txt", "/flags.txt", "/flag.php", "/app/flag.txt"}
_CRED_PAIRS = {("admin", "admin"), ("admin", "password"), ("root", "root")}
_IDOR_SECRET = "13"


def _page(body: str, status: int = 200) -> tuple[int, str]:
    return status, f"<html><title>Vuln Lab</title><body>{body}</body></html>"


def make_handler(flag: str, enabled: frozenset[str]):
    def decide(method: str, path: str, query: str, body: str,
               headers: dict | None = None) -> tuple[int, str]:
        raw_q = unquote(query)
        q = {k: [unquote(x) for x in v] for k, v in parse_qs(query).items()}
        vals = [v for vs in q.values() for v in vs]
        low_body = body.lower()
        headers = headers or {}
        cookie = headers.get("Cookie", "")
        authz = headers.get("Authorization", "")

        # 1. Exposed flag endpoints / files.
        if "exposed_files" in enabled and path.rstrip("/") in {p.rstrip("/") for p in _DEFAULT_PATHS}:
            return _page(f"flag: {flag}")

        # 2. Path traversal / LFI (value references a flag file, not a URL scheme).
        if "path_traversal" in enabled:
            for v in vals:
                if "://" in v and not v.startswith("php://"):
                    continue
                if "flag" in v and ("../" in v or "..\\" in v or "filter" in v
                                    or v.lstrip("/").startswith("flag") or v in {"/flag", "flag"}):
                    return _page(f"file contents: {flag}")
                if "etc/passwd" in v:
                    return _page("root:x:0:0:root:/root:/bin/bash")

        # 3. SQL injection (UNION-based read).
        if "sqli" in enabled:
            for v in vals:
                if "union" in v.lower() and "select" in v.lower() and "flag" in v.lower():
                    return _page(f"query result row: {flag}")

        # 4. OS command injection (read-only cat).
        if "command_injection" in enabled:
            for v in vals:
                if "cat" in v and "flag" in v:
                    return _page(f"PING 127.0.0.1 ...\n{flag}")

        # 5. Server-side template injection.
        if "ssti" in enabled:
            for v in vals:
                if any(tok in v for tok in ("open('/flag", 'open("/flag', "file_get_contents('/flag",
                                            "cat /flag", "Runtime", "{/php}")):
                    return _page(f"rendered: {flag}")
                if "7*7" in v:
                    return _page("rendered: 49")

        # 6. NoSQL operator injection (auth/filter bypass).
        if "nosqli" in enabled:
            if any("[$" in k for k in q) or any(op in low_body for op in ('"$ne"', '"$gt"', '"$regex"')):
                return _page(f"authenticated: {flag}")

        # 7. Default credentials on a login endpoint.
        if "default_creds" in enabled and method == "POST":
            form = {k: [unquote(x) for x in v] for k, v in parse_qs(body).items()}
            fvals = [v for vs in form.values() for v in vs]
            for user, pw in _CRED_PAIRS:
                if user in fvals and pw in fvals:
                    return _page(f"welcome admin! {flag}")

        # 8. IDOR: one privileged object id leaks the flag.
        if "idor" in enabled:
            if any(v == _IDOR_SECRET for v in vals) or path.rstrip("/").endswith("/" + _IDOR_SECRET):
                return _page(f"record #{_IDOR_SECRET}: {flag}")

        # 9. SSRF: proxying an internal flag URL.
        if "ssrf" in enabled:
            for v in vals:
                if (v.startswith("http://127.0.0.1") or v.startswith("http://localhost")
                        or v.startswith("file://")) and "flag" in v:
                    return _page(f"fetched: {flag}")

        # 10. XXE: external entity reads the flag file.
        if "xxe" in enabled and method == "POST":
            if "SYSTEM" in body and "file:" in low_body and "flag" in low_body:
                return _page(f"<r>{flag}</r>")
            if "SYSTEM" in body and "etc/passwd" in low_body:
                return _page("<r>root:x:0:0:root</r>")

        # 11. GraphQL flag query.
        if "graphql" in enabled and method == "POST" and '"query"' in body:
            if "flag" in low_body or "getflag" in low_body or "secret" in low_body:
                return _page('{"data":{"flag":"' + flag + '"}}')
            if "__schema" in body:
                return _page('{"data":{"__schema":{"types":[{"name":"Flag"}]}}}')

        # 12. Unauthenticated Elasticsearch search.
        if "elasticsearch" in enabled and ("_search" in path or "_cat/indices" in path):
            return _page('{"hits":{"total":1,"hits":[{"_index":"flag",'
                         '"_source":{"flag":"' + flag + '"}}]}}')

        # 13. Weak-JWT auth bypass: a correctly-forged privileged token unlocks the flag.
        if "jwt" in enabled and path.rstrip("/") in {p.rstrip("/") for p in _JWT_ENDPOINTS}:
            token = ""
            if authz.lower().startswith("bearer "):
                token = authz[7:].strip()
            if not token and cookie:
                for part in cookie.split(";"):
                    part = part.strip()
                    for name in ("token=", "jwt=", "session="):
                        if part.startswith(name):
                            token = part[len(name):]
            if token and _jwt_authorizes(token):
                return _page(f"admin area: {flag}")

        # 14. Insecure deserialization: a flag-reading gadget in a param or the session cookie.
        if "deserialization" in enabled:
            cookie_vals = [c.split("=", 1)[1] for c in cookie.split(";") if "=" in c]
            for v in vals + cookie_vals:
                if _looks_like_deser_gadget(v):
                    return _page(f"object restored: {flag}")

        return _page("nothing here", status=404)

    class _Handler(BaseHTTPRequestHandler):
        def _respond(self, method: str) -> None:
            parsed = urlparse(self.path)
            body = ""
            if method == "POST":
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            hdrs = {"Cookie": self.headers.get("Cookie", ""),
                    "Authorization": self.headers.get("Authorization", "")}
            status, text = decide(method, parsed.path, parsed.query, body, hdrs)
            data = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Server", "VulnLab/1.0")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            self._respond("GET")

        def do_POST(self):  # noqa: N802
            self._respond("POST")

        def log_message(self, *args):  # silence
            return

    return _Handler


class VulnLabService:
    """Context-manager friendly deliberately-vulnerable lab server for tests."""

    def __init__(self, flag: str, host: str = "127.0.0.1", port: int = 0,
                 enabled: frozenset[str] = ALL_VULNS) -> None:
        self._server = ThreadingHTTPServer((host, port), make_handler(flag, enabled))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    def start(self) -> "VulnLabService":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> "VulnLabService":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8098)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--flag", default="IONIC{vuln_lab_demo}")
    args = ap.parse_args()
    svc = VulnLabService(args.flag, args.host, args.port).start()
    print(f"VULN lab service on http://{svc.host}:{svc.port}/  (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        svc.stop()
