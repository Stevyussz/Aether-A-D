"""OastListener — self-hosted out-of-band callback catcher (Interactsh-style).

Some bugs give no response you can read directly — blind SSRF, blind RCE, blind XXE, blind
XSS. You confirm them by making the target reach out to a server YOU control: inject a unique
callback URL into the payload, and if it pings back, the bug is real (and may carry exfiltrated
data in the path/body).

This is a self-hosted HTTP listener so the callback — and any data in it — lands on the team's
own box, never a public third party (Burp Collaborator / oast.fun leak your findings to whoever
runs them). Each probe gets a unique token; a hit on that token is proof of out-of-band
execution.

Safety: this only RECEIVES connections and records them; it sends nothing and performs no
attack itself. It binds where the operator tells it (team IP), and the payload URL it mints is
purely informational — the operator chooses where to inject it.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Interaction:
    id: int
    token: str
    ts: str
    epoch: float
    src_ip: str
    method: str
    path: str
    host: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self, *, include_body: bool = True) -> dict:
        d = {"id": self.id, "token": self.token, "ts": self.ts, "src_ip": self.src_ip,
             "method": self.method, "path": self.path, "host": self.host,
             "headers": dict(self.headers)}
        if include_body:
            d["body"] = self.body
        return d


def _token_from_path(path: str) -> str:
    """First path segment is the token: /<token>/anything -> <token>."""
    seg = path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
    return seg.strip()


class OastListener:
    """A background HTTP server that records every inbound callback, keyed by token."""

    def __init__(self, pub_host: str = "127.0.0.1", capacity: int = 500) -> None:
        self.pub_host = pub_host            # address advertised in minted payload URLs (team IP)
        self.listen_host = "0.0.0.0"
        self.listen_port = 0
        self._buf: deque[Interaction] = deque(maxlen=max(1, capacity))
        self._tokens: set[str] = set()
        self._lock = threading.Lock()
        self._seq = 0
        self.total = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def new_token(self) -> str:
        tok = secrets.token_hex(8)
        with self._lock:
            self._tokens.add(tok)
        return tok

    def payload_url(self, token: str | None = None, scheme: str = "http") -> str:
        """Mint a callback URL to inject into a payload. Uses the advertised pub_host:port."""
        token = token or self.new_token()
        port = self.listen_port
        hostport = self.pub_host if port in (80, 0) else f"{self.pub_host}:{port}"
        return f"{scheme}://{hostport}/{token}"

    def _record(self, *, src_ip: str, method: str, path: str,
                headers: dict[str, str], body: str, host: str) -> Interaction:
        token = _token_from_path(path)
        with self._lock:
            self._seq += 1
            it = Interaction(id=self._seq, token=token, ts=time.strftime("%H:%M:%S"),
                             epoch=time.time(), src_ip=src_ip or "?", method=method,
                             path=path, host=host, headers=dict(headers), body=body or "")
            self._buf.append(it)
            self.total += 1
            return it

    def interactions(self, token: str | None = None, limit: int = 50,
                     *, include_body: bool = False) -> list[dict]:
        with self._lock:
            items = list(self._buf)
        if token:
            items = [i for i in items if i.token == token]
        items = items[-limit:][::-1]
        return [i.to_dict(include_body=include_body) for i in items]

    def poll(self, token: str) -> list[dict]:
        return self.interactions(token=token, include_body=True)

    def has_hit(self, token: str) -> bool:
        with self._lock:
            return any(i.token == token for i in self._buf)

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    def stats(self) -> dict:
        with self._lock:
            return {"total": self.total, "buffered": len(self._buf),
                    "tokens": len(self._tokens), "running": self.running,
                    "listen_port": self.listen_port, "pub_host": self.pub_host}

    def start(self, listen_host: str = "0.0.0.0", listen_port: int = 0,
              pub_host: str | None = None) -> int:
        if self._server is not None:
            self.stop()
        self.listen_host = listen_host
        if pub_host:
            self.pub_host = pub_host
        oast = self

        class _H(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""
                hdrs = {k: v for k, v in self.headers.items()}
                src = self.client_address[0] if self.client_address else "?"
                oast._record(src_ip=src, method=self.command, path=self.path,
                             headers=hdrs, body=body, host=hdrs.get("Host", ""))
                # Benign 1x1-style response; reveal nothing useful to a scanner.
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def do_GET(self): self._handle()      # noqa: E704,N802
            def do_POST(self): self._handle()     # noqa: E704,N802
            def do_PUT(self): self._handle()      # noqa: E704,N802
            def do_HEAD(self): self._handle()     # noqa: E704,N802
            def do_OPTIONS(self): self._handle()  # noqa: E704,N802

            def log_message(self, *a):            # noqa: N802
                return

        self._server = ThreadingHTTPServer((listen_host, listen_port), _H)
        self.listen_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.listen_port

    def stop(self) -> None:
        srv = self._server
        self._server = None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:  # noqa: BLE001
                pass
