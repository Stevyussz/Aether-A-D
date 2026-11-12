"""ShieldProxy — lightweight HTTP reverse-proxy filter with runtime ON/OFF switch.

Sits in front of a self-owned HTTP service and inspects incoming request paths, query
parameters, and request bodies using `request_filter`.

- When `enabled=True` (Blocking ON): requests matching suspicious input patterns are
  rejected with HTTP 403 before reaching the backend service, while normal SLA checker
  requests are forwarded transparently.
- When `enabled=False` (Pass-Through OFF): all requests are forwarded to the backend
  without blocking, allowing instant operator toggle without dropping connections.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from ..core.logger import get_logger
from .request_filter import inspect_value, validate_params
from .traffic_recorder import TrafficRecorder

log = get_logger("shield_proxy")


@dataclass
class ShieldStats:
    running: bool = False
    enabled: bool = True
    listen_host: str = "0.0.0.0"
    listen_port: int = 0
    backend_host: str = "127.0.0.1"
    backend_port: int = 0
    total_requests: int = 0
    blocked_requests: int = 0
    forwarded_requests: int = 0
    allowlisted_requests: int = 0
    allow_ips: list[str] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    recent_blocks: list[dict[str, str]] = field(default_factory=list)


class ShieldProxy:
    """Thread-safe HTTP reverse proxy with live ON/OFF filtering switch."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        backend_host: str = "127.0.0.1",
        backend_port: int = 8000,
        *,
        enabled: bool = True,
        allow_ips: tuple[str, ...] = (),
        allow_paths: tuple[str, ...] = (),
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.enabled = enabled
        # SLA SAFETY: requests from these source IPs, or to these path prefixes, are NEVER
        # blocked — they are forwarded straight to the backend so the organizer's SLA checker
        # can never be filtered out (a false block = a failed SLA tick = lost points). They are
        # still recorded so you can see what the checker sends.
        self.allow_ips: set[str] = set(allow_ips)
        self.allow_paths: list[str] = list(allow_paths)
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.total_requests = 0
        self.blocked_requests = 0
        self.forwarded_requests = 0
        self.allowlisted_requests = 0
        self.recent_blocks: list[dict[str, str]] = []
        # Tulip-style capture of every incoming request (enemy exploits land here).
        self.recorder = TrafficRecorder()

    def set_allowlist(self, *, ips=None, paths=None) -> dict:
        """Update the SLA-safe allowlist at runtime. Returns the current allowlist."""
        with self._lock:
            if ips is not None:
                self.allow_ips = set(ips)
            if paths is not None:
                self.allow_paths = list(paths)
            return {"ips": sorted(self.allow_ips), "paths": list(self.allow_paths)}

    def is_allowlisted(self, src_ip: str, raw_path: str) -> bool:
        """True if this request bypasses filtering (SLA checker / known-good path)."""
        if src_ip and src_ip in self.allow_ips:
            return True
        path = (raw_path or "").split("?", 1)[0]
        return any(path == p or path.startswith(p) for p in self.allow_paths if p)

    @property
    def running(self) -> bool:
        return self._server is not None

    def set_enabled(self, enabled: bool) -> bool:
        """Toggle request blocking ON (True) or Pass-Through OFF (False) at runtime."""
        with self._lock:
            self.enabled = bool(enabled)
        log.info("shield filter toggled", extra={"ctx": {"enabled": self.enabled}})
        return self.enabled

    def inspect_request(self, raw_path: str, body_text: str, headers: dict[str, str]) -> list[str]:
        """Check request path, query parameters, body, and selected headers."""
        reasons: list[str] = []
        decoded_path = unquote(raw_path)
        for hit in inspect_value(raw_path) + inspect_value(decoded_path):
            reasons.append(f"path:{hit}")

        parsed = urlparse(raw_path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        ok, q_hits = validate_params(qs)
        if not ok:
            reasons.extend(q_hits)

        if body_text:
            for hit in inspect_value(body_text) + inspect_value(unquote(body_text)):
                reasons.append(f"body:{hit}")

        for hname in ("User-Agent", "Referer", "Cookie", "X-Forwarded-For"):
            hval = headers.get(hname, "")
            if hval:
                for hit in inspect_value(hval):
                    reasons.append(f"header({hname}):{hit}")
        for spoof_hdr in ("X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization"):
            if headers.get(spoof_hdr):
                reasons.append(f"header_spoof:{spoof_hdr}")

        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for r in reasons:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    def _record_block(self, method: str, path: str, reasons: list[str]) -> None:
        with self._lock:
            self.total_requests += 1
            self.blocked_requests += 1
            self.recent_blocks.append(
                {
                    "ts": time.strftime("%H:%M:%S"),
                    "method": method,
                    "path": path[:120],
                    "reasons": ", ".join(reasons),
                }
            )
            if len(self.recent_blocks) > 25:
                self.recent_blocks = self.recent_blocks[-25:]

    def _record_forward(self) -> None:
        with self._lock:
            self.total_requests += 1
            self.forwarded_requests += 1

    def start(
        self,
        listen_host: str | None = None,
        listen_port: int | None = None,
        backend_host: str | None = None,
        backend_port: int | None = None,
    ) -> int:
        """Start the reverse proxy listener in a background daemon thread. Returns bound port."""
        if self._server is not None:
            self.stop()
        if listen_host is not None:
            self.listen_host = listen_host
        if listen_port is not None:
            self.listen_port = int(listen_port)
        if backend_host is not None:
            self.backend_host = backend_host
        if backend_port is not None:
            self.backend_port = int(backend_port)

        proxy = self

        class _ProxyHandler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw_body = self.rfile.read(length) if length > 0 else b""
                body_text = raw_body.decode("utf-8", "replace") if raw_body else ""
                hdrs = {k: v for k, v in self.headers.items()}

                # Always inspect (even in pass-through) so enemy exploits are captured for
                # replay; only BLOCK when filtering is enabled.
                reasons = proxy.inspect_request(self.path, body_text, hdrs)
                src_ip = self.client_address[0] if self.client_address else "?"
                # SLA-safe: allowlisted source IPs / paths (e.g. the organizer SLA checker) are
                # NEVER blocked, even if a rule matches — a false block costs an SLA tick.
                allowlisted = proxy.is_allowlisted(src_ip, self.path)
                blocked = proxy.enabled and bool(reasons) and not allowlisted
                if allowlisted:
                    with proxy._lock:
                        proxy.allowlisted_requests += 1
                try:
                    proxy.recorder.record(src_ip=src_ip, method=self.command, path=self.path,
                                          headers=hdrs, body=body_text, blocked=blocked,
                                          rule_hits=reasons)
                except Exception:  # noqa: BLE001 - capture must never break the proxy
                    pass

                if blocked:
                    proxy._record_block(self.command, self.path, reasons)
                    payload = json.dumps(
                        {"error": "request rejected by AETHER shield", "rules": reasons}
                    ).encode("utf-8")
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                proxy._record_forward()
                try:
                    conn = http.client.HTTPConnection(
                        proxy.backend_host, proxy.backend_port, timeout=10
                    )
                    fwd_headers = {
                        k: v
                        for k, v in hdrs.items()
                        if k.lower() not in ("host", "connection", "transfer-encoding")
                    }
                    fwd_headers["Host"] = f"{proxy.backend_host}:{proxy.backend_port}"
                    conn.request(self.command, self.path, body=raw_body if raw_body else None, headers=fwd_headers)
                    resp = conn.getresponse()
                    resp_body = resp.read()
                    self.send_response(resp.status)
                    for hk, hv in resp.getheaders():
                        if hk.lower() in ("transfer-encoding", "connection", "content-length"):
                            continue
                        self.send_header(hk, hv)
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(resp_body)
                    conn.close()
                except Exception as exc:  # noqa: BLE001
                    err_payload = json.dumps({"error": f"backend unavailable: {exc}"}).encode("utf-8")
                    self.send_response(502)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_payload)))
                    self.end_headers()
                    self.wfile.write(err_payload)

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle()

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle()

            def do_HEAD(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, *args) -> None:
                return

        self._server = ThreadingHTTPServer((self.listen_host, self.listen_port), _ProxyHandler)
        self.listen_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log.info(
            "shield proxy started",
            extra={
                "ctx": {
                    "listen": f"{self.listen_host}:{self.listen_port}",
                    "backend": f"{self.backend_host}:{self.backend_port}",
                    "enabled": self.enabled,
                }
            },
        )
        return self.listen_port

    def stop(self) -> None:
        """Stop the reverse proxy listener if running."""
        srv = self._server
        self._server = None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:  # noqa: BLE001
                pass
            log.info("shield proxy stopped")

    def status(self) -> ShieldStats:
        with self._lock:
            return ShieldStats(
                running=self.running,
                enabled=self.enabled,
                listen_host=self.listen_host,
                listen_port=self.listen_port,
                backend_host=self.backend_host,
                backend_port=self.backend_port,
                total_requests=self.total_requests,
                blocked_requests=self.blocked_requests,
                forwarded_requests=self.forwarded_requests,
                allowlisted_requests=self.allowlisted_requests,
                allow_ips=sorted(self.allow_ips),
                allow_paths=list(self.allow_paths),
                recent_blocks=list(self.recent_blocks),
            )
