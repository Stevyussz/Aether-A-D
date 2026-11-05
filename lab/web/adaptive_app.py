"""Lab app whose flag is reachable ONLY via a non-standard endpoint + parameter.

The vulnerable endpoint (`/secret_corner.php`) and its parameter (`weird_param`) are not in
any static exploit wordlist — they are only learnable by crawling the site. This proves the
adaptive recon crawler adds genuine value: a blind sweep misses the flag; a recon-driven
sweep discovers the surface and lands it. 127.0.0.1 only; not for competition use.
"""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

_HOME = (
    "<html><title>Adaptive Lab</title><body>"
    "<h1>welcome</h1>"
    "<a href='/secret_corner.php?weird_param=1'>corner</a>"
    "<form action='/hidden_login.php' method='post'>"
    "<input name='odd_user'><input name='odd_pass'></form>"
    "</body></html>"
)


def make_handler(flag: str):
    def body(method: str, path: str, query: str) -> tuple[int, str]:
        vals = [unquote(x) for vs in parse_qs(query).values() for x in vs]
        if path.rstrip("/") in ("", "/"):
            return 200, _HOME
        # SQLi only on the discovered endpoint+param.
        if path == "/secret_corner.php":
            for v in vals:
                if "union" in v.lower() and "select" in v.lower() and "flag" in v.lower():
                    return 200, f"<html><body>row: {flag}</body></html>"
            return 200, "<html><body>corner (nothing)</body></html>"
        return 404, "<html><body>not found</body></html>"

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            status, text = body("GET", parsed.path, parsed.query)
            data = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):  # silence
            return

    return _Handler


class AdaptiveLabService:
    def __init__(self, flag: str, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), make_handler(flag))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> "AdaptiveLabService":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8097)
    ap.add_argument("--flag", default="IONIC{adaptive_only}")
    args = ap.parse_args()
    svc = AdaptiveLabService(args.flag, port=args.port).start()
    print(f"adaptive lab on 127.0.0.1:{svc.port}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        svc.stop()
