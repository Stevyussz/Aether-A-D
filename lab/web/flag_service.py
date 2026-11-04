"""Isolated local LAB web service that serves a flag.

Used ONLY for safe local testing of the attack pipeline against 127.0.0.1. It is not part
of the competition runtime and must never be pointed at real infrastructure. Run standalone:

    python lab/web/flag_service.py --port 8099 --flag 'CTF{lab_demo}'
"""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(flag: str):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("", "/flag"):
                body = f"<html><title>Lab Service</title><body>flag: {flag}</body></html>"
                self.send_response(200)
            else:
                body = "<html><title>Lab Service</title><body>nothing here</body></html>"
                self.send_response(404)
            data = body.encode()
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Server", "LabService/1.0")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):  # silence
            return

    return _Handler


class LabWebService:
    """Context-manager friendly lab server for tests."""

    def __init__(self, flag: str, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), make_handler(flag))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    def start(self) -> "LabWebService":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> "LabWebService":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--flag", default="CTF{lab_demo_flag}")
    args = ap.parse_args()
    svc = LabWebService(args.flag, args.host, args.port).start()
    print(f"lab web service on http://{svc.host}:{svc.port}/  (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        svc.stop()
