"""The crawler must survive hostile/odd pages: a data:/javascript: link (e.g. a phpinfo
page's embedded logo) must never fuse into the authority and crash URL parsing.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aether.attack.recon.web_crawl import WebCrawlModule
from aether.core.models import TaskState
from aether.core.plugin import RunContext
from aether.core.scope_guard import ScopeGuard

# A page like phpinfo: a data: image, a javascript: link, and one real relative link.
PAGE = (
    '<html><body>'
    '<img src="data:image/gif;base64,R0lGODlhAQABAAAAACwAAAAAAQABAAA=">'
    '<a href="javascript:void(0)">x</a>'
    '<a href="mailto:a@b.c">mail</a>'
    '<a href="real.php?id=1">real</a>'
    '</body></html>'
)


def _server():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


async def test_crawler_survives_data_and_js_links():
    httpd = _server()
    port = httpd.server_address[1]
    try:
        scope = ScopeGuard(enforce=True)
        scope.allow("127.0.0.1", ports=(port,))
        ctx = RunContext(target_host="127.0.0.1", target_port=port, service="web", scope=scope)
        res = await WebCrawlModule().run(ctx)
        # No crash, and the real link was discovered; the data:/js/mailto links did not.
        assert res.state == TaskState.SUCCEEDED
        eps = res.data["endpoints"]
        assert "/real.php" in eps
        assert all("image/gif" not in e and "void" not in e for e in eps)
        # every discovered endpoint is a clean, slash-rooted path
        assert all(e.startswith("/") for e in eps)
    finally:
        httpd.shutdown()
