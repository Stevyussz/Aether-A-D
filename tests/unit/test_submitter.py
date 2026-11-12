"""FlagSubmitter: fail-closed, submits only VALIDATED+PENDING flags to the organizer,
classifies the response, and deduplicates so a flag is never submitted twice.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.core.models import Flag, SubmissionStatus
from aether.core.state_manager import StateManager
from aether.scoring.submitter import (
    SubmitConfig,
    FlagSubmitter,
    classify_response,
)

PATTERN = r"IONIC\{[^}]+\}"


async def _inbox(tmp_path):
    sm = StateManager(str(tmp_path / "s.sqlite"))
    await sm.open()
    ib = FlagInbox(sm, FlagValidator(PATTERN))
    return sm, ib


def test_ready_is_fail_closed():
    assert SubmitConfig(enabled=False, endpoint="http://x").ready()[0] is False
    assert SubmitConfig(enabled=True, protocol="http", endpoint=None).ready()[0] is False
    assert SubmitConfig(enabled=True, protocol="tcp", tcp_host="h", tcp_port=None).ready()[0] is False
    assert SubmitConfig(enabled=True, protocol="http", endpoint="http://g/submit").ready()[0] is True
    assert SubmitConfig(enabled=True, protocol="tcp", tcp_host="h", tcp_port=9).ready()[0] is True


def test_classify_response_buckets():
    c = SubmitConfig()
    assert classify_response("Flag accepted!", c) == SubmissionStatus.ACCEPTED
    assert classify_response("invalid flag", c) == SubmissionStatus.REJECTED
    assert classify_response("flag is too old", c) == SubmissionStatus.EXPIRED
    assert classify_response("already submitted", c) == SubmissionStatus.ACCEPTED  # dup => done
    assert classify_response("weird server noise", c) == SubmissionStatus.SUBMITTED  # unknown


async def test_disabled_submitter_refuses_and_sends_nothing(tmp_path):
    sm, ib = await _inbox(tmp_path)
    try:
        await ib.ingest(Flag(value="IONIC{a}", target="10.0.0.9", service="web",
                             module="exploit.web.ssti"))
        sub = FlagSubmitter(ib, SubmitConfig(enabled=False, endpoint="http://unused"))
        report = await sub.submit_pending()
        assert report.refused and report.attempted == 0
        # flag stays PENDING (never touched)
        assert (await ib.pending())[0]["submission"] == SubmissionStatus.PENDING.value
    finally:
        await sm.close()


async def test_http_submit_accepts_and_dedups(tmp_path):
    # Fake organizer game server.
    seen: list[bytes] = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0) or 0)
            seen.append(self.rfile.read(n))
            body = b"Flag accepted, +10 points"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/submit"

    sm, ib = await _inbox(tmp_path)
    try:
        # One VALIDATED flag (eligible) and one INVALID flag (never eligible).
        await ib.ingest(Flag(value="IONIC{win}", target="10.0.0.9", service="web",
                             module="exploit.web.ssti"))
        await ib.ingest(Flag(value="NOTAFLAG", target="10.0.0.9", service="web",
                             module="exploit.web.ssti"))
        cfg = SubmitConfig(enabled=True, protocol="http", endpoint=url,
                           token="t0ken", token_header="X-Team-Token")
        sub = FlagSubmitter(ib, cfg)

        r1 = await sub.submit_pending()
        assert r1.attempted == 1 and r1.accepted == 1   # only the VALIDATED one
        assert len(seen) == 1 and b"IONIC{win}" in seen[0]
        # Flag moved out of PENDING -> ACCEPTED.
        rows = await ib.list()
        win = [x for x in rows if x["value"] == "IONIC{win}"][0]
        assert win["submission"] == SubmissionStatus.ACCEPTED.value

        # DEDUP: a second run submits nothing (no new request to the server).
        r2 = await sub.submit_pending()
        assert r2.attempted == 0
        assert len(seen) == 1
    finally:
        httpd.shutdown()
        await sm.close()


async def test_tcp_submit_line_protocol(tmp_path):
    received: list[str] = []

    async def handle(reader, writer):
        line = await reader.readline()
        received.append(line.decode().strip())
        writer.write(b"OK accepted\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    sm, ib = await _inbox(tmp_path)
    try:
        await ib.ingest(Flag(value="IONIC{tcp}", target="10.0.0.9", service="web",
                             module="exploit.web.sqli"))
        cfg = SubmitConfig(enabled=True, protocol="tcp", tcp_host="127.0.0.1", tcp_port=port)
        sub = FlagSubmitter(ib, cfg)
        async with server:
            report = await sub.submit_pending()
        assert report.accepted == 1
        assert received == ["IONIC{tcp}"]
    finally:
        await sm.close()
