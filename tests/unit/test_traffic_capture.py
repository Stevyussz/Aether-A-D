"""Traffic capture (Tulip-style): the recorder buffers enemy requests, and the replayer
refires them at OTHER teams — scope-enforced, extracting real flags into the inbox.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from aether.attack.flags.extractor import FlagExtractor
from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.attack.replay import ExploitReplayer
from aether.core.models import SubmissionStatus
from aether.core.scope_guard import ScopeGuard
from aether.core.state_manager import StateManager
from aether.defense.traffic_recorder import TrafficRecorder

PATTERN = r"IONIC\{[^}]+\}"


def test_recorder_buffers_and_classifies_attacks():
    rec = TrafficRecorder(capacity=3)
    rec.record(src_ip="10.0.0.5", method="GET", path="/?name=guest")  # clean
    rec.record(src_ip="10.0.0.9", method="GET", path="/?name=x",
               rule_hits=["template_expr"], blocked=True)             # attack
    s = rec.stats()
    assert s["total"] == 2 and s["attacks"] == 1
    attacks = rec.recent(attacks_only=True)
    assert len(attacks) == 1 and attacks[0]["src_ip"] == "10.0.0.9" and attacks[0]["is_attack"]
    # capacity is a ring buffer
    for i in range(5):
        rec.record(src_ip="10.0.0.1", method="GET", path=f"/{i}")
    assert rec.stats()["buffered"] == 3


def test_recorder_caps_body_size():
    rec = TrafficRecorder()
    cap = rec.record(src_ip="x", method="POST", path="/", body="A" * 20000)
    assert len(cap.body) < 20000 and "bytes)" in cap.body


async def test_replay_is_scope_enforced_and_extracts_flag(tmp_path):
    FLAG = "IONIC{replayed_enemy_exploit}"

    # A "victim" team box: reflects the flag when the SSTI-looking payload is present.
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            q = parse_qs(urlparse(self.path).query)
            name = (q.get("name") or [""])[0]
            body = (FLAG if "__class__" in name or "config" in name else "Hello " + name).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    sm = StateManager(str(tmp_path / "s.sqlite"))
    await sm.open()
    try:
        inbox = FlagInbox(sm, FlagValidator(PATTERN))
        scope = ScopeGuard(enforce=True)
        scope.allow("127.0.0.1", ports=(port,))
        replayer = ExploitReplayer(scope, FlagExtractor(PATTERN), inbox=inbox)

        # Captured enemy request (an SSTI exploit against our box).
        rec = TrafficRecorder()
        cap = rec.record(src_ip="10.9.9.9", method="GET",
                         path="/?name={{config.__class__}}", rule_hits=["template_expr"])

        report = await replayer.replay(
            cap,
            targets=[("127.0.0.1", port), ("10.255.255.1", port)],  # 2nd is OUT of scope
        )
        # In-scope target yielded the flag; out-of-scope target was skipped, never sent.
        assert FLAG in report.flags_found
        assert report.sent == 1
        skipped = [r for r in report.results if r.skipped]
        assert len(skipped) == 1 and skipped[0].host == "10.255.255.1"
        # Flag landed in the inbox PENDING (never auto-submitted).
        rows = await inbox.list()
        got = [r for r in rows if r["value"] == FLAG]
        assert got and got[0]["submission"] == SubmissionStatus.PENDING.value
    finally:
        httpd.shutdown()
        await sm.close()


async def test_replay_applies_flag_id_substitution(tmp_path):
    # The victim only returns the flag for ITS OWN flag_id, proving substitution happened.
    FLAG = "IONIC{per_target_flag_id}"

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            q = parse_qs(urlparse(self.path).query)
            body = (FLAG if (q.get("id") or [""])[0] == "TARGET-ID" else "no flag").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    sm = StateManager(str(tmp_path / "s.sqlite"))
    await sm.open()
    try:
        inbox = FlagInbox(sm, FlagValidator(PATTERN))
        scope = ScopeGuard(enforce=True)
        scope.allow("127.0.0.1", ports=(port,))
        replayer = ExploitReplayer(scope, FlagExtractor(PATTERN), inbox=inbox)

        rec = TrafficRecorder()
        cap = rec.record(src_ip="10.9.9.9", method="GET", path="/?id=OUR-ID")

        # Without substitution: no flag (wrong flag_id).
        r0 = await replayer.replay(cap, targets=[("127.0.0.1", port)])
        assert not r0.flags_found
        # With substitution OUR-ID -> TARGET-ID: flag returned.
        r1 = await replayer.replay(cap, targets=[("127.0.0.1", port)],
                                   substitutions=[("OUR-ID", "TARGET-ID")])
        assert FLAG in r1.flags_found
    finally:
        httpd.shutdown()
        await sm.close()
