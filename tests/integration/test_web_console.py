"""The AETHER Web Console serves real data and enforces every safety invariant:
localhost token-gated actions, fail-closed scope, no auto-submit, fail-closed config save.
"""

import asyncio
import textwrap
import threading
from http.server import ThreadingHTTPServer

import httpx
import pytest

from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.cli.webserver import Backend, _make_handler
from aether.core.config_manager import load_config
from aether.core.models import Flag
from aether.core.state_manager import StateManager

PATTERN = r"IONIC\{[^}]+\}"
TOKEN = "testtoken123"


def _write_cfg(tmp_path, enforce=True):
    db = tmp_path / "s.sqlite"
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent(f"""
        engine: {{state_db: {db}, log_file: null, log_level: ERROR}}
        scope:
          enforce: {str(enforce).lower()}
          targets:
            - {{name: opp, host: 127.0.0.1, ports: [8099], kind: web, owner: opponent}}
        flags: {{pattern: "IONIC\\\\{{[^}}]+\\\\}}", auto_submit: false}}
        scoring: {{tick_seconds: 120}}
        """), encoding="utf-8")
    return cfg, db


async def _seed(db):
    sm = StateManager(str(db))
    await sm.open()
    ib = FlagInbox(sm, FlagValidator(PATTERN))
    await ib.ingest(Flag(value="IONIC{web_console_demo}", target="127.0.0.1",
                         service="web", module="exploit.web.sqli"))
    key = (await sm.list_flags())[0]["dedup_key"]
    await sm.close()
    return key


@pytest.fixture
def server(tmp_path):
    cfg_path, db = _write_cfg(tmp_path)
    key = asyncio.run(_seed(db))
    backend = Backend(load_config(cfg_path), cfg_path)
    backend.start()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(backend, TOKEN))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, key, cfg_path
    httpd.shutdown()
    backend.shutdown()


def test_page_and_state(server):
    base, _key, _ = server
    page = httpx.get(base + "/").text
    assert "AETHER Web Console" in page
    assert "__TOKEN__" not in page and TOKEN in page       # token injected
    s = httpx.get(base + "/api/state").json()
    assert "tick" in s and "services" in s and "resources" in s
    assert s["flags"]["total"] == 1 and s["flags"]["by_validation"].get("VALIDATED") == 1


def test_flags_hidden_then_revealed(server):
    base, _key, _ = server
    hidden = httpx.get(base + "/api/flags").json()["flags"][0]["value"]
    assert "IONIC{web_console_demo}" not in hidden          # masked by default
    shown = httpx.get(base + "/api/flags?show=1").json()["flags"][0]["value"]
    assert shown == "IONIC{web_console_demo}"


def test_mutations_require_token(server):
    base, key, _ = server
    r = httpx.post(base + "/api/flags/mark", json={"key": key, "status": "SUBMITTED"})
    assert r.status_code == 403                             # no token -> refused
    r2 = httpx.post(base + "/api/flags/mark", json={"key": key, "status": "SUBMITTED"},
                    headers={"X-AETHER-Token": TOKEN})
    assert r2.status_code == 200 and r2.json().get("ok") is True


def test_sweep_is_scope_enforced(server):
    base, _key, _ = server
    r = httpx.post(base + "/api/attack/sweep", json={"host": "10.10.10.10", "port": 80},
                   headers={"X-AETHER-Token": TOKEN}).json()
    assert "error" in r and "scope" in r["error"].lower()   # out of scope -> refused


def test_config_save_is_fail_closed(server):
    base, _key, cfg_path = server
    # Try to disable scope enforcement via the UI — must be refused.
    bad = cfg_path.read_text().replace("enforce: true", "enforce: false")
    r = httpx.post(base + "/api/config/save", json={"yaml": bad},
                   headers={"X-AETHER-Token": TOKEN}).json()
    assert "error" in r and "scope" in r["error"].lower()
    # The on-disk config is unchanged (still enforcing).
    assert "enforce: true" in cfg_path.read_text()
