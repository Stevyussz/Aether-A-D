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


def test_flag_submit_is_fail_closed(server):
    base, _key, _ = server
    # submission.enabled defaults to false -> the organizer submit endpoint refuses, sends nothing.
    r = httpx.post(base + "/api/flags/submit", json={},
                   headers={"X-AETHER-Token": TOKEN}).json()
    assert "error" in r and "submission" in r["error"].lower()
    # token is still required for this mutation.
    r2 = httpx.post(base + "/api/flags/submit", json={})
    assert r2.status_code == 403


def test_traffic_capture_and_replay_endpoints(server):
    base, _key, _ = server
    # Captured-traffic view is readable and well-formed (buffer starts empty).
    t = httpx.get(base + "/api/defense/traffic").json()
    assert "stats" in t and "captures" in t and isinstance(t["captures"], list)
    # Replay is a mutation -> token required.
    assert httpx.post(base + "/api/attack/replay", json={"id": 1}).status_code == 403
    # Replaying a capture that does not exist is a clean error, never a crash.
    r = httpx.post(base + "/api/attack/replay", json={"id": 999999},
                   headers={"X-AETHER-Token": TOKEN}).json()
    assert "error" in r


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


def test_config_apply_form_sets_scope(server):
    base, _key, cfg_path = server
    # The dashboard scope-builder form posts structured targets; they get written + armed.
    r = httpx.post(base + "/api/config/apply", headers={"X-AETHER-Token": TOKEN}, json={
        "pattern": r"IONIC\{[^}]+\}", "tick": "60",
        "flag_id_endpoint": "http://10.60.0.1/flag_ids.json",
        "enforce": True,
        "targets": [
            {"name": "enemy1", "host": "10.1.2.3", "ports": "80,8080", "kind": "web",
             "owner": "opponent", "notes": ""},
            {"name": "ours", "host": "127.0.0.1", "ports": "80", "kind": "web",
             "owner": "self", "notes": "/var/www/html"},
        ]}).json()
    assert r.get("ok") is True
    cfg = httpx.get(base + "/api/config").json()
    hosts = {t["host"] for t in cfg["targets"]}
    assert "10.1.2.3" in hosts and "127.0.0.1" in hosts
    assert cfg["tick"] == 60
    assert cfg["flag_id_endpoint"] == "http://10.60.0.1/flag_ids.json"
    ours_row = next(t for t in cfg["targets"] if t["name"] == "ours")
    assert ours_row["notes"] == "/var/www/html"
    assert "enemy1" in cfg_path.read_text()          # persisted to disk
    # Live engine scope is hot-reloaded without requiring a server restart:
    # 99.99.99.99 is still out-of-scope, while 10.1.2.3:80 is now authorized in live scope.
    r_out = httpx.post(base + "/api/attack/sweep", json={"host": "99.99.99.99", "port": 80},
                       headers={"X-AETHER-Token": TOKEN}).json()
    assert "error" in r_out and "scope" in r_out["error"].lower()


def test_config_apply_is_fail_closed(server):
    base, _key, cfg_path = server
    before = cfg_path.read_text()
    # enforce=false -> refused.
    r1 = httpx.post(base + "/api/config/apply", headers={"X-AETHER-Token": TOKEN}, json={
        "pattern": "IONIC", "enforce": False,
        "targets": [{"name": "x", "host": "1.2.3.4", "ports": "80", "owner": "opponent"}]}).json()
    assert "error" in r1 and "scope" in r1["error"].lower()
    # empty targets -> refused.
    r2 = httpx.post(base + "/api/config/apply", headers={"X-AETHER-Token": TOKEN},
                    json={"enforce": True, "targets": []}).json()
    assert "error" in r2
    assert cfg_path.read_text() == before            # nothing written on refusal
