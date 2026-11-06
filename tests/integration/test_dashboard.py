"""The live monitor dashboard renders REAL data from engine + state (not placeholder text)."""

import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.cli.main import app
from aether.core.models import Flag
from aether.core.state_manager import StateManager

runner = CliRunner()
PATTERN = r"IONIC\{[^}]+\}"


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "s.sqlite"
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    (webroot / "index.html").write_text("home")
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent(f"""
        engine: {{state_db: {db}, log_file: null, log_level: ERROR}}
        scope:
          enforce: true
          targets:
            - {{name: our-web, host: 127.0.0.1, ports: [80], kind: web, owner: self, notes: "{webroot}"}}
            - {{name: opp, host: 127.0.0.1, ports: [8099], kind: web, owner: opponent}}
        flags: {{pattern: "IONIC\\\\{{[^}}]+\\\\}}", auto_submit: false}}
        scoring: {{tick_seconds: 120}}
        """), encoding="utf-8")
    return cfg, db


async def _seed(db):
    sm = StateManager(str(db))
    await sm.open()
    ib = FlagInbox(sm, FlagValidator(PATTERN))
    await ib.ingest(Flag(value="IONIC{d1}", target="127.0.0.1", service="web", module="exploit.web.sqli"))
    await ib.ingest(Flag(value="IONIC{d2}", target="127.0.0.1", service="web", module="exploit.web.idor"))
    await sm.record_modification("patch_manager", "COMMITTED", target="our-web", detail="patched")
    await sm.close()


def test_dashboard_once_renders_real_data(seeded):
    import asyncio
    cfg, db = seeded
    asyncio.run(_seed(db))

    r = runner.invoke(app, ["monitor", "dashboard", "-c", str(cfg), "--once",
                            "--log-text", "GET /shell.php 200 attacker"],
                      env={"COLUMNS": "140"})
    assert r.exit_code == 0, r.output
    out = r.output
    # Panels present
    assert "DEFENSE MONITOR" in out
    assert "file integrity" in out
    assert "incidents" in out
    assert "flag inbox" in out
    assert "modification / patch log" in out
    # Real numbers from seeded state
    assert "our-web" in out                 # watched self service
    assert "VALIDATED" in out and "2" in out  # two validated flags
    assert "COMMITTED" in out               # the modification we logged
    assert "log_ioc" in out                 # incident from the fed log line
    assert "tick 0" in out                  # tick clock configured
