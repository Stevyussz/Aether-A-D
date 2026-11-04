"""DefenseEngine coordinates signals into incidents and emits operator events."""

import pytest

from aether.defense.engine import DefenseEngine
from tests.conftest import make_config
from aether.core.orchestrator import Orchestrator


@pytest.fixture
async def orch(tmp_path):
    o = Orchestrator(make_config(tmp_path))
    await o.start()
    yield o
    await o.shutdown()


async def test_sweep_raises_integrity_incident(tmp_path, orch):
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("home", encoding="utf-8")
    engine = DefenseEngine(orch, backup_root=tmp_path / "bk")
    engine.watch_path("web", web, protected=())

    incident_events = []
    orch.events.subscribe(
        "defense.incident", lambda e: incident_events.append(e.payload) or _noop()
    )

    # Opponent drops a webshell.
    (web / "shell.php").write_text("<?php ?>", encoding="utf-8")
    incidents = await engine.sweep(log_text="GET /shell.php?c=id 200\nUser-Agent: nikto")

    kinds = {i.kind for i in incidents}
    assert "integrity_drift" in kinds
    assert "log_ioc" in kinds
    assert incident_events  # operator alerted


async def test_sweep_clean_no_incident(tmp_path, orch):
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("home", encoding="utf-8")
    engine = DefenseEngine(orch, backup_root=tmp_path / "bk")
    engine.watch_path("web", web)
    incidents = await engine.sweep(log_text="GET /index.html 200")
    assert incidents == []


async def _noop():
    return None
