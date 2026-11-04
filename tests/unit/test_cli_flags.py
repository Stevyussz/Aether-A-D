"""CLI flag-inbox commands, exercised against a real sqlite state seeded with a flag."""

import textwrap

import asyncio

import pytest
from typer.testing import CliRunner

from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.cli.main import app
from aether.core.models import Flag
from aether.core.state_manager import StateManager

runner = CliRunner()
PATTERN = r"CTF\{[^}]+\}"


@pytest.fixture
def cfg_file(tmp_path):
    db = tmp_path / "state.sqlite"
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        textwrap.dedent(
            f"""
            engine:
              state_db: {db}
              log_file: null
            scope:
              enforce: true
              targets:
                - name: opp
                  host: 10.0.10.9
                  ports: [80]
                  owner: opponent
            flags:
              pattern: "CTF\\\\{{[^}}]+\\\\}}"
            """
        ),
        encoding="utf-8",
    )
    return cfg, db


async def _seed(db):
    sm = StateManager(db)
    await sm.open()
    inbox = FlagInbox(sm, FlagValidator(PATTERN))
    await inbox.ingest(Flag(value="CTF{seeded}", target="10.0.10.9", service="web", module="m"))
    key = Flag(value="CTF{seeded}", target="10.0.10.9", service="web", module="m").dedup_key()
    await sm.close()
    return key


def test_inbox_lists_pending(cfg_file):
    cfg, db = cfg_file
    asyncio.run(_seed(db))
    r = runner.invoke(app, ["flags", "inbox", "-c", str(cfg)])
    assert r.exit_code == 0
    assert "PENDING" in r.stdout
    assert "CTF{seeded}" not in r.stdout  # hidden by default


def test_inbox_show_values(cfg_file):
    cfg, db = cfg_file
    asyncio.run(_seed(db))
    r = runner.invoke(app, ["flags", "inbox", "-c", str(cfg), "--show-values"],
                      env={"COLUMNS": "250"})
    assert r.exit_code == 0
    assert "CTF{seeded}" in r.stdout


def test_copy_prints_bare_value(cfg_file):
    cfg, db = cfg_file
    key = asyncio.run(_seed(db))
    r = runner.invoke(app, ["flags", "copy", key[:10], "-c", str(cfg)])
    assert r.exit_code == 0
    assert r.stdout.strip() == "CTF{seeded}"


def test_mark_submitted_moves_out_of_pending(cfg_file):
    cfg, db = cfg_file
    key = asyncio.run(_seed(db))
    r = runner.invoke(app, ["flags", "mark-submitted", key[:10], "-c", str(cfg)])
    assert r.exit_code == 0
    assert "SUBMITTED" in r.stdout
    r2 = runner.invoke(app, ["flags", "inbox", "-c", str(cfg)])
    assert "(none)" in r2.stdout


def test_mark_pending_rejected(cfg_file):
    cfg, db = cfg_file
    key = asyncio.run(_seed(db))
    r = runner.invoke(app, ["flags", "mark-submitted", key[:10], "--status", "PENDING", "-c", str(cfg)])
    assert r.exit_code == 1


def test_attack_status(cfg_file):
    cfg, _ = cfg_file
    r = runner.invoke(app, ["attack", "status", "-c", str(cfg)])
    assert r.exit_code == 0
    assert "exploit modules" in r.stdout
