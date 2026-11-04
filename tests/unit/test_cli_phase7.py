"""CLI tests for report generate, lab test, monitor once/stop."""

import textwrap
from pathlib import Path

from typer.testing import CliRunner

from aether.cli.main import app

runner = CliRunner()


def _cfg(tmp_path, enforce=True):
    p = tmp_path / "c.yaml"
    p.write_text(
        textwrap.dedent(
            f"""
            engine:
              state_db: {tmp_path / 's.sqlite'}
              log_file: null
            scope:
              enforce: {str(enforce).lower()}
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
    return p


def test_report_generate_writes_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _cfg(tmp_path)
    r = runner.invoke(app, ["report", "generate", "-c", str(cfg)])
    assert r.exit_code == 0
    assert "report written" in r.stdout
    reports = list((tmp_path / "runtime" / "reports").glob("*.md"))
    assert reports
    text = reports[0].read_text()
    assert "AETHER A&D — Operator Report" in text
    assert "never auto-submits" in text


def test_lab_test_end_to_end():
    r = runner.invoke(app, ["lab", "test"])
    assert r.exit_code == 0
    assert "end-to-end pipeline OK" in r.stdout
    assert "Submission: PENDING" in r.stdout


def test_monitor_once_runs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _cfg(tmp_path)
    r = runner.invoke(app, ["monitor", "start", "-c", str(cfg), "--once"])
    assert r.exit_code == 0
    assert "sweep" in r.stdout


def test_monitor_stop_writes_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["monitor", "stop"])
    assert r.exit_code == 0
    assert (tmp_path / "runtime" / "monitor.stop").exists()
