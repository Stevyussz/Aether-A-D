"""CLI-level: `aether attack sweep` / `attack loop` against a vulnerable local lab.

Proves the operator-facing commands drive the arsenal, land a real flag in the inbox as
PENDING, and refuse out-of-scope targets (fail closed).
"""

import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from vuln_service import VulnLabService  # noqa: E402

from aether.cli.main import app  # noqa: E402

runner = CliRunner()
FLAG = "IONIC{cli_sweep_flag}"


@pytest.fixture
def lab():
    svc = VulnLabService(FLAG, port=0).start()
    yield svc
    svc.stop()


def _cfg(tmp_path, port, host="127.0.0.1"):
    db = tmp_path / "s.sqlite"
    cfg = tmp_path / "c.yaml"
    cfg.write_text(textwrap.dedent(f"""
        engine:
          state_db: {db}
          log_file: null
          log_level: ERROR
        scope:
          enforce: true
          targets:
            - name: opp
              host: {host}
              ports: [{port}]
              kind: web
              owner: opponent
        flags:
          pattern: "IONIC\\\\{{[^}}]+\\\\}}"
          auto_submit: false
        """), encoding="utf-8")
    return cfg


def test_cli_sweep_finds_flag(tmp_path, lab):
    cfg = _cfg(tmp_path, lab.port)
    r = runner.invoke(app, ["attack", "sweep", "127.0.0.1", "-c", str(cfg),
                            "--show-values", "--max-probes", "40"],
                      env={"COLUMNS": "250"})
    assert r.exit_code == 0, r.output
    assert "confirmed" in r.output
    assert FLAG in r.output
    assert "PENDING" in r.output


def test_cli_loop_once_finds_flag(tmp_path, lab):
    cfg = _cfg(tmp_path, lab.port)
    r = runner.invoke(app, ["attack", "loop", "127.0.0.1", "-c", str(cfg),
                            "--once", "--max-probes", "30"])
    assert r.exit_code == 0, r.output
    assert "round 1" in r.output
    assert "1 unique in inbox" in r.output


def test_cli_sweep_refuses_out_of_scope(tmp_path, lab):
    cfg = _cfg(tmp_path, lab.port)  # only 127.0.0.1 authorized
    r = runner.invoke(app, ["attack", "sweep", "8.8.8.8", "-c", str(cfg)])
    assert r.exit_code == 1
    assert "NOT in authorized scope" in r.output or "nothing authorized" in r.output
