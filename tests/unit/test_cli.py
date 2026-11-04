"""CLI smoke/behaviour tests via Typer's CliRunner. No network, no real infra."""

import textwrap

from typer.testing import CliRunner

from aether.cli.main import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "AETHER" in r.stdout


def test_system_health_passes():
    r = runner.invoke(app, ["system", "health"])
    assert r.exit_code == 0
    assert "Python >= 3.12" in r.stdout
    assert "No-AI runtime" in r.stdout


def test_config_validate_fails_closed_on_placeholder(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            scope:
              enforce: true
              targets:
                - name: opp
                  host: CHANGEME
            """
        ),
        encoding="utf-8",
    )
    r = runner.invoke(app, ["config", "validate", "-c", str(cfg)])
    assert r.exit_code == 2
    assert "NOT READY" in r.stdout


def test_config_validate_ready(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            scope:
              enforce: true
              targets:
                - name: opp
                  host: 10.0.10.9
                  ports: [80]
            flags:
              pattern: "CTF\\\\{[^}]+\\\\}"
            scoring:
              tick_seconds: 60
            """
        ),
        encoding="utf-8",
    )
    r = runner.invoke(app, ["config", "validate", "-c", str(cfg)])
    assert r.exit_code == 0
    assert "READY" in r.stdout


def test_scope_show(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            scope:
              enforce: true
              targets:
                - name: opp
                  host: 10.0.10.9
                  ports: [80]
                  owner: opponent
            """
        ),
        encoding="utf-8",
    )
    r = runner.invoke(app, ["scope", "show", "-c", str(cfg)])
    assert r.exit_code == 0
    assert "10.0.10.9" in r.stdout


def test_modules_list_and_test_run():
    # At minimum these must not crash even if few modules exist.
    r1 = runner.invoke(app, ["modules", "list"])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["modules", "test"])
    assert r2.exit_code == 0
