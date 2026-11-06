"""Interactive control menu: renders the home banner and dispatches to real commands."""

from typer.testing import CliRunner

from aether.cli.main import app

runner = CliRunner()


def test_bare_invocation_launches_menu_and_exits():
    # No subcommand -> interactive console; "0" exits cleanly.
    r = runner.invoke(app, [], input="0\n", env={"COLUMNS": "100"})
    assert r.exit_code == 0
    assert "AETHER control menu" in r.output
    assert "Attack & Defense CTF framework" in r.output


def test_menu_command_runs_system_health_then_exits():
    # Select 1 (system health), press Enter to continue, then 0 to exit.
    r = runner.invoke(app, ["menu"], input="1\n\n0\n", env={"COLUMNS": "100"})
    assert r.exit_code == 0
    assert "AETHER system health" in r.output
    assert "No-AI runtime" in r.output


def test_menu_cancel_flag_copy_without_key():
    # Option 7 (copy) with an empty key cancels without error.
    r = runner.invoke(app, ["menu"], input="7\n\n0\n", env={"COLUMNS": "100"})
    assert r.exit_code == 0
    assert "cancelled" in r.output
