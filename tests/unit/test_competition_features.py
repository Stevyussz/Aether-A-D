"""Tests for competition-readiness additions: TickInfoClient, PatchTemplates, CustomScriptPlugin."""

from __future__ import annotations

import textwrap

from aether.core.custom_script import CustomScriptPlugin, load_custom_scripts
from aether.core.models import TaskState
from aether.core.plugin import RunContext
from aether.core.scope_guard import ScopeGuard
from aether.defense.backup_manager import BackupManager
from aether.defense.patch_manager import PatchManager, PatchOutcome
from aether.defense.patch_templates import apply_regex_patch, harden_upload_dir
from aether.scoring.tick_info import TickInfoClient, extract_flag_ids


def test_extract_flag_ids_formats():
    # Format A: service -> host -> list
    fmt_a = {"flag_ids": {"web": {"10.60.1.1": ["user_a", "user_b"], "10.60.2.1": ["user_c"]}}}
    assert extract_flag_ids(fmt_a, host="10.60.1.1", service="web") == ["user_a", "user_b"]

    # Format B: host -> service -> list
    fmt_b = {"10.60.1.1": {"web": ["id_1", "id_2"]}}
    assert extract_flag_ids(fmt_b, host="10.60.1.1", service="web") == ["id_1", "id_2"]

    # Format C: flat list
    assert extract_flag_ids(["f1", "f2", "f1"]) == ["f1", "f2"]


async def test_tick_info_reads_local_file(tmp_path):
    # Organizers sometimes drop flag_ids as a local file instead of serving HTTP.
    import json
    f = tmp_path / "flag_ids.json"
    f.write_text(json.dumps({"web": {"10.60.1.1": ["acct_42", "acct_43"]}}), encoding="utf-8")
    client = TickInfoClient(str(f))
    assert await client.fetch_for("10.60.1.1", "web") == ["acct_42", "acct_43"]


async def test_tick_info_missing_file_is_safe(tmp_path):
    # A bad path must fail closed (empty), never crash the sweep.
    client = TickInfoClient(str(tmp_path / "does_not_exist.json"))
    assert await client.fetch_for("10.60.1.1", "web") == []


def test_tick_info_stores_auth_headers():
    # Private scoreboards gate the flag_id endpoint behind a team token.
    client = TickInfoClient("https://score.ctf/flag_ids", headers={"X-Team-Token": "abc123"})
    assert client.headers == {"X-Team-Token": "abc123"}
    assert client._is_http()
    assert not TickInfoClient("/mnt/flag_ids.json")._is_http()


async def test_harden_upload_dir_and_rollback(tmp_path):
    backups = BackupManager(tmp_path / "backups")
    patcher = PatchManager(backups)
    up_dir = tmp_path / "uploads"
    up_dir.mkdir()

    async def ok_check():
        return True, "service healthy"

    res = await harden_upload_dir(patcher, up_dir, ok_check)
    assert res.outcome == PatchOutcome.COMMITTED
    assert (up_dir / ".htaccess").is_file()

    # Rollback test: if functional check fails, newly added .htaccess is removed by exact restore.
    up_dir2 = tmp_path / "uploads2"
    up_dir2.mkdir()

    async def fail_check():
        return False, "service down"

    res2 = await harden_upload_dir(patcher, up_dir2, fail_check)
    assert res2.outcome == PatchOutcome.ROLLED_BACK
    assert not (up_dir2 / ".htaccess").exists()


async def test_apply_regex_patch(tmp_path):
    backups = BackupManager(tmp_path / "backups")
    patcher = PatchManager(backups)
    src = tmp_path / "app.py"
    src.write_text("DEBUG = True\n", encoding="utf-8")

    async def ok_check():
        return True, "ok"

    res = await apply_regex_patch(
        patcher, src, r"DEBUG\s*=\s*True", "DEBUG = False", ok_check, label="disable-debug"
    )
    assert res.outcome == PatchOutcome.COMMITTED
    assert "DEBUG = False" in src.read_text(encoding="utf-8")


async def test_custom_script_loader_and_runner(tmp_path):
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    (custom_dir / "example_template.py").write_text("# ignored", encoding="utf-8")
    script = custom_dir / "svc_check.py"
    script.write_text(
        textwrap.dedent(
            """
            async def check_target(host, port, flag_ids, client):
                return [f"checked {host}:{port} ids={','.join(flag_ids)} IONIC{{custom_ok}}"]
            """
        ),
        encoding="utf-8",
    )

    plugins = load_custom_scripts(custom_dir)
    assert len(plugins) == 1
    plugin: CustomScriptPlugin = plugins[0]
    guard = ScopeGuard(enforce=True)
    guard.allow("127.0.0.1", ports=(8080,))

    res = await plugin.run(
        RunContext(
            target_host="127.0.0.1",
            target_port=8080,
            service="web",
            scope=guard,
            extra={"flag_ids": ["u1", "u2"]},
        )
    )
    assert res.state == TaskState.SUCCEEDED
    assert "IONIC{custom_ok}" in res.data["responses"]["out_0"]
