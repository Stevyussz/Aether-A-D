"""Prove the 'attack the server' capability: once web RCE lands, AETHER reads the flag off
the SERVER filesystem — the A&D / HTB / THM / VulnHub convention where the flag is NOT in
the HTTP response but at /root/root.txt, /home/*/user.txt, or anywhere `grep <prefix>` finds.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from vuln_service import VulnLabService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits._server_flags import (  # noqa: E402
    literal_prefix, read_commands, shell_payloads, ssti_payloads,
)
from aether.attack.exploits.web_command_injection import CommandInjectionExploit  # noqa: E402
from aether.attack.exploits.web_ssti import SstiExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import Target, TaskState  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

PATTERN = r"IONIC\{[^}]+\}"
# A flag at a server path, NOT a plain /flag.txt — only reachable by reading the server FS.
FLAG = "IONIC{ngepwn_server_lalu_baca_root_txt}"


def test_literal_prefix_derives_grep_token():
    assert literal_prefix(r"IONIC\{[^}]+\}") == "IONIC{"
    assert literal_prefix(r"FLAG\{.*\}") == "FLAG{"
    assert literal_prefix(r"flag_[0-9a-f]+") == "flag_"
    assert literal_prefix(None) is None
    assert literal_prefix(r"[a-z]+") is None  # nothing literal leads it


def test_payloads_hunt_the_server_filesystem():
    # With the prefix known, the FIRST command both cats the conventional root-level flag files
    # (e.g. /flag.txt — NOT under the recursive roots) AND greps the bounded roots, so a single
    # one-shot RCE (SSTI/upload/shellshock) never misses either placement.
    cmds = read_commands("IONIC{")
    assert cmds[0].startswith("cat ") and "/flag.txt" in cmds[0]
    assert "grep -rsho" in cmds[0] and "IONIC" in cmds[0]
    assert '"' not in cmds[0]                                        # stays double-quote safe
    assert any("/root" in c and "root.txt" in c for c in cmds)       # conventional file
    assert any("user.txt" in c for c in cmds)                        # home flag
    # Shell payloads wrap the grep through real separators, and still cat known files.
    shells = shell_payloads("IONIC{")
    assert any("grep" in p and "IONIC" in p for p in shells)
    assert any("/root/root.txt" in p for p in shells)
    # SSTI payloads keep the detection marker and add RCE reads.
    sstis = ssti_payloads("IONIC{")
    assert "{{7*7}}" in sstis
    assert any("popen" in p and "grep" in p for p in sstis)


async def _engine(tmp_path, port, enabled):
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None, log_level="ERROR"),
        scope=ScopeConfig(enforce=True, targets=[
            Target(name="lab", host="127.0.0.1", ports=(port,), kind="web", owner="opponent"),
        ]),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
    return orch, inbox, AttackEngine(orch, inbox)


async def test_command_injection_reads_server_flag(tmp_path):
    svc = VulnLabService(FLAG, port=0, enabled=frozenset({"command_injection"})).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, {"command_injection"})
        ctx = RunContext(target_host="127.0.0.1", target_port=svc.port, service="web")
        run = await engine.run_exploit(CommandInjectionExploit(), ctx)

        assert run.result.state == TaskState.SUCCEEDED
        # The engine injected the grep token so the module hunts the filesystem.
        assert ctx.extra.get("flag_grep") == "IONIC{"
        # A recursive-grep probe was genuinely SENT (not just configured).
        assert any("grep" in label for label in run.result.data["responses"])
        # The real flag came back and landed in the manual inbox.
        assert FLAG in run.result.flags[0].value or any(f.value == FLAG for f in run.result.flags)
        assert run.confirmed
    finally:
        svc.stop()
        await orch.shutdown()


async def test_ssti_reads_server_flag(tmp_path):
    svc = VulnLabService(FLAG, port=0, enabled=frozenset({"ssti"})).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, {"ssti"})
        ctx = RunContext(target_host="127.0.0.1", target_port=svc.port, service="web")
        run = await engine.run_exploit(SstiExploit(), ctx)
        assert run.result.state == TaskState.SUCCEEDED
        assert any(f.value == FLAG for f in run.result.flags)
        assert run.confirmed
    finally:
        svc.stop()
        await orch.shutdown()
