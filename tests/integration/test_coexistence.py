"""Acceptance: attack and defense pipelines coexist under one orchestrator."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from flag_service import LabWebService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.lab_http_flag import LabHttpFlagExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.defense.engine import DefenseEngine  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig,
    EngineConfig,
    FlagConfig,
    ScopeConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

PATTERN = r"CTF\{[^}]+\}"


async def test_attack_and_defense_run_concurrently(tmp_path):
    import asyncio

    svc = LabWebService("CTF{coexist}", port=0).start()
    try:
        cfg = AetherConfig(
            engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None,
                                max_concurrency=4),
            scope=ScopeConfig(
                enforce=True,
                targets=[
                    Target(name="opp", host="127.0.0.1", ports=(svc.port,), kind="web",
                           owner="opponent"),
                ],
            ),
            flags=FlagConfig(pattern=PATTERN),
        )
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
            attack = AttackEngine(orch, inbox)
            defense = DefenseEngine(orch, backup_root=tmp_path / "bk")

            web_root = tmp_path / "ourweb"
            web_root.mkdir()
            (web_root / "index.html").write_text("home", encoding="utf-8")
            defense.watch_path("ourweb", web_root)

            # Opponent tampers with our service while we attack theirs — concurrently.
            async def defend():
                (web_root / "shell.php").write_text("<?php ?>", encoding="utf-8")
                return await defense.sweep(log_text="GET /shell.php?c=id 200")

            async def attack_run():
                return await attack.run_exploit(
                    LabHttpFlagExploit(),
                    RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
                )

            defend_res, attack_res = await asyncio.gather(defend(), attack_run())

            # Both sides produced results without interfering.
            assert attack_res.confirmed
            assert len(await inbox.list()) == 1
            assert any(i.kind == "integrity_drift" for i in defend_res)
        finally:
            await orch.shutdown()
    finally:
        svc.stop()
