"""Scoring wiring: attack engine stamps the current tick onto discovered flags."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from flag_service import LabWebService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.lab_http_flag import LabHttpFlagExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig,
    EngineConfig,
    FlagConfig,
    ScopeConfig,
    ScoringConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

PATTERN = r"CTF\{[^}]+\}"


async def test_flag_stamped_with_tick(tmp_path):
    svc = LabWebService("CTF{tick_flag}", port=0).start()
    try:
        cfg = AetherConfig(
            engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None),
            scope=ScopeConfig(
                enforce=True,
                targets=[Target(name="lab", host="127.0.0.1", ports=(svc.port,),
                                kind="web", owner="opponent")],
            ),
            flags=FlagConfig(pattern=PATTERN),
            # tick 0 started 90s ago with 60s ticks -> we are in tick 1.
            scoring=ScoringConfig(tick_seconds=60, epoch=time.time() - 90),
        )
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            inbox = FlagInbox(orch.state, FlagValidator(PATTERN))
            engine = AttackEngine(orch, inbox)
            run = await engine.run_exploit(
                LabHttpFlagExploit(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
            )
            assert run.confirmed
            flags = await inbox.list()
            assert flags[0]["tick"] == "tick-1"
        finally:
            await orch.shutdown()
    finally:
        svc.stop()
