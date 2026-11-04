"""End-to-end: lab web service -> exploit -> extract -> verify -> MANUAL inbox.

Acceptance criterion: valid lab flags appear in the manual inbox immediately after
validation, as PENDING, deduplicated, with no automatic submission.
"""

import sys
from pathlib import Path

import pytest

# Make the lab package importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from flag_service import LabWebService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.lab_http_flag import LabHttpFlagExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.recon.port_scan import PortScanModule  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig,
    EngineConfig,
    FlagConfig,
    ScopeConfig,
)
from aether.core.models import FlagValidation, SubmissionStatus, Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

LAB_FLAG = "CTF{lab_end_to_end_flag}"
PATTERN = r"CTF\{[^}]+\}"


@pytest.fixture
def lab_service():
    svc = LabWebService(LAB_FLAG, host="127.0.0.1", port=0).start()
    yield svc
    svc.stop()


@pytest.fixture
async def attack_setup(tmp_path, lab_service):
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None),
        scope=ScopeConfig(
            enforce=True,
            targets=[Target(name="lab", host="127.0.0.1", ports=(lab_service.port,),
                            kind="web", owner="opponent")],
        ),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
    engine = AttackEngine(orch, inbox)
    yield engine, inbox, orch, lab_service
    await orch.shutdown()


async def test_lab_flag_reaches_inbox_validated_and_pending(attack_setup):
    engine, inbox, orch, lab = attack_setup

    flag_events = []
    orch.events.subscribe("flag.detected", lambda e: flag_events.append(e.payload) or _noop())

    run = await engine.run_exploit(
        LabHttpFlagExploit(),
        RunContext(target_host="127.0.0.1", target_port=lab.port, service="web"),
    )
    assert run.confirmed
    assert run.verification.validated_flags == 1

    flags = await inbox.list()
    assert len(flags) == 1
    assert flags[0]["value"] == LAB_FLAG
    assert flags[0]["validation"] == FlagValidation.VALIDATED.value
    assert flags[0]["submission"] == SubmissionStatus.PENDING.value  # NOT auto-submitted
    assert flag_events  # operator notified immediately


async def test_rerun_is_deduplicated(attack_setup):
    engine, inbox, orch, lab = attack_setup
    ctx = RunContext(target_host="127.0.0.1", target_port=lab.port, service="web")
    await engine.run_exploit(LabHttpFlagExploit(), ctx)
    await engine.run_exploit(LabHttpFlagExploit(), ctx)
    flags = await inbox.list()
    assert len(flags) == 1
    assert flags[0]["seen_count"] == 2


async def test_out_of_scope_exploit_blocked(attack_setup):
    engine, inbox, orch, lab = attack_setup
    # 8.8.8.8 is not in scope -> orchestrator blocks before any request.
    run = await engine.run_exploit(
        LabHttpFlagExploit(),
        RunContext(target_host="8.8.8.8", target_port=lab.port, service="web"),
    )
    assert not run.confirmed
    assert await inbox.list() == []


async def test_recon_portscan_finds_lab_port(attack_setup):
    engine, inbox, orch, lab = attack_setup
    res = await engine.recon(
        PortScanModule(),
        RunContext(target_host="127.0.0.1", service="web",
                   extra={"ports": [lab.port], "port_timeout": 1.0}),
    )
    assert res.ok
    open_ports = [p["port"] for p in res.data["open_ports"]]
    assert lab.port in open_ports


async def _noop():
    return None
