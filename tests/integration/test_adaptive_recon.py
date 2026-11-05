"""Prove adaptive recon makes the sweep smarter.

The lab app hides its flag behind a non-standard endpoint + parameter that appear in NO
static wordlist. A blind sweep must miss it; a recon-driven sweep must crawl, discover the
surface, and land the flag. Also checks the crawler reports the discovered endpoint/param.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from adaptive_app import AdaptiveLabService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.recon.web_crawl import WebCrawlModule  # noqa: E402
from aether.attack.sweep import AttackSweep  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

FLAG = "IONIC{adaptive_recon_only}"
PATTERN = r"IONIC\{[^}]+\}"


async def _engine(tmp_path, port):
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


async def test_crawler_discovers_hidden_surface(tmp_path):
    svc = AdaptiveLabService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port)
        try:
            res = await engine.recon(
                WebCrawlModule(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
            )
            assert res.ok
            assert "/secret_corner.php" in res.data["endpoints"]
            assert "weird_param" in res.data["params"]
            # form fields discovered too
            assert "odd_user" in res.data["params"]
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_blind_sweep_misses_recon_sweep_lands(tmp_path):
    svc = AdaptiveLabService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port)
        try:
            sweep = AttackSweep(engine)
            # Blind: static wordlists don't know the endpoint/param -> no flag.
            blind = await sweep.run(
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
                recon=False,
            )
            assert not blind.any_flag

            # Smart: crawl first, then aim -> flag found.
            smart = await sweep.run(
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
                recon=True,
            )
            assert smart.any_flag
            assert FLAG in smart.flags_found
            assert "/secret_corner.php" in smart.discovered_endpoints
        finally:
            await orch.shutdown()
    finally:
        svc.stop()
