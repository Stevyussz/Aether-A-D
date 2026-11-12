"""End-to-end training & verification against Community A&D Vulnbox archetypes.

Tests AETHER's AttackSweep, flag_id integration, and Defense ShieldProxy against the
5 community A&D web archetypes plus custom TCP flag_id vault.
"""

from __future__ import annotations

import http.client
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from community_vulnbox import CommunityVulnboxService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.web_ad_community import AdCommunityVulnboxExploit  # noqa: E402
from aether.attack.exploits.web_idor import IdorExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.sweep import AttackSweep  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig,
    EngineConfig,
    FlagConfig,
    ScopeConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402
from aether.defense.shield_proxy import ShieldProxy  # noqa: E402

PATTERN = r"IONIC\{[^}]+\}"


def _make_orch(tmp_path: Path, port: int) -> Orchestrator:
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / f"state_{port}.db"), log_file=None),
        scope=ScopeConfig(
            enforce=True,
            targets=[Target(name="vulnbox", host="127.0.0.1", ports=(port,), kind="web", owner="opponent")],
        ),
        flags=FlagConfig(pattern=PATTERN, auto_submit=False),
    )
    return Orchestrator(cfg)


@pytest.mark.parametrize(
    "mode,expected_flag,flag_id",
    [
        ("paste_note_idor", "IONIC{paste_note_flag_id_991a}", "note-uuid-991a"),
        ("gateway_header_bypass", "IONIC{gateway_xff_bypass_2026}", "item-1"),
        ("portal_cookie_forge", "IONIC{cookie_b64_admin_forged}", "item-2"),
        ("config_proto_pollution", "IONIC{proto_pollution_merged}", "item-3"),
        ("export_backup_leak", "IONIC{export_all_records_leak}", "item-4"),
    ],
)
async def test_community_vulnbox_archetypes_captured(
    tmp_path: Path, mode: str, expected_flag: str, flag_id: str
) -> None:
    svc = CommunityVulnboxService(mode=mode, flag=expected_flag, flag_id=flag_id).start()
    orch = _make_orch(tmp_path, svc.port)
    await orch.start()
    try:
        inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
        eng = AttackEngine(orch, inbox)
        sweep = AttackSweep(eng)
        plugins = [IdorExploit(), AdCommunityVulnboxExploit()]
        report = await sweep.run(
            RunContext(
                target_host="127.0.0.1",
                target_port=svc.port,
                service="web",
                extra={"flag_ids": [flag_id]},
            ),
            plugins=plugins,
            recon=False,
            login=False,
        )
        assert report.any_flag, f"Expected flag for {mode}, got 0 flags"
        assert expected_flag in report.flags_found
        pending = await inbox.pending()
        assert any(r["value"] == expected_flag for r in pending)
    finally:
        await orch.shutdown()
        svc.stop()


def test_shield_proxy_blocks_prototype_pollution_and_header_spoof() -> None:
    svc = CommunityVulnboxService(
        mode="config_proto_pollution",
        flag="IONIC{protected_by_shield}",
    ).start()
    shield = ShieldProxy("127.0.0.1", 0, "127.0.0.1", svc.port, enabled=True)
    sport = shield.start()
    try:
        # 1. Attempt prototype pollution through ShieldProxy -> blocked with 403
        conn = http.client.HTTPConnection("127.0.0.1", sport, timeout=5)
        conn.request(
            "POST",
            "/api/merge",
            body='{"__proto__": {"isAdmin": true}}',
            headers={"Content-Type": "application/json"},
        )
        r1 = conn.getresponse()
        assert r1.status == 403
        r1.read()
        conn.close()

        # 2. Attempt X-Original-URL header spoofing through ShieldProxy -> blocked with 403
        conn = http.client.HTTPConnection("127.0.0.1", sport, timeout=5)
        conn.request("GET", "/", headers={"X-Original-URL": "/internal/flags"})
        r2 = conn.getresponse()
        assert r2.status == 403
        r2.read()
        conn.close()

        # Verify backend remained unpolluted
        assert svc.polluted_admin is False
        assert shield.status().blocked_requests == 2
    finally:
        shield.stop()
        svc.stop()
