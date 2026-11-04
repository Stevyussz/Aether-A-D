"""Failure simulation: network interruptions, service crashes, exploit failures,
invalid flags, patch failures, rollback failures, database interruptions."""

import asyncio

import pytest

from aether.adapters.web import WebAdapter
from aether.core.models import ModuleResult, TaskState
from aether.core.scope_guard import ScopeGuard
from aether.core.state_manager import StateManager
from aether.defense.backup_manager import BackupManager
from aether.defense.patch_manager import PatchManager, PatchOutcome
from aether.defense.service_monitor import ServiceHealthMonitor


async def test_network_interruption_handled():
    scope = ScopeGuard(enforce=True)
    scope.allow("127.0.0.1")
    async with WebAdapter(scope=scope, timeout=0.3) as web:
        # Nothing listening on this port -> connection refused, surfaced as exception.
        with pytest.raises(Exception):
            await web.get("http://127.0.0.1:1/")  # port 1 almost certainly closed


async def test_service_crash_detected():
    hm = ServiceHealthMonitor()

    async def crashed():
        raise ConnectionRefusedError("connection refused")

    hm.register("web", crashed)
    results = await hm.check_all()
    assert not results[0].up
    assert "refused" in results[0].detail.lower()


async def test_exploit_failure_produces_no_flag():
    # A module reporting FAILED must not be treated as a success anywhere.
    res = ModuleResult(module="exploit.x", state=TaskState.FAILED, detail="target unreachable")
    assert not res.ok
    assert res.flags == []


async def test_patch_failure_rolls_back(tmp_path):
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "app").write_text("good", encoding="utf-8")
    bm = BackupManager(tmp_path / "bk")
    pm = PatchManager(bm)

    async def apply():
        (svc / "app").write_text("broken", encoding="utf-8")
        return True, "applied"

    async def functional():
        return (svc / "app").read_text() == "good", "content changed"

    res = await pm.apply("p", svc, apply=apply, functional_test=functional)
    assert res.outcome == PatchOutcome.ROLLED_BACK
    assert (svc / "app").read_text() == "good"  # restored


async def test_rollback_failure_is_reported_not_hidden(tmp_path):
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "app").write_text("good", encoding="utf-8")
    bm = BackupManager(tmp_path / "bk")
    pm = PatchManager(bm)

    async def apply():
        return False, "apply failed"  # triggers rollback

    async def functional():
        return True, "ok"

    # Break restore so rollback itself fails -> must surface ROLLBACK_FAILED, not silent.
    def boom_restore(*a, **k):
        raise OSError("disk gone")

    bm.restore = boom_restore  # type: ignore[assignment]
    res = await pm.apply("p", svc, apply=apply, functional_test=functional)
    assert res.outcome == PatchOutcome.ROLLBACK_FAILED
    assert not res.safe
    assert "ROLLBACK FAILED" in res.detail


async def test_invalid_flag_does_not_verify():
    from aether.attack.flags.validator import FlagValidator
    from aether.attack.verification.verifier import ExploitVerifier
    from aether.core.models import Flag

    v = ExploitVerifier(FlagValidator(r"CTF\{[^}]+\}"))
    res = ModuleResult(module="m", state=TaskState.SUCCEEDED,
                       flags=[Flag(value="not-a-real-flag", target="t")])
    assert not v.verify(res).verified


async def test_database_interruption_raises_cleanly(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    await sm.close()
    # Using it after close must raise a clear error, not corrupt silently.
    with pytest.raises(RuntimeError, match="not open"):
        await sm.get("x")
