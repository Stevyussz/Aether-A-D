"""Patch workflow: PRE-CHECK -> BACKUP -> PATCH -> FUNCTIONAL -> VERIFY -> COMMIT/ROLLBACK."""

import pytest

from aether.core.event_bus import EventBus, Event
from aether.defense.backup_manager import BackupManager
from aether.defense.patch_manager import PatchManager, PatchOutcome
from aether.defense.recovery_manager import RecoveryManager


@pytest.fixture
def vuln_service(tmp_path):
    """A service dir with a vulnerable file we will patch."""
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "app.py").write_text("VULNERABLE = True\n", encoding="utf-8")
    (svc / "flags.db").write_text("flag-store-intact", encoding="utf-8")
    return svc


async def test_successful_patch_commits(tmp_path, vuln_service):
    bm = BackupManager(tmp_path / "backups")
    pm = PatchManager(bm)
    app = vuln_service / "app.py"

    async def pre_check():
        return app.exists(), "target present"

    async def apply():
        app.write_text("VULNERABLE = False\n", encoding="utf-8")
        return True, "hardened"

    async def functional():
        # flag store preserved + service still has its file
        return (vuln_service / "flags.db").read_text() == "flag-store-intact", "flags intact"

    async def verify():
        return "VULNERABLE = False" in app.read_text(), "vuln closed"

    res = await pm.apply("harden-1", vuln_service, apply=apply,
                         functional_test=functional, pre_check=pre_check, verify=verify)
    assert res.outcome == PatchOutcome.COMMITTED
    assert res.safe
    assert "VULNERABLE = False" in app.read_text()


async def test_failed_functional_test_rolls_back(tmp_path, vuln_service):
    bm = BackupManager(tmp_path / "backups")
    pm = PatchManager(bm)
    app = vuln_service / "app.py"
    original = app.read_text()

    async def apply():
        # A "patch" that breaks the service (deletes the flag store!).
        (vuln_service / "flags.db").unlink()
        app.write_text("BROKEN", encoding="utf-8")
        return True, "applied"

    async def functional():
        return (vuln_service / "flags.db").exists(), "flag store missing!"

    res = await pm.apply("bad-patch", vuln_service, apply=apply, functional_test=functional)
    assert res.outcome == PatchOutcome.ROLLED_BACK
    assert res.safe
    # Rollback restored both the app file AND the flag store.
    assert app.read_text() == original
    assert (vuln_service / "flags.db").read_text() == "flag-store-intact"


async def test_precheck_abort_touches_nothing(tmp_path, vuln_service):
    bm = BackupManager(tmp_path / "backups")
    pm = PatchManager(bm)
    app = vuln_service / "app.py"
    before = app.read_text()
    applied = False

    async def pre_check():
        return False, "service busy"

    async def apply():
        nonlocal applied
        applied = True
        return True, "x"

    async def functional():
        return True, "x"

    res = await pm.apply("p", vuln_service, apply=apply, functional_test=functional, pre_check=pre_check)
    assert res.outcome == PatchOutcome.ABORTED_PRECHECK
    assert not applied
    assert app.read_text() == before
    assert bm.list_snapshots() == []  # no backup taken either


async def test_remediation_alert_emitted_on_rollback(tmp_path, vuln_service):
    bus = EventBus()
    alerts = []

    async def on_alert(e: Event):
        alerts.append(e.payload)

    bus.subscribe("defense.remediation_alert", on_alert)
    bm = BackupManager(tmp_path / "backups")
    pm = PatchManager(bm, events=bus)

    async def apply():
        return False, "could not apply"

    async def functional():
        return True, "ok"

    res = await pm.apply("p", vuln_service, apply=apply, functional_test=functional)
    assert res.outcome == PatchOutcome.ROLLED_BACK
    assert alerts and alerts[0]["outcome"] == "ROLLED_BACK"


async def test_recovery_restores_snapshot(tmp_path, vuln_service):
    bm = BackupManager(tmp_path / "backups")
    snap = bm.create(vuln_service, label="good")
    rm = RecoveryManager(bm)

    # Simulate compromise: wipe the service.
    for p in vuln_service.iterdir():
        p.unlink()

    async def functional():
        return (vuln_service / "flags.db").exists(), "flags present"

    res = await rm.recover(snap.snapshot_id, functional_test=functional)
    assert res.succeeded
    assert (vuln_service / "flags.db").read_text() == "flag-store-intact"
