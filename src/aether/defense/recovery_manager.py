"""Recovery manager — restore known-good state after a confirmed compromise.

Coordinates BackupManager restores and re-verifies service functionality afterward. Unlike
the patch manager (which makes a forward change), recovery returns a service to a prior
snapshot. It is explicitly operator-gated for destructive restores: auto_restore defaults
to False, and a restore that leaves the service non-functional is reported, not hidden.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..core.event_bus import Event, EventBus
from ..core.logger import get_logger
from .backup_manager import BackupManager

log = get_logger("recovery_manager")

Step = Callable[[], Awaitable[tuple[bool, str]]]


@dataclass
class RecoveryResult:
    snapshot_id: str
    restored: bool
    functional: bool | None
    steps: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return self.restored and (self.functional is not False)


class RecoveryManager:
    def __init__(
        self,
        backup_manager: BackupManager,
        events: EventBus | None = None,
        state=None,
    ) -> None:
        self._backups = backup_manager
        self._events = events
        self._state = state

    async def recover(
        self,
        snapshot_id: str,
        *,
        functional_test: Step | None = None,
        dest=None,
    ) -> RecoveryResult:
        steps: list[str] = []
        result = RecoveryResult(snapshot_id=snapshot_id, restored=False, functional=None, steps=steps)

        if not self._backups.verify(snapshot_id):
            result.detail = "snapshot failed integrity verification; refusing to restore"
            steps.append("VERIFY-BACKUP: FAIL")
            await self._alert(result)
            return result
        steps.append("VERIFY-BACKUP: ok")

        try:
            self._backups.restore(snapshot_id, dest=dest)
            result.restored = True
            steps.append("RESTORE: ok")
        except Exception as exc:  # noqa: BLE001
            result.detail = f"restore failed: {exc}"
            steps.append(f"RESTORE: FAIL ({exc})")
            await self._alert(result)
            return result

        if functional_test is not None:
            ok, detail = await functional_test()
            result.functional = ok
            steps.append(f"FUNCTIONAL: {'pass' if ok else 'FAIL'} ({detail})")
            if not ok:
                result.detail = f"restored but service not functional: {detail}"
                await self._alert(result)

        if self._state is not None:
            await self._state.record_modification(
                "recovery_manager", f"restore:{snapshot_id}", str(dest or ""),
                result.detail or "restored", True
            )
        if result.succeeded:
            log.info("recovery succeeded", extra={"ctx": {"snapshot": snapshot_id}})
        return result

    async def _alert(self, result: RecoveryResult) -> None:
        if self._events is not None:
            await self._events.publish(
                Event(
                    "defense.recovery_alert",
                    payload={"snapshot": result.snapshot_id, "detail": result.detail},
                    source="recovery_manager",
                )
            )
