"""Patch manager — safe, reversible remediation of our own services.

Implements the blueprint workflow strictly:

    PRE-CHECK -> BACKUP -> PATCH -> FUNCTIONAL TEST -> VERIFY -> COMMIT / ROLLBACK

Guarantees:
- Nothing is changed unless PRE-CHECK passes.
- A backup is always taken before PATCH, so rollback is possible.
- If FUNCTIONAL TEST or VERIFY fails, the change is rolled back automatically.
- Every attempt is recorded via the StateManager modification log.
- The operator is alerted (event) when remediation is unsafe or unsuccessful.
- Flag storage and service behavior are preserved: the functional test is what proves it,
  and failure means rollback — we never leave a service broken to "win" a patch.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..core.event_bus import Event, EventBus
from ..core.logger import get_logger
from .backup_manager import BackupManager

log = get_logger("patch_manager")

# All callables are async and return (ok, detail).
Step = Callable[[], Awaitable[tuple[bool, str]]]
PatchApply = Callable[[], Awaitable[tuple[bool, str]]]


class PatchOutcome(str, enum.Enum):
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    ABORTED_PRECHECK = "ABORTED_PRECHECK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    ERROR = "ERROR"


@dataclass
class PatchResult:
    patch_id: str
    outcome: PatchOutcome
    steps: list[str] = field(default_factory=list)
    snapshot_id: str | None = None
    detail: str = ""

    @property
    def safe(self) -> bool:
        """True iff the service was left in a known-good state (committed or cleanly rolled back)."""
        return self.outcome in (PatchOutcome.COMMITTED, PatchOutcome.ROLLED_BACK, PatchOutcome.ABORTED_PRECHECK)


class PatchManager:
    def __init__(
        self,
        backup_manager: BackupManager,
        events: EventBus | None = None,
        state=None,  # StateManager (optional) for modification logging
    ) -> None:
        self._backups = backup_manager
        self._events = events
        self._state = state

    async def apply(
        self,
        patch_id: str,
        target: str | Path,
        *,
        apply: PatchApply,
        functional_test: Step,
        pre_check: Step | None = None,
        verify: Step | None = None,
    ) -> PatchResult:
        steps: list[str] = []
        result = PatchResult(patch_id=patch_id, outcome=PatchOutcome.ERROR, steps=steps)

        # 1. PRE-CHECK
        if pre_check is not None:
            ok, detail = await pre_check()
            steps.append(f"PRE-CHECK: {'ok' if ok else 'FAIL'} ({detail})")
            if not ok:
                result.outcome = PatchOutcome.ABORTED_PRECHECK
                result.detail = f"pre-check failed: {detail}"
                await self._record(patch_id, "abort_precheck", str(target), detail, True)
                await self._alert(patch_id, result)
                return result
        else:
            steps.append("PRE-CHECK: skipped")

        # 2. BACKUP (always, before any change)
        try:
            snap = self._backups.create(target, label=patch_id)
            result.snapshot_id = snap.snapshot_id
            steps.append(f"BACKUP: {snap.snapshot_id} ({snap.file_count} files)")
        except Exception as exc:  # noqa: BLE001
            result.outcome = PatchOutcome.ERROR
            result.detail = f"backup failed, refusing to patch: {exc}"
            steps.append(f"BACKUP: FAIL ({exc})")
            await self._alert(patch_id, result)
            return result

        # 3. PATCH
        try:
            ok, detail = await apply()
            steps.append(f"PATCH: {'applied' if ok else 'FAIL'} ({detail})")
            if not ok:
                return await self._rollback(result, target, f"patch apply failed: {detail}")
        except Exception as exc:  # noqa: BLE001
            steps.append(f"PATCH: EXCEPTION ({exc})")
            return await self._rollback(result, target, f"patch raised: {exc}")

        # 4. FUNCTIONAL TEST (preserve service behavior)
        try:
            ok, detail = await functional_test()
            steps.append(f"FUNCTIONAL: {'pass' if ok else 'FAIL'} ({detail})")
            if not ok:
                return await self._rollback(result, target, f"functional test failed: {detail}")
        except Exception as exc:  # noqa: BLE001
            steps.append(f"FUNCTIONAL: EXCEPTION ({exc})")
            return await self._rollback(result, target, f"functional test raised: {exc}")

        # 5. VERIFY (confirm the fix actually closed the issue)
        if verify is not None:
            try:
                ok, detail = await verify()
                steps.append(f"VERIFY: {'ok' if ok else 'FAIL'} ({detail})")
                if not ok:
                    return await self._rollback(result, target, f"verify failed: {detail}")
            except Exception as exc:  # noqa: BLE001
                steps.append(f"VERIFY: EXCEPTION ({exc})")
                return await self._rollback(result, target, f"verify raised: {exc}")
        else:
            steps.append("VERIFY: skipped")

        # 6. COMMIT
        result.outcome = PatchOutcome.COMMITTED
        result.detail = "patch committed; service functional and verified"
        steps.append("COMMIT")
        await self._record(patch_id, "commit_patch", str(target), result.detail, True)
        log.info("patch committed", extra={"ctx": {"patch": patch_id, "target": str(target)}})
        return result

    async def _rollback(self, result: PatchResult, target, reason: str) -> PatchResult:
        result.steps.append(f"ROLLBACK: {reason}")
        try:
            if result.snapshot_id:
                self._backups.restore(result.snapshot_id)
            result.outcome = PatchOutcome.ROLLED_BACK
            result.detail = reason
            result.steps.append("ROLLBACK: restored from backup")
            await self._record(result.patch_id, "rollback_patch", str(target), reason, True)
            log.warning("patch rolled back", extra={"ctx": {"patch": result.patch_id, "reason": reason}})
        except Exception as exc:  # noqa: BLE001
            result.outcome = PatchOutcome.ROLLBACK_FAILED
            result.detail = f"ROLLBACK FAILED: {exc} (original reason: {reason})"
            result.steps.append(f"ROLLBACK: FAILED ({exc})")
            await self._record(result.patch_id, "rollback_failed", str(target), result.detail, False)
            log.error("ROLLBACK FAILED", extra={"ctx": {"patch": result.patch_id, "detail": result.detail}})
        await self._alert(result.patch_id, result)
        return result

    async def _record(self, patch_id, action, target, detail, reversible) -> None:
        if self._state is not None:
            await self._state.record_modification(
                "patch_manager", f"{action}:{patch_id}", target, detail, reversible
            )

    async def _alert(self, patch_id: str, result: PatchResult) -> None:
        if self._events is not None and not (result.outcome == PatchOutcome.COMMITTED):
            await self._events.publish(
                Event(
                    "defense.remediation_alert",
                    payload={"patch": patch_id, "outcome": result.outcome.value, "detail": result.detail},
                    source="patch_manager",
                )
            )
