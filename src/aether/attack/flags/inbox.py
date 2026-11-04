"""The manual Flag Inbox — AETHER's single source of truth for discovered flags.

CRITICAL RULES (blueprint §"MANUAL FLAG SUBMISSION"):
- AETHER NEVER automatically submits flags. The operator (Stev) submits.
- Every flag is stored PENDING until the operator explicitly marks it submitted.
- Flags are deduplicated.
- Flags are validated; valid / unverified / invalid / duplicate are clearly separated.
- Flag values are registered with the logger for redaction so they never leak into
  ordinary logs.
- A flag is only ingested from a genuine execution result — callers pass real extracted
  values; the inbox never fabricates.

The inbox is backed by the StateManager (sqlite) so flags persist across restarts and the
dedup set survives. A notification callback/event fires immediately on a newly-accepted flag.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ...core.event_bus import Event, EventBus
from ...core.logger import get_logger, register_secret
from ...core.models import Flag, FlagValidation, SubmissionStatus
from ...core.state_manager import StateManager
from .validator import FlagValidator

log = get_logger("flag_inbox")

Notifier = Callable[[Flag], Awaitable[None]]


@dataclass
class IngestOutcome:
    flag: Flag
    accepted: bool  # True if newly stored (not a duplicate)
    duplicate: bool
    validation: FlagValidation
    seen_count: int


class FlagInbox:
    def __init__(
        self,
        state: StateManager,
        validator: FlagValidator,
        events: EventBus | None = None,
    ) -> None:
        self._state = state
        self._validator = validator
        self._events = events
        self._notifiers: list[Notifier] = []

    def on_flag(self, notifier: Notifier) -> None:
        """Register a real-time notifier invoked for each newly-accepted flag."""
        self._notifiers.append(notifier)

    async def ingest(self, flag: Flag) -> IngestOutcome:
        """Validate, dedup, persist, redact, and notify. Never submits."""
        # 1. Validate (sets validation status; never fabricates VALIDATED).
        flag.validation = self._validator.validate(flag.value)
        # 2. Safety: submission always starts PENDING, regardless of caller.
        flag.submission = SubmissionStatus.PENDING

        # 3. Redact the value from all logs immediately.
        register_secret(flag.value)

        # 4. Deduplicate + persist.
        is_new, seen_count = await self._state.upsert_flag(flag)
        flag.duplicate = not is_new

        outcome = IngestOutcome(
            flag=flag,
            accepted=is_new,
            duplicate=not is_new,
            validation=flag.validation,
            seen_count=seen_count,
        )

        # Log WITHOUT the value (redactor would catch it, but we don't log it at all).
        log.info(
            "flag ingested",
            extra={
                "ctx": {
                    "target": flag.target,
                    "service": flag.service,
                    "module": flag.module,
                    "validation": flag.validation.value,
                    "duplicate": flag.duplicate,
                    "seen_count": seen_count,
                }
            },
        )

        # 5. Notify immediately on a newly-accepted flag.
        if is_new:
            for n in self._notifiers:
                try:
                    await n(flag)
                except Exception:  # noqa: BLE001
                    log.exception("flag notifier failed")
            if self._events is not None:
                await self._events.publish(
                    Event(
                        "flag.detected",
                        payload={
                            "target": flag.target,
                            "service": flag.service,
                            "module": flag.module,
                            "validation": flag.validation.value,
                        },
                        source="flag_inbox",
                    )
                )
        return outcome

    async def ingest_many(self, flags: list[Flag]) -> list[IngestOutcome]:
        return [await self.ingest(f) for f in flags]

    async def list(self, validation: FlagValidation | None = None) -> list[dict]:
        return await self._state.list_flags(validation)

    async def pending(self) -> list[dict]:
        rows = await self._state.list_flags()
        return [r for r in rows if r["submission"] == SubmissionStatus.PENDING.value]

    async def mark_submitted(
        self, dedup_key: str, status: SubmissionStatus = SubmissionStatus.SUBMITTED
    ) -> bool:
        """Operator-only action. AETHER never calls this automatically."""
        if status == SubmissionStatus.PENDING:
            raise ValueError("cannot mark a flag back to PENDING via submission action")
        ok = await self._state.set_submission(dedup_key, status)
        if ok:
            log.info(
                "operator marked flag",
                extra={"ctx": {"dedup_key": dedup_key[:12] + "…", "status": status.value}},
            )
        return ok


def render_detection(flag: Flag) -> str:
    """Operator-facing CLI presentation for a detected flag (blueprint example format)."""
    dup = "  (DUPLICATE)" if flag.duplicate else ""
    return (
        "\n[FLAG DETECTED]\n"
        f"Target: {flag.target}\n"
        f"Service: {flag.service}\n"
        f"Module: {flag.module}\n"
        f"Tick: {flag.tick or '-'}\n"
        f"Status: {flag.validation.value}\n"
        f"Submission: {flag.submission.value}{dup}\n"
        "\n"
        f"FLAG: {flag.value}\n"
    )
