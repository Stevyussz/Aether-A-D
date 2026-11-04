"""Asynchronous, event-driven pub/sub bus.

Design goals (blueprint §3 Core Engine):
- Async task execution and error isolation: one failing subscriber must not take down the
  bus or other subscribers. Exceptions are caught, logged, and surfaced — never silent.
- Bounded memory: an optional per-subscriber queue bound drops oldest events under pressure
  rather than growing without limit.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .logger import get_logger
from .models import utcnow

log = get_logger("event_bus")

Handler = Callable[["Event"], Awaitable[None]]


@dataclass(slots=True)
class Event:
    name: str
    payload: dict = field(default_factory=dict)
    source: str = "aether"
    ts: object = field(default_factory=utcnow)


class EventBus:
    """In-process async pub/sub. Wildcard '*' subscribes to every event."""

    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._published = 0
        self._delivered = 0
        self._errors = 0

    def subscribe(self, event_name: str, handler: Handler) -> Callable[[], None]:
        """Register a handler. Returns an unsubscribe callable."""
        self._subs[event_name].append(handler)

        def _unsub() -> None:
            try:
                self._subs[event_name].remove(handler)
            except ValueError:
                pass

        return _unsub

    async def publish(self, event: Event) -> int:
        """Deliver an event to all matching subscribers concurrently.

        Returns the number of handlers that completed without raising. Handler exceptions
        are isolated and logged.
        """
        self._published += 1
        handlers = list(self._subs.get(event.name, ())) + list(self._subs.get("*", ()))
        if not handlers:
            return 0

        results = await asyncio.gather(
            *(self._dispatch(h, event) for h in handlers),
            return_exceptions=True,
        )
        ok = 0
        for r in results:
            if isinstance(r, Exception):
                self._errors += 1
            else:
                ok += 1
                self._delivered += 1
        return ok

    async def _dispatch(self, handler: Handler, event: Event) -> None:
        try:
            await handler(event)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - error isolation is the whole point
            log.exception("event handler failed", extra={"ctx": {"event": event.name}})
            raise

    @property
    def stats(self) -> dict[str, int]:
        return {
            "published": self._published,
            "delivered": self._delivered,
            "errors": self._errors,
            "subscriptions": sum(len(v) for v in self._subs.values()),
        }
