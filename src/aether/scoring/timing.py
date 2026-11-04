"""Competition timing — tick/round synchronization.

The round/tick length is UNKNOWN until the briefing, so TickClock takes it as config.
It converts wall-clock time into a tick number and tells callers how long until the next
tick, so attack sweeps and flag re-collection can be aligned to the scoring cadence
(efficient polling, no wasteful spinning). If tick timing is not configured, the clock is
"unconfigured" and callers fall back to a fixed interval.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class TickInfo:
    tick: int
    seconds_into_tick: float
    seconds_to_next: float


class TickClock:
    def __init__(self, tick_seconds: int | None, epoch: float | None = None) -> None:
        """epoch is the unix time of tick 0's start; defaults to process start-ish (now)."""
        self._tick_seconds = tick_seconds
        self._epoch = epoch if epoch is not None else time.time()

    @property
    def configured(self) -> bool:
        return self._tick_seconds is not None and self._tick_seconds > 0

    def info(self, now: float | None = None) -> TickInfo | None:
        if not self.configured:
            return None
        now = now if now is not None else time.time()
        elapsed = max(0.0, now - self._epoch)
        ts = self._tick_seconds
        tick = int(elapsed // ts)
        into = elapsed - tick * ts
        return TickInfo(tick=tick, seconds_into_tick=round(into, 3),
                        seconds_to_next=round(ts - into, 3))

    def current_tick(self, now: float | None = None) -> int | None:
        info = self.info(now)
        return info.tick if info else None

    def tick_label(self, now: float | None = None) -> str | None:
        t = self.current_tick(now)
        return f"tick-{t}" if t is not None else None

    def seconds_to_next(self, now: float | None = None) -> float | None:
        info = self.info(now)
        return info.seconds_to_next if info else None
