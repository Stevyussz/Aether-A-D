"""Score history tracking and flag expiration.

- ScoreTracker records ScoreSnapshots over time (persisted via StateManager KV) and reports
  deltas, so the operator can see attack/defense/SLA trends.
- flag_is_expired() applies configurable expiration metadata (expiry in ticks) to decide
  whether a PENDING flag is likely stale and should be deprioritized — many A&D games only
  accept a flag within a few ticks of its capture.
"""

from __future__ import annotations

from dataclasses import asdict

from ..core.logger import get_logger
from ..core.state_manager import StateManager
from .scoreboard import ScoreSnapshot
from .timing import TickClock

log = get_logger("score_tracker")

_HISTORY_KEY = "scoring.history"


class ScoreTracker:
    def __init__(self, state: StateManager) -> None:
        self._state = state

    async def record(self, snap: ScoreSnapshot) -> None:
        history = await self._state.get(_HISTORY_KEY, []) or []
        import time

        entry = {"ts": time.time(), **{k: v for k, v in asdict(snap).items() if k != "raw"}}
        history.append(entry)
        # Keep bounded (last 500 snapshots) for bounded memory/storage.
        await self._state.set(_HISTORY_KEY, history[-500:])

    async def history(self) -> list[dict]:
        return await self._state.get(_HISTORY_KEY, []) or []

    async def latest(self) -> dict | None:
        h = await self.history()
        return h[-1] if h else None

    async def delta(self) -> dict | None:
        """Difference between the two most recent snapshots (attack/defense/sla)."""
        h = await self.history()
        if len(h) < 2:
            return None
        prev, cur = h[-2], h[-1]
        out = {}
        for k in ("attack_points", "defense_points", "sla_percent"):
            if cur.get(k) is not None and prev.get(k) is not None:
                out[k] = round(cur[k] - prev[k], 3)
        return out


def flag_is_expired(
    flag_tick: int | None,
    clock: TickClock,
    expiry_ticks: int | None,
    now: float | None = None,
) -> bool:
    """Return True if a flag captured at flag_tick is past its acceptance window.

    Fail safe: if we lack the information to decide (no tick timing, no expiry policy, or
    no recorded capture tick), we return False — we never mark a flag expired on a guess,
    because that could make the operator skip a still-valid flag.
    """
    if flag_tick is None or expiry_ticks is None or not clock.configured:
        return False
    current = clock.current_tick(now)
    if current is None:
        return False
    return (current - flag_tick) >= expiry_ticks
