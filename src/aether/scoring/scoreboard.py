"""Scoreboard integration — configurable, optional, fail-safe.

We never hardcode an assumed scoring system. The scoreboard endpoint and the function that
parses its response are both configurable. Until an operator supplies a parser matching the
official scoreboard, the client is "unconfigured" and returns None rather than inventing
numbers. Submission status is read-only here — AETHER still never submits flags.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..core.logger import get_logger

log = get_logger("scoreboard")


@dataclass
class ScoreSnapshot:
    attack_points: float | None = None
    defense_points: float | None = None
    sla_percent: float | None = None
    rank: int | None = None
    raw: dict = field(default_factory=dict)


# A parser converts a raw scoreboard payload (already fetched) into a ScoreSnapshot.
ScoreParser = Callable[[dict], ScoreSnapshot]
# A fetcher returns the raw payload from the official endpoint (injected; may use WebAdapter).
ScoreFetcher = Callable[[], Awaitable[dict]]


class ScoreboardClient:
    def __init__(
        self,
        fetcher: ScoreFetcher | None = None,
        parser: ScoreParser | None = None,
    ) -> None:
        self._fetcher = fetcher
        self._parser = parser

    @property
    def configured(self) -> bool:
        return self._fetcher is not None and self._parser is not None

    async def fetch(self) -> ScoreSnapshot | None:
        """Fetch + parse a snapshot, or None if unconfigured/unavailable (fail safe)."""
        if not self.configured:
            return None
        try:
            raw = await self._fetcher()
            return self._parser(raw)
        except Exception as exc:  # noqa: BLE001
            log.warning("scoreboard fetch failed", extra={"ctx": {"error": str(exc)}})
            return None
