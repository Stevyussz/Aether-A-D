"""Flag extraction — pull genuine flag strings out of raw execution output.

Extraction is driven entirely by the configured flag pattern (a regex). If no pattern is
configured, NOTHING is extracted — we never invent a flag or guess a format. The flag
format is UNKNOWN until the organizer briefing, so this stays data-driven.
"""

from __future__ import annotations

import re

from ...core.logger import get_logger

log = get_logger("flag_extractor")


class FlagExtractor:
    def __init__(self, pattern: str | None) -> None:
        self._pattern_src = pattern
        self._rx = re.compile(pattern) if pattern else None

    @property
    def configured(self) -> bool:
        return self._rx is not None

    def extract(self, text: str) -> list[str]:
        """Return all distinct flag matches in order of first appearance.

        Returns [] when no pattern is configured (fail safe — no fabrication).
        """
        if self._rx is None or not text:
            return []
        seen: dict[str, None] = {}
        for m in self._rx.finditer(text):
            value = m.group(0)
            if value not in seen:
                seen[value] = None
        return list(seen.keys())
