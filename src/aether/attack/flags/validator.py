"""Flag validation — decide whether an extracted candidate is a real, well-formed flag.

Validation is conservative and data-driven:
- a candidate must fully match the official flag pattern to be VALIDATED,
- a candidate that does not match is INVALID,
- if no pattern is configured we cannot be sure, so the result is UNVERIFIED (never
  silently promoted to VALIDATED — no fabrication).

Optional extra constraints (length bounds) can be supplied once known from the briefing.
"""

from __future__ import annotations

import re

from ...core.models import FlagValidation


class FlagValidator:
    def __init__(
        self,
        pattern: str | None,
        min_len: int | None = None,
        max_len: int | None = None,
    ) -> None:
        self._rx = re.compile(f"^(?:{pattern})$") if pattern else None
        self._min = min_len
        self._max = max_len

    def validate(self, candidate: str) -> FlagValidation:
        if not candidate:
            return FlagValidation.INVALID
        if self._min is not None and len(candidate) < self._min:
            return FlagValidation.INVALID
        if self._max is not None and len(candidate) > self._max:
            return FlagValidation.INVALID
        if self._rx is None:
            # No official pattern yet — cannot confirm. Do not fabricate a VALIDATED.
            return FlagValidation.UNVERIFIED
        return FlagValidation.VALIDATED if self._rx.match(candidate) else FlagValidation.INVALID
