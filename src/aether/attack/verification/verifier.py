"""Exploit verification — independently confirm an exploit actually succeeded.

"Never assume that a detected vulnerability automatically means a successful exploit."
A ModuleResult is only treated as a genuine success if:
  - its state is SUCCEEDED, and
  - it carries at least one flag, and
  - every carried flag passes validation (when a flag pattern is configured).

When no flag pattern is configured we cannot fully verify; such results are reported as
UNVERIFIED rather than being promoted to success (no fabrication).
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core.models import FlagValidation, ModuleResult, TaskState
from ..flags.validator import FlagValidator


@dataclass
class VerificationReport:
    verified: bool
    reason: str
    validated_flags: int = 0
    unverified_flags: int = 0
    invalid_flags: int = 0


class ExploitVerifier:
    def __init__(self, validator: FlagValidator) -> None:
        self._validator = validator

    def verify(self, result: ModuleResult) -> VerificationReport:
        if result.state != TaskState.SUCCEEDED:
            return VerificationReport(False, f"module state is {result.state.value}")
        if not result.flags:
            return VerificationReport(False, "no flags extracted — not a confirmed exploit")

        validated = unverified = invalid = 0
        for f in result.flags:
            status = self._validator.validate(f.value)
            if status == FlagValidation.VALIDATED:
                validated += 1
            elif status == FlagValidation.UNVERIFIED:
                unverified += 1
            else:
                invalid += 1

        if invalid and not validated:
            return VerificationReport(
                False, "extracted values failed flag validation", validated, unverified, invalid
            )
        if validated:
            return VerificationReport(
                True, "exploit confirmed: validated flag(s) extracted",
                validated, unverified, invalid,
            )
        # Only unverified (no pattern configured): report honestly, not as success.
        return VerificationReport(
            False, "flags extracted but unverifiable (no flag pattern configured)",
            validated, unverified, invalid,
        )
