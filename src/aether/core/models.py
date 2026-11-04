"""Shared data models for AETHER A&D.

These are deliberately framework-neutral: the core must not depend on any specific
competition environment, flag format, or scoring system. Everything here is validated
with pydantic so bad data fails loudly rather than silently.
"""

from __future__ import annotations

import enum
import hashlib
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    """Timezone-aware UTC now (never naive)."""
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TaskState(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class FlagValidation(str, enum.Enum):
    VALIDATED = "VALIDATED"
    UNVERIFIED = "UNVERIFIED"
    INVALID = "INVALID"


class SubmissionStatus(str, enum.Enum):
    """AETHER only ever sets PENDING automatically. The operator moves it forward."""

    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class Flag(BaseModel):
    """A flag discovered by an exploit module.

    `value` is the genuine extracted string — never a placeholder. The inbox computes a
    stable dedup key so the same flag from the same source is only surfaced once.
    """

    model_config = ConfigDict(frozen=False)

    value: str = Field(min_length=1)
    target: str
    service: str = "unknown"
    module: str = "unknown"
    tick: str | None = None
    discovered_at: datetime = Field(default_factory=utcnow)
    validation: FlagValidation = FlagValidation.UNVERIFIED
    submission: SubmissionStatus = SubmissionStatus.PENDING
    duplicate: bool = False

    def dedup_key(self) -> str:
        """Stable identity for deduplication: flag value + source target + service.

        Tick is intentionally excluded by default because many A&D games rotate the same
        logical flag per tick; callers that want per-tick dedup can override.
        """
        raw = f"{self.value}\x00{self.target}\x00{self.service}"
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


class Target(BaseModel):
    """An explicitly authorized competition target."""

    model_config = ConfigDict(frozen=True)

    name: str
    host: str
    ports: tuple[int, ...] = ()
    kind: str = "unknown"  # web | linux | docker | ...
    owner: str = "opponent"  # opponent | self
    notes: str = ""


class ModuleResult(BaseModel):
    """Result of running a module (recon/exploit/defense check)."""

    module: str
    target: str | None = None
    state: TaskState = TaskState.SUCCEEDED
    detail: str = ""
    flags: list[Flag] = Field(default_factory=list)
    data: dict = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == TaskState.SUCCEEDED
