"""Configuration loading and validation.

The real competition values are UNKNOWN until the organizer briefing (blueprint §10). So:
- every environment-specific value is a clearly-marked placeholder,
- validation fails closed: if scope is unconfigured or still a placeholder, the config is
  flagged not-ready-for-competition (but still usable for local lab simulation).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from .logger import get_logger
from .models import Target

log = get_logger("config_manager")

PLACEHOLDER_TOKENS = {"", "CHANGEME", "PLACEHOLDER", "TODO", "UNKNOWN", "0.0.0.0"}


class EngineConfig(BaseModel):
    max_concurrency: int = Field(default=8, ge=1, le=128)
    default_timeout: float = Field(default=30.0, gt=0)
    state_db: str = "runtime/aether.sqlite"
    log_file: str | None = "runtime/aether.log"
    log_level: str = "INFO"


class ScopeConfig(BaseModel):
    enforce: bool = True
    targets: list[Target] = Field(default_factory=list)


class FlagConfig(BaseModel):
    # Flag format is UNKNOWN until briefing; placeholder regex matches nothing useful by
    # default so operators must set it deliberately.
    pattern: str | None = None
    auto_submit: bool = False  # MUST remain False — enforced in validation.


class ScoringConfig(BaseModel):
    tick_seconds: int | None = None
    epoch: float | None = None  # unix time of tick 0 start, if known
    expiry_ticks: int | None = None  # flag acceptance window, in ticks
    submit_endpoint: str | None = None  # informational only — operator submits manually
    scoreboard_endpoint: str | None = None


class AetherConfig(BaseModel):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    flags: FlagConfig = Field(default_factory=FlagConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)


class ConfigReadiness(BaseModel):
    ready: bool
    issues: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def load_config(path: str | Path) -> AetherConfig:
    """Load and validate a YAML config into an AetherConfig. Raises on invalid structure."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config not found: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("config root must be a mapping")
    try:
        cfg = AetherConfig.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"invalid configuration: {exc}") from exc

    # Hard safety invariant: auto-submit can never be enabled.
    if cfg.flags.auto_submit:
        raise ValueError(
            "flags.auto_submit=true is forbidden — AETHER never auto-submits flags"
        )
    return cfg


def assess_readiness(cfg: AetherConfig) -> ConfigReadiness:
    """Fail-closed readiness check. ready=False while placeholders remain."""
    issues: list[str] = []
    warnings: list[str] = []

    if cfg.scope.enforce and not cfg.scope.targets:
        issues.append("scope.enforce=true but no authorized targets configured (fail closed)")

    for t in cfg.scope.targets:
        if t.host.strip().upper() in PLACEHOLDER_TOKENS:
            issues.append(f"target '{t.name}' host is a placeholder: {t.host!r}")

    if cfg.flags.pattern is None:
        warnings.append("flags.pattern not set — flag extraction will not match anything")

    if cfg.scoring.tick_seconds is None:
        warnings.append("scoring.tick_seconds not set — polling cadence unknown")

    if not cfg.scope.enforce:
        warnings.append("scope.enforce=false — LAB MODE ONLY, never use in competition")

    return ConfigReadiness(ready=not issues, issues=issues, warnings=warnings)
