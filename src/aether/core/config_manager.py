"""Configuration loading and validation.

The real competition values are UNKNOWN until the organizer briefing (blueprint §10). So:
- every environment-specific value is a clearly-marked placeholder,
- validation fails closed: if scope is unconfigured or still a placeholder, the config is
  flagged not-ready-for-competition (but still usable for local lab simulation).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from .logger import get_logger
from .models import Target

log = get_logger("config_manager")

PLACEHOLDER_TOKENS = {"", "CHANGEME", "PLACEHOLDER", "TODO", "UNKNOWN", "0.0.0.0"}
PLACEHOLDER_SUBSTRINGS = ("CHANGEME", "PLACEHOLDER", "TODO", "OURTEAM")


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
    flag_id_endpoint: str | None = None  # organizer endpoint publishing per-tick flag IDs


class SubmissionConfig(BaseModel):
    """Explicit, operator-opt-in channel for sending VALIDATED flags to the OFFICIAL
    organizer game server. Separate from flags.auto_submit (which stays forbidden): this is
    cooperation with the scoring server, not an attack, and is FAIL-CLOSED — nothing is sent
    unless ``enabled=true`` AND a concrete endpoint/target is configured."""

    enabled: bool = False
    protocol: str = "http"            # "http" | "tcp"
    endpoint: str | None = None       # http(s) URL (protocol=http)
    http_method: str = "POST"
    http_body: str = "json"           # "json" | "form" | "raw"
    flag_field: str = "flag"
    token: str | None = None
    token_header: str | None = None   # e.g. "X-Team-Token"
    tcp_host: str | None = None       # protocol=tcp
    tcp_port: int | None = None
    timeout: float = 10.0
    accepted_patterns: list[str] | None = None
    duplicate_patterns: list[str] | None = None
    expired_patterns: list[str] | None = None
    rejected_patterns: list[str] | None = None


class AetherConfig(BaseModel):
    engine: EngineConfig = Field(default_factory=EngineConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    flags: FlagConfig = Field(default_factory=FlagConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    submission: SubmissionConfig = Field(default_factory=SubmissionConfig)


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
        host_up = t.host.strip().upper()
        name_up = t.name.strip().upper()
        if host_up in PLACEHOLDER_TOKENS or any(tok in host_up for tok in PLACEHOLDER_SUBSTRINGS):
            issues.append(f"target '{t.name}' host is a placeholder: {t.host!r}")
        if any(tok in name_up for tok in PLACEHOLDER_SUBSTRINGS):
            issues.append(f"target '{t.name}' name still contains a placeholder token")
        if t.owner not in ("opponent", "self"):
            issues.append(f"target '{t.name}' has invalid owner {t.owner!r} (must be 'opponent' or 'self')")
        if any(p < 1 or p > 65535 for p in t.ports):
            issues.append(f"target '{t.name}' has out-of-range port(s): {list(t.ports)}")
        if not t.ports:
            warnings.append(f"target '{t.name}' has no ports specified — will default to port 80")
        if t.owner == "self" and t.notes and not Path(t.notes).exists():
            warnings.append(f"self target '{t.name}' notes path does not exist: {t.notes}")

    if cfg.scope.targets and not any(t.owner == "opponent" for t in cfg.scope.targets):
        warnings.append("no target with owner='opponent' configured")

    if cfg.flags.pattern is None or not cfg.flags.pattern.strip():
        warnings.append("flags.pattern not set — flag extraction will not match anything")
    else:
        try:
            re.compile(cfg.flags.pattern)
        except re.error as exc:
            issues.append(f"flags.pattern is not a valid regex ({cfg.flags.pattern!r}): {exc}")

    if cfg.scoring.tick_seconds is None:
        warnings.append("scoring.tick_seconds not set — polling cadence unknown")

    if cfg.submission.enabled:
        if cfg.submission.protocol == "http" and not cfg.submission.endpoint:
            issues.append("submission.enabled=true but submission.endpoint is not set (fail closed)")
        elif cfg.submission.protocol == "tcp" and not (
                cfg.submission.tcp_host and cfg.submission.tcp_port):
            issues.append("submission.enabled=true but submission.tcp_host/tcp_port not set (fail closed)")
        elif cfg.submission.protocol not in ("http", "tcp"):
            issues.append(f"submission.protocol invalid: {cfg.submission.protocol!r} (use http|tcp)")
        else:
            warnings.append("submission.enabled=true — VALIDATED flags will be SENT to the "
                            "configured organizer endpoint (ensure it is the official game server)")

    if not cfg.scope.enforce:
        warnings.append("scope.enforce=false — LAB MODE ONLY, never use in competition")

    return ConfigReadiness(ready=not issues, issues=issues, warnings=warnings)
