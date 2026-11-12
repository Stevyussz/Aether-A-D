"""FlagSubmitter — the ONLY path by which AETHER sends flags to the OFFICIAL organizer.

This closes the one real A&D gap the manual inbox leaves open: in Attack & Defense the flag
rotates every tick, so validated flags must be submitted to the game server automatically or
they expire worthless. It is NOT an attack and never touches scope — it POSTs/sends to the
organizer's submission endpoint only.

NON-NEGOTIABLE safety design (mirrors the inbox's "operator in control" rule):
- FAIL-CLOSED: refuses unless ``enabled=True`` AND a concrete endpoint is configured. Default
  config is OFF; the operator must explicitly opt in.
- Only submits flags that are genuinely in the inbox, VALIDATED, and still PENDING. Never
  fabricates a flag and never submits an unvalidated or already-submitted one.
- DEDUP: every attempted flag is moved out of PENDING (ACCEPTED / REJECTED / EXPIRED /
  SUBMITTED) so it is never submitted twice.
- The organizer endpoint is addressed directly and is explicitly NOT a scope target — this is
  cooperation with the game server, not an exploit, so the scope guard does not gate it.
- Flag values are already registered for log redaction by the inbox; this module never logs a
  raw flag value.

Two transport protocols cover the vast majority of A&D game servers; the exact protocol is
unknown until the organizer briefing, so both are configuration-driven:
- ``http``: one HTTP request per flag (default) to the submission URL, optional auth header.
- ``tcp`` : classic line protocol — connect, send ``<flag>\n``, read one response line.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from ..core.logger import get_logger
from ..core.models import FlagValidation, SubmissionStatus

log = get_logger("flag_submitter")

# Default organizer-response classification (case-insensitive substring match). Real patterns
# vary per game server; the operator overrides these from config once the protocol is known.
DEFAULT_ACCEPTED = ("accepted", "correct", "valid", "ok", "congrat", "+")
DEFAULT_DUPLICATE = ("already", "duplicate", "claimed", "resubmit", "own")
DEFAULT_EXPIRED = ("expired", "too old", "old flag", "timeout", "stale")
DEFAULT_REJECTED = ("invalid", "wrong", "incorrect", "nop", "not found", "denied", "no such")


@dataclass
class SubmitConfig:
    """Everything needed to talk to one organizer submission endpoint. All optional so an
    empty config is safely inert (fail-closed)."""

    enabled: bool = False
    protocol: str = "http"            # "http" | "tcp"
    endpoint: str | None = None       # http(s) URL for protocol=http
    http_method: str = "POST"
    http_body: str = "json"           # "json" | "form" | "raw"
    flag_field: str = "flag"          # body field name carrying the flag (json/form)
    token: str | None = None
    token_header: str | None = None   # e.g. "X-Team-Token"; sent only if both token+header set
    tcp_host: str | None = None       # for protocol=tcp
    tcp_port: int | None = None
    timeout: float = 10.0
    accepted_patterns: tuple[str, ...] = DEFAULT_ACCEPTED
    duplicate_patterns: tuple[str, ...] = DEFAULT_DUPLICATE
    expired_patterns: tuple[str, ...] = DEFAULT_EXPIRED
    rejected_patterns: tuple[str, ...] = DEFAULT_REJECTED

    def ready(self) -> tuple[bool, str]:
        """Return (ok, reason). Fail-closed: must be enabled and have a concrete target."""
        if not self.enabled:
            return False, "submission disabled (submission.enabled=false)"
        if self.protocol == "http":
            if not self.endpoint:
                return False, "submission.endpoint not set"
        elif self.protocol == "tcp":
            if not (self.tcp_host and self.tcp_port):
                return False, "submission.tcp_host/tcp_port not set"
        else:
            return False, f"unknown submission.protocol: {self.protocol!r}"
        return True, "ready"


def classify_response(text: str, cfg: SubmitConfig) -> SubmissionStatus:
    """Map an organizer response line to a terminal submission status. Unknown → SUBMITTED
    (sent; outcome unclear) so the flag is never retried blindly."""
    low = (text or "").lower()
    for pat in cfg.duplicate_patterns:
        if pat and pat in low:
            return SubmissionStatus.ACCEPTED  # already scored — treat as done, never resubmit
    for pat in cfg.expired_patterns:
        if pat and pat in low:
            return SubmissionStatus.EXPIRED
    for pat in cfg.rejected_patterns:
        if pat and pat in low:
            return SubmissionStatus.REJECTED
    for pat in cfg.accepted_patterns:
        if pat and pat in low:
            return SubmissionStatus.ACCEPTED
    return SubmissionStatus.SUBMITTED


def submit_config_from(sub) -> SubmitConfig:
    """Build a SubmitConfig from a config_manager.SubmissionConfig (duck-typed), applying
    default response-classification patterns where the operator left them unset."""
    def _pat(v, default):
        return tuple(v) if v else default
    return SubmitConfig(
        enabled=sub.enabled, protocol=sub.protocol, endpoint=sub.endpoint,
        http_method=sub.http_method, http_body=sub.http_body, flag_field=sub.flag_field,
        token=sub.token, token_header=sub.token_header,
        tcp_host=sub.tcp_host, tcp_port=sub.tcp_port, timeout=sub.timeout,
        accepted_patterns=_pat(sub.accepted_patterns, DEFAULT_ACCEPTED),
        duplicate_patterns=_pat(sub.duplicate_patterns, DEFAULT_DUPLICATE),
        expired_patterns=_pat(sub.expired_patterns, DEFAULT_EXPIRED),
        rejected_patterns=_pat(sub.rejected_patterns, DEFAULT_REJECTED),
    )


@dataclass
class FlagResult:
    dedup_key: str
    status: SubmissionStatus
    response: str


@dataclass
class SubmitReport:
    attempted: int = 0
    accepted: int = 0
    rejected: int = 0
    expired: int = 0
    submitted: int = 0           # sent, outcome unknown
    errors: list[str] = field(default_factory=list)
    results: list[FlagResult] = field(default_factory=list)
    refused: str | None = None   # set when fail-closed refused the whole run

    def tally(self, status: SubmissionStatus) -> None:
        self.attempted += 1
        if status == SubmissionStatus.ACCEPTED:
            self.accepted += 1
        elif status == SubmissionStatus.REJECTED:
            self.rejected += 1
        elif status == SubmissionStatus.EXPIRED:
            self.expired += 1
        else:
            self.submitted += 1

    def summary(self) -> str:
        if self.refused:
            return f"submission refused: {self.refused}"
        return (f"submitted {self.attempted} flag(s): {self.accepted} accepted, "
                f"{self.rejected} rejected, {self.expired} expired, "
                f"{self.submitted} unknown, {len(self.errors)} error(s)")


class FlagSubmitter:
    """Submit VALIDATED+PENDING inbox flags to the official organizer endpoint."""

    def __init__(self, inbox, cfg: SubmitConfig) -> None:
        self._inbox = inbox
        self._cfg = cfg

    async def _eligible(self) -> list[dict]:
        """VALIDATED flags still PENDING submission — the only ones we may send."""
        rows = await self._inbox.list(FlagValidation.VALIDATED)
        return [r for r in rows if r.get("submission") == SubmissionStatus.PENDING.value]

    async def _send_http(self, client: httpx.AsyncClient, flag: str) -> str:
        cfg = self._cfg
        headers = {}
        if cfg.token and cfg.token_header:
            headers[cfg.token_header] = cfg.token
        kwargs: dict = {"headers": headers, "timeout": cfg.timeout}
        if cfg.http_body == "json":
            kwargs["json"] = {cfg.flag_field: flag}
        elif cfg.http_body == "form":
            kwargs["data"] = {cfg.flag_field: flag}
        else:  # raw
            kwargs["content"] = flag
        resp = await client.request(cfg.http_method, cfg.endpoint, **kwargs)
        return resp.text.strip()

    async def _send_tcp(self, flag: str) -> str:
        cfg = self._cfg
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.tcp_host, cfg.tcp_port), timeout=cfg.timeout)
        try:
            writer.write((flag + "\n").encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=cfg.timeout)
            return data.decode("utf-8", "replace").strip()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def submit_pending(self, limit: int | None = None) -> SubmitReport:
        """Submit each eligible flag to the organizer and record the outcome in the inbox.

        Fail-closed: if submission is disabled/misconfigured, nothing is sent."""
        report = SubmitReport()
        ok, reason = self._cfg.ready()
        if not ok:
            report.refused = reason
            log.warning("submission refused (fail-closed)", extra={"ctx": {"reason": reason}})
            return report

        eligible = await self._eligible()
        if limit is not None:
            eligible = eligible[:limit]
        if not eligible:
            return report

        client: httpx.AsyncClient | None = None
        if self._cfg.protocol == "http":
            client = httpx.AsyncClient()
        try:
            for row in eligible:
                flag = row.get("value")
                key = row.get("dedup_key")
                if not flag or not key:
                    continue
                try:
                    if self._cfg.protocol == "http":
                        text = await self._send_http(client, flag)
                    else:
                        text = await self._send_tcp(flag)
                except Exception as exc:  # noqa: BLE001 - network error: leave PENDING, retry next tick
                    report.errors.append(f"{key[:12]}…: {exc}")
                    log.warning("submission error",
                                extra={"ctx": {"dedup_key": key[:12] + "…", "error": str(exc)}})
                    continue
                status = classify_response(text, self._cfg)
                await self._inbox.mark_submitted(key, status)
                report.tally(status)
                report.results.append(FlagResult(key, status, text[:200]))
                log.info("flag submitted to organizer",
                         extra={"ctx": {"dedup_key": key[:12] + "…", "status": status.value,
                                        "target": row.get("target")}})
        finally:
            if client is not None:
                await client.aclose()
        return report
