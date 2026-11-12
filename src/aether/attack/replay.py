"""ExploitReplayer — refire a captured enemy request at every other team ("steal the exploit").

The TrafficRecorder captures the requests enemies send at our vulnbox. Each is a working
exploit for the shared service, so the highest-value attack move is to replay it against every
OTHER authorized team, swapping in that team's current-tick flag_id. This is the attack half of
the Tulip workflow.

SAFETY: replaying is an ATTACK, so it is SCOPE-ENFORCED per target — a request is only sent to
a host/port the scope guard authorizes; out-of-scope targets are skipped, never sent. Flags are
extracted from genuine responses only and land in the manual inbox PENDING (AETHER never
auto-submits here). Nothing is fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from ..core.logger import get_logger
from ..core.models import Flag

log = get_logger("replay")

# Headers we must not copy verbatim when replaying (httpx/host set these).
_DROP_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}


@dataclass
class ReplayTargetResult:
    host: str
    port: int
    status: int | None = None
    flags: list[str] = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None   # scope reason when not sent


@dataclass
class ReplayReport:
    source_id: int
    results: list[ReplayTargetResult] = field(default_factory=list)

    @property
    def flags_found(self) -> list[str]:
        seen: dict[str, None] = {}
        for r in self.results:
            for f in r.flags:
                seen.setdefault(f, None)
        return list(seen)

    @property
    def sent(self) -> int:
        return sum(1 for r in self.results if r.skipped is None)

    def summary(self) -> str:
        return (f"replayed capture #{self.source_id} to {self.sent} target(s): "
                f"{len(self.flags_found)} flag(s), "
                f"{sum(1 for r in self.results if r.skipped)} skipped (scope)")


def _apply(text: str, subs: list[tuple[str, str]]) -> str:
    for old, new in subs:
        if old:
            text = text.replace(old, new)
    return text


class ExploitReplayer:
    """Replay a captured request against authorized opponent targets, scope-enforced."""

    def __init__(self, scope, extractor, inbox=None, service: str = "web") -> None:
        self._scope = scope
        self._extractor = extractor
        self._inbox = inbox
        self._service = service

    async def replay(
        self,
        captured,                       # CapturedRequest
        targets: list[tuple[str, int]],
        *,
        substitutions: list[tuple[str, str]] | None = None,
        module: str = "attack.replay",
        timeout: float = 10.0,
    ) -> ReplayReport:
        subs = substitutions or []
        report = ReplayReport(source_id=getattr(captured, "id", 0))

        path = _apply(captured.path, subs)
        body = _apply(captured.body or "", subs)
        base_headers = {k: _apply(v, subs) for k, v in (captured.headers or {}).items()
                        if k.lower() not in _DROP_HEADERS}

        async with httpx.AsyncClient(timeout=timeout) as client:
            for host, port in targets:
                res = ReplayTargetResult(host=host, port=port)
                decision = self._scope.check(host, port)
                if not decision.allowed:
                    res.skipped = decision.reason
                    report.results.append(res)
                    log.info("replay skipped (scope)",
                             extra={"ctx": {"host": host, "port": port, "reason": decision.reason}})
                    continue
                url = f"http://{host}:{port}{path if path.startswith('/') else '/' + path}"
                try:
                    resp = await client.request(
                        captured.method or "GET", url,
                        headers=base_headers or None,
                        content=body.encode("utf-8", "replace") if body else None,
                    )
                    res.status = resp.status_code
                    flags = self._extractor.extract(resp.text) if self._extractor else []
                    res.flags = flags
                    for value in flags:
                        if self._inbox is not None:
                            await self._inbox.ingest(Flag(
                                value=value, target=host, service=self._service, module=module))
                    if flags:
                        log.info("replay captured flag(s)",
                                 extra={"ctx": {"host": host, "port": port, "count": len(flags)}})
                except Exception as exc:  # noqa: BLE001 - one target failing never stops the rest
                    res.error = str(exc)
                report.results.append(res)
        return report
