"""TargetsClient — pull the live opponent roster from the game's Targets API each tick.

A&D is attack-first: you must know every other team's container IP:port per service, and that
list changes (resets/admin stops reassign IPs). The platform publishes the canonical list at an
authenticated endpoint; this module fetches and normalizes it so the farm loop can aim the
arsenal at every healthy opponent automatically.

Response shape handled (tccpens/RSCTF style)::

    {"currentRound": 7,
     "challenges": [
       {"challengeId": 76, "title": "nginx", "tickSeconds": 60,
        "teams": [{"participationId": 3, "teamName": "Bravo",
                   "ip": "172.0.9.4", "port": 80, "lastCheckStatus": "Ok"}, ...]}]}

The endpoint already EXCLUDES your own team, so every listed team is a legal opponent target.
``lastCheckStatus`` is Ok / Mumble / Offline — only Ok reliably serves the flag.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..core.logger import get_logger

log = get_logger("targets_sync")


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    challenge_id: int | None = None
    title: str = ""
    team: str = ""
    status: str = ""          # Ok | Mumble | Offline | ""
    tick_seconds: int | None = None

    @property
    def healthy(self) -> bool:
        return self.status.lower() in ("ok", "up", "healthy", "")


def parse_targets(payload: object) -> list[Target]:
    """Normalize the Targets API JSON into a flat list of Target. Tolerant of shape drift."""
    out: list[Target] = []
    if not isinstance(payload, dict):
        return out
    challenges = payload.get("challenges")
    if not isinstance(challenges, list):
        # Some servers return a flat team list — accept {"teams":[...]} too.
        challenges = [payload] if payload.get("teams") else []
    for ch in challenges:
        if not isinstance(ch, dict):
            continue
        cid = ch.get("challengeId") or ch.get("id")
        title = str(ch.get("title") or "")
        tick = ch.get("tickSeconds") or ch.get("tick_seconds")
        teams = ch.get("teams")
        if not isinstance(teams, list):
            continue
        for t in teams:
            if not isinstance(t, dict):
                continue
            host = str(t.get("ip") or t.get("host") or "").strip()
            if not host:
                continue
            try:
                port = int(t.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if not port:
                continue
            out.append(Target(
                host=host, port=port,
                challenge_id=int(cid) if isinstance(cid, int) or str(cid).isdigit() else None,
                title=title, team=str(t.get("teamName") or t.get("team") or ""),
                status=str(t.get("lastCheckStatus") or t.get("status") or ""),
                tick_seconds=int(tick) if isinstance(tick, int) or str(tick).isdigit() else None,
            ))
    return out


class TargetsClient:
    """Async client for the authenticated Targets endpoint."""

    def __init__(self, endpoint: str | None, token: str | None = None,
                 token_header: str | None = "Authorization", timeout: float = 8.0) -> None:
        self.endpoint = (endpoint or "").strip() or None
        self.token = token
        self.token_header = token_header or "Authorization"
        self.timeout = timeout

    async def fetch(self) -> list[Target]:
        if not self.endpoint:
            return []
        headers: dict[str, str] = {}
        if self.token:
            headers[self.token_header] = self.token
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(self.endpoint, headers=headers or None)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001 - never crash the farm loop on a transient error
            log.warning("targets fetch failed", extra={"ctx": {"error": str(exc)}})
            return []
        return parse_targets(data)
