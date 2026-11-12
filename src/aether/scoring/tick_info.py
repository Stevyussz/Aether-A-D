"""Tick metadata fetcher — retrieves active flag IDs from the organizer endpoint.

Many competitions publish active account/record identifiers (``flag_id``) per tick so teams
know which specific user or object holds the current tick's flag. This module fetches and
normalizes standard JSON formats into a flat list of strings for a given ``(host, service)``.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core.logger import get_logger

log = get_logger("tick_info")


def extract_flag_ids(payload: Any, host: str = "", service: str = "") -> list[str]:
    """Normalize organizer JSON into a deduplicated list of flag_id strings."""
    out: list[str] = []

    def _collect(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, (str, int)):
            s = str(node).strip()
            if s and s not in out:
                out.append(s)
            return
        if isinstance(node, list):
            for item in node:
                _collect(item)
            return
        if isinstance(node, dict):
            # Unwrap common top-level wrapper keys first.
            for wrap in ("flag_ids", "teams", "services", "data"):
                if wrap in node and isinstance(node[wrap], (dict, list)):
                    _collect(node[wrap])
                    return
            # Check if keyed by host or service.
            if host and host in node:
                sub = node[host]
                if isinstance(sub, dict) and service and service in sub:
                    _collect(sub[service])
                else:
                    _collect(sub)
                return
            if service and service in node:
                sub = node[service]
                if isinstance(sub, dict) and host and host in sub:
                    _collect(sub[host])
                else:
                    _collect(sub)
                return
            # Fallback: collect all leaf values matching host if present anywhere, else all leaves.
            matched_host = False
            if host:
                for k, v in node.items():
                    if k == host:
                        _collect(v)
                        matched_host = True
                    elif isinstance(v, dict) and host in v:
                        _collect(v[host])
                        matched_host = True
            if not matched_host:
                for v in node.values():
                    _collect(v)

    _collect(payload)
    return out


class TickInfoClient:
    """Async client for retrieving per-tick flag IDs from the competition scoreboard API."""

    def __init__(self, endpoint: str | None, timeout: float = 5.0) -> None:
        self.endpoint = (endpoint or "").strip() or None
        self.timeout = timeout

    async def fetch_for(self, host: str, service: str = "") -> list[str]:
        if not self.endpoint:
            return []
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(self.endpoint)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("tick_info fetch failed", extra={"ctx": {"error": str(exc)}})
            return []
        return extract_flag_ids(data, host=host, service=service)
