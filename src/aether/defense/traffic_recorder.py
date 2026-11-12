"""TrafficRecorder — capture incoming HTTP requests to our own service (Tulip-style).

In Attack & Defense the enemy attacks YOUR vulnbox to steal your flags. Every one of those
requests is a free exploit: capture it, read how they popped your service, and replay the same
request at every other team ("steal the exploit"). The ShieldProxy already sits in the request
path in front of a self-owned service, so it feeds each request here.

This module only RECORDS (a bounded, in-memory ring buffer); replaying is a separate,
scope-enforced attack step (see aether.attack.replay). Flag values that appear in captured
bodies are left intact here because a captured request is the ENEMY's exploit, not our flag;
the recorder is for our own operators on localhost.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

_MAX_BODY = 8192  # cap stored body so a flood can't exhaust memory


@dataclass
class CapturedRequest:
    id: int
    ts: str
    epoch: float
    src_ip: str
    method: str
    path: str                       # full path + query string as received
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    blocked: bool = False           # True if the shield rejected it (403)
    rule_hits: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.blocked or bool(self.rule_hits)

    def to_dict(self, *, include_body: bool = True) -> dict:
        d = {
            "id": self.id, "ts": self.ts, "src_ip": self.src_ip, "method": self.method,
            "path": self.path, "blocked": self.blocked, "rule_hits": list(self.rule_hits),
            "is_attack": self.is_attack, "headers": dict(self.headers),
        }
        if include_body:
            d["body"] = self.body
        return d


class TrafficRecorder:
    """Thread-safe bounded ring buffer of captured requests."""

    def __init__(self, capacity: int = 500) -> None:
        self._buf: deque[CapturedRequest] = deque(maxlen=max(1, capacity))
        self._lock = threading.Lock()
        self._seq = 0
        self.total = 0
        self.attacks = 0

    def record(self, *, src_ip: str, method: str, path: str,
               headers: dict[str, str] | None = None, body: str = "",
               blocked: bool = False, rule_hits: list[str] | None = None) -> CapturedRequest:
        hits = list(rule_hits or [])
        body = body or ""
        if len(body) > _MAX_BODY:
            body = body[:_MAX_BODY] + f"...(+{len(body) - _MAX_BODY} bytes)"
        with self._lock:
            self._seq += 1
            cap = CapturedRequest(
                id=self._seq, ts=time.strftime("%H:%M:%S"), epoch=time.time(),
                src_ip=src_ip or "?", method=method, path=path,
                headers=dict(headers or {}), body=body,
                blocked=bool(blocked), rule_hits=hits,
            )
            self._buf.append(cap)
            self.total += 1
            if cap.is_attack:
                self.attacks += 1
            return cap

    def recent(self, limit: int = 50, *, attacks_only: bool = False,
               include_body: bool = False) -> list[dict]:
        with self._lock:
            items = list(self._buf)
        if attacks_only:
            items = [c for c in items if c.is_attack]
        items = items[-limit:][::-1]  # newest first
        return [c.to_dict(include_body=include_body) for c in items]

    def get(self, cap_id: int) -> CapturedRequest | None:
        with self._lock:
            for c in self._buf:
                if c.id == cap_id:
                    return c
        return None

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    def stats(self) -> dict:
        with self._lock:
            return {"total": self.total, "attacks": self.attacks, "buffered": len(self._buf)}
