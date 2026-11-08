"""Incident detector — fuse signals (integrity, logs, health) into incidents.

Takes the structured outputs of the other defense components and decides whether an
incident should be raised, at what severity, and publishes an event so the operator is
alerted. It does not act on its own; remediation is the patch/recovery managers' job and
is always gated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.event_bus import Event, EventBus
from ..core.logger import get_logger
from ..core.models import Severity
from .integrity_monitor import IntegrityReport
from .log_analyzer import LogMatch
from .service_monitor import HealthResult

log = get_logger("incident_detector")


@dataclass
class Incident:
    kind: str
    severity: Severity
    summary: str
    evidence: dict = field(default_factory=dict)


class IncidentDetector:
    def __init__(self, events: EventBus | None = None) -> None:
        self._events = events

    async def evaluate(
        self,
        *,
        integrity: IntegrityReport | None = None,
        log_matches: list[LogMatch] | None = None,
        health: list[HealthResult] | None = None,
        webshell_hits: list | None = None,
    ) -> list[Incident]:
        incidents: list[Incident] = []

        if webshell_hits:
            incidents.append(
                Incident(
                    kind="webshell",
                    severity=Severity.CRITICAL,
                    summary=(
                        f"{len(webshell_hits)} suspected web shell(s) planted: "
                        f"{[getattr(h, 'path', str(h)) for h in webshell_hits]}"
                    ),
                    evidence={
                        "hits": [
                            {"path": getattr(h, "path", str(h)),
                             "abs_path": getattr(h, "abs_path", ""),
                             "signatures": list(getattr(h, "signatures", [])),
                             "snippet": getattr(h, "snippet", "")}
                            for h in webshell_hits
                        ]
                    },
                )
            )

        if integrity is not None and not integrity.clean:
            sev = Severity.CRITICAL if integrity.protected_hits else Severity.WARNING
            incidents.append(
                Incident(
                    kind="integrity_drift",
                    severity=sev,
                    summary=(
                        f"file integrity drift: +{len(integrity.added)} "
                        f"-{len(integrity.removed)} ~{len(integrity.modified)}"
                        + (f" (PROTECTED: {integrity.protected_hits})" if integrity.protected_hits else "")
                    ),
                    evidence={
                        "added": integrity.added,
                        "removed": integrity.removed,
                        "modified": integrity.modified,
                        "protected_hits": integrity.protected_hits,
                    },
                )
            )

        if log_matches:
            crit = [m for m in log_matches if m.severity == "CRITICAL"]
            incidents.append(
                Incident(
                    kind="log_ioc",
                    severity=Severity.CRITICAL if crit else Severity.WARNING,
                    summary=f"{len(log_matches)} suspicious log line(s); "
                    f"{len(crit)} critical",
                    evidence={"matches": [m.rule for m in log_matches]},
                )
            )

        if health:
            down = [h for h in health if not h.up]
            if down:
                incidents.append(
                    Incident(
                        kind="service_down",
                        severity=Severity.CRITICAL,
                        summary=f"{len(down)} service(s) DOWN: {[h.service for h in down]}",
                        evidence={"down": [h.service for h in down]},
                    )
                )

        for inc in incidents:
            log.warning(
                "INCIDENT",
                extra={"ctx": {"kind": inc.kind, "severity": inc.severity.value, "summary": inc.summary}},
            )
            if self._events is not None:
                await self._events.publish(
                    Event(
                        "defense.incident",
                        payload={"kind": inc.kind, "severity": inc.severity.value, "summary": inc.summary},
                        source="incident_detector",
                    )
                )
        return incidents
