"""DefenseEngine — composes the defense components over a shared orchestrator.

Holds the monitors/managers and exposes a single async `sweep()` that gathers signals and
evaluates incidents. Remediation (patch/recovery) is deliberately NOT auto-triggered here;
it is invoked explicitly (operator-gated) so we never restart or modify services blindly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger
from ..core.orchestrator import Orchestrator
from .backup_manager import BackupManager
from .incident_detector import Incident, IncidentDetector
from .integrity_monitor import IntegrityMonitor
from .log_analyzer import LogAnalyzer
from .patch_manager import PatchManager
from .recovery_manager import RecoveryManager
from .service_monitor import ServiceFunctionalityChecker, ServiceHealthMonitor
from .vulnerability_assessment import VulnerabilityAssessment

log = get_logger("defense_engine")


@dataclass
class DefenseStatus:
    services_monitored: int
    integrity_watched: int
    last_incidents: list[str] = field(default_factory=list)


class DefenseEngine:
    def __init__(self, orch: Orchestrator, backup_root: str | Path = "runtime/backups") -> None:
        self.orch = orch
        self.health = ServiceHealthMonitor()
        self.functional = ServiceFunctionalityChecker()
        self.log_analyzer = LogAnalyzer()
        self.vuln = VulnerabilityAssessment()
        self.backups = BackupManager(backup_root)
        self.integrity: dict[str, IntegrityMonitor] = {}
        self.incidents = IncidentDetector(events=orch.events)
        self.patcher = PatchManager(self.backups, events=orch.events, state=orch.state)
        self.recovery = RecoveryManager(self.backups, events=orch.events, state=orch.state)
        self._last: list[Incident] = []

    def watch_path(self, name: str, root: str | Path, protected: tuple[str, ...] = ()) -> IntegrityMonitor:
        mon = IntegrityMonitor(root, protected=protected)
        mon.establish_baseline()
        self.integrity[name] = mon
        return mon

    async def sweep(self, log_text: str | None = None) -> list[Incident]:
        """One monitoring pass: health + integrity + logs -> incidents."""
        health = await self.health.check_all() if self.health._probes else []
        integrity_report = None
        for mon in self.integrity.values():
            r = mon.scan()
            if not r.clean:
                integrity_report = r
                break
        log_matches = self.log_analyzer.analyze_text(log_text) if log_text else []
        incidents = await self.incidents.evaluate(
            integrity=integrity_report, log_matches=log_matches, health=health
        )
        self._last = incidents
        return incidents

    @property
    def status(self) -> DefenseStatus:
        return DefenseStatus(
            services_monitored=len(self.health._probes),
            integrity_watched=len(self.integrity),
            last_incidents=[i.summary for i in self._last],
        )
