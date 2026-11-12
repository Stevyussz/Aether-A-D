"""DefenseEngine — composes the defense components over a shared orchestrator.

Holds the monitors/managers and exposes a single async `sweep()` that gathers signals and
evaluates incidents. Remediation (patch/recovery) is deliberately NOT auto-triggered here;
it is invoked explicitly (operator-gated) so we never restart or modify services blindly.
"""

from __future__ import annotations

import time
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
from .source_audit import AuditFinding, SourceAuditor
from .webshell_scanner import WebshellHit, WebshellScanner
from .auto_guard import AutoGuard, GuardCycleReport
from .shield_proxy import ShieldProxy

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
        self.webshells = WebshellScanner()
        self.auditor = SourceAuditor()
        self._roots: dict[str, Path] = {}      # name -> watched root (for webshell scans)
        self.quarantine_dir = Path(backup_root).parent / "quarantine"
        self.incidents = IncidentDetector(events=orch.events)
        self.patcher = PatchManager(self.backups, events=orch.events, state=orch.state)
        self.recovery = RecoveryManager(self.backups, events=orch.events, state=orch.state)
        self.auto_guard = AutoGuard(self)
        self.shield = ShieldProxy()
        self._last: list[Incident] = []

    def watch_path(self, name: str, root: str | Path, protected: tuple[str, ...] = ()) -> IntegrityMonitor:
        mon = IntegrityMonitor(root, protected=protected)
        mon.establish_baseline()
        self.integrity[name] = mon
        self._roots[name] = Path(root)
        self.auto_guard.ensure_snapshots()
        return mon

    async def auto_guard_once(self) -> GuardCycleReport:
        """Run a single AutoGuard integrity enforcement and restoration pass."""
        return await self.auto_guard.enforce_once()

    def scan_webshells(self) -> list[WebshellHit]:
        """Read-only scan of every watched root for planted web shells."""
        hits: list[WebshellHit] = []
        for root in self._roots.values():
            hits.extend(self.webshells.scan_root(root))
        return hits

    def audit_sources(self, root: str | Path | None = None) -> list[AuditFinding]:
        """Static self-audit of our own service source for exploitable sinks (read-only).

        'Patch yourself first': finds the LFI/cmdi/SSTI/SQLi/upload/exposed-file issues an
        opponent would exploit, with file:line + a remediation hint. Scans one root if given,
        else every watched self-owned root.
        """
        roots = [Path(root)] if root is not None else list(self._roots.values())
        findings: list[AuditFinding] = []
        for r in roots:
            findings.extend(self.auditor.audit_root(r))
        # Most severe first.
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: order.get(f.severity, 9))
        return findings

    async def sweep(self, log_text: str | None = None) -> list[Incident]:
        """One monitoring pass: health + integrity + logs + webshells -> incidents."""
        if self.auto_guard.enabled:
            await self.auto_guard.enforce_once()
        health = await self.health.check_all() if self.health._probes else []
        integrity_report = None
        for mon in self.integrity.values():
            r = mon.scan()
            if not r.clean:
                integrity_report = r
                break
        log_matches = self.log_analyzer.analyze_text(log_text) if log_text else []
        webshell_hits = self.scan_webshells()
        incidents = await self.incidents.evaluate(
            integrity=integrity_report, log_matches=log_matches, health=health,
            webshell_hits=webshell_hits,
        )
        self._last = incidents
        return incidents

    async def quarantine_webshell(self, abs_path: str | Path, *, functional_test=None):
        """Operator-gated: safely remove a detected web shell (backup first, reversible).

        Runs the standard patch workflow (PRE-CHECK -> BACKUP -> APPLY -> FUNCTIONAL ->
        VERIFY -> COMMIT/ROLLBACK): it confirms the file still looks like a shell, backs it
        up, MOVES it out of the web root into ``runtime/quarantine/`` (so the service can no
        longer serve it), checks the service still works, and verifies the shell is gone. If
        the functional test fails, the move is rolled back automatically. Never auto-invoked;
        the operator calls this explicitly.
        """
        from .webshell_scanner import scan_file

        target = Path(abs_path)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        dest = self.quarantine_dir / f"{target.name}.{int(time.time())}.quarantined"

        async def pre_check() -> tuple[bool, str]:
            if not target.is_file():
                return False, f"{target} does not exist"
            hit = scan_file(target)
            if hit is None:
                return False, f"{target} no longer matches web-shell signatures (refusing)"
            return True, f"confirmed shell signatures: {', '.join(hit.signatures)}"

        async def apply() -> tuple[bool, str]:
            try:
                target.rename(dest)
            except OSError as exc:
                return False, f"move failed: {exc}"
            return True, f"moved to {dest}"

        async def _default_functional() -> tuple[bool, str]:
            # No service probe supplied: the legitimate service is unaffected by removing a
            # planted file, so success = the shell is gone from the web root.
            return (not target.exists()), ("shell removed from web root"
                                           if not target.exists() else "shell still present")

        async def verify() -> tuple[bool, str]:
            still = scan_file(target) if target.exists() else None
            return (still is None), ("web root clean of this shell" if still is None
                                     else "shell still served")

        return await self.patcher.apply(
            f"quarantine-{target.name}", target,
            apply=apply,
            functional_test=functional_test or _default_functional,
            pre_check=pre_check,
            verify=verify,
        )

    @property
    def status(self) -> DefenseStatus:
        return DefenseStatus(
            services_monitored=len(self.health._probes),
            integrity_watched=len(self.integrity),
            last_incidents=[i.summary for i in self._last],
        )
