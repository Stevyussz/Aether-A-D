"""AutoGuard — automated integrity enforcement and snapshot restoration loop.

Monitors watched service roots, takes initial baseline snapshots via BackupManager,
automatically quarantines unauthorized newly added script files, and restores modified
or deleted baseline files from verified snapshots while preserving protected paths
(such as competition flag storage files updated by the checker).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.logger import get_logger

if TYPE_CHECKING:
    from .engine import DefenseEngine

log = get_logger("auto_guard")


@dataclass
class GuardCycleReport:
    roots_checked: int = 0
    files_quarantined: list[str] = field(default_factory=list)
    files_restored: list[str] = field(default_factory=list)
    protected_skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def actions_taken(self) -> int:
        return len(self.files_quarantined) + len(self.files_restored)


class AutoGuard:
    """Automated integrity enforcement helper bound to a DefenseEngine."""

    def __init__(self, engine: DefenseEngine) -> None:
        self.engine = engine
        self.enabled: bool = False
        self.cycles: int = 0
        self.total_quarantined: int = 0
        self.total_restored: int = 0
        self._snapshots: dict[str, dict[str, str]] = {}  # root_name -> {rel_path -> snapshot_id}

    def set_enabled(self, enabled: bool) -> bool:
        """Toggle continuous AutoGuard enforcement ON (True) or OFF (False)."""
        self.enabled = bool(enabled)
        if self.enabled:
            self.ensure_snapshots()
        log.info("auto_guard toggled", extra={"ctx": {"enabled": self.enabled}})
        return self.enabled

    def ensure_snapshots(self) -> int:
        """Create per-file baseline snapshots for all watched roots if not already recorded."""
        created = 0
        for name, root in self.engine._roots.items():
            if not root.exists():
                continue
            mon = self.engine.integrity.get(name)
            protected = mon._protected if mon else ()
            snap_map = self._snapshots.setdefault(name, {})
            for p in sorted(root.rglob("*")):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(root))
                if self._is_protected(rel, protected):
                    continue
                if rel not in snap_map:
                    rec = self.engine.backups.create(p, label=f"autoguard-{name}-{rel}")
                    snap_map[rel] = rec.snapshot_id
                    created += 1
        return created

    @staticmethod
    def _is_protected(rel: str, protected: tuple[str, ...]) -> bool:
        return any(rel == pr or rel.startswith(pr.rstrip("/") + "/") for pr in protected)

    async def enforce_once(self, *, quarantine_added: bool = True, restore_drifted: bool = True) -> GuardCycleReport:
        """Run a single verification and remediation pass across all watched roots."""
        self.ensure_snapshots()
        report = GuardCycleReport()

        # 1. Scan for known suspicious scripts in watched roots and quarantine them
        for hit in self.engine.scan_webshells():
            res = await self.engine.quarantine_webshell(hit.path)
            if res.succeeded:
                report.files_quarantined.append(str(hit.path))
            else:
                report.errors.append(f"quarantine {hit.path}: {res.detail}")

        # 2. Check integrity monitors for unauthorized additions, modifications, or removals
        for name, mon in self.engine.integrity.items():
            root = self.engine._roots.get(name)
            if root is None or not root.exists():
                continue
            report.roots_checked += 1
            drift = mon.scan()
            if drift.clean:
                continue

            snap_map = self._snapshots.get(name, {})

            # Handle unauthorized added files not caught by signature scan
            if quarantine_added:
                for rel in drift.added:
                    if self._is_protected(rel, mon._protected):
                        report.protected_skipped.append(f"{name}:{rel}")
                        continue
                    target = root / rel
                    if not target.exists():
                        continue
                    self.engine.quarantine_dir.mkdir(parents=True, exist_ok=True)
                    dest = self.engine.quarantine_dir / f"{target.name}.untracked.quarantined"
                    try:
                        target.rename(dest)
                        report.files_quarantined.append(str(target))
                    except OSError as exc:
                        report.errors.append(f"move {target}: {exc}")

            # Handle modified or removed baseline files
            if restore_drifted:
                for rel in list(drift.modified) + list(drift.removed):
                    if self._is_protected(rel, mon._protected):
                        report.protected_skipped.append(f"{name}:{rel}")
                        continue
                    snap_id = snap_map.get(rel)
                    if not snap_id:
                        continue
                    target = root / rel
                    rec_res = await self.engine.recovery.recover(snap_id, dest=target)
                    if rec_res.succeeded:
                        report.files_restored.append(str(target))
                    else:
                        report.errors.append(f"restore {target}: {rec_res.detail}")

        self.cycles += 1
        self.total_quarantined += len(report.files_quarantined)
        self.total_restored += len(report.files_restored)
        if report.actions_taken > 0:
            log.info(
                "auto_guard actions completed",
                extra={
                    "ctx": {
                        "quarantined": report.files_quarantined,
                        "restored": report.files_restored,
                    }
                },
            )
        return report

    async def run_loop(self, interval: float = 5.0, max_cycles: int | None = None) -> list[GuardCycleReport]:
        """Run enforce_once periodically."""
        reports: list[GuardCycleReport] = []
        cycle = 0
        while max_cycles is None or cycle < max_cycles:
            cycle += 1
            rep = await self.enforce_once()
            reports.append(rep)
            if max_cycles is not None and cycle >= max_cycles:
                break
            await asyncio.sleep(interval)
        return reports
