"""Integrity monitor — detect unauthorized changes to our own service files.

Takes a baseline (path -> sha256) and reports added / removed / modified files on each
scan. This is how we notice an opponent planting a webshell or tampering with our service.
Flag storage paths can be marked protected so changes to them are escalated.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger

log = get_logger("integrity_monitor")


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class IntegrityReport:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    protected_hits: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.modified)


class IntegrityMonitor:
    def __init__(self, root: str | Path, protected: tuple[str, ...] = ()) -> None:
        self._root = Path(root)
        self._baseline: dict[str, str] = {}
        self._protected = protected

    def _scan(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if not self._root.exists():
            return result
        for p in sorted(self._root.rglob("*")):
            if p.is_file():
                result[str(p.relative_to(self._root))] = _hash(p)
        return result

    def establish_baseline(self) -> dict[str, str]:
        self._baseline = self._scan()
        log.info("integrity baseline set", extra={"ctx": {"files": len(self._baseline)}})
        return dict(self._baseline)

    def load_baseline(self, baseline: dict[str, str]) -> None:
        self._baseline = dict(baseline)

    def scan(self) -> IntegrityReport:
        current = self._scan()
        report = IntegrityReport()
        for rel, digest in current.items():
            if rel not in self._baseline:
                report.added.append(rel)
            elif self._baseline[rel] != digest:
                report.modified.append(rel)
        for rel in self._baseline:
            if rel not in current:
                report.removed.append(rel)

        changed = set(report.added) | set(report.removed) | set(report.modified)
        for rel in sorted(changed):
            if any(rel == pr or rel.startswith(pr.rstrip("/") + "/") for pr in self._protected):
                report.protected_hits.append(rel)

        if not report.clean:
            log.warning(
                "integrity drift",
                extra={
                    "ctx": {
                        "added": len(report.added),
                        "removed": len(report.removed),
                        "modified": len(report.modified),
                        "protected": report.protected_hits,
                    }
                },
            )
        return report
