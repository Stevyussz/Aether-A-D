"""Backup manager — snapshot and restore our own service files/directories.

Backups are content-addressed snapshots stored under a backup root. Each snapshot records
a manifest (relative path -> sha256 + stored blob). Restore is exact. This underpins the
patch workflow (BACKUP step) and recovery_manager.

Scope: operates ONLY on local paths we own (our defended services). It never touches the
network and never reads opponent infrastructure.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from ..core.logger import get_logger

log = get_logger("backup_manager")


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    source: str
    created_at: float
    files: dict[str, str]  # relative path -> sha256

    @property
    def file_count(self) -> int:
        return len(self.files)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class BackupManager:
    def __init__(self, backup_root: str | Path) -> None:
        self._root = Path(backup_root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _snap_dir(self, snapshot_id: str) -> Path:
        return self._root / snapshot_id

    def create(self, source: str | Path, label: str = "") -> Snapshot:
        """Create a snapshot of a file or directory. Returns the Snapshot manifest."""
        src = Path(source)
        if not src.exists():
            raise FileNotFoundError(f"backup source does not exist: {src}")
        snapshot_id = f"{int(time.time()*1000)}-{label or src.name}".replace("/", "_")
        snap_dir = self._snap_dir(snapshot_id)
        blobs = snap_dir / "blobs"
        blobs.mkdir(parents=True, exist_ok=True)

        files: dict[str, str] = {}
        if src.is_file():
            digest = _sha256_file(src)
            shutil.copy2(src, blobs / digest)
            files[src.name] = digest
            base = src.parent
        else:
            base = src
            for p in sorted(src.rglob("*")):
                if p.is_file():
                    digest = _sha256_file(p)
                    rel = str(p.relative_to(src))
                    if not (blobs / digest).exists():
                        shutil.copy2(p, blobs / digest)
                    files[rel] = digest

        snap = Snapshot(
            snapshot_id=snapshot_id,
            source=str(src),
            created_at=time.time(),
            files=files,
        )
        (snap_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "snapshot_id": snap.snapshot_id,
                    "source": snap.source,
                    "created_at": snap.created_at,
                    "is_file": src.is_file(),
                    "base": str(base),
                    "files": files,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        log.info(
            "backup created",
            extra={"ctx": {"id": snapshot_id, "files": len(files), "source": str(src)}},
        )
        return snap

    def list_snapshots(self) -> list[str]:
        return sorted(
            p.name for p in self._root.iterdir() if (p / "manifest.json").exists()
        )

    def _load_manifest(self, snapshot_id: str) -> dict:
        mf = self._snap_dir(snapshot_id) / "manifest.json"
        if not mf.exists():
            raise FileNotFoundError(f"unknown snapshot: {snapshot_id}")
        return json.loads(mf.read_text(encoding="utf-8"))

    def restore(self, snapshot_id: str, dest: str | Path | None = None) -> Path:
        """Restore a snapshot to its original location (or dest). Returns the target path."""
        manifest = self._load_manifest(snapshot_id)
        blobs = self._snap_dir(snapshot_id) / "blobs"
        is_file = manifest["is_file"]
        target = Path(dest) if dest is not None else Path(manifest["base"])

        if is_file:
            name, digest = next(iter(manifest["files"].items()))
            out = Path(dest) if dest else Path(manifest["base"]) / name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(blobs / digest, out)
            log.info("backup restored", extra={"ctx": {"id": snapshot_id, "dest": str(out)}})
            return out

        target.mkdir(parents=True, exist_ok=True)
        expected_rels = set(manifest["files"].keys())
        for existing in sorted(target.rglob("*"), reverse=True):
            if existing.is_file():
                rel = str(existing.relative_to(target))
                if rel not in expected_rels:
                    existing.unlink(missing_ok=True)
        for rel, digest in manifest["files"].items():
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(blobs / digest, out)
        log.info("backup restored", extra={"ctx": {"id": snapshot_id, "dest": str(target)}})
        return target

    def verify(self, snapshot_id: str) -> bool:
        """Verify all blobs exist and match their recorded digests."""
        manifest = self._load_manifest(snapshot_id)
        blobs = self._snap_dir(snapshot_id) / "blobs"
        for _rel, digest in manifest["files"].items():
            blob = blobs / digest
            if not blob.exists() or _sha256_file(blob) != digest:
                return False
        return True
