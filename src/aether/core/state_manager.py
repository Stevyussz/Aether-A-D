"""Persistent state on stdlib sqlite3 (no external DB dependency).

Stores:
- a key/value store for arbitrary orchestrator/engine state,
- discovered flags (the authoritative inbox backing store),
- a modification log (every defensive change, for audit/rollback).

sqlite3 calls are synchronous; we marshal them onto a thread with asyncio.to_thread and
serialize writes with a lock so the async engine never blocks the event loop. A single
shared connection is used with check_same_thread=False plus the lock.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .logger import get_logger
from .models import Flag, FlagValidation, SubmissionStatus, utcnow

log = get_logger("state_manager")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
    dedup_key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    target TEXT NOT NULL,
    service TEXT NOT NULL,
    module TEXT NOT NULL,
    tick TEXT,
    discovered_at TEXT NOT NULL,
    validation TEXT NOT NULL,
    submission TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS modifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    component TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    reversible INTEGER NOT NULL DEFAULT 1
);
"""


class StateManager:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._path = str(db_path)
        self._lock = asyncio.Lock()
        self._conn: sqlite3.Connection | None = None

    async def open(self) -> None:
        if self._conn is not None:
            return
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)

        def _connect() -> sqlite3.Connection:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.executescript(_SCHEMA)
            conn.commit()
            return conn

        self._conn = await asyncio.to_thread(_connect)
        log.info("state opened", extra={"ctx": {"path": self._path}})

    async def close(self) -> None:
        if self._conn is not None:
            conn = self._conn
            self._conn = None
            await asyncio.to_thread(conn.close)

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("StateManager is not open; call await open() first")
        return self._conn

    # --- key/value -------------------------------------------------------------
    async def set(self, key: str, value: object) -> None:
        payload = json.dumps(value, default=str)
        ts = utcnow().isoformat()

        def _do() -> None:
            self._db().execute(
                "INSERT INTO kv(key,value,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, payload, ts),
            )
            self._db().commit()

        async with self._lock:
            await asyncio.to_thread(_do)

    async def get(self, key: str, default: object = None) -> object:
        def _do() -> object:
            row = self._db().execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return json.loads(row["value"]) if row else default

        async with self._lock:
            return await asyncio.to_thread(_do)

    # --- flags -----------------------------------------------------------------
    async def upsert_flag(self, flag: Flag) -> tuple[bool, int]:
        """Insert a flag or bump its seen_count if already present.

        Returns (is_new, seen_count). is_new=False means it was a duplicate.
        """
        key = flag.dedup_key()

        def _do() -> tuple[bool, int]:
            db = self._db()
            existing = db.execute(
                "SELECT seen_count FROM flags WHERE dedup_key=?", (key,)
            ).fetchone()
            if existing:
                new_count = existing["seen_count"] + 1
                db.execute(
                    "UPDATE flags SET seen_count=? WHERE dedup_key=?", (new_count, key)
                )
                db.commit()
                return False, new_count
            db.execute(
                "INSERT INTO flags(dedup_key,value,target,service,module,tick,"
                "discovered_at,validation,submission,seen_count) VALUES(?,?,?,?,?,?,?,?,?,1)",
                (
                    key,
                    flag.value,
                    flag.target,
                    flag.service,
                    flag.module,
                    flag.tick,
                    flag.discovered_at.isoformat(),
                    flag.validation.value,
                    flag.submission.value,
                ),
            )
            db.commit()
            return True, 1

        async with self._lock:
            return await asyncio.to_thread(_do)

    async def set_submission(self, dedup_key: str, status: SubmissionStatus) -> bool:
        def _do() -> bool:
            db = self._db()
            cur = db.execute(
                "UPDATE flags SET submission=? WHERE dedup_key=?",
                (status.value, dedup_key),
            )
            db.commit()
            return cur.rowcount > 0

        async with self._lock:
            return await asyncio.to_thread(_do)

    async def list_flags(
        self, validation: FlagValidation | None = None
    ) -> list[dict]:
        def _do() -> list[dict]:
            db = self._db()
            if validation is not None:
                rows = db.execute(
                    "SELECT * FROM flags WHERE validation=? ORDER BY discovered_at DESC",
                    (validation.value,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM flags ORDER BY discovered_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

        async with self._lock:
            return await asyncio.to_thread(_do)

    # --- modification log ------------------------------------------------------
    async def record_modification(
        self,
        component: str,
        action: str,
        target: str | None = None,
        detail: str = "",
        reversible: bool = True,
    ) -> int:
        def _do() -> int:
            db = self._db()
            cur = db.execute(
                "INSERT INTO modifications(ts,component,action,target,detail,reversible) "
                "VALUES(?,?,?,?,?,?)",
                (utcnow().isoformat(), component, action, target, detail, int(reversible)),
            )
            db.commit()
            return int(cur.lastrowid)

        async with self._lock:
            return await asyncio.to_thread(_do)

    async def list_modifications(self) -> list[dict]:
        def _do() -> list[dict]:
            rows = self._db().execute(
                "SELECT * FROM modifications ORDER BY id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

        async with self._lock:
            return await asyncio.to_thread(_do)
