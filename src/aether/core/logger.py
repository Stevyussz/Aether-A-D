"""Structured logging for AETHER.

Two hard requirements from the blueprint:
- Structured logging (machine-parseable JSON lines) with no silent failures.
- Flags must never appear in ordinary logs. We register discovered flag values with the
  logger so any accidental log line containing them is redacted before it is written.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

_REDACTED = "[REDACTED-FLAG]"


class _FlagRedactor(logging.Filter):
    """Redacts any registered flag value appearing in a log record's message."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def register(self, secret: str) -> None:
        if secret:
            with self._lock:
                self._secrets.add(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        with self._lock:
            secrets = tuple(self._secrets)
        if secrets:
            redacted = msg
            for s in secrets:
                if s and s in redacted:
                    redacted = redacted.replace(s, _REDACTED)
            if redacted != msg:
                record.msg = redacted
                record.args = ()
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach structured extras (anything the caller passed via extra={"ctx": ...}).
        ctx = getattr(record, "ctx", None)
        if ctx is not None:
            payload["ctx"] = ctx
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


_redactor = _FlagRedactor()
_configured = False
_lock = threading.Lock()


def configure_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    json_console: bool = False,
) -> None:
    """Configure root logging once. Idempotent."""
    global _configured
    with _lock:
        root = logging.getLogger("aether")
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        # Clear existing handlers so re-configuration (e.g. in tests) is clean.
        for h in list(root.handlers):
            root.removeHandler(h)
        root.addFilter(_redactor)

        console = logging.StreamHandler(stream=sys.stderr)
        console.addFilter(_redactor)
        if json_console:
            console.setFormatter(_JsonFormatter())
        else:
            console.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-8s %(name)s | %(message)s")
            )
        root.addHandler(console)

        if log_file is not None:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(path, encoding="utf-8")
            fh.addFilter(_redactor)
            fh.setFormatter(_JsonFormatter())
            root.addHandler(fh)

        root.propagate = False
        _configured = True


def get_logger(name: str = "aether") -> logging.Logger:
    """Return a namespaced logger under the 'aether' root."""
    if not _configured:
        configure_logging()
    if name == "aether" or name.startswith("aether."):
        return logging.getLogger(name)
    return logging.getLogger(f"aether.{name}")


def register_secret(value: str) -> None:
    """Register a flag value so it is redacted from all log output."""
    _redactor.register(value)
