"""Adapter protocols.

Adapters are the only place that talks to a concrete environment. The core and modules
depend on these abstractions, never on a specific transport. Every adapter is constructed
with an optional ScopeGuard and refuses operations against out-of-scope hosts (defense in
depth on top of the orchestrator).

A command adapter runs a shell command and returns (exit_code, stdout, stderr).
"""

from __future__ import annotations

import abc
from collections.abc import Awaitable, Callable

from ..core.scope_guard import ScopeGuard, ScopeViolation

# A low-level process runner: argv -> (code, stdout, stderr). Injectable for testing.
ProcRunner = Callable[[list[str]], Awaitable[tuple[int, str, str]]]


class CommandAdapter(abc.ABC):
    """Runs commands against a host environment."""

    def __init__(self, host: str, scope: ScopeGuard | None = None) -> None:
        self.host = host
        self._scope = scope

    def _check_scope(self, port: int | None = None) -> None:
        if self._scope is not None:
            self._scope.enforce(self.host, port)

    @abc.abstractmethod
    async def run(self, command: str) -> tuple[int, str, str]:
        """Run a command, returning (exit_code, stdout, stderr)."""


async def default_proc_runner(argv: list[str]) -> tuple[int, str, str]:
    """Default process runner using asyncio subprocess (no shell)."""
    import asyncio

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return (
        proc.returncode if proc.returncode is not None else -1,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )
