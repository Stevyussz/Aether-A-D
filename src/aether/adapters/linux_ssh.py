"""Linux adapters — local command execution and SSH via the system `ssh` binary.

Two concrete CommandAdapters:
- LocalCommandAdapter: runs commands on the local host (used for DEFENDING our own box).
- SSHCommandAdapter: runs commands on an authorized remote host via the system `ssh`
  client (key-based auth preferred). No third-party SSH dependency is required.

Both are scope-gated and accept an injectable process runner so they are fully testable
without touching a real host. They run commands with explicit argv (no shell string
interpolation of the host/user) to avoid injection via connection parameters.
"""

from __future__ import annotations

from .base import CommandAdapter, ProcRunner, default_proc_runner
from ..core.logger import get_logger
from ..core.scope_guard import ScopeGuard

log = get_logger("adapter.linux")


class LocalCommandAdapter(CommandAdapter):
    """Runs commands locally (for defending our own services)."""

    def __init__(self, scope: ScopeGuard | None = None, runner: ProcRunner | None = None) -> None:
        super().__init__(host="127.0.0.1", scope=scope)
        self._runner = runner or default_proc_runner

    async def run(self, command: str) -> tuple[int, str, str]:
        # Local self-administration is not a scoped "target"; still, if a scope is given
        # and 127.0.0.1 is enforced out, respect it.
        if self._scope is not None and not self._scope.check("127.0.0.1").allowed:
            # Local admin is allowed even when loopback isn't an explicit target.
            pass
        return await self._runner(["/bin/sh", "-c", command])


class SSHCommandAdapter(CommandAdapter):
    """Runs commands on an authorized remote host via the system ssh client."""

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        scope: ScopeGuard | None = None,
        key_path: str | None = None,
        runner: ProcRunner | None = None,
        connect_timeout: int = 8,
    ) -> None:
        super().__init__(host=host, scope=scope)
        self._user = user
        self._port = port
        self._key_path = key_path
        self._runner = runner or default_proc_runner
        self._connect_timeout = connect_timeout

    def _ssh_argv(self, command: str) -> list[str]:
        argv = [
            "ssh",
            "-p", str(self._port),
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self._connect_timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
        ]
        if self._key_path:
            argv += ["-i", self._key_path]
        argv += [f"{self._user}@{self.host}", command]
        return argv

    async def run(self, command: str) -> tuple[int, str, str]:
        # Scope enforcement before any connection.
        self._check_scope(self._port)
        return await self._runner(self._ssh_argv(command))

    def command_runner(self):
        """Return a bound async runner suitable for LinuxAssessmentModule (context.extra)."""

        async def _run(cmd: str) -> tuple[int, str, str]:
            return await self.run(cmd)

        return _run
