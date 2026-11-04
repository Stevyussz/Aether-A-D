"""Linux service assessment — scope-gated, adapter-driven.

Executes a small set of read-only enumeration commands on an authorized host through an
injected async command runner (supplied by the Linux/SSH adapter in Phase 5). Commands are
read-only enumeration (uname, service listing, listening sockets) — no destructive actions,
no persistence, no data exfiltration beyond assessment metadata.

If no runner is supplied, the module fails clearly rather than guessing or fabricating.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from ...core.logger import get_logger
from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext

log = get_logger("linux.assessment")

# runner(command) -> (exit_code, stdout, stderr)
CommandRunner = Callable[[str], Awaitable[tuple[int, str, str]]]

# Read-only enumeration only.
DEFAULT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("kernel", "uname -a"),
    ("os_release", "cat /etc/os-release 2>/dev/null | head -5"),
    ("listening", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("whoami", "id"),
)


class LinuxAssessmentModule(Module):
    meta = ModuleMeta(
        identifier="linux.assessment",
        description="Read-only Linux service enumeration via an injected SSH command runner.",
        supported_kinds=("linux",),
        category="assessment",
        timeout=30.0,
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        if not host:
            return ModuleResult(module=self.identifier, state=TaskState.FAILED, detail="no host")

        if context.scope is not None and not context.scope.check(host, context.target_port).allowed:
            return ModuleResult(module=self.identifier, target=host, state=TaskState.FAILED,
                                detail="target out of scope")

        runner: CommandRunner | None = context.extra.get("runner")
        if runner is None:
            return ModuleResult(
                module=self.identifier, target=host, state=TaskState.FAILED,
                detail="no command runner/adapter provided (SSH adapter required)",
            )

        commands = context.extra.get("commands") or DEFAULT_COMMANDS
        findings: dict[str, dict] = {}
        for name, cmd in commands:
            try:
                code, out, err = await runner(cmd)
                findings[name] = {"cmd": cmd, "exit": code, "stdout": out[:2000], "stderr": err[:500]}
            except Exception as exc:  # noqa: BLE001
                findings[name] = {"cmd": cmd, "error": f"{type(exc).__name__}: {exc}"}

        return ModuleResult(
            module=self.identifier, target=host, state=TaskState.SUCCEEDED,
            detail=f"collected {len(findings)} enumeration result(s)", data={"findings": findings},
        )
