"""Reconnaissance — scope-gated TCP connect probe + light banner grab.

Non-destructive: it only performs a standard TCP connect (3-way handshake) and optionally
reads a short banner. No raw packets, no flooding, bounded concurrency, per-port timeout.
Every port touched is checked against the scope guard first (defense in depth on top of the
orchestrator's enforcement).
"""

from __future__ import annotations

import asyncio

from ...core.logger import get_logger
from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext

log = get_logger("recon.port_scan")

# Common A&D service ports; the real set comes from config/briefing.
DEFAULT_PORTS: tuple[int, ...] = (22, 80, 443, 3306, 5000, 8000, 8080, 9000)


async def probe_port(host: str, port: int, timeout: float, grab: bool = True) -> dict:
    """Return {'port', 'open', 'banner'} for one TCP connect probe."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return {"port": port, "open": False, "banner": ""}
    banner = ""
    try:
        if grab:
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 1.0))
                banner = data.decode("latin-1", "replace").strip()
            except (asyncio.TimeoutError, OSError):
                banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass
    return {"port": port, "open": True, "banner": banner}


class PortScanModule(Module):
    meta = ModuleMeta(
        identifier="recon.port_scan",
        description="Scope-gated TCP connect scan with optional banner grab.",
        supported_kinds=("linux", "web", "docker"),
        category="recon",
        timeout=20.0,
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        if not host:
            return ModuleResult(module=self.identifier, state=TaskState.FAILED,
                                detail="no target host")
        ports = tuple(context.extra.get("ports") or DEFAULT_PORTS)
        per_port_timeout = float(context.extra.get("port_timeout", 1.5))

        # Defense in depth: enforce scope per port before probing.
        if context.scope is not None:
            ports = tuple(p for p in ports if context.scope.check(host, p).allowed)
            if not ports:
                return ModuleResult(
                    module=self.identifier, target=host, state=TaskState.FAILED,
                    detail="no in-scope ports to probe",
                )

        sem = asyncio.Semaphore(int(context.extra.get("concurrency", 32)))

        async def _bounded(p: int) -> dict:
            async with sem:
                return await probe_port(host, p, per_port_timeout)

        results = await asyncio.gather(*(_bounded(p) for p in ports))
        open_ports = [r for r in results if r["open"]]
        return ModuleResult(
            module=self.identifier,
            target=host,
            state=TaskState.SUCCEEDED,
            detail=f"{len(open_ports)}/{len(ports)} ports open",
            data={"open_ports": open_ports, "scanned": list(ports)},
        )
