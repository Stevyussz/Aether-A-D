"""Docker adapter — manage authorized containers via the `docker` CLI.

Wraps a small set of docker operations used by defense (inspect/restart our own service
containers, copy files for backup/restore, exec read-only checks). Uses the system docker
CLI through an injectable process runner, so it is testable without a daemon.

Destructive operations are deliberately limited: there is no `rm -f` of volumes or images.
Restart is allowed because it is a standard, reversible service recovery action — but the
caller (defense engine / operator) decides when, never a blind automatic trigger.
"""

from __future__ import annotations

import json

from .base import ProcRunner, default_proc_runner
from ..core.logger import get_logger

log = get_logger("adapter.docker")


class DockerAdapter:
    def __init__(self, runner: ProcRunner | None = None) -> None:
        self._runner = runner or default_proc_runner

    async def _docker(self, *args: str) -> tuple[int, str, str]:
        return await self._runner(["docker", *args])

    async def ps(self) -> list[dict]:
        """List running containers as dicts (name, image, status)."""
        code, out, err = await self._docker("ps", "--format", "{{json .}}")
        if code != 0:
            raise RuntimeError(f"docker ps failed: {err.strip()}")
        containers = []
        for line in out.splitlines():
            line = line.strip()
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return containers

    async def inspect(self, container: str) -> dict:
        code, out, err = await self._docker("inspect", container)
        if code != 0:
            raise RuntimeError(f"docker inspect failed: {err.strip()}")
        data = json.loads(out)
        return data[0] if isinstance(data, list) and data else {}

    async def exec(self, container: str, command: str) -> tuple[int, str, str]:
        """Exec a command inside a container (read-only enumeration intended)."""
        return await self._docker("exec", container, "/bin/sh", "-c", command)

    async def copy_out(self, container: str, src_path: str, dest_path: str) -> tuple[int, str, str]:
        """docker cp container:src dest — used to back up in-container service files."""
        return await self._docker("cp", f"{container}:{src_path}", dest_path)

    async def copy_in(self, container: str, src_path: str, dest_path: str) -> tuple[int, str, str]:
        """docker cp src container:dest — used to restore/patch in-container files."""
        return await self._docker("cp", src_path, f"{container}:{dest_path}")

    async def restart(self, container: str) -> tuple[int, str, str]:
        """Restart a container (reversible recovery action; caller gates when)."""
        log.warning("docker restart requested", extra={"ctx": {"container": container}})
        return await self._docker("restart", container)

    def exec_runner(self, container: str):
        """Return an async command runner that execs inside a container."""

        async def _run(cmd: str) -> tuple[int, str, str]:
            return await self.exec(container, cmd)

        return _run
