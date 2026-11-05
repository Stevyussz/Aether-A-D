"""Exploit memory — the "exploit farm" fast path.

In Attack & Defense the flag rotates every round but the *vulnerability* persists. AETHER
remembers which exploit modules have confirmed a flag against each target and runs those
FIRST on the next round, so a continuous `attack loop` re-pulls the fresh flag immediately
instead of re-scanning blindly. Backed by the persistent state store, so the knowledge
survives restarts.

This records only module identifiers and hit counts (metadata), never flag values.
"""

from __future__ import annotations


class ExploitMemory:
    KEY = "learned_exploits"

    def __init__(self, state) -> None:
        self.state = state

    @staticmethod
    def _key(target: str, service: str | None) -> str:
        return f"{target}|{service or 'web'}"

    async def _load(self) -> dict:
        data = await self.state.get(self.KEY, {})
        return data if isinstance(data, dict) else {}

    async def learned(self, target: str, service: str | None) -> list[str]:
        """Module ids that have confirmed against this target, most reliable first."""
        entry = (await self._load()).get(self._key(target, service), {})
        if not isinstance(entry, dict):
            return []
        return [m for m, _ in sorted(entry.items(), key=lambda kv: (-int(kv[1]), kv[0]))]

    async def record(self, target: str, service: str | None, modules: list[str]) -> None:
        """Bump the hit count for each module that confirmed a flag on this target."""
        if not modules:
            return
        data = await self._load()
        key = self._key(target, service)
        entry = data.get(key, {})
        if not isinstance(entry, dict):
            entry = {}
        for module in modules:
            entry[module] = int(entry.get(module, 0)) + 1
        data[key] = entry
        await self.state.set(self.KEY, data)
