"""Async scheduler: priority one-shot tasks + periodic jobs.

Blueprint: priority queues, efficient polling based on official timing, bounded concurrency
(delegated to ExecutionGuard), graceful shutdown. Periodic jobs are the basis for defense
monitoring loops and tick-synchronized attack sweeps.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .execution_guard import ExecutionGuard
from .logger import get_logger

log = get_logger("scheduler")

AsyncJob = Callable[[], Awaitable[object]]


@dataclass(order=True)
class _PrioritizedItem:
    priority: int
    seq: int
    job: AsyncJob = field(compare=False)
    name: str = field(compare=False, default="task")


class Scheduler:
    """Runs queued priority tasks and registered periodic jobs until stopped."""

    def __init__(self, guard: ExecutionGuard) -> None:
        self._guard = guard
        self._queue: asyncio.PriorityQueue[_PrioritizedItem] = asyncio.PriorityQueue()
        self._counter = itertools.count()
        self._periodic: list[asyncio.Task] = []
        self._running = False
        self._stop = asyncio.Event()
        self._completed = 0

    async def submit(self, job: AsyncJob, *, priority: int = 100, name: str = "task") -> None:
        """Queue a one-shot job. Lower priority number = runs sooner."""
        await self._queue.put(
            _PrioritizedItem(priority=priority, seq=next(self._counter), job=job, name=name)
        )

    def every(
        self,
        interval: float,
        job: AsyncJob,
        *,
        name: str = "periodic",
        timeout: float | None = None,
        jitter: float = 0.0,
    ) -> None:
        """Register a periodic job that runs every `interval` seconds while active."""

        async def _loop() -> None:
            import random

            try:
                while not self._stop.is_set():
                    try:
                        await self._guard.run_module(name, job, timeout=timeout)
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001
                        log.exception("periodic job error", extra={"ctx": {"name": name}})
                    delay = interval + (random.uniform(0, jitter) if jitter else 0.0)
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
            except asyncio.CancelledError:
                pass

        self._periodic.append(asyncio.create_task(_loop(), name=f"periodic:{name}"))

    async def run_until_idle(self) -> int:
        """Drain the one-shot queue. Returns number of tasks completed."""
        completed = 0
        while not self._queue.empty():
            item = await self._queue.get()
            try:
                await self._guard.run_module(item.name, item.job)
                completed += 1
                self._completed += 1
            finally:
                self._queue.task_done()
        return completed

    async def start(self) -> None:
        self._running = True
        self._stop.clear()

    async def stop(self) -> None:
        """Graceful shutdown: signal periodic loops and await their completion."""
        self._stop.set()
        for t in self._periodic:
            t.cancel()
        if self._periodic:
            await asyncio.gather(*self._periodic, return_exceptions=True)
        self._periodic.clear()
        self._running = False
        log.info("scheduler stopped", extra={"ctx": {"completed": self._completed}})

    @property
    def stats(self) -> dict:
        return {
            "running": self._running,
            "queued": self._queue.qsize(),
            "periodic": len(self._periodic),
            "completed": self._completed,
        }
