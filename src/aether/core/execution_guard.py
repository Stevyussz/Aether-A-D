"""Execution isolation: per-task timeouts and global concurrency limiting.

Blueprint requirements: timeout isolation, concurrency limits, bounded resource usage,
no silent failures. A task that exceeds its timeout is cancelled and reported as TIMEOUT;
a task that raises is reported as FAILED with the error captured.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from .logger import get_logger
from .models import ModuleResult, TaskState, utcnow

log = get_logger("execution_guard")

T = TypeVar("T")


class ExecutionGuard:
    def __init__(self, max_concurrency: int = 8, default_timeout: float = 30.0) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if default_timeout <= 0:
            raise ValueError("default_timeout must be > 0")
        self._sem = asyncio.Semaphore(max_concurrency)
        self._default_timeout = default_timeout
        self._max_concurrency = max_concurrency
        self._active = 0
        self._peak = 0

    @property
    def stats(self) -> dict:
        return {
            "max_concurrency": self._max_concurrency,
            "active": self._active,
            "peak": self._peak,
            "default_timeout": self._default_timeout,
        }

    async def run(
        self,
        coro_factory: Callable[[], Awaitable[T]],
        *,
        timeout: float | None = None,
    ) -> T:
        """Run a coroutine under the concurrency limit with a hard timeout.

        Raises asyncio.TimeoutError on timeout; propagates other exceptions. Prefer
        run_module() for modules so results are normalized instead of raising.
        """
        timeout = timeout or self._default_timeout
        async with self._sem:
            self._active += 1
            self._peak = max(self._peak, self._active)
            try:
                return await asyncio.wait_for(coro_factory(), timeout=timeout)
            finally:
                self._active -= 1

    async def run_module(
        self,
        module_name: str,
        coro_factory: Callable[[], Awaitable[ModuleResult]],
        *,
        target: str | None = None,
        timeout: float | None = None,
    ) -> ModuleResult:
        """Run a module coroutine and always return a normalized ModuleResult.

        Never raises for module-level failures — timeouts and exceptions become result
        states so the orchestrator pipeline cannot be silently derailed.
        """
        started = utcnow()
        try:
            result = await self.run(coro_factory, timeout=timeout)
            if result.finished_at is None:
                result.finished_at = utcnow()
            return result
        except asyncio.TimeoutError:
            log.warning(
                "module TIMEOUT",
                extra={"ctx": {"module": module_name, "target": target, "timeout": timeout}},
            )
            return ModuleResult(
                module=module_name,
                target=target,
                state=TaskState.TIMEOUT,
                detail="execution exceeded timeout",
                started_at=started,
                finished_at=utcnow(),
                error="TimeoutError",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalize, never silent
            log.exception(
                "module FAILED", extra={"ctx": {"module": module_name, "target": target}}
            )
            return ModuleResult(
                module=module_name,
                target=target,
                state=TaskState.FAILED,
                detail="module raised an exception",
                started_at=started,
                finished_at=utcnow(),
                error=f"{type(exc).__name__}: {exc}",
            )
