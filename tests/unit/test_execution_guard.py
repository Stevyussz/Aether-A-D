import asyncio

import pytest

from aether.core.execution_guard import ExecutionGuard
from aether.core.models import ModuleResult, TaskState


async def test_run_returns_value():
    g = ExecutionGuard(max_concurrency=2, default_timeout=1.0)

    async def work():
        return 42

    assert await g.run(work) == 42


async def test_timeout_raises_in_run():
    g = ExecutionGuard(max_concurrency=2, default_timeout=0.05)

    async def slow():
        await asyncio.sleep(1)

    with pytest.raises(asyncio.TimeoutError):
        await g.run(slow)


async def test_run_module_normalizes_timeout():
    g = ExecutionGuard(max_concurrency=2, default_timeout=0.05)

    async def slow() -> ModuleResult:
        await asyncio.sleep(1)
        return ModuleResult(module="m")

    res = await g.run_module("m", slow)
    assert res.state == TaskState.TIMEOUT
    assert res.error == "TimeoutError"


async def test_run_module_normalizes_exception():
    g = ExecutionGuard()

    async def boom() -> ModuleResult:
        raise ValueError("nope")

    res = await g.run_module("m", boom)
    assert res.state == TaskState.FAILED
    assert "ValueError" in res.error


async def test_concurrency_limit_enforced():
    g = ExecutionGuard(max_concurrency=2, default_timeout=2.0)
    started = 0
    peak = 0

    async def work() -> ModuleResult:
        nonlocal started, peak
        started += 1
        peak = max(peak, started)
        await asyncio.sleep(0.05)
        started -= 1
        return ModuleResult(module="w")

    await asyncio.gather(*(g.run_module("w", work) for _ in range(6)))
    assert peak <= 2
    assert g.stats["peak"] <= 2


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        ExecutionGuard(max_concurrency=0)
    with pytest.raises(ValueError):
        ExecutionGuard(default_timeout=0)
