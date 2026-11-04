"""Stress / endurance: concurrency bounds, large event volume, memory, graceful shutdown."""

import asyncio
import tracemalloc

import pytest

from aether.core.event_bus import Event, EventBus
from aether.core.execution_guard import ExecutionGuard
from aether.core.models import Flag, ModuleResult
from aether.core.scheduler import Scheduler
from aether.core.state_manager import StateManager

pytestmark = pytest.mark.stress


async def test_many_concurrent_tasks_stay_bounded():
    guard = ExecutionGuard(max_concurrency=8, default_timeout=5.0)
    active = 0
    peak = 0

    async def work() -> ModuleResult:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.005)
        active -= 1
        return ModuleResult(module="w")

    await asyncio.gather(*(guard.run_module("w", work) for _ in range(500)))
    assert peak <= 8
    assert guard.stats["peak"] <= 8


async def test_large_event_volume():
    bus = EventBus()
    counter = {"n": 0}

    async def handler(e: Event):
        counter["n"] += 1

    bus.subscribe("tick", handler)
    await asyncio.gather(*(bus.publish(Event("tick")) for _ in range(5000)))
    assert counter["n"] == 5000
    assert bus.stats["published"] == 5000
    assert bus.stats["errors"] == 0


async def test_flag_store_memory_bounded(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    try:
        tracemalloc.start()
        base = tracemalloc.get_traced_memory()[0]
        for i in range(2000):
            await sm.upsert_flag(Flag(value=f"CTF{{f{i}}}", target="t", service="s", module="m"))
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        rows = await sm.list_flags()
        assert len(rows) == 2000
        # Sanity bound: 2000 flags should not cost hundreds of MB in Python heap.
        assert (peak - base) < 80 * 1024 * 1024
    finally:
        await sm.close()


async def test_graceful_shutdown_with_periodic_jobs():
    guard = ExecutionGuard(max_concurrency=4, default_timeout=2.0)
    sched = Scheduler(guard)
    await sched.start()
    runs = {"n": 0}

    async def job() -> ModuleResult:
        runs["n"] += 1
        return ModuleResult(module="j")

    sched.every(0.01, job, name="heartbeat")
    await asyncio.sleep(0.08)
    await sched.stop()  # must return promptly and cancel the loop
    n_after_stop = runs["n"]
    assert n_after_stop >= 1
    await asyncio.sleep(0.05)
    # No further runs after a clean stop.
    assert runs["n"] == n_after_stop
    assert sched.stats["periodic"] == 0


async def test_endurance_repeated_sweeps_no_leak(tmp_path):
    # Simulate a long-running monitor: many state writes + reads, bounded growth.
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    try:
        for i in range(300):
            await sm.set("heartbeat", {"i": i})
            await sm.record_modification("monitor", "sweep", detail=f"iter {i}")
        mods = await sm.list_modifications()
        assert len(mods) == 300
        assert (await sm.get("heartbeat"))["i"] == 299
    finally:
        await sm.close()
