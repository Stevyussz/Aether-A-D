import asyncio

import pytest

from aether.core.event_bus import Event, EventBus


async def test_publish_subscribe_delivers():
    bus = EventBus()
    seen = []
    bus.subscribe("ping", lambda e: seen.append(e.name) or asyncio.sleep(0))
    ok = await bus.publish(Event("ping"))
    assert ok == 1
    assert seen == ["ping"]


async def test_wildcard_subscription():
    bus = EventBus()
    seen = []

    async def handler(e: Event):
        seen.append(e.name)

    bus.subscribe("*", handler)
    await bus.publish(Event("a"))
    await bus.publish(Event("b"))
    assert seen == ["a", "b"]


async def test_handler_error_is_isolated():
    bus = EventBus()
    good = []

    async def boom(e: Event):
        raise RuntimeError("explode")

    async def good_handler(e: Event):
        good.append(1)

    bus.subscribe("evt", boom)
    bus.subscribe("evt", good_handler)
    ok = await bus.publish(Event("evt"))
    assert ok == 1  # good handler still ran
    assert good == [1]
    assert bus.stats["errors"] == 1


async def test_unsubscribe():
    bus = EventBus()
    seen = []

    async def h(e: Event):
        seen.append(e.name)

    unsub = bus.subscribe("x", h)
    await bus.publish(Event("x"))
    unsub()
    await bus.publish(Event("x"))
    assert seen == ["x"]


async def test_no_subscribers_returns_zero():
    bus = EventBus()
    assert await bus.publish(Event("nobody")) == 0
