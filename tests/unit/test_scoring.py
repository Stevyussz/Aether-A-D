import pytest

from aether.core.state_manager import StateManager
from aether.scoring.scoreboard import ScoreboardClient, ScoreSnapshot
from aether.scoring.timing import TickClock
from aether.scoring.tracker import ScoreTracker, flag_is_expired


# --- TickClock --------------------------------------------------------------
def test_tickclock_unconfigured():
    c = TickClock(None)
    assert not c.configured
    assert c.info() is None
    assert c.current_tick() is None


def test_tickclock_computes_tick_and_remainder():
    c = TickClock(tick_seconds=60, epoch=1000.0)
    info = c.info(now=1000.0 + 150)  # 2.5 ticks in
    assert info.tick == 2
    assert info.seconds_into_tick == pytest.approx(30.0)
    assert info.seconds_to_next == pytest.approx(30.0)
    assert c.tick_label(now=1000.0 + 150) == "tick-2"


def test_tickclock_before_epoch_clamped():
    c = TickClock(tick_seconds=60, epoch=1000.0)
    info = c.info(now=500.0)
    assert info.tick == 0


# --- ScoreboardClient -------------------------------------------------------
async def test_scoreboard_unconfigured_returns_none():
    client = ScoreboardClient()
    assert not client.configured
    assert await client.fetch() is None


async def test_scoreboard_fetch_and_parse():
    async def fetcher():
        return {"atk": 120, "def": 80, "sla": 99.5}

    def parser(raw):
        return ScoreSnapshot(
            attack_points=raw["atk"], defense_points=raw["def"], sla_percent=raw["sla"]
        )

    client = ScoreboardClient(fetcher=fetcher, parser=parser)
    snap = await client.fetch()
    assert snap.attack_points == 120 and snap.sla_percent == 99.5


async def test_scoreboard_fetch_error_is_safe():
    async def fetcher():
        raise ConnectionError("down")

    client = ScoreboardClient(fetcher=fetcher, parser=lambda r: ScoreSnapshot())
    assert await client.fetch() is None  # no crash, no fabrication


# --- ScoreTracker -----------------------------------------------------------
@pytest.fixture
async def state(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    yield sm
    await sm.close()


async def test_tracker_records_and_deltas(state):
    t = ScoreTracker(state)
    await t.record(ScoreSnapshot(attack_points=100, defense_points=50, sla_percent=100))
    await t.record(ScoreSnapshot(attack_points=130, defense_points=45, sla_percent=98))
    latest = await t.latest()
    assert latest["attack_points"] == 130
    delta = await t.delta()
    assert delta["attack_points"] == 30
    assert delta["defense_points"] == -5


async def test_tracker_delta_none_with_one_point(state):
    t = ScoreTracker(state)
    await t.record(ScoreSnapshot(attack_points=1))
    assert await t.delta() is None


# --- flag expiration --------------------------------------------------------
def test_flag_expiry_within_window_not_expired():
    clock = TickClock(tick_seconds=60, epoch=1000.0)
    # now at tick 5; flag captured at tick 4; expiry 3 ticks -> not expired
    assert not flag_is_expired(4, clock, expiry_ticks=3, now=1000.0 + 5 * 60 + 1)


def test_flag_expiry_past_window_expired():
    clock = TickClock(tick_seconds=60, epoch=1000.0)
    # now tick 10; flag tick 4; expiry 3 -> expired
    assert flag_is_expired(4, clock, expiry_ticks=3, now=1000.0 + 10 * 60 + 1)


def test_flag_expiry_fail_safe_when_unknown():
    clock = TickClock(None)
    assert not flag_is_expired(4, clock, expiry_ticks=3)
    clock2 = TickClock(tick_seconds=60, epoch=1000.0)
    assert not flag_is_expired(None, clock2, expiry_ticks=3, now=2000.0)
    assert not flag_is_expired(4, clock2, expiry_ticks=None, now=2000.0)
