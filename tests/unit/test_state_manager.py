import pytest

from aether.core.models import Flag, FlagValidation, SubmissionStatus
from aether.core.state_manager import StateManager


@pytest.fixture
async def state(tmp_path):
    sm = StateManager(tmp_path / "state.sqlite")
    await sm.open()
    yield sm
    await sm.close()


async def test_kv_roundtrip(state):
    await state.set("round", {"n": 3})
    assert await state.get("round") == {"n": 3}
    assert await state.get("missing", "default") == "default"


async def test_flag_insert_and_dedup(state):
    f = Flag(value="CTF{abc}", target="10.0.0.5", service="web", module="m1")
    is_new, count = await state.upsert_flag(f)
    assert is_new and count == 1
    # Same logical flag -> duplicate.
    is_new2, count2 = await state.upsert_flag(
        Flag(value="CTF{abc}", target="10.0.0.5", service="web", module="m2")
    )
    assert not is_new2 and count2 == 2
    flags = await state.list_flags()
    assert len(flags) == 1
    assert flags[0]["seen_count"] == 2


async def test_flag_submission_update(state):
    f = Flag(value="CTF{xyz}", target="t", service="s", module="m")
    await state.upsert_flag(f)
    ok = await state.set_submission(f.dedup_key(), SubmissionStatus.SUBMITTED)
    assert ok
    flags = await state.list_flags()
    assert flags[0]["submission"] == "SUBMITTED"


async def test_list_flags_filter_by_validation(state):
    await state.upsert_flag(
        Flag(value="a", target="t", service="s", module="m", validation=FlagValidation.VALIDATED)
    )
    await state.upsert_flag(
        Flag(value="b", target="t", service="s", module="m", validation=FlagValidation.UNVERIFIED)
    )
    validated = await state.list_flags(FlagValidation.VALIDATED)
    assert len(validated) == 1
    assert validated[0]["value"] == "a"


async def test_modification_log(state):
    mid = await state.record_modification("patch_manager", "apply_patch", target="svc", detail="x")
    assert mid > 0
    mods = await state.list_modifications()
    assert mods[0]["action"] == "apply_patch"
    assert mods[0]["reversible"] == 1


async def test_persistence_across_reopen(tmp_path):
    path = tmp_path / "persist.sqlite"
    sm = StateManager(path)
    await sm.open()
    await sm.set("k", "v")
    await sm.close()
    sm2 = StateManager(path)
    await sm2.open()
    assert await sm2.get("k") == "v"
    await sm2.close()
