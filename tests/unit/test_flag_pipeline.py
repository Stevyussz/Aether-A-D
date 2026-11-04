import pytest

from aether.attack.flags.extractor import FlagExtractor
from aether.attack.flags.inbox import FlagInbox, render_detection
from aether.attack.flags.validator import FlagValidator
from aether.attack.verification.verifier import ExploitVerifier
from aether.core.models import Flag, FlagValidation, ModuleResult, SubmissionStatus, TaskState
from aether.core.state_manager import StateManager

PATTERN = r"CTF\{[^}]+\}"


# --- extractor --------------------------------------------------------------
def test_extractor_finds_flags():
    ex = FlagExtractor(PATTERN)
    out = ex.extract("noise CTF{abc} more CTF{def} CTF{abc}")
    assert out == ["CTF{abc}", "CTF{def}"]


def test_extractor_without_pattern_extracts_nothing():
    ex = FlagExtractor(None)
    assert ex.extract("CTF{abc}") == []
    assert not ex.configured


# --- validator --------------------------------------------------------------
def test_validator_full_match_required():
    v = FlagValidator(PATTERN)
    assert v.validate("CTF{good}") == FlagValidation.VALIDATED
    assert v.validate("prefixCTF{good}suffix") == FlagValidation.INVALID
    assert v.validate("nope") == FlagValidation.INVALID


def test_validator_unverified_without_pattern():
    v = FlagValidator(None)
    assert v.validate("CTF{x}") == FlagValidation.UNVERIFIED


def test_validator_length_bounds():
    v = FlagValidator(PATTERN, min_len=8, max_len=20)
    assert v.validate("CTF{x}") == FlagValidation.INVALID  # too short


# --- verifier ---------------------------------------------------------------
def test_verifier_requires_success_and_flags():
    v = ExploitVerifier(FlagValidator(PATTERN))
    assert not v.verify(ModuleResult(module="m", state=TaskState.FAILED)).verified
    assert not v.verify(ModuleResult(module="m", state=TaskState.SUCCEEDED)).verified


def test_verifier_confirms_validated_flag():
    v = ExploitVerifier(FlagValidator(PATTERN))
    r = ModuleResult(module="m", state=TaskState.SUCCEEDED,
                     flags=[Flag(value="CTF{ok}", target="t")])
    rep = v.verify(r)
    assert rep.verified and rep.validated_flags == 1


def test_verifier_rejects_invalid_only():
    v = ExploitVerifier(FlagValidator(PATTERN))
    r = ModuleResult(module="m", state=TaskState.SUCCEEDED,
                     flags=[Flag(value="not-a-flag", target="t")])
    assert not v.verify(r).verified


# --- inbox ------------------------------------------------------------------
@pytest.fixture
async def inbox(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    yield FlagInbox(sm, FlagValidator(PATTERN))
    await sm.close()


async def test_inbox_ingest_validates_and_pending(inbox):
    out = await inbox.ingest(Flag(value="CTF{win}", target="10.0.0.5", service="web", module="m"))
    assert out.accepted and not out.duplicate
    assert out.validation == FlagValidation.VALIDATED
    assert out.flag.submission == SubmissionStatus.PENDING  # never auto-submitted


async def test_inbox_dedup(inbox):
    f1 = Flag(value="CTF{dup}", target="t", service="web", module="m1")
    f2 = Flag(value="CTF{dup}", target="t", service="web", module="m2")
    o1 = await inbox.ingest(f1)
    o2 = await inbox.ingest(f2)
    assert o1.accepted and not o2.accepted
    assert o2.duplicate and o2.seen_count == 2
    assert len(await inbox.list()) == 1


async def test_inbox_notifier_fires_once_per_new_flag(inbox):
    seen = []
    inbox.on_flag(lambda f: _collect(seen, f))
    await inbox.ingest(Flag(value="CTF{a}", target="t", service="s", module="m"))
    await inbox.ingest(Flag(value="CTF{a}", target="t", service="s", module="m"))  # dup
    assert len(seen) == 1


async def test_operator_mark_submitted_and_no_auto(inbox):
    f = Flag(value="CTF{z}", target="t", service="s", module="m")
    await inbox.ingest(f)
    # Still pending until operator acts.
    assert len(await inbox.pending()) == 1
    ok = await inbox.mark_submitted(f.dedup_key(), SubmissionStatus.SUBMITTED)
    assert ok
    assert len(await inbox.pending()) == 0


async def test_cannot_mark_back_to_pending(inbox):
    f = Flag(value="CTF{z}", target="t", service="s", module="m")
    await inbox.ingest(f)
    with pytest.raises(ValueError):
        await inbox.mark_submitted(f.dedup_key(), SubmissionStatus.PENDING)


def test_render_detection_format():
    f = Flag(value="CTF{shown}", target="10.0.0.5", service="web", module="m",
             validation=FlagValidation.VALIDATED)
    text = render_detection(f)
    assert "[FLAG DETECTED]" in text
    assert "Submission: PENDING" in text
    assert "CTF{shown}" in text


async def _collect(bucket, f):
    bucket.append(f.value)
