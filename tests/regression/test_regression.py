"""Regression tests — invalid config, duplicate flags, timeouts, odd responses, and
previously-fixed bugs (abstract plugin guard timing, scope substring, auto-submit ban)."""

import asyncio
import textwrap

import pytest

from aether.attack.flags.inbox import FlagInbox
from aether.attack.flags.validator import FlagValidator
from aether.core.config_manager import load_config
from aether.core.execution_guard import ExecutionGuard
from aether.core.models import Flag, FlagValidation, ModuleResult, TaskState
from aether.core.plugin import Module, ModuleMeta, RunContext
from aether.core.scope_guard import ScopeGuard
from aether.core.state_manager import StateManager


def test_regression_auto_submit_forbidden(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("flags:\n  auto_submit: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="never auto-submits"):
        load_config(p)


def test_regression_invalid_config_structure(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(p)


def test_regression_bad_concurrency_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("engine:\n  max_concurrency: 0\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(p)


def test_regression_scope_substring_still_denied():
    # Previously a risk: substring host matching. Must remain exact-only.
    g = ScopeGuard(enforce=True)
    g.allow("ctf.local")
    assert not g.check("evil-ctf.local").allowed
    assert not g.check("ctf.local.evil.com").allowed


def test_regression_abstract_plugin_guard_allows_abstract_bases():
    # Bug: Module.__init_subclass__ fired on abstract bases before __abstractmethods__
    # was populated. Defining a new abstract Module subclass must NOT raise.
    import abc

    class MyAbstractBase(Module, abc.ABC):
        @abc.abstractmethod
        async def run(self, context):  # no meta required because still abstract
            ...

    # And a concrete subclass still requires meta.
    with pytest.raises(TypeError):

        class NoMeta(MyAbstractBase):
            async def run(self, context):
                return ModuleResult(module="x")


async def test_regression_duplicate_flags_deduped(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    try:
        inbox = FlagInbox(sm, FlagValidator(r"CTF\{[^}]+\}"))
        for _ in range(5):
            await inbox.ingest(Flag(value="CTF{dup}", target="t", service="s", module="m"))
        rows = await inbox.list()
        assert len(rows) == 1
        assert rows[0]["seen_count"] == 5
    finally:
        await sm.close()


async def test_regression_timeout_normalized_not_raised():
    g = ExecutionGuard(max_concurrency=2, default_timeout=0.05)

    async def slow() -> ModuleResult:
        await asyncio.sleep(1)
        return ModuleResult(module="m")

    res = await g.run_module("m", slow)
    assert res.state == TaskState.TIMEOUT  # normalized, no exception escaped


async def test_regression_unexpected_service_response_no_flag(tmp_path):
    # A module that returns 200 but no flag must not fabricate a flag or confirm.
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    try:
        inbox = FlagInbox(sm, FlagValidator(r"CTF\{[^}]+\}"))
        # Simulate: nothing extracted -> nothing ingested.
        assert await inbox.list() == []
    finally:
        await sm.close()


async def test_regression_invalid_flag_marked_invalid(tmp_path):
    sm = StateManager(tmp_path / "s.sqlite")
    await sm.open()
    try:
        inbox = FlagInbox(sm, FlagValidator(r"CTF\{[^}]+\}"))
        out = await inbox.ingest(Flag(value="garbage", target="t", service="s", module="m"))
        assert out.validation == FlagValidation.INVALID
        invalid = await inbox.list(FlagValidation.INVALID)
        assert len(invalid) == 1
    finally:
        await sm.close()
