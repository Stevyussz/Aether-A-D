"""Shared fixtures. All runtime state goes to tmp paths; nothing touches real infra."""

import pytest

from aether.core.config_manager import (
    AetherConfig,
    EngineConfig,
    ScopeConfig,
)
from aether.core.models import Target
from aether.core.orchestrator import Orchestrator


def make_config(tmp_path, *, enforce=True, targets=None, max_concurrency=4):
    return AetherConfig(
        engine=EngineConfig(
            max_concurrency=max_concurrency,
            default_timeout=2.0,
            state_db=str(tmp_path / "state.sqlite"),
            log_file=None,
        ),
        scope=ScopeConfig(
            enforce=enforce,
            targets=targets
            or [Target(name="lab-web", host="127.0.0.1", ports=(8080,), kind="web", owner="self")],
        ),
    )


@pytest.fixture
async def orchestrator(tmp_path):
    cfg = make_config(tmp_path)
    orch = Orchestrator(cfg)
    await orch.start()
    yield orch
    await orch.shutdown()
