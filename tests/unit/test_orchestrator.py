import pytest

from aether.core.models import ModuleResult, TaskState
from aether.core.plugin import Module, ModuleMeta, RunContext
from tests.conftest import make_config
from aether.core.orchestrator import Orchestrator


class InScopeProbe(Module):
    meta = ModuleMeta(identifier="probe.inscope", supported_kinds=("web",), timeout=1.0)

    async def run(self, context: RunContext) -> ModuleResult:
        # Prove scope was already enforced before we ran.
        context.scope.enforce(context.target_host, context.target_port)
        return ModuleResult(module=self.identifier, target=context.target_host, detail="ok")


async def test_orchestrator_runs_in_scope_module(orchestrator):
    res = await orchestrator.run_module(
        InScopeProbe(), RunContext(target_host="127.0.0.1", target_port=8080)
    )
    assert res.state == TaskState.SUCCEEDED
    assert res.detail == "ok"


async def test_orchestrator_blocks_out_of_scope(orchestrator):
    res = await orchestrator.run_module(
        InScopeProbe(), RunContext(target_host="8.8.8.8", target_port=80)
    )
    assert res.state == TaskState.FAILED
    assert "scope" in res.detail.lower()


async def test_scope_denied_event_emitted(tmp_path):
    cfg = make_config(tmp_path)
    orch = Orchestrator(cfg)
    await orch.start()
    try:
        denied = []
        orch.events.subscribe(
            "scope.denied", lambda e: denied.append(e.payload) or _noop()
        )
        await orch.run_module(InScopeProbe(), RunContext(target_host="1.2.3.4"))
        assert denied and denied[0]["host"] == "1.2.3.4"
    finally:
        await orch.shutdown()


async def test_status_reports_components(orchestrator):
    st = orchestrator.status
    assert st["started"] is True
    assert "scope" in st and "execution" in st


async def _noop():
    return None
