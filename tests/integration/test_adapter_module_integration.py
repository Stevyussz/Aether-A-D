"""Modules run through adapters: linux.assessment via an SSH adapter command runner."""

import pytest

from aether.adapters.linux_ssh import SSHCommandAdapter
from aether.attack.linux.assessment import LinuxAssessmentModule
from aether.core.plugin import RunContext
from aether.core.scope_guard import ScopeGuard
from tests.conftest import make_config
from aether.core.models import Target
from aether.core.orchestrator import Orchestrator


async def test_linux_assessment_via_ssh_adapter(tmp_path):
    # Fake ssh runner returns canned enumeration output.
    responses = {
        "uname -a": (0, "Linux ctfbox 5.15 x86_64", ""),
        "id": (0, "uid=1000(ctf)", ""),
    }

    async def fake_runner(argv):
        cmd = argv[-1]
        return responses.get(cmd, (0, "ok", ""))

    cfg = make_config(
        tmp_path,
        targets=[Target(name="box", host="10.0.10.5", ports=(22,), kind="linux", owner="self")],
    )
    orch = Orchestrator(cfg)
    await orch.start()
    try:
        ssh = SSHCommandAdapter("10.0.10.5", "ctf", port=22, scope=orch.scope, runner=fake_runner)
        ctx = RunContext(
            target_host="10.0.10.5", target_port=22, service="linux",
            extra={
                "runner": ssh.command_runner(),
                "commands": (("kernel", "uname -a"), ("whoami", "id")),
            },
        )
        res = await orch.run_module(LinuxAssessmentModule(), ctx)
        assert res.ok
        findings = res.data["findings"]
        assert "Linux ctfbox" in findings["kernel"]["stdout"]
        assert "ctf" in findings["whoami"]["stdout"]
    finally:
        await orch.shutdown()


async def test_linux_assessment_without_runner_fails_clearly(tmp_path):
    cfg = make_config(
        tmp_path,
        targets=[Target(name="box", host="10.0.10.5", ports=(22,), kind="linux", owner="self")],
    )
    orch = Orchestrator(cfg)
    await orch.start()
    try:
        ctx = RunContext(target_host="10.0.10.5", target_port=22, service="linux")
        res = await orch.run_module(LinuxAssessmentModule(), ctx)
        assert not res.ok
        assert "no command runner" in res.detail
    finally:
        await orch.shutdown()
