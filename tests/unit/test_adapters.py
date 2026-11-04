import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from flag_service import LabWebService  # noqa: E402

from aether.adapters.docker import DockerAdapter
from aether.adapters.linux_ssh import LocalCommandAdapter, SSHCommandAdapter
from aether.adapters.web import WebAdapter
from aether.core.scope_guard import ScopeGuard, ScopeViolation


# --- web adapter ------------------------------------------------------------
async def test_web_adapter_get_in_scope():
    svc = LabWebService("CTF{x}", port=0).start()
    try:
        scope = ScopeGuard(enforce=True)
        scope.allow("127.0.0.1", ports=(svc.port,))
        async with WebAdapter(scope=scope) as web:
            r = await web.get(f"http://127.0.0.1:{svc.port}/flag")
            assert r.status == 200
            assert "CTF{x}" in r.text
    finally:
        svc.stop()


async def test_web_adapter_blocks_out_of_scope():
    scope = ScopeGuard(enforce=True)
    scope.allow("127.0.0.1")
    async with WebAdapter(scope=scope) as web:
        with pytest.raises(ScopeViolation):
            await web.get("http://8.8.8.8/")


async def test_web_health_probe():
    svc = LabWebService("CTF{x}", port=0).start()
    try:
        scope = ScopeGuard(enforce=True)
        scope.allow("127.0.0.1", ports=(svc.port,))
        async with WebAdapter(scope=scope) as web:
            probe = web.health_probe(f"http://127.0.0.1:{svc.port}/flag")
            ok, detail = await probe()
            assert ok and "200" in detail
    finally:
        svc.stop()


# --- local command adapter --------------------------------------------------
async def test_local_command_adapter_runs():
    adapter = LocalCommandAdapter()
    code, out, err = await adapter.run("echo hello-aether")
    assert code == 0
    assert "hello-aether" in out


# --- ssh adapter (fake runner) ----------------------------------------------
async def test_ssh_adapter_builds_argv_and_enforces_scope():
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return 0, "uid=0(root)", ""

    scope = ScopeGuard(enforce=True)
    scope.allow("10.0.10.5", ports=(22,))
    ssh = SSHCommandAdapter("10.0.10.5", "ctf", port=22, scope=scope,
                            key_path="/keys/id", runner=fake_runner)
    code, out, err = await ssh.run("id")
    assert code == 0 and "root" in out
    argv = captured["argv"]
    assert argv[0] == "ssh"
    assert "ctf@10.0.10.5" in argv
    assert "-i" in argv and "/keys/id" in argv
    assert "BatchMode=yes" in argv


async def test_ssh_adapter_blocks_out_of_scope():
    async def fake_runner(argv):
        raise AssertionError("runner must not be called for out-of-scope host")

    scope = ScopeGuard(enforce=True)
    scope.allow("10.0.10.5")
    ssh = SSHCommandAdapter("10.0.99.99", "ctf", scope=scope, runner=fake_runner)
    with pytest.raises(ScopeViolation):
        await ssh.run("id")


# --- docker adapter (fake runner) -------------------------------------------
async def test_docker_ps_parses_json():
    async def fake_runner(argv):
        assert argv[:2] == ["docker", "ps"]
        return 0, '{"Names":"web","Image":"nginx","Status":"Up 2m"}\n', ""

    d = DockerAdapter(runner=fake_runner)
    containers = await d.ps()
    assert containers[0]["Names"] == "web"


async def test_docker_exec_runner():
    async def fake_runner(argv):
        # docker exec <c> /bin/sh -c <cmd>
        assert argv[1] == "exec"
        return 0, "ok", ""

    d = DockerAdapter(runner=fake_runner)
    runner = d.exec_runner("web")
    code, out, err = await runner("ls")
    assert code == 0 and out == "ok"


async def test_docker_ps_error_raises():
    async def fake_runner(argv):
        return 1, "", "Cannot connect to the Docker daemon"

    d = DockerAdapter(runner=fake_runner)
    with pytest.raises(RuntimeError, match="docker ps failed"):
        await d.ps()
