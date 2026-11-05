"""Prove the raw-TCP / data-store exploit modules genuinely recover flags.

Each module runs against a deliberately-vulnerable local TCP service (custom vault protocol,
unauthenticated Redis speaking RESP, unauthenticated Memcached) and must pull the real flag
into the MANUAL inbox as PENDING — from a genuine protocol exchange, never fabricated.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "tcp"))
from vuln_tcp import FakeMemcachedService, FakeRedisService, VaultTcpService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.memcached_unauth import MemcachedUnauthExploit  # noqa: E402
from aether.attack.exploits.redis_unauth import RedisUnauthExploit  # noqa: E402
from aether.attack.exploits.tcp_vault import TcpVaultExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.sweep import AttackSweep  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import SubmissionStatus, Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

FLAG = "IONIC{tcp_datastore_flag}"
PATTERN = r"IONIC\{[^}]+\}"


async def _engine(tmp_path, port, kind):
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None, log_level="ERROR"),
        scope=ScopeConfig(enforce=True, targets=[
            Target(name="svc", host="127.0.0.1", ports=(port,), kind=kind, owner="opponent"),
        ]),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
    return orch, inbox, AttackEngine(orch, inbox)


async def test_tcp_vault_module(tmp_path):
    svc = VaultTcpService(FLAG, port=0, secret_id="7").start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, "tcp")
        try:
            run = await engine.run_exploit(
                TcpVaultExploit(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="tcp"),
            )
            assert run.confirmed
            flags = await inbox.list()
            assert any(f["value"] == FLAG for f in flags)
            assert flags[0]["submission"] == SubmissionStatus.PENDING.value
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_redis_unauth_module(tmp_path):
    svc = FakeRedisService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, "redis")
        try:
            run = await engine.run_exploit(
                RedisUnauthExploit(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="redis"),
            )
            assert run.confirmed
            assert any(f["value"] == FLAG for f in await inbox.list())
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_memcached_unauth_module(tmp_path):
    svc = FakeMemcachedService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, "memcached")
        try:
            run = await engine.run_exploit(
                MemcachedUnauthExploit(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="memcached"),
            )
            assert run.confirmed
            assert any(f["value"] == FLAG for f in await inbox.list())
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_sweep_selects_network_set_for_redis(tmp_path):
    svc = FakeRedisService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, "redis")
        try:
            # kind="redis" -> sweep auto-selects the redis module only.
            report = await AttackSweep(engine).run(
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="redis")
            )
            assert report.any_flag and FLAG in report.flags_found
            assert "exploit.datastore.redis_unauth" in report.confirmed_modules
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_network_module_respects_scope(tmp_path):
    svc = FakeRedisService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _engine(tmp_path, svc.port, "redis")
        try:
            run = await engine.run_exploit(
                RedisUnauthExploit(),
                RunContext(target_host="8.8.8.8", target_port=svc.port, service="redis"),
            )
            assert not run.confirmed
            assert await inbox.list() == []
        finally:
            await orch.shutdown()
    finally:
        svc.stop()
