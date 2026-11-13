"""Prove the exploit arsenal genuinely extracts flags from REAL responses.

Each exploit module is pointed at a deliberately-vulnerable local lab service and must pull
the real flag into the MANUAL inbox as PENDING. A negative test confirms that against a
non-vulnerable service NOTHING is reported (no fabrication). A full-sweep test proves the
"point it and it finds the flag" workflow.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from vuln_service import ALL_VULNS, VulnLabService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.web_ad_community import AdCommunityVulnboxExploit  # noqa: E402
from aether.attack.exploits.web_command_injection import CommandInjectionExploit  # noqa: E402
from aether.attack.exploits.web_default_creds import DefaultCredsExploit  # noqa: E402
from aether.attack.exploits.web_deserialization import DeserializationExploit  # noqa: E402
from aether.attack.exploits.web_elasticsearch import ElasticsearchExploit  # noqa: E402
from aether.attack.exploits.web_exposed_files import ExposedFilesExploit  # noqa: E402
from aether.attack.exploits.web_harvest import HarvestExploit  # noqa: E402
from aether.attack.exploits.web_file_upload import FileUploadExploit  # noqa: E402
from aether.attack.exploits.web_graphql import GraphqlExploit  # noqa: E402
from aether.attack.exploits.web_idor import IdorExploit  # noqa: E402
from aether.attack.exploits.web_jwt import JwtWeaknessExploit  # noqa: E402
from aether.attack.exploits.web_nosqli import NoSqlInjectionExploit  # noqa: E402
from aether.attack.exploits.web_path_traversal import PathTraversalExploit  # noqa: E402
from aether.attack.exploits.web_sqli import SqlInjectionExploit  # noqa: E402
from aether.attack.exploits.web_ssrf import SsrfExploit  # noqa: E402
from aether.attack.exploits.web_shellshock import ShellshockExploit  # noqa: E402
from aether.attack.exploits.web_ssti import SstiExploit  # noqa: E402
from aether.attack.exploits.web_xxe import XxeExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.sweep import AttackSweep, default_web_exploits  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import FlagValidation, SubmissionStatus, Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402

FLAG = "IONIC{sw33p_m3n3muk4n_flag_otomatis}"
PATTERN = r"IONIC\{[^}]+\}"

MODULES = [
    HarvestExploit,
    ExposedFilesExploit, PathTraversalExploit, SqlInjectionExploit, CommandInjectionExploit,
    SstiExploit, FileUploadExploit, ShellshockExploit, NoSqlInjectionExploit,
    DefaultCredsExploit, IdorExploit, SsrfExploit, XxeExploit, GraphqlExploit,
    ElasticsearchExploit, JwtWeaknessExploit, DeserializationExploit,
    AdCommunityVulnboxExploit,
]

# New modules proven in ISOLATION (only their own vuln enabled) so no overlapping branch
# can mask a genuine detection — e.g. the JWT double actually verifies the forged token.
ISOLATED = {
    ElasticsearchExploit: frozenset({"elasticsearch"}),
    JwtWeaknessExploit: frozenset({"jwt"}),
    DeserializationExploit: frozenset({"deserialization"}),
    FileUploadExploit: frozenset({"file_upload"}),
    ShellshockExploit: frozenset({"shellshock"}),
    AdCommunityVulnboxExploit: frozenset({"ad_community"}),
}


async def _make_engine(tmp_path, port, enabled=ALL_VULNS):
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None, log_level="ERROR"),
        scope=ScopeConfig(enforce=True, targets=[
            Target(name="lab", host="127.0.0.1", ports=(port,), kind="web", owner="opponent"),
        ]),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
    engine = AttackEngine(orch, inbox)
    return orch, inbox, engine


# HarvestExploit is operator-config-driven (fetches known paths), not an autonomous vuln
# detector, so it is covered by its own test below, not this generic-lab one.
_AUTONOMOUS = [m for m in MODULES if m is not HarvestExploit]


@pytest.mark.parametrize("module_cls", _AUTONOMOUS, ids=[m.__name__ for m in _AUTONOMOUS])
async def test_each_module_extracts_real_flag(tmp_path, module_cls):
    svc = VulnLabService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _make_engine(tmp_path, svc.port)
        try:
            run = await engine.run_exploit(
                module_cls(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
            )
            assert run.confirmed, f"{module_cls.__name__} did not confirm a flag"
            flags = await inbox.list()
            assert any(f["value"] == FLAG for f in flags)
            got = [f for f in flags if f["value"] == FLAG][0]
            assert got["validation"] == FlagValidation.VALIDATED.value
            assert got["submission"] == SubmissionStatus.PENDING.value  # never auto-submitted
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_harvest_fetches_configured_known_path(tmp_path):
    # HarvestExploit fires operator-known flag paths at the target and extracts the flag.
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if "page=/home/mahasiswa/flag.txt" in self.path:
                self.send_response(200); self.end_headers()
                self.wfile.write(f"hdr\n{FLAG}\nftr".encode())
            else:
                self.send_response(404); self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        orch, inbox, engine = await _make_engine(tmp_path, port)
        try:
            run = await engine.run_exploit(
                HarvestExploit(),
                RunContext(target_host="127.0.0.1", target_port=port, service="web",
                           extra={"harvest_paths": ["/index.php?page=/home/mahasiswa/flag.txt"]}),
            )
            assert run.confirmed
            assert any(f["value"] == FLAG for f in await inbox.list())
        finally:
            await orch.shutdown()
    finally:
        srv.shutdown()


@pytest.mark.parametrize("module_cls", list(ISOLATED), ids=[m.__name__ for m in ISOLATED])
async def test_new_module_extracts_flag_in_isolation(tmp_path, module_cls):
    # Only this module's own vulnerability is enabled, so no other branch can supply the flag.
    svc = VulnLabService(FLAG, port=0, enabled=ISOLATED[module_cls]).start()
    try:
        orch, inbox, engine = await _make_engine(tmp_path, svc.port)
        try:
            run = await engine.run_exploit(
                module_cls(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
            )
            assert run.confirmed, f"{module_cls.__name__} failed to genuinely extract the flag"
            assert any(f["value"] == FLAG for f in await inbox.list())
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_full_sweep_finds_flag_and_dedups(tmp_path):
    svc = VulnLabService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _make_engine(tmp_path, svc.port)
        try:
            sweep = AttackSweep(engine)
            report = await sweep.run(
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web",
                           extra={"max_probes": 25})
            )
            assert report.any_flag
            assert FLAG in report.flags_found
            # Many modules confirm the same flag...
            assert len(report.confirmed_modules) >= 5
            # ...but the manual inbox holds exactly one deduplicated PENDING entry.
            flags = await inbox.list()
            assert len([f for f in flags if f["value"] == FLAG]) == 1
            assert flags[0]["submission"] == SubmissionStatus.PENDING.value
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_no_fabrication_against_clean_service(tmp_path):
    # All vulns disabled: a correct arsenal must find NOTHING (never invent a flag).
    svc = VulnLabService(FLAG, port=0, enabled=frozenset()).start()
    try:
        orch, inbox, engine = await _make_engine(tmp_path, svc.port)
        try:
            report = await AttackSweep(engine).run(
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web",
                           extra={"max_probes": 25})
            )
            assert not report.any_flag
            assert await inbox.list() == []
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


async def test_sweep_respects_scope(tmp_path):
    svc = VulnLabService(FLAG, port=0).start()
    try:
        orch, inbox, engine = await _make_engine(tmp_path, svc.port)
        try:
            # Out-of-scope host: every module must be blocked, no flag, no inbox entry.
            report = await AttackSweep(engine).run(
                RunContext(target_host="8.8.8.8", target_port=svc.port, service="web")
            )
            assert not report.any_flag
            assert await inbox.list() == []
        finally:
            await orch.shutdown()
    finally:
        svc.stop()


def test_registry_is_complete():
    from aether.attack.sweep import NETWORK_EXPLOITS, exploits_for

    ids = {p.identifier for p in default_web_exploits()}
    assert len(ids) == len(MODULES)  # every web module registered exactly once
    assert all(i.startswith("exploit.web.") for i in ids)
    # Network set is selected for non-web kinds.
    assert len(NETWORK_EXPLOITS) == 3
    assert {p.identifier for p in exploits_for("redis")} == {"exploit.datastore.redis_unauth"}
    assert {p.identifier for p in exploits_for("memcached")} == {"exploit.datastore.memcached_unauth"}
    # Exclude dynamically-loaded operator custom scripts (scripts/custom/*): they are a runtime
    # addition, not part of the static registry this test validates.
    assert len([p for p in exploits_for("vault")
                if not p.identifier.startswith("custom.")]) == len(NETWORK_EXPLOITS)
    assert len([p for p in exploits_for("web")
                if not p.identifier.startswith("custom.")]) == len(MODULES)
