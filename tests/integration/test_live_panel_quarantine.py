"""Prove the two newest capabilities:

A. LIVE ATTACK PANEL — ``AttackSweep.run(progress=...)`` streams structured progress events
   (start → recon → login → arsenal → per-module → done) so the Web Console can show the
   sweep in real time. The callback never affects results and never breaks the sweep.
B. SMARTER DEFENSE — a read-only web-shell scanner detects opponent-planted shells (without
   false-flagging legitimate code), the defense sweep turns hits into a CRITICAL incident, and
   ``quarantine_webshell`` safely removes a shell (backup → move → functional test → verify),
   operator-gated and reversible.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "web"))
from vuln_service import VulnLabService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.attack.sweep import AttackSweep  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402
from aether.defense.engine import DefenseEngine  # noqa: E402
from aether.defense.patch_manager import PatchOutcome  # noqa: E402
from aether.defense.webshell_scanner import WebshellScanner, scan_file  # noqa: E402

PATTERN = r"IONIC\{[^}]+\}"
FLAG = "IONIC{live_panel_and_quarantine}"

# --- a clean web root with ONE planted shell among legitimate files -------------------------
CLEAN_INDEX = "<html><body>Welcome to our service</body></html>"
LEGIT_PHP = ("<?php\n$name = $_GET['name'] ?? 'guest';\n"
             "echo 'Hello, ' . htmlspecialchars($name);\n"
             "$rows = $db->query('SELECT 1');\n?>")       # uses $_GET but NO code-exec sink
SHELL_PHP = "<?php @eval($_POST['cmd']); ?>"              # textbook PHP web shell
OBFUSCATED = "<?php eval(base64_decode($_REQUEST['z'])); ?>"


def _make_webroot(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "index.html").write_text(CLEAN_INDEX)
    (root / "app.php").write_text(LEGIT_PHP)
    (root / "uploads").mkdir()
    (root / "uploads" / "shell.php").write_text(SHELL_PHP)
    return root


async def _orch(tmp_path, port=9):
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "s.sqlite"), log_file=None, log_level="ERROR"),
        scope=ScopeConfig(enforce=True, targets=[
            Target(name="lab", host="127.0.0.1", ports=(port,), kind="web", owner="opponent"),
        ]),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    return orch


# =========================== B — web-shell scanner ==========================================
def test_webshell_scanner_detects_shells_and_ignores_legit_code(tmp_path):
    root = _make_webroot(tmp_path)
    hits = {h.path: h for h in WebshellScanner().scan_root(root)}
    # The two shells are caught...
    assert "uploads/shell.php" in hits
    # ...the legitimate PHP (which merely reads $_GET) and static HTML are NOT flagged.
    assert "app.php" not in hits
    assert "index.html" not in hits
    assert hits["uploads/shell.php"].signatures          # has named signatures
    assert hits["uploads/shell.php"].snippet             # has an excerpt


def test_scanner_catches_obfuscated_eval(tmp_path):
    f = tmp_path / "x.php"
    f.write_text(OBFUSCATED)
    hit = scan_file(f)
    assert hit is not None


async def test_defense_sweep_raises_webshell_incident(tmp_path):
    root = _make_webroot(tmp_path)
    orch = await _orch(tmp_path)
    try:
        engine = DefenseEngine(orch, backup_root=tmp_path / "backups")
        engine.watch_path("www", root)
        incidents = await engine.sweep()
        kinds = {i.kind for i in incidents}
        assert "webshell" in kinds
        ws = next(i for i in incidents if i.kind == "webshell")
        assert ws.severity.value == "CRITICAL"
        assert ws.evidence["hits"]
    finally:
        await orch.shutdown()


async def test_quarantine_is_safe_and_reversible(tmp_path):
    root = _make_webroot(tmp_path)
    shell = root / "uploads" / "shell.php"
    orch = await _orch(tmp_path)
    try:
        engine = DefenseEngine(orch, backup_root=tmp_path / "backups")
        engine.watch_path("www", root)
        assert shell.exists()

        result = await engine.quarantine_webshell(shell)
        assert result.outcome == PatchOutcome.COMMITTED
        assert result.safe
        # The shell is gone from the web root and can no longer be served...
        assert not shell.exists()
        assert not WebshellScanner().scan_root(root)      # root is clean of shells now
        # ...the legitimate files are untouched...
        assert (root / "app.php").exists() and (root / "index.html").exists()
        # ...and it is reversible: a backup snapshot exists and restores the file.
        assert result.snapshot_id
        engine.backups.restore(result.snapshot_id)
        assert shell.exists()
    finally:
        await orch.shutdown()


async def test_quarantine_refuses_when_not_a_shell(tmp_path):
    root = _make_webroot(tmp_path)
    orch = await _orch(tmp_path)
    try:
        engine = DefenseEngine(orch, backup_root=tmp_path / "backups")
        engine.watch_path("www", root)
        # app.php is legitimate — pre-check must refuse (nothing moved).
        result = await engine.quarantine_webshell(root / "app.php")
        assert result.outcome == PatchOutcome.ABORTED_PRECHECK
        assert (root / "app.php").exists()
    finally:
        await orch.shutdown()


# =========================== A — live sweep progress ========================================
async def test_sweep_progress_streams_events(tmp_path):
    svc = VulnLabService(FLAG, port=0, enabled=frozenset({"command_injection"})).start()
    try:
        orch = await _orch(tmp_path, port=svc.port)
        inbox = FlagInbox(orch.state, FlagValidator(PATTERN), events=orch.events)
        engine = AttackEngine(orch, inbox)
        sweep = AttackSweep(engine)
        events: list[dict] = []
        ctx = RunContext(target_host="127.0.0.1", target_port=svc.port, service="web")
        report = await sweep.run(ctx, recon=True, login=True, progress=events.append)

        phases = [e["phase"] for e in events]
        assert phases[0] == "start"
        assert "arsenal" in phases and "done" in phases
        assert any(e["phase"] == "module" for e in events)         # per-module events stream
        done = next(e for e in events if e["phase"] == "done")
        assert done["modules"] == report.modules_run               # totals line up
        # module events carry index/total so a progress bar can be drawn
        mod_events = [e for e in events if e["phase"] == "module_start"]
        assert mod_events and all("index" in e and "total" in e for e in mod_events)
    finally:
        svc.stop()
        await orch.shutdown()


def test_progress_callback_errors_never_break_the_sweep(tmp_path):
    # A throwing callback must be swallowed (telemetry must not break the attack).
    from aether.attack.sweep import _emit
    calls = {"n": 0}

    def boom(_ev):
        calls["n"] += 1
        raise RuntimeError("callback blew up")

    _emit(boom, {"phase": "start"})      # must not raise
    assert calls["n"] == 1
