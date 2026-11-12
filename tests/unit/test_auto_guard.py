"""Unit tests for AutoGuard and request_filter defense helpers."""

from __future__ import annotations

from pathlib import Path

from aether.core.config_manager import AetherConfig, EngineConfig, FlagConfig, ScopeConfig
from aether.core.orchestrator import Orchestrator
from aether.defense.engine import DefenseEngine
from aether.defense.request_filter import inspect_value, is_safe_input, validate_params
from aether.defense.shield_proxy import ShieldProxy


def _make_orch(tmp_path: Path) -> Orchestrator:
    cfg = AetherConfig(
        engine=EngineConfig(state_db=str(tmp_path / "state.db")),
        scope=ScopeConfig(enforce=True, targets=()),
        flags=FlagConfig(pattern=r"FLAG\{[A-Za-z0-9_]+\}", auto_submit=False),
    )
    return Orchestrator(cfg)


async def test_auto_guard_restores_modified_and_deleted_and_quarantines_added(tmp_path: Path) -> None:
    svc_root = tmp_path / "service"
    svc_root.mkdir()
    app_py = svc_root / "app.py"
    app_py.write_text("print('clean v1')\n", encoding="utf-8")
    helper_py = svc_root / "helper.py"
    helper_py.write_text("def add(a, b): return a + b\n", encoding="utf-8")
    flag_txt = svc_root / "flag.txt"
    flag_txt.write_text("FLAG{initial_tick}\n", encoding="utf-8")

    orch = _make_orch(tmp_path)
    await orch.start()
    try:
        engine = DefenseEngine(orch, backup_root=tmp_path / "backups")
        engine.watch_path("web", svc_root, protected=("flag.txt",))

        # Simulate unauthorized drift:
        # 1. Modify app.py
        app_py.write_text("print('tampered')\n", encoding="utf-8")
        # 2. Delete helper.py
        helper_py.unlink()
        # 3. Add an untracked file
        untracked = svc_root / "extra.py"
        untracked.write_text("x = 1\n", encoding="utf-8")
        # 4. Checker updates protected flag.txt (must NOT be rolled back)
        flag_txt.write_text("FLAG{new_tick_flag}\n", encoding="utf-8")

        report = await engine.auto_guard_once()
        assert report.roots_checked == 1
        assert str(untracked) in report.files_quarantined
        assert not untracked.exists()
        assert str(app_py) in report.files_restored
        assert str(helper_py) in report.files_restored
        assert app_py.read_text(encoding="utf-8") == "print('clean v1')\n"
        assert helper_py.exists()
        assert flag_txt.read_text(encoding="utf-8") == "FLAG{new_tick_flag}\n"
        assert "web:flag.txt" in report.protected_skipped
    finally:
        await orch.shutdown()


def test_request_filter_detects_suspicious_inputs_and_allows_normal() -> None:
    assert is_safe_input("hello_world_123")
    assert is_safe_input("user@example.com")
    assert not is_safe_input("../../etc/hosts")
    assert "path_traversal" in inspect_value("../secret")
    assert not is_safe_input("{{ config.items() }}")
    assert not is_safe_input("1 UNION SELECT username, password FROM users")

    ok, hits = validate_params({"page": "home", "q": "normal search"})
    assert ok
    assert hits == []

    ok2, hits2 = validate_params({"file": "../../config.yaml"})
    assert not ok2
    assert "file:path_traversal" in hits2


def test_shield_proxy_blocks_when_on_and_passes_when_off() -> None:
    import http.client
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _BackendHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = f"OK:{self.path}".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            return

    backend = HTTPServer(("127.0.0.1", 0), _BackendHandler)
    bport = backend.server_address[1]
    bthread = threading.Thread(target=backend.serve_forever, daemon=True)
    bthread.start()

    proxy = ShieldProxy("127.0.0.1", 0, "127.0.0.1", bport, enabled=True)
    lport = proxy.start()
    try:
        # 1. Normal request passes through when Shield is ON
        conn = http.client.HTTPConnection("127.0.0.1", lport, timeout=5)
        conn.request("GET", "/hello?user=alice")
        r1 = conn.getresponse()
        assert r1.status == 200
        assert r1.read() == b"OK:/hello?user=alice"
        conn.close()

        # 2. Suspicious traversal request is blocked (HTTP 403) when Shield is ON
        conn = http.client.HTTPConnection("127.0.0.1", lport, timeout=5)
        conn.request("GET", "/view?file=../../secret.txt")
        r2 = conn.getresponse()
        assert r2.status == 403
        r2.read()
        conn.close()
        assert proxy.status().blocked_requests == 1

        # 3. Switch Shield OFF -> pass-through mode allows the same request
        proxy.set_enabled(False)
        assert not proxy.status().enabled
        conn = http.client.HTTPConnection("127.0.0.1", lport, timeout=5)
        conn.request("GET", "/view?file=../../secret.txt")
        r3 = conn.getresponse()
        assert r3.status == 200
        r3.read()
        conn.close()

        # 4. Switch Shield back ON -> blocks again
        proxy.set_enabled(True)
        conn = http.client.HTTPConnection("127.0.0.1", lport, timeout=5)
        conn.request("GET", "/view?file=../../secret.txt")
        r4 = conn.getresponse()
        assert r4.status == 403
        r4.read()
        conn.close()
        assert proxy.status().blocked_requests == 2
    finally:
        proxy.stop()
        backend.shutdown()
        backend.server_close()
