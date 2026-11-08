"""AETHER Web Console — a local browser UI for monitoring and control.

A lightweight dashboard served over HTTP on localhost ONLY (127.0.0.1), built on the Python
standard library (no extra web-framework dependency, nothing exposed to the network). It
shows the same REAL data as the terminal dashboard (service health, file integrity,
incidents, flag inbox, patch log, tick clock, resources) and offers the safe operator
controls: run a scope-enforced attack sweep, run a defense sweep, reveal/mark flags, and
view/validate/save config.

Every safety invariant holds exactly as in the CLI:
- bound to 127.0.0.1 only; mutating actions require the one-time token printed at startup;
- scope is fail-closed (out-of-scope sweeps refused); AETHER NEVER auto-submits flags
  (``mark`` only records what the operator did on the portal);
- config save refuses to disable scope enforcement or empty the target list (fail closed),
  and auto-submit can never be turned on.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import psutil

from ..core.config_manager import assess_readiness, load_config
from ..core.models import SubmissionStatus
from ..core.orchestrator import Orchestrator
from ..scoring.timing import TickClock
from .web_page import PAGE


class Backend:
    """Holds a persistent orchestrator on a background asyncio loop; callable from threads."""

    def __init__(self, cfg, config_path: Path) -> None:
        self.cfg = cfg
        self.config_path = Path(config_path)
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._runner, daemon=True)
        self.orch = None
        self.inbox = None
        self.defense = None
        self.sweeps = 0
        self.started = time.time()
        # Live attack panel state (updated from the sweep's progress callback).
        self._attack_lock = threading.Lock()
        self._attack_future = None
        self.rounds = 0
        self.attack: dict = {"status": "idle", "log": []}

    # --- lifecycle --------------------------------------------------------------------
    def start(self) -> None:
        self._thread.start()
        self._call(self._startup(), timeout=20)
        psutil.cpu_percent(interval=None)  # prime

    def _runner(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _call(self, coro, timeout: float = 120):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout=timeout)

    async def _startup(self) -> None:
        from ..attack.flags.inbox import FlagInbox
        from ..attack.flags.validator import FlagValidator
        from ..defense.engine import DefenseEngine

        self.orch = Orchestrator(self.cfg)
        await self.orch.start()
        self.inbox = FlagInbox(self.orch.state, FlagValidator(self.cfg.flags.pattern),
                               events=self.orch.events)
        self.defense = DefenseEngine(self.orch)
        for t in self.cfg.scope.targets:
            notes = getattr(t, "notes", None)
            if t.owner == "self" and notes and Path(notes).exists():
                self.defense.watch_path(t.name, notes)

    def shutdown(self) -> None:
        try:
            self._call(self.orch.shutdown(), timeout=10)
        except Exception:  # noqa: BLE001
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)

    # --- read snapshots ---------------------------------------------------------------
    def state(self) -> dict:
        return self._call(self._state())

    async def _state(self) -> dict:
        from .dashboard import _gather

        self.sweeps += 1
        incidents, health, functional, integrity, flags, mods = await _gather(
            self.defense, self.orch.state, None)
        tick = TickClock(self.cfg.scoring.tick_seconds, self.cfg.scoring.epoch)
        tinfo = tick.info() if tick.configured else None
        vm = psutil.virtual_memory()
        try:
            rss = psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:  # noqa: BLE001
            rss = 0.0

        by_val: dict[str, int] = {}
        by_sub: dict[str, int] = {}
        for f in flags:
            by_val[f["validation"]] = by_val.get(f["validation"], 0) + 1
            by_sub[f["submission"]] = by_sub.get(f["submission"], 0) + 1

        try:
            shells = self.defense.scan_webshells()
        except Exception:  # noqa: BLE001
            shells = []

        return {
            "tick": (None if tinfo is None else
                     {"tick": tinfo.tick, "next_in": round(tinfo.seconds_to_next, 1)}),
            "sweeps": self.sweeps,
            "uptime": int(time.time() - self.started),
            "incidents": [{"severity": getattr(i.severity, "value", str(i.severity)),
                           "kind": i.kind, "summary": i.summary} for i in incidents],
            "services": [{"service": h.service, "up": bool(h.up),
                          "latency_ms": round(h.latency_ms, 1),
                          "functional": (None if functional.get(h.service) is None else
                                         bool(functional[h.service].passed))}
                         for h in health],
            "integrity": [{"path": name, "baseline": bn,
                           "clean": bool(rep.clean),
                           "added": len(rep.added), "modified": len(rep.modified),
                           "removed": len(rep.removed)}
                          for name, (bn, rep) in integrity.items()],
            "flags": {"total": len(flags), "by_validation": by_val, "by_submission": by_sub},
            "webshells": [{"path": h.path, "abs_path": h.abs_path,
                           "signatures": list(h.signatures), "snippet": h.snippet}
                          for h in shells],
            "mods": [{"ts": (m.get("ts") or "")[11:19], "component": m.get("component", ""),
                      "action": m.get("action", ""), "target": m.get("target") or ""}
                     for m in mods[:8]],
            "resources": {"cpu": psutil.cpu_percent(interval=None),
                          "mem_percent": vm.percent,
                          "mem_free_mib": vm.available // (1024 * 1024),
                          "rss_mib": round(rss)},
        }

    def flags(self, show: bool) -> dict:
        return self._call(self._flags(show))

    async def _flags(self, show: bool) -> dict:
        rows = await self.inbox.list()
        out = []
        for r in rows:
            val = r["value"] if show else (r["value"][:6] + "…" + "•" * 4)
            out.append({"key": r["dedup_key"], "key_short": r["dedup_key"][:10],
                        "value": val, "target": r["target"], "module": r["module"],
                        "validation": r["validation"], "submission": r["submission"],
                        "tick": r["tick"] or "-", "seen": r["seen_count"]})
        return {"flags": out, "revealed": show}

    def config_view(self) -> dict:
        r = assess_readiness(self.cfg)
        try:
            text = self.config_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        return {
            "path": str(self.config_path), "ready": r.ready,
            "issues": r.issues, "warnings": r.warnings, "yaml": text,
            "pattern": self.cfg.flags.pattern, "tick": self.cfg.scoring.tick_seconds,
            "enforce": self.cfg.scope.enforce,
            "targets": [{"name": t.name, "host": t.host,
                         "ports": list(t.ports), "kind": t.kind, "owner": t.owner}
                        for t in self.cfg.scope.targets],
        }

    # --- mutating actions (token-gated) -----------------------------------------------
    def start_sweep(self, host: str, port: int | None, tools: bool = True) -> dict:
        """Kick off a sweep in the background and stream progress via :meth:`attack_progress`.

        The scope check is synchronous so an out-of-scope request is refused immediately
        (fail closed). An in-scope sweep runs on the background loop; the UI polls
        ``/api/attack/progress`` to watch it live.
        """
        port_by_host = {t.host: (t.ports[0] if t.ports else 80) for t in self.cfg.scope.targets}
        p = port or port_by_host.get(host, 80)
        with self._attack_lock:
            if self.attack.get("status") == "running":
                return {"error": "a sweep is already running — wait for it to finish"}
        if not self.orch.scope.check(host, p).allowed:
            return {"error": f"{host}:{p} is NOT in authorized scope (fail closed)"}
        with self._attack_lock:
            self.rounds += 1
            self.attack = {
                "status": "running", "host": host, "port": p, "round": self.rounds,
                "phase": "queued", "index": 0, "total": 0, "current": "",
                "confirmed": [], "flags": 0, "authenticated": False, "login_as": None,
                "summary": "", "started": time.time(), "open_ports": [], "fingerprints": [],
                "log": [f"round {self.rounds}: ▶ sweep {host}:{p}"
                        + (" (tools + recon + login + arsenal)" if tools
                           else " (recon + login + arsenal)")],
            }
        self._attack_future = asyncio.run_coroutine_threadsafe(
            self._sweep_tracked(host, p, tools), self.loop)
        return {"started": True, "host": host, "port": p, "round": self.rounds}

    def attack_progress(self) -> dict:
        with self._attack_lock:
            snap = dict(self.attack)
            snap["log"] = list(self.attack.get("log", []))
            snap["confirmed"] = list(self.attack.get("confirmed", []))
            return snap

    def _on_progress(self, ev: dict) -> None:
        phase = ev.get("phase", "")
        with self._attack_lock:
            a = self.attack
            a["phase"] = phase
            log = a.setdefault("log", [])
            if phase == "tools":
                log.append("• tools: running external scanners (nmap/rustscan/gobuster/whatweb)…")
            elif phase == "tools_done":
                log.append(f"• tools: {ev.get('ports', 0)} open port(s), "
                           f"{ev.get('paths', 0)} path(s), {ev.get('tech', 0)} tech token(s)")
            elif phase == "recon":
                log.append("• recon: crawling the target…")
            elif phase == "recon_done":
                log.append(f"• recon: {ev.get('endpoints', 0)} endpoint(s), "
                           f"{ev.get('params', 0)} param(s)")
            elif phase == "login":
                log.append("• login: attempting authentication…")
            elif phase == "login_done":
                a["authenticated"] = bool(ev.get("authenticated"))
                a["login_as"] = ev.get("as")
                log.append(f"✓ logged in as {ev.get('as')}" if ev.get("authenticated")
                           else "• login: no credentials worked")
            elif phase == "arsenal":
                a["total"] = ev.get("total", 0)
                log.append(f"• arsenal: {ev.get('total', 0)} module(s) to run")
            elif phase == "module_start":
                a["index"] = ev.get("index", a.get("index", 0))
                a["total"] = ev.get("total", a.get("total", 0))
                a["current"] = ev.get("module", "")
            elif phase == "module":
                a["index"] = ev.get("index", a.get("index", 0))
                if ev.get("confirmed"):
                    mod = ev.get("module", "")
                    if mod not in a["confirmed"]:
                        a["confirmed"].append(mod)
                    a["flags"] += ev.get("flags", 0)
                    log.append(f"  ✓ {mod} CONFIRMED ({ev.get('flags', 0)} flag)")
            if len(log) > 80:
                a["log"] = log[-80:]

    async def _sweep_tracked(self, host: str, port: int, tools: bool = True) -> None:
        from ..attack.engine import AttackEngine
        from ..attack.memory import ExploitMemory
        from ..attack.sweep import AttackSweep
        from ..core.plugin import RunContext

        kind_by_host = {t.host: t.kind for t in self.cfg.scope.targets}
        try:
            sweep = AttackSweep(AttackEngine(self.orch, self.inbox),
                                memory=ExploitMemory(self.orch.state))
            report = await sweep.run(
                RunContext(target_host=host, target_port=port,
                           service=kind_by_host.get(host, "web")),
                recon=True, login=True, tools=tools, progress=self._on_progress)
            with self._attack_lock:
                a = self.attack
                a["status"] = "done"
                a["phase"] = "done"
                a["summary"] = report.summary()
                a["confirmed"] = list(report.confirmed_modules)
                a["flags"] = len(report.flags_found)
                a["authenticated"] = report.authenticated
                a["login_as"] = report.login_as
                a["open_ports"] = list(report.open_ports)
                a["fingerprints"] = list(report.fingerprints)
                a.setdefault("log", []).append(
                    f"✓ done — {report.summary()} → check the Flags tab (PENDING; you submit)")
        except Exception as exc:  # noqa: BLE001
            with self._attack_lock:
                self.attack["status"] = "error"
                self.attack["phase"] = "error"
                self.attack["summary"] = f"{type(exc).__name__}: {exc}"
                self.attack.setdefault("log", []).append(f"✗ {type(exc).__name__}: {exc}")

    def quarantine(self, abs_path: str) -> dict:
        return self._call(self._quarantine(abs_path), timeout=120)

    async def _quarantine(self, abs_path: str) -> dict:
        if not abs_path:
            return {"error": "no path given"}
        # Only quarantine a file inside one of our watched (self-owned) roots — fail closed.
        from pathlib import Path as _P
        target = _P(abs_path).resolve()
        roots = [r.resolve() for r in self.defense._roots.values()]
        if not any(str(target).startswith(str(r) + "/") or target == r for r in roots):
            return {"error": "refused: path is not inside a watched self-owned root"}
        result = await self.defense.quarantine_webshell(target)
        return {"outcome": result.outcome.value, "safe": result.safe,
                "steps": result.steps, "detail": result.detail}

    def defense_sweep(self) -> dict:
        return self._call(self._defense_sweep())

    async def _defense_sweep(self) -> dict:
        incidents = await self.defense.sweep()
        return {"incidents": len(incidents)}

    def mark(self, key: str, status: str) -> dict:
        return self._call(self._mark(key, status))

    async def _mark(self, key: str, status: str) -> dict:
        try:
            st = SubmissionStatus(status)
        except ValueError:
            return {"error": f"invalid status {status!r}"}
        ok = await self.inbox.mark_submitted(key, st)
        return {"ok": bool(ok)}

    def config_apply(self, data: dict) -> dict:
        """Build config from the dashboard's structured form, then save it (fail-closed).

        Preserves the existing engine/scoring settings and only rewrites the operator-facing
        bits (scope targets, flag pattern, tick, enforce). Reuses :meth:`config_save` so the
        same guards apply: auto-submit stays off, scope can't be disabled or emptied.
        """
        import yaml

        cfg = self.cfg
        try:
            enforce = bool(data.get("enforce", True))
            pattern = (data.get("pattern") or "").strip() or None
            tick_raw = data.get("tick")
            tick = int(tick_raw) if str(tick_raw).strip() not in ("", "None", "0") else None
            targets_in = data.get("targets") or []
        except (TypeError, ValueError) as exc:
            return {"error": f"bad input: {exc}"}

        targets: list[dict] = []
        for t in targets_in:
            name = str(t.get("name", "")).strip()
            host = str(t.get("host", "")).strip()
            if not name or not host:
                return {"error": "every target needs both a name and a host"}
            ports_raw = t.get("ports")
            try:
                if isinstance(ports_raw, str):
                    ports = [int(x) for x in ports_raw.replace(" ", "").split(",") if x]
                else:
                    ports = [int(x) for x in (ports_raw or [])]
            except ValueError:
                return {"error": f"target '{name}': ports must be numbers"}
            tgt = {"name": name, "host": host, "ports": ports,
                   "kind": (str(t.get("kind", "web")).strip() or "web"),
                   "owner": (str(t.get("owner", "opponent")).strip() or "opponent")}
            notes = str(t.get("notes", "")).strip()
            if notes:
                tgt["notes"] = notes
            targets.append(tgt)

        doc = {
            "engine": {"max_concurrency": cfg.engine.max_concurrency,
                       "default_timeout": cfg.engine.default_timeout,
                       "state_db": cfg.engine.state_db,
                       "log_file": cfg.engine.log_file,
                       "log_level": cfg.engine.log_level},
            "scope": {"enforce": enforce, "targets": targets},
            "flags": {"pattern": pattern, "auto_submit": False},
            "scoring": {"tick_seconds": tick, "epoch": cfg.scoring.epoch,
                        "expiry_ticks": cfg.scoring.expiry_ticks,
                        "submit_endpoint": cfg.scoring.submit_endpoint,
                        "scoreboard_endpoint": cfg.scoring.scoreboard_endpoint}}
        text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
        return self.config_save(text)

    def config_save(self, yaml_text: str) -> dict:
        import tempfile

        tmp = Path(tempfile.gettempdir()) / f"aether_cfg_{secrets.token_hex(6)}.yaml"
        tmp.write_text(yaml_text, encoding="utf-8")
        try:
            cfg = load_config(tmp)  # raises on auto_submit=true and on parse errors
        except Exception as exc:  # noqa: BLE001
            return {"error": f"invalid config: {exc}"}
        finally:
            tmp.unlink(missing_ok=True)
        # Fail-closed guard: the web UI must never be able to loosen scope.
        if not cfg.scope.enforce:
            return {"error": "refused: scope.enforce=false would disable fail-closed scope"}
        if not cfg.scope.targets:
            return {"error": "refused: empty scope.targets (fail closed)"}
        self.config_path.write_text(yaml_text, encoding="utf-8")
        self.cfg = cfg  # new sweeps read this; restart the console to re-arm the live engine
        r = assess_readiness(cfg)
        return {"ok": True, "ready": r.ready, "issues": r.issues, "warnings": r.warnings,
                "note": "saved — restart the web console to apply scope to the live engine"}


def _make_handler(backend: Backend, token: str):
    def _json(h, obj, status=200):
        data = json.dumps(obj).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    class _H(BaseHTTPRequestHandler):
        def _authed(self) -> bool:
            if self.headers.get("X-AETHER-Token") == token:
                return True
            q = parse_qs(urlparse(self.path).query)
            return q.get("token", [""])[0] == token

        def do_GET(self):  # noqa: N802
            path = urlparse(self.path).path
            q = parse_qs(urlparse(self.path).query)
            try:
                if path in ("/", "/index.html"):
                    body = PAGE.replace("__TOKEN__", token).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path == "/api/state":
                    _json(self, backend.state())
                elif path == "/api/attack/progress":
                    _json(self, backend.attack_progress())
                elif path == "/api/flags":
                    _json(self, backend.flags(q.get("show", ["0"])[0] == "1"))
                elif path == "/api/config":
                    _json(self, backend.config_view())
                else:
                    _json(self, {"error": "not found"}, 404)
            except Exception as exc:  # noqa: BLE001
                _json(self, {"error": f"{type(exc).__name__}: {exc}"}, 500)

        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path
            if not self._authed():
                _json(self, {"error": "forbidden: missing/invalid token"}, 403)
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                payload = {}
            try:
                if path == "/api/attack/sweep":
                    _json(self, backend.start_sweep(payload.get("host", ""),
                                                    payload.get("port"),
                                                    bool(payload.get("tools", True))))
                elif path == "/api/defense/sweep":
                    _json(self, backend.defense_sweep())
                elif path == "/api/defense/quarantine":
                    _json(self, backend.quarantine(payload.get("path", "")))
                elif path == "/api/flags/mark":
                    _json(self, backend.mark(payload.get("key", ""),
                                             payload.get("status", "SUBMITTED")))
                elif path == "/api/config/save":
                    _json(self, backend.config_save(payload.get("yaml", "")))
                elif path == "/api/config/apply":
                    _json(self, backend.config_apply(payload))
                else:
                    _json(self, {"error": "not found"}, 404)
            except Exception as exc:  # noqa: BLE001
                _json(self, {"error": f"{type(exc).__name__}: {exc}"}, 500)

        def log_message(self, *args):  # silence default logging
            return

    return _H


def serve(cfg, config_path, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Start the web console (blocking). Binds localhost only and prints the access URL+token."""
    from .context import console

    if host not in ("127.0.0.1", "localhost", "::1"):
        host = "127.0.0.1"  # never expose beyond localhost
    backend = Backend(cfg, config_path)
    backend.start()
    token = secrets.token_urlsafe(16)
    httpd = ThreadingHTTPServer((host, port), _make_handler(backend, token))
    bound = httpd.server_address[1]
    url = f"http://{host}:{bound}/?token={token}"
    console.print(f"[bold green]AETHER Web Console[/] → [bold cyan]{url}[/]")
    console.print("[dim]localhost only • token-gated actions • AETHER never auto-submits • "
                  "Ctrl-C to stop[/]")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping web console…[/]")
    finally:
        httpd.shutdown()
        backend.shutdown()
