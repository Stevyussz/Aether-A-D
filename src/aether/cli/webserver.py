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
        from ..attack.oast import OastListener
        self.oast = OastListener()      # self-hosted OOB callback catcher (started on demand)
        self.sweeps = 0
        self.started = time.time()
        # Live attack panel state (updated from the sweep's progress callback).
        self._attack_lock = threading.Lock()
        self._attack_future = None
        self.rounds = 0
        self.attack: dict = {"status": "idle", "log": []}
        self.attack_loop_enabled: bool = False
        self._last_auto_sweep: float = 0.0

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
            if self.defense is not None:
                self.defense.shield.stop()
            self.oast.stop()
        except Exception:  # noqa: BLE001
            pass
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
            "guard": {
                "enabled": self.defense.auto_guard.enabled,
                "cycles": self.defense.auto_guard.cycles,
                "total_quarantined": self.defense.auto_guard.total_quarantined,
                "total_restored": self.defense.auto_guard.total_restored,
            },
            "shield": {
                "running": self.defense.shield.running,
                "enabled": self.defense.shield.enabled,
                "listen_host": self.defense.shield.listen_host,
                "listen_port": self.defense.shield.listen_port,
                "backend_host": self.defense.shield.backend_host,
                "backend_port": self.defense.shield.backend_port,
                "total_requests": self.defense.shield.total_requests,
                "blocked_requests": self.defense.shield.blocked_requests,
                "forwarded_requests": self.defense.shield.forwarded_requests,
                "recent_blocks": list(self.defense.shield.recent_blocks),
                "traffic": self.defense.shield.recorder.stats(),
            },
        }

    def traffic(self, limit: int = 40, attacks_only: bool = True) -> dict:
        if self.defense is None:
            return {"captures": [], "stats": {"total": 0, "attacks": 0, "buffered": 0}}
        rec = self.defense.shield.recorder
        return {"captures": rec.recent(limit=limit, attacks_only=attacks_only),
                "stats": rec.stats()}

    def replay(self, cap_id: int, substitutions=None) -> dict:
        return self._call(self._replay(cap_id, substitutions))

    async def _replay(self, cap_id: int, substitutions=None) -> dict:
        """Replay a captured enemy request against ALL authorized opponent targets (scope-
        enforced). Any extracted flags land in the manual inbox PENDING."""
        from ..attack.replay import ExploitReplayer
        from ..attack.flags.extractor import FlagExtractor

        if self.defense is None:
            return {"error": "defense not started"}
        cap = self.defense.shield.recorder.get(int(cap_id))
        if cap is None:
            return {"error": f"capture #{cap_id} not found"}
        targets: list[tuple[str, int]] = []
        for t in self.cfg.scope.targets:
            if t.owner == "opponent":
                for p in (t.ports or (80,)):
                    targets.append((t.host, p))
        if not targets:
            return {"error": "no opponent targets in scope to replay against"}
        subs = [(s.get("from", ""), s.get("to", "")) for s in (substitutions or [])
                if s.get("from")]
        replayer = ExploitReplayer(self.orch.scope, FlagExtractor(self.cfg.flags.pattern),
                                   inbox=self.inbox)
        report = await replayer.replay(cap, targets, substitutions=subs)
        return {"ok": True, "summary": report.summary(),
                "flags": len(report.flags_found), "sent": report.sent,
                "results": [{"host": r.host, "port": r.port, "status": r.status,
                             "flags": len(r.flags), "skipped": r.skipped, "error": r.error}
                            for r in report.results]}

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
            "flag_id_endpoint": self.cfg.scoring.flag_id_endpoint or "",
            "enforce": self.cfg.scope.enforce,
            "targets": [{"name": t.name, "host": t.host,
                         "ports": list(t.ports), "kind": t.kind, "owner": t.owner,
                         "notes": t.notes or ""}
                        for t in self.cfg.scope.targets],
        }

    # --- mutating actions (token-gated) -----------------------------------------------
    def _resolve_sweep_targets(self, host: str, port: int | None) -> tuple[list[tuple[str, int]], str | None]:
        """Resolve (host, port) pairs to sweep. Supports '*' / 'all' for all opponent targets."""
        h = (host or "").strip()
        opp_targets = [t for t in self.cfg.scope.targets if t.owner == "opponent"]
        if h in ("*", "all", "ALL"):
            pairs = [
                (t.host, p)
                for t in opp_targets
                for p in (t.ports if t.ports else (80,))
                if self.orch.scope.check(t.host, p).allowed
            ]
            pairs = list(dict.fromkeys(pairs))
            if not pairs:
                return [], "no authorized opponent targets in scope (fail closed)"
            return pairs, None

        matches = [t for t in opp_targets if t.host == h]
        if port is not None:
            p = int(port)
            if not self.orch.scope.check(h, p).allowed:
                return [], f"{h}:{p} is NOT in authorized scope (fail closed)"
            return [(h, p)], None

        if matches:
            pairs = list(
                dict.fromkeys(
                    (h, p) for m in matches for p in (m.ports if m.ports else (80,))
                )
            )
        else:
            all_matches = [t for t in self.cfg.scope.targets if t.host == h]
            p = all_matches[0].ports[0] if all_matches and all_matches[0].ports else 80
            pairs = [(h, p)]

        authorized = [(th, tp) for th, tp in pairs if self.orch.scope.check(th, tp).allowed]
        if not authorized:
            first_p = pairs[0][1] if pairs else 80
            return [], f"{h}:{first_p} is NOT in authorized scope (fail closed)"
        return authorized, None

    def start_sweep(self, host: str, port: int | None, tools: bool = True,
                    nuclei: bool = False) -> dict:
        """Kick off a sweep in the background and stream progress via :meth:`attack_progress`.

        The scope check is synchronous so an out-of-scope request is refused immediately
        (fail closed). An in-scope sweep runs on the background loop; the UI polls
        ``/api/attack/progress`` to watch it live.
        """
        with self._attack_lock:
            if self.attack.get("status") == "running":
                return {"error": "a sweep is already running — wait for it to finish"}
        pairs, err = self._resolve_sweep_targets(host, port)
        if err:
            return {"error": err}
        label = (f"ALL ({len(pairs)} target/port)" if len(pairs) > 1
                 else f"{pairs[0][0]}:{pairs[0][1]}")
        with self._attack_lock:
            self.rounds += 1
            self._last_auto_sweep = time.time()
            self.attack = {
                "status": "running", "host": pairs[0][0], "port": pairs[0][1],
                "round": self.rounds, "loop_enabled": self.attack_loop_enabled,
                "phase": "queued", "index": 0, "total": 0, "current": "",
                "confirmed": [], "flags": 0, "authenticated": False, "login_as": None,
                "summary": "", "started": time.time(), "open_ports": [], "fingerprints": [],
                "paths": [], "nuclei": [],
                "log": [f"round {self.rounds}: ▶ sweep {label}"
                        + ((" (tools+nuclei + recon + login + arsenal)" if nuclei
                            else " (tools + recon + login + arsenal)") if (tools or nuclei)
                           else " (recon + login + arsenal)")],
            }
        self._attack_future = asyncio.run_coroutine_threadsafe(
            self._sweep_tracked_multi(pairs, tools or nuclei, nuclei), self.loop)
        return {"started": True, "host": pairs[0][0], "port": pairs[0][1],
                "targets_count": len(pairs), "round": self.rounds}

    def toggle_attack_loop(self, enabled: bool | None = None) -> dict:
        with self._attack_lock:
            self.attack_loop_enabled = (
                (not self.attack_loop_enabled) if enabled is None else bool(enabled)
            )
            self.attack["loop_enabled"] = self.attack_loop_enabled
            active = self.attack_loop_enabled
            running = self.attack.get("status") == "running"
        if active and not running:
            self.start_sweep("*", None, tools=False, nuclei=False)
        return {"ok": True, "loop_enabled": active}

    def attack_progress(self) -> dict:
        if self.attack_loop_enabled:
            interval = max(15, int(self.cfg.scoring.tick_seconds or 60))
            with self._attack_lock:
                idle = self.attack.get("status") != "running"
                due = (time.time() - self._last_auto_sweep) >= interval
            if idle and due:
                self.start_sweep("*", None, tools=False, nuclei=False)
        with self._attack_lock:
            snap = dict(self.attack)
            snap["loop_enabled"] = self.attack_loop_enabled
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
                           f"{ev.get('paths', 0)} path(s), {ev.get('tech', 0)} tech token(s), "
                           f"{ev.get('nuclei', 0)} nuclei finding(s)")
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

    async def _sweep_tracked(self, host: str, port: int, tools: bool = True,
                             nuclei: bool = False) -> None:
        await self._sweep_tracked_multi([(host, port)], tools, nuclei)

    async def _sweep_tracked_multi(self, pairs: list[tuple[str, int]], tools: bool = True,
                                   nuclei: bool = False) -> None:
        from ..attack.engine import AttackEngine
        from ..attack.memory import ExploitMemory
        from ..attack.sweep import AttackSweep
        from ..core.plugin import RunContext
        from ..scoring.tick_info import TickInfoClient

        kind_by_host = {t.host: t.kind for t in self.cfg.scope.targets}
        kind_by_hp = {(t.host, p): t.kind for t in self.cfg.scope.targets for p in t.ports}
        try:
            eng = AttackEngine(self.orch, self.inbox)
            sweep = AttackSweep(eng, memory=ExploitMemory(self.orch.state))
            tick_info = TickInfoClient(self.cfg.scoring.flag_id_endpoint)
            all_confirmed: list[str] = []
            total_flags = 0
            any_auth = False
            last_login = None
            all_ports: list[dict] = []
            all_fps: list[str] = []
            all_paths: list[dict] = []
            all_nuclei: list[dict] = []
            summaries: list[str] = []

            for idx, (host, port) in enumerate(pairs, start=1):
                with self._attack_lock:
                    self.attack["host"] = host
                    self.attack["port"] = port
                    if len(pairs) > 1:
                        self.attack.setdefault("log", []).append(
                            f"▶ [{idx}/{len(pairs)}] sweeping {host}:{port} …"
                        )
                svc_kind = kind_by_hp.get((host, port), kind_by_host.get(host, "web"))
                run_extra: dict = {"tool_nuclei": nuclei}
                fids = await tick_info.fetch_for(host, svc_kind)
                if fids:
                    run_extra["flag_ids"] = fids
                report = await sweep.run(
                    RunContext(target_host=host, target_port=port,
                               service=svc_kind,
                               extra=run_extra),
                    recon=True, login=True, tools=tools, progress=self._on_progress)
                for m in report.confirmed_modules:
                    if m not in all_confirmed:
                        all_confirmed.append(m)
                total_flags += len(report.flags_found)
                if report.authenticated:
                    any_auth = True
                    last_login = report.login_as
                all_ports.extend(report.open_ports)
                all_fps.extend(report.fingerprints)
                all_paths.extend(report.discovered_paths_tool)
                all_nuclei.extend(report.nuclei)
                summaries.append(report.summary())

            final_summary = (summaries[0] if len(summaries) == 1
                             else f"swept {len(pairs)} target(s): {len(all_confirmed)} confirmed, {total_flags} flag(s)")
            with self._attack_lock:
                a = self.attack
                a["status"] = "done"
                a["phase"] = "done"
                a["summary"] = final_summary
                a["confirmed"] = all_confirmed
                a["flags"] = total_flags
                a["authenticated"] = any_auth
                a["login_as"] = last_login
                a["open_ports"] = all_ports
                a["fingerprints"] = list(dict.fromkeys(all_fps))
                a["paths"] = all_paths
                a["nuclei"] = all_nuclei
                a.setdefault("log", []).append(
                    f"✓ done — {final_summary} → check the Flags tab (PENDING; you submit)")
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

    def audit(self) -> dict:
        return self._call(self._audit(), timeout=120)

    async def _audit(self) -> dict:
        findings = self.defense.audit_sources()
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {"by_severity": by_sev,
                "findings": [{"severity": f.severity, "category": f.category, "path": f.path,
                              "line": f.line, "snippet": f.snippet,
                              "remediation": f.remediation} for f in findings]}

    def defense_sweep(self) -> dict:
        return self._call(self._defense_sweep())

    async def _defense_sweep(self) -> dict:
        incidents = await self.defense.sweep()
        return {"incidents": len(incidents)}

    def defense_guard(self, enabled: bool | None = None) -> dict:
        return self._call(self._defense_guard(enabled), timeout=120)

    async def _defense_guard(self, enabled: bool | None = None) -> dict:
        if enabled is not None:
            self.defense.auto_guard.set_enabled(enabled)
        rep = await self.defense.auto_guard_once()
        return {
            "enabled": self.defense.auto_guard.enabled,
            "roots_checked": rep.roots_checked,
            "files_quarantined": rep.files_quarantined,
            "files_restored": rep.files_restored,
            "protected_skipped": rep.protected_skipped,
            "errors": rep.errors,
            "actions_taken": rep.actions_taken,
        }

    def defense_shield(self, payload: dict) -> dict:
        action = str(payload.get("action", "toggle")).strip().lower()
        sh = self.defense.shield
        if action == "start":
            lhost = str(payload.get("listen_host", "0.0.0.0") or "0.0.0.0").strip()
            lport = int(payload.get("listen_port", 8080) or 8080)
            bhost = str(payload.get("backend_host", "127.0.0.1") or "127.0.0.1").strip()
            bport = int(payload.get("backend_port", 8000) or 8000)
            if "enabled" in payload and payload["enabled"] is not None:
                sh.set_enabled(bool(payload["enabled"]))
            if payload.get("allow_ips") is not None or payload.get("allow_paths") is not None:
                sh.set_allowlist(ips=payload.get("allow_ips"), paths=payload.get("allow_paths"))
            bound = sh.start(lhost, lport, bhost, bport)
            return {"ok": True, "running": sh.running, "enabled": sh.enabled, "listen_port": bound}
        if action == "stop":
            sh.stop()
            return {"ok": True, "running": sh.running, "enabled": sh.enabled}
        if action == "allowlist":
            al = sh.set_allowlist(ips=payload.get("allow_ips"), paths=payload.get("allow_paths"))
            return {"ok": True, "allowlist": al}
        # Default: toggle or set enabled ON/OFF
        new_state = (not sh.enabled) if payload.get("enabled") is None else bool(payload["enabled"])
        sh.set_enabled(new_state)
        return {"ok": True, "running": sh.running, "enabled": sh.enabled}

    def mark(self, key: str, status: str) -> dict:
        return self._call(self._mark(key, status))

    async def _mark(self, key: str, status: str) -> dict:
        try:
            st = SubmissionStatus(status)
        except ValueError:
            return {"error": f"invalid status {status!r}"}
        ok = await self.inbox.mark_submitted(key, st)
        return {"ok": bool(ok)}

    def submit_flags(self, limit=None) -> dict:
        return self._call(self._submit_flags(limit))

    async def _submit_flags(self, limit=None) -> dict:
        """Submit VALIDATED+PENDING flags to the official organizer (fail-closed via config)."""
        from ..scoring.submitter import FlagSubmitter, submit_config_from

        scfg = submit_config_from(self.cfg.submission)
        ok, reason = scfg.ready()
        if not ok:
            return {"error": f"submission not armed: {reason}"}
        report = await FlagSubmitter(self.inbox, scfg).submit_pending(limit=limit)
        if report.refused:
            return {"error": report.refused}
        return {"ok": True, "attempted": report.attempted, "accepted": report.accepted,
                "rejected": report.rejected, "expired": report.expired,
                "unknown": report.submitted, "errors": report.errors,
                "summary": report.summary()}

    def oast_view(self, limit: int = 40) -> dict:
        return {"stats": self.oast.stats(),
                "interactions": self.oast.interactions(limit=limit, include_body=True)}

    def oast_control(self, data: dict) -> dict:
        """Start/stop the OOB listener, mint a callback URL, or clear interactions."""
        action = (data.get("action") or "").lower()
        if action == "start":
            port = int(data.get("listen_port") or 0)
            pub = (data.get("pub_host") or "").strip() or None
            bound = self.oast.start(listen_host="0.0.0.0", listen_port=port, pub_host=pub)
            return {"ok": True, "running": True, "listen_port": bound,
                    "pub_host": self.oast.pub_host}
        if action == "stop":
            self.oast.stop()
            return {"ok": True, "running": False}
        if action == "clear":
            self.oast.clear()
            return {"ok": True}
        if action == "token":
            if not self.oast.running:
                return {"error": "start the OAST listener first"}
            tok = self.oast.new_token()
            return {"ok": True, "token": tok, "url": self.oast.payload_url(tok)}
        return {"error": f"unknown action {action!r}"}

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
            if "flag_id_endpoint" in data:
                flag_id_ep = (str(data.get("flag_id_endpoint") or "").strip() or None)
            else:
                flag_id_ep = cfg.scoring.flag_id_endpoint
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
                        "flag_id_endpoint": flag_id_ep,
                        "submit_endpoint": cfg.scoring.submit_endpoint,
                        "scoreboard_endpoint": cfg.scoring.scoreboard_endpoint}}
        text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
        return self.config_save(text)

    def config_save(self, yaml_text: str) -> dict:
        import tempfile
        from ..attack.flags.validator import FlagValidator
        from .context import DEFAULT_CONFIG, EXAMPLE_CONFIG

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
        # Never overwrite the example template — promote to config/aether.yaml automatically.
        if self.config_path.resolve() == EXAMPLE_CONFIG.resolve():
            self.config_path = DEFAULT_CONFIG
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(yaml_text, encoding="utf-8")
        self.cfg = cfg
        # Hot-reload the live engine so operator changes take effect immediately without restart.
        if self.orch is not None:
            self.orch.config = cfg
            self.orch.scope._enforce = cfg.scope.enforce
            self.orch.scope.load_targets(cfg.scope.targets)
        if self.inbox is not None:
            self.inbox._validator = FlagValidator(cfg.flags.pattern)
        if self.defense is not None:
            active_self: set[str] = set()
            for t in cfg.scope.targets:
                notes = getattr(t, "notes", None)
                if t.owner == "self" and notes and Path(notes).exists():
                    active_self.add(t.name)
                    if t.name not in self.defense._roots or self.defense._roots[t.name] != Path(notes):
                        self.defense.watch_path(t.name, notes)
            for old_name in list(self.defense._roots.keys()):
                if old_name not in active_self:
                    self.defense._roots.pop(old_name, None)
                    self.defense.integrity.pop(old_name, None)
        r = assess_readiness(cfg)
        return {"ok": True, "ready": r.ready, "issues": r.issues, "warnings": r.warnings,
                "note": "saved and applied to live engine"}


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
                elif path == "/api/defense/traffic":
                    _json(self, backend.traffic(
                        attacks_only=q.get("all", ["0"])[0] != "1"))
                elif path == "/api/attack/oast":
                    _json(self, backend.oast_view())
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
                                                    bool(payload.get("tools", True)),
                                                    bool(payload.get("nuclei", False))))
                elif path == "/api/attack/loop":
                    _json(self, backend.toggle_attack_loop(payload.get("enabled")))
                elif path == "/api/defense/sweep":
                    _json(self, backend.defense_sweep())
                elif path == "/api/defense/guard":
                    _json(self, backend.defense_guard(payload.get("enabled")))
                elif path == "/api/defense/shield":
                    _json(self, backend.defense_shield(payload))
                elif path == "/api/defense/quarantine":
                    _json(self, backend.quarantine(payload.get("path", "")))
                elif path == "/api/defense/audit":
                    _json(self, backend.audit())
                elif path == "/api/flags/mark":
                    _json(self, backend.mark(payload.get("key", ""),
                                             payload.get("status", "SUBMITTED")))
                elif path == "/api/flags/submit":
                    _json(self, backend.submit_flags(payload.get("limit")))
                elif path == "/api/attack/replay":
                    _json(self, backend.replay(payload.get("id"),
                                               payload.get("substitutions")))
                elif path == "/api/attack/oast":
                    _json(self, backend.oast_control(payload))
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
