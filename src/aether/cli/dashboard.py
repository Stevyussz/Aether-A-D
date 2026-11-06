"""Live defense monitoring dashboard.

Renders a continuously-updating operator screen with REAL data gathered from the running
engine and persistent state — service health, file-integrity status, incidents, flag-inbox
statistics, the modification/patch log, competition tick timing, and host resources. Nothing
is faked: every number comes from an actual probe, scan, or state query. Remediation stays
operator-gated — the dashboard observes, it never patches on its own.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import psutil
from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.models import FlagValidation, SubmissionStatus
from ..core.orchestrator import Orchestrator
from ..scoring.timing import TickClock
from .context import console

_SEV_STYLE = {"CRITICAL": "bold red", "WARNING": "yellow", "INFO": "cyan"}


def _header(cfg, tick: TickClock, sweeps: int, started: float, last_incident_count: int) -> Panel:
    now = time.time()
    t = Text()
    t.append("AETHER ", style="bold cyan")
    t.append("DEFENSE MONITOR", style="bold white")
    t.append("   •   ", style="dim")
    info = tick.info() if tick.configured else None
    if info is not None:
        t.append(f"tick {info.tick}", style="bold green")
        t.append(f"  (next in {info.seconds_to_next:4.0f}s)", style="dim")
    else:
        t.append("tick: not configured", style="yellow")
    t.append("   •   ", style="dim")
    t.append(f"sweeps {sweeps}", style="bold")
    t.append(f"   •   uptime {int(now - started)}s", style="dim")
    t.append(f"   •   {datetime.now().strftime('%H:%M:%S')}", style="dim")
    t.append("   •   ", style="dim")
    t.append(f"incidents(now) {last_incident_count}",
             style="bold red" if last_incident_count else "green")
    return Panel(t, border_style="cyan")


def _services_panel(health: list, functional: dict) -> Panel:
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("service")
    table.add_column("health")
    table.add_column("latency")
    table.add_column("functional")
    if not health:
        table.add_row("[dim]—[/]", "[dim]no probes[/]", "", "")
    for h in health:
        up = "[green]● UP[/]" if h.up else "[red]● DOWN[/]"
        fr = functional.get(h.service)
        if fr is None:
            fcell = "[dim]n/a[/]"
        elif fr.passed:
            fcell = "[green]pass[/]"
        else:
            fcell = f"[red]FAIL[/] ({', '.join(fr.failed_checks) or 'checks'})"
        table.add_row(h.service, up, f"{h.latency_ms:.0f} ms", fcell)
    return Panel(table, title="[bold]services[/]", border_style="green")


def _integrity_panel(integrity: dict) -> Panel:
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("path")
    table.add_column("baseline")
    table.add_column("status")
    if not integrity:
        table.add_row("[dim]—[/]", "", "[dim]no paths watched[/]")
    for name, (baseline_n, report) in integrity.items():
        if report.clean:
            status = "[green]clean[/]"
        else:
            parts = []
            if report.added:
                parts.append(f"+{len(report.added)} added")
            if report.modified:
                parts.append(f"~{len(report.modified)} modified")
            if report.removed:
                parts.append(f"-{len(report.removed)} removed")
            status = "[red]" + ", ".join(parts) + "[/]"
        table.add_row(name, f"{baseline_n} files", status)
    return Panel(table, title="[bold]file integrity[/]", border_style="green")


def _incidents_panel(incidents: list) -> Panel:
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("severity")
    table.add_column("kind")
    table.add_column("summary")
    if not incidents:
        table.add_row("[green]OK[/]", "[dim]—[/]", "[dim]no incidents this sweep[/]")
    for inc in incidents:
        sev = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
        table.add_row(f"[{_SEV_STYLE.get(sev, 'white')}]{sev}[/]", inc.kind, inc.summary)
    return Panel(table, title="[bold]incidents (latest sweep)[/]", border_style="red")


def _flags_panel(flags: list) -> Panel:
    by_val = {v.value: 0 for v in FlagValidation}
    by_sub = {s.value: 0 for s in SubmissionStatus}
    for f in flags:
        by_val[f["validation"]] = by_val.get(f["validation"], 0) + 1
        by_sub[f["submission"]] = by_sub.get(f["submission"], 0) + 1
    table = Table(show_header=False, box=None, expand=True)
    table.add_column(style="dim")
    table.add_column(justify="right", style="bold")
    table.add_row("total flags", str(len(flags)))
    table.add_row("VALIDATED", f"[green]{by_val.get('VALIDATED', 0)}[/]")
    table.add_row("UNVERIFIED", f"[yellow]{by_val.get('UNVERIFIED', 0)}[/]")
    table.add_row("PENDING submit", f"[bold yellow]{by_sub.get('PENDING', 0)}[/]")
    table.add_row("SUBMITTED/ACCEPTED",
                  f"{by_sub.get('SUBMITTED', 0)}/{by_sub.get('ACCEPTED', 0)}")
    return Panel(table, title="[bold]flag inbox[/]", border_style="magenta")


def _mods_panel(mods: list) -> Panel:
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("time", no_wrap=True)
    table.add_column("component")
    table.add_column("action")
    table.add_column("target")
    if not mods:
        table.add_row("[dim]—[/]", "[dim]no changes logged[/]", "", "")
    for m in mods[:6]:
        ts = (m.get("ts") or "")[11:19]
        table.add_row(ts, m.get("component", ""), m.get("action", ""), m.get("target") or "")
    return Panel(table, title="[bold]modification / patch log[/]", border_style="blue")


def _footer() -> Panel:
    vm = psutil.virtual_memory()
    try:
        rss = psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:  # noqa: BLE001
        rss = 0.0
    cpu = psutil.cpu_percent(interval=None)
    t = Text()
    t.append(f"cpu {cpu:4.1f}%", style="bold")
    t.append(f"   mem {vm.percent:4.1f}% used ({vm.available // (1024 * 1024)} MiB free)",
             style="dim")
    t.append(f"   aether RSS {rss:.0f} MiB", style="dim")
    t.append("    remediation is operator-gated — AETHER never patches on its own",
             style="italic dim")
    return Panel(t, border_style="dim")


async def _gather(engine, state, log_text):
    incidents = await engine.sweep(log_text=log_text)
    health = await engine.health.check_all() if engine.health._probes else []
    functional = {}
    for svc in list(getattr(engine.functional, "_suites", {})):
        try:
            functional[svc] = await engine.functional.verify(svc)
        except Exception:  # noqa: BLE001
            pass
    integrity = {name: (len(mon._baseline), mon.scan()) for name, mon in engine.integrity.items()}
    flags = await state.list_flags()
    mods = await state.list_modifications()
    return incidents, health, functional, integrity, flags, mods


def _build(cfg, tick, sweeps, started, data) -> Group:
    incidents, health, functional, integrity, flags, mods = data
    return Group(
        _header(cfg, tick, sweeps, started, len(incidents)),
        Columns([_services_panel(health, functional), _integrity_panel(integrity)],
                equal=True, expand=True),
        _incidents_panel(incidents),
        Columns([_flags_panel(flags), _mods_panel(mods)], equal=True, expand=True),
        _footer(),
    )


async def run_dashboard(cfg, interval: float = 5.0, duration: float = 0.0,
                        once: bool = False, log_text: str | None = None,
                        stop_flag: Path | None = None) -> None:
    """Run the live defense dashboard until stopped/duration reached (or a single frame)."""
    import asyncio

    from ..defense.engine import DefenseEngine

    orch = Orchestrator(cfg)
    await orch.start()
    engine = DefenseEngine(orch)
    for t in cfg.scope.targets:
        if t.owner == "self" and getattr(t, "notes", None) and Path(t.notes).exists():
            engine.watch_path(t.name, t.notes)
    tick = TickClock(cfg.scoring.tick_seconds, cfg.scoring.epoch)
    started = time.time()
    sweeps = 0
    psutil.cpu_percent(interval=None)  # prime cpu reading

    try:
        if once:
            sweeps = 1
            data = await _gather(engine, orch.state, log_text)
            console.print(_build(cfg, tick, sweeps, started, data))
            return
        with Live(console=console, screen=True, refresh_per_second=4, transient=True) as live:
            while True:
                sweeps += 1
                data = await _gather(engine, orch.state, log_text)
                live.update(_build(cfg, tick, sweeps, started, data))
                if duration and (time.time() - started) >= duration:
                    break
                if stop_flag is not None and stop_flag.exists():
                    stop_flag.unlink()
                    break
                await asyncio.sleep(interval)
    finally:
        await orch.shutdown()
    console.print(f"[dim]dashboard stopped after {sweeps} sweep(s).[/]")
