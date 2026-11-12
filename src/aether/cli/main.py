"""AETHER A&D command-line interface (Typer + Rich).

Commands are grouped into sub-apps. Each command does real work backed by the core engine;
attack/defense/flags/monitor commands are registered by their respective phase modules.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import typer
from rich.panel import Panel
from rich.table import Table

from .. import __version__
from ..core.config_manager import assess_readiness
from ..core.module_loader import ModuleLoader
from .context import DEFAULT_CONFIG, EXAMPLE_CONFIG, console, err_console, load_cli_config

app = typer.Typer(
    name="aether",
    help="AETHER A&D — competition-grade Attack & Defense CTF framework (no AI runtime).",
    no_args_is_help=False,
    add_completion=False,
)

system_app = typer.Typer(help="System / environment checks.", no_args_is_help=True)
config_app = typer.Typer(help="Configuration management.", no_args_is_help=True)
scope_app = typer.Typer(help="Authorized-scope inspection.", no_args_is_help=True)
modules_app = typer.Typer(help="Module/plugin inspection and self-test.", no_args_is_help=True)
defense_app = typer.Typer(help="Defense engine status.", no_args_is_help=True)
attack_app = typer.Typer(help="Attack engine status.", no_args_is_help=True)
flags_app = typer.Typer(help="Manual flag inbox (operator submits — AETHER never does).",
                        no_args_is_help=True)
scoring_app = typer.Typer(help="Scoring & competition timing.", no_args_is_help=True)
monitor_app = typer.Typer(help="Defense monitoring loop.", no_args_is_help=True)
report_app = typer.Typer(help="Operator reports.", no_args_is_help=True)
lab_app = typer.Typer(help="Isolated local lab self-test.", no_args_is_help=True)

_MONITOR_STOP_FLAG = Path("runtime/monitor.stop")
_ATTACK_STOP_FLAG = Path("runtime/attack.stop")

app.add_typer(system_app, name="system")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")
app.add_typer(modules_app, name="modules")
app.add_typer(defense_app, name="defense")
app.add_typer(attack_app, name="attack")
app.add_typer(flags_app, name="flags")
app.add_typer(scoring_app, name="scoring")
app.add_typer(monitor_app, name="monitor")
app.add_typer(report_app, name="report")
app.add_typer(lab_app, name="lab")


def _build_loader() -> ModuleLoader:
    loader = ModuleLoader()
    # Discover built-in modules from attack/defense packages as they are implemented.
    for pkg in ("aether.attack", "aether.defense"):
        loader.discover(pkg)
    return loader


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    """Launch the interactive control console when run with no subcommand."""
    if ctx.invoked_subcommand is None:
        from .menu import run_menu
        run_menu()


@app.command()
def menu() -> None:
    """Open the interactive operator console (ASCII home + guided control menu)."""
    from .menu import run_menu
    run_menu()


@app.command()
def version() -> None:
    """Print the AETHER version."""
    console.print(f"AETHER A&D v{__version__}")


@app.command()
def web(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    port: int = typer.Option(8787, "--port", "-p", help="Local port (localhost only)."),
) -> None:
    """Launch the AETHER Web Console — a browser dashboard with monitoring + safe controls.

    Serves on 127.0.0.1 ONLY and prints a tokenised URL. Shows live monitoring (health,
    integrity, incidents, flags, patch log, tick, resources) and offers scope-enforced attack
    sweeps, defense sweeps, flag review/mark, and config view/validate/save — never
    auto-submitting and never loosening scope.
    """
    try:
        cfg, path = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)
    from .webserver import serve
    serve(cfg, path, port=port)


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config."),
) -> None:
    """Initialize the working directory (runtime dir + config from example)."""
    Path("runtime").mkdir(exist_ok=True)
    console.print("[green]✓[/] runtime/ directory ready")

    if DEFAULT_CONFIG.exists() and not force:
        console.print(f"[yellow]•[/] {DEFAULT_CONFIG} already exists (use --force to replace)")
    elif EXAMPLE_CONFIG.exists():
        DEFAULT_CONFIG.parent.mkdir(exist_ok=True)
        shutil.copyfile(EXAMPLE_CONFIG, DEFAULT_CONFIG)
        console.print(f"[green]✓[/] wrote {DEFAULT_CONFIG} from example")
        console.print(
            "[yellow]![/] Edit it with official scope — AETHER fails closed until then."
        )
    else:
        err_console.print("[red]✗[/] no example config found to seed from")
        raise typer.Exit(1)
    console.print(Panel.fit("Next: edit config/aether.yaml, then `aether config validate`"))


@system_app.command("health")
def system_health() -> None:
    """Check Python, dependencies, state writability, and resources."""
    table = Table(title="AETHER system health", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    ok = True

    # Python version
    py_ok = sys.version_info >= (3, 12)
    ok &= py_ok
    table.add_row(
        "Python >= 3.12",
        "[green]OK[/]" if py_ok else "[red]FAIL[/]",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    # Core deps
    for dep in ("typer", "rich", "pydantic", "yaml", "httpx", "psutil"):
        present = importlib.util.find_spec(dep) is not None
        ok &= present
        table.add_row(f"dep: {dep}", "[green]OK[/]" if present else "[red]MISSING[/]", "")

    # No-AI invariant: ensure no known AI SDKs are importable in the runtime.
    def _present(pkg: str) -> bool:
        try:
            return importlib.util.find_spec(pkg) is not None
        except (ModuleNotFoundError, ValueError):
            return False

    ai_pkgs = [p for p in ("openai", "anthropic", "google.generativeai", "cohere")
               if _present(p)]
    table.add_row(
        "No-AI runtime",
        "[green]OK[/]" if not ai_pkgs else "[yellow]WARN[/]",
        "clean" if not ai_pkgs else f"AI SDK present: {', '.join(ai_pkgs)}",
    )

    # State dir writable
    try:
        Path("runtime").mkdir(exist_ok=True)
        probe = Path("runtime/.healthcheck")
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        table.add_row("runtime/ writable", "[green]OK[/]", "")
    except Exception as exc:  # noqa: BLE001
        ok = False
        table.add_row("runtime/ writable", "[red]FAIL[/]", str(exc))

    # Resources
    try:
        import psutil

        vm = psutil.virtual_memory()
        table.add_row(
            "memory",
            "[green]OK[/]",
            f"{vm.available // (1024**2)} MiB available / {vm.total // (1024**2)} MiB",
        )
        table.add_row("cpu", "[green]OK[/]", f"{psutil.cpu_count()} logical cores")
    except Exception as exc:  # noqa: BLE001
        table.add_row("resources", "[yellow]WARN[/]", str(exc))

    console.print(table)
    if not ok:
        raise typer.Exit(1)


@config_app.command("validate")
def config_validate(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Validate configuration and report competition readiness (fail-closed)."""
    try:
        cfg, path = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    readiness = assess_readiness(cfg)
    console.print(f"Loaded config: [cyan]{path}[/]")
    console.print(
        f"Readiness: "
        + ("[green]READY[/]" if readiness.ready else "[red]NOT READY (fail closed)[/]")
    )
    for issue in readiness.issues:
        console.print(f"  [red]✗ {issue}[/]")
    for warn in readiness.warnings:
        console.print(f"  [yellow]! {warn}[/]")
    if readiness.ready and not readiness.warnings:
        console.print("  [green]✓ no issues[/]")
    if not readiness.ready:
        raise typer.Exit(2)


@scope_app.command("show")
def scope_show(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Show the authorized target allowlist."""
    try:
        cfg, path = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    mode = "[green]ENFORCED[/]" if cfg.scope.enforce else "[red]LAB (not enforced)[/]"
    console.print(f"Scope enforcement: {mode}   (config: {path})")
    if not cfg.scope.targets:
        console.print("[red]No authorized targets — AETHER will fail closed.[/]")
        return
    table = Table(title="Authorized targets")
    for col in ("name", "host", "ports", "kind", "owner"):
        table.add_column(col)
    for t in cfg.scope.targets:
        ports = ",".join(str(p) for p in t.ports) or "(any)"
        owner_style = "red" if t.owner == "opponent" else "cyan"
        table.add_row(t.name, t.host, ports, t.kind, f"[{owner_style}]{t.owner}[/]")
    console.print(table)


@modules_app.command("list")
def modules_list() -> None:
    """List all discovered modules with their metadata."""
    loader = _build_loader()
    mods = loader.list_modules()
    if not mods:
        console.print("[yellow]No modules discovered yet.[/]")
        return
    table = Table(title=f"Discovered modules ({len(mods)})")
    for col in ("identifier", "category", "kinds", "scope", "timeout"):
        table.add_column(col)
    for m in sorted(mods, key=lambda c: c.meta.identifier):
        meta = m.meta
        table.add_row(
            meta.identifier,
            meta.category,
            ",".join(meta.supported_kinds) or "-",
            "req" if meta.requires_scope else "no",
            f"{meta.timeout:g}s",
        )
    console.print(table)


@modules_app.command("test")
def modules_test() -> None:
    """Self-test: verify every discovered module loads and is constructible."""
    loader = _build_loader()
    mods = loader.list_modules()
    if not mods:
        console.print("[yellow]No modules to test.[/]")
        return
    failures = 0
    for m in sorted(mods, key=lambda c: c.meta.identifier):
        try:
            inst = m()
            assert inst.identifier == m.meta.identifier
            console.print(f"[green]✓[/] {m.meta.identifier}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            console.print(f"[red]✗ {m.meta.identifier}: {exc}[/]")
    if failures:
        raise typer.Exit(1)


@defense_app.command("status")
def defense_status(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Show defense engine status (monitored services, watched paths, last incidents)."""
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            engine = DefenseEngine(orch)
            # Watch any self-owned targets that name a local path in notes (best-effort).
            st = engine.status
            table = Table(title="Defense status")
            table.add_column("Metric")
            table.add_column("Value")
            table.add_row("services monitored", str(st.services_monitored))
            table.add_row("integrity paths watched", str(st.integrity_watched))
            table.add_row("last incidents", str(len(st.last_incidents)) or "0")
            console.print(table)
            console.print(
                "[dim]Live probes/paths are registered at runtime by adapters once "
                "official scope is configured.[/]"
            )
        finally:
            await orch.shutdown()

    asyncio.run(_run())


def _watch_self_roots(engine, cfg) -> int:
    """Register every self-owned target whose notes name an existing local path."""
    n = 0
    for t in cfg.scope.targets:
        if t.owner == "self" and t.notes and Path(t.notes).exists():
            engine.watch_path(t.name, t.notes)
            n += 1
    return n


@defense_app.command("webshells")
def defense_webshells(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    path: str = typer.Option(None, "--path", help="Scan this directory instead of scope."),
) -> None:
    """Read-only scan of our own web roots for planted web shells."""
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            engine = DefenseEngine(orch)
            if path:
                engine.watch_path("cli", path)
            else:
                _watch_self_roots(engine, cfg)
            hits = engine.scan_webshells()
            if not hits:
                console.print("[green]✓ no web shells detected in watched roots[/]")
                return
            table = Table(title="Suspected web shells (READ-ONLY detection)")
            table.add_column("path"); table.add_column("signatures")
            table.add_column("excerpt", overflow="fold")
            for h in hits:
                table.add_row(f"[red]{h.path}[/]", ", ".join(h.signatures), h.snippet)
            console.print(table)
            console.print("[yellow]Review, then quarantine with:[/] "
                          "[bold]aether defense quarantine <abs-path>[/] "
                          "[dim](backs up first, reversible)[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@defense_app.command("audit")
def defense_audit(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    path: str = typer.Option(None, "--path", help="Audit this directory instead of scope."),
) -> None:
    """Self-audit our own service source for exploitable sinks (LFI/cmdi/SSTI/SQLi/upload/...).

    'Patch yourself first' — this is the highest-value defensive move. Read-only static
    analysis; prints each finding with file:line, severity, and a concrete remediation.
    """
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            engine = DefenseEngine(orch)
            if path:
                engine.watch_path("cli", path)
            else:
                _watch_self_roots(engine, cfg)
            findings = engine.audit_sources()
            if not findings:
                console.print("[green]✓ no obvious exploitable sinks found in our source[/]")
                console.print("[dim]Still verify manually; a clean static scan is not a "
                              "guarantee.[/]")
                return
            colour = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
            table = Table(title="Self-audit — patch these before opponents do")
            table.add_column("severity"); table.add_column("category")
            table.add_column("location"); table.add_column("fix", overflow="fold")
            for f in findings:
                loc = f"{f.path}:{f.line}" if f.line else f.path
                c = colour.get(f.severity, "white")
                table.add_row(f"[{c}]{f.severity}[/]", f.category, loc, f.remediation)
            console.print(table)
            crit = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
            console.print(f"[bold]{len(findings)} finding(s), {crit} high/critical.[/] "
                          "[dim]Patch, keep the service UP, then re-run this audit.[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@defense_app.command("quarantine")
def defense_quarantine(
    target: str = typer.Argument(..., help="Absolute path of the shell to quarantine."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Operator-gated: safely remove a detected web shell (backup → move → verify, reversible)."""
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            engine = DefenseEngine(orch)
            _watch_self_roots(engine, cfg)
            result = await engine.quarantine_webshell(target)
            colour = "green" if result.safe else "red"
            console.print(f"[{colour}]{result.outcome.value}[/]: {result.detail}")
            for step in result.steps:
                console.print(f"  [dim]{step}[/]")
            if result.snapshot_id:
                console.print(f"[dim]backup snapshot: {result.snapshot_id} "
                              f"(restore with recovery if needed)[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@defense_app.command("guard")
def defense_guard(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    path: str = typer.Option(None, "--path", help="Guard this directory instead of scope."),
    interval: float = typer.Option(0.0, "--interval", "-i", help="If >0, loop every N seconds."),
) -> None:
    """Run AutoGuard integrity enforcement and snapshot restoration on watched roots."""
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            engine = DefenseEngine(orch)
            if path:
                engine.watch_path("cli", path)
            else:
                _watch_self_roots(engine, cfg)
            while True:
                rep = await engine.auto_guard_once()
                console.print(
                    f"[green]✓ AutoGuard pass[/]: checked={rep.roots_checked} "
                    f"quarantined={len(rep.files_quarantined)} "
                    f"restored={len(rep.files_restored)}"
                )
                for qf in rep.files_quarantined:
                    console.print(f"  [yellow]quarantined:[/] {qf}")
                for rf in rep.files_restored:
                    console.print(f"  [cyan]restored:[/] {rf}")
                for err in rep.errors:
                    console.print(f"  [red]error:[/] {err}")
                if interval <= 0:
                    break
                await asyncio.sleep(interval)
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@defense_app.command("shield")
def defense_shield(
    listen_port: int = typer.Option(8080, "--listen", "-l", help="Frontend port to listen on."),
    backend_port: int = typer.Option(8000, "--backend", "-b", help="Backend service port to forward to."),
    listen_host: str = typer.Option("0.0.0.0", "--host", help="Bind address for shield proxy."),
    backend_host: str = typer.Option("127.0.0.1", "--backend-host", help="Backend host."),
    off: bool = typer.Option(False, "--off", help="Start in pass-through mode (filtering OFF)."),
) -> None:
    """Start the HTTP Shield reverse-proxy in front of a self-owned web service."""
    import time

    from ..defense.shield_proxy import ShieldProxy

    proxy = ShieldProxy(
        listen_host=listen_host,
        listen_port=listen_port,
        backend_host=backend_host,
        backend_port=backend_port,
        enabled=(not off),
    )
    bound = proxy.start()
    mode_str = "[green]ON (BLOCKING)[/]" if proxy.enabled else "[yellow]OFF (PASS-THROUGH)[/]"
    console.print(
        f"[bold cyan]AETHER HTTP Shield Proxy[/] listening on [bold]{listen_host}:{bound}[/] "
        f"→ forwarding to [bold]{backend_host}:{backend_port}[/] • Filter: {mode_str}"
    )
    console.print("[dim]Press Ctrl-C to stop[/]")
    try:
        while True:
            time.sleep(2.0)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping shield proxy…[/]")
    finally:
        proxy.stop()


def _open_state_and_inbox(cfg):
    """Build a StateManager + FlagInbox for CLI flag commands (async)."""
    from ..attack.flags.inbox import FlagInbox
    from ..attack.flags.validator import FlagValidator
    from ..core.state_manager import StateManager

    state = StateManager(cfg.engine.state_db)
    inbox = FlagInbox(state, FlagValidator(cfg.flags.pattern))
    return state, inbox


@attack_app.command("status")
def attack_status(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Show attack-side status: loaded modules and in-scope opponent targets."""
    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)
    loader = _build_loader()
    exploit_mods = [m for m in loader.list_modules() if m.meta.category == "exploit"]
    recon_mods = [m for m in loader.list_modules() if m.meta.category in ("recon", "assessment")]
    opponents = [t for t in cfg.scope.targets if t.owner == "opponent"]
    table = Table(title="Attack status")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("recon/assessment modules", str(len(recon_mods)))
    table.add_row("exploit modules", str(len(exploit_mods)))
    table.add_row("authorized opponent targets", str(len(opponents)))
    console.print(table)
    console.print("[dim]Flags are surfaced to the manual inbox; AETHER never submits.[/]")


@attack_app.command("sweep")
def attack_sweep(
    host: str = typer.Argument(None, help="Authorized opponent host to sweep. "
                                          "Omit to sweep all in-scope opponent web targets."),
    port: int = typer.Option(None, "--port", "-p", help="Target port (default: from scope)."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    show: bool = typer.Option(False, "--show-values", help="Reveal flag values."),
    max_probes: int = typer.Option(None, "--max-probes", help="Cap probes per module."),
    recon: bool = typer.Option(True, "--recon/--no-recon",
                               help="Crawl the target first and aim payloads at discovered "
                                    "endpoints/params (smarter, higher hit-rate)."),
    login: bool = typer.Option(True, "--login/--no-login",
                               help="Auto-login first (default/weak or --cred creds), then "
                                    "attack BEHIND the session."),
    tools: bool = typer.Option(False, "--tools/--no-tools",
                               help="Also drive installed external scanners first "
                                    "(nmap/rustscan ports, gobuster/ffuf paths, whatweb tech) "
                                    "to widen the attack surface."),
    nuclei: bool = typer.Option(False, "--nuclei/--no-nuclei",
                                help="Also run nuclei templated CVE checks (implies --tools; "
                                     "slower). Findings are surfaced as leads, not auto-exploited."),
    cred: list[str] = typer.Option(None, "--cred",
                                   help="Credential to try as user:pass (repeatable)."),
) -> None:
    """Run the full validated exploit arsenal against an authorized target.

    Scope-enforced (out-of-scope targets are refused), read-only/non-destructive, and every
    genuine flag lands in the MANUAL inbox as PENDING. AETHER never submits and never
    fabricates a flag.
    """
    import asyncio

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    if not cfg.flags.pattern:
        console.print("[yellow]⚠ no flag pattern configured — flags would be UNVERIFIED. "
                      "Set flags.pattern (e.g. IONIC\\{...\\}) first.[/]")

    from ..attack.engine import AttackEngine
    from ..attack.flags.inbox import FlagInbox
    from ..attack.flags.validator import FlagValidator
    from ..attack.memory import ExploitMemory
    from ..attack.sweep import AttackSweep
    from ..core.orchestrator import Orchestrator
    from ..core.plugin import RunContext

    # Resolve targets: explicit host, or every in-scope opponent target across all ports.
    opp_targets = [t for t in cfg.scope.targets if t.owner == "opponent"]
    if host:
        matches = [t for t in opp_targets if t.host == host]
        if port:
            targets = [(host, port)]
        elif matches:
            targets = list(
                dict.fromkeys(
                    (host, p) for m in matches for p in (m.ports if m.ports else (80,))
                )
            )
        else:
            targets = [(host, 80)]
    else:
        if not opp_targets:
            err_console.print("[red]✗ no in-scope opponent targets. Configure scope "
                              "or pass a host.[/]")
            raise typer.Exit(1)
        if port:
            targets = [(t.host, port) for t in opp_targets]
        else:
            targets = [
                (t.host, p)
                for t in opp_targets
                for p in (t.ports if t.ports else (80,))
            ]

    async def _run():
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            # Fail closed: refuse any target not explicitly authorized in scope.
            authorized = []
            for h, p in targets:
                if orch.scope.check(h, p).allowed:
                    authorized.append((h, p))
                else:
                    err_console.print(f"[red]✗ {h}:{p} is NOT in authorized scope — skipped[/]")
            if not authorized:
                err_console.print("[red]✗ nothing authorized to sweep. Aborting (fail closed).[/]")
                raise typer.Exit(1)

            from ..scoring.tick_info import TickInfoClient

            inbox = FlagInbox(orch.state, FlagValidator(cfg.flags.pattern), events=orch.events)
            eng = AttackEngine(orch, inbox)
            sweep = AttackSweep(eng, memory=ExploitMemory(orch.state))
            tick_info = TickInfoClient(cfg.scoring.flag_id_endpoint)
            extra = {}
            if max_probes:
                extra["max_probes"] = max_probes
            if cred:
                extra["credentials"] = list(cred)
            if nuclei:
                extra["tool_nuclei"] = True
            use_tools = tools or nuclei
            kind_by_host = {t.host: t.kind for t in cfg.scope.targets}
            kind_by_hp = {(t.host, p): t.kind for t in cfg.scope.targets for p in t.ports}
            for h, p in authorized:
                console.print(f"[cyan]▶ sweeping {h}:{p} …[/]")
                svc_kind = kind_by_hp.get((h, p), kind_by_host.get(h, "web"))
                run_extra = dict(extra)
                fids = await tick_info.fetch_for(h, svc_kind)
                if fids:
                    run_extra["flag_ids"] = fids
                report = await sweep.run(
                    RunContext(target_host=h, target_port=p,
                               service=svc_kind,
                               extra=run_extra),
                    recon=recon,
                    login=login,
                    tools=use_tools,
                )
                if report.open_ports:
                    console.print(f"  [cyan]ports:[/] " + ", ".join(
                        f"{s['port']}/{s.get('service','?')}" for s in report.open_ports[:12]))
                if report.fingerprints:
                    console.print(f"  [cyan]tech:[/] " + ", ".join(report.fingerprints[:8]))
                for nf in report.nuclei[:12]:
                    console.print(f"  [magenta]nuclei[/] [{nf.get('severity','?')}] "
                                  f"{nf.get('template','')} @ {nf.get('matched','')}")
                if report.authenticated:
                    console.print(f"  [green]✓ logged in as {report.login_as} "
                                  f"at {report.login_endpoint} — attacking authenticated[/]")
                if report.fast_path:
                    console.print(f"  [dim]fast-path (learned): {', '.join(report.fast_path)}[/]")
                if report.discovered_endpoints or report.discovered_params:
                    console.print(f"  [dim]recon: {len(report.discovered_endpoints)} "
                                  f"endpoint(s), {len(report.discovered_params)} param(s)[/]")
                style = "green" if report.any_flag else "yellow"
                console.print(f"[{style}]{report.summary()}[/]")
                if report.confirmed_modules:
                    console.print("  confirmed: " + ", ".join(report.confirmed_modules))
            rows = await inbox.pending()
            _render_flag_table(rows, "PENDING flags (operator submits manually)", show)
            console.print("[dim]AETHER never submits. Review, then submit on the official "
                          "portal yourself.[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@attack_app.command("recon")
def attack_recon(
    host: str = typer.Argument(..., help="Authorized host to scan."),
    port: int = typer.Option(None, "--port", "-p", help="Target port (default: from scope/80)."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    nuclei: bool = typer.Option(False, "--nuclei", help="Also run nuclei CVE checks (slower)."),
) -> None:
    """Drive installed external scanners (nmap/rustscan, gobuster/ffuf, whatweb) at a target.

    Read-only discovery, scope-enforced. Shows open ports+services, discovered paths, and the
    detected tech stack — the same intel `sweep --tools` feeds into the exploit arsenal.
    """
    import asyncio

    from ..attack.engine import AttackEngine
    from ..attack.flags.inbox import FlagInbox
    from ..attack.flags.validator import FlagValidator
    from ..attack.recon.tool_recon import ToolReconModule
    from ..attack.recon.toolscan import detect_tools
    from ..core.orchestrator import Orchestrator
    from ..core.plugin import RunContext

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    installed = [t for t, ok in detect_tools().items() if ok]
    console.print(f"[dim]external tools detected: {', '.join(installed) or 'none (python fallback)'}[/]")
    p = port or next((t.ports[0] for t in cfg.scope.targets
                      if t.host == host and t.ports), 80)

    async def _run():
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            if not orch.scope.check(host, p).allowed:
                err_console.print(f"[red]✗ {host}:{p} is NOT in authorized scope (fail closed)[/]")
                raise typer.Exit(1)
            inbox = FlagInbox(orch.state, FlagValidator(cfg.flags.pattern or r"IONIC\{[^}]+\}"))
            engine = AttackEngine(orch, inbox)
            kind = next((t.kind for t in cfg.scope.targets if t.host == host), "web")
            console.print(f"[cyan]▶ recon {host}:{p} …[/] [dim](this may take a bit)[/]")
            res = await engine.recon(ToolReconModule(),
                                     RunContext(target_host=host, target_port=p, service=kind,
                                                extra={"tool_nuclei": nuclei}))
            data = res.data
            ports = data.get("open_ports", [])
            if ports:
                t = Table(title=f"Open ports — {host}")
                t.add_column("port"); t.add_column("service"); t.add_column("product")
                for s in ports:
                    t.add_row(str(s["port"]), s.get("service", "?"), s.get("product", ""))
                console.print(t)
            paths = data.get("discovered_paths", [])
            if paths:
                t = Table(title="Discovered paths")
                t.add_column("path"); t.add_column("status")
                for pth in paths[:40]:
                    t.add_row(pth.get("path", ""), str(pth.get("status", "")))
                console.print(t)
            if data.get("fingerprints"):
                console.print("[cyan]tech:[/] " + ", ".join(data["fingerprints"]))
            if data.get("nuclei"):
                t = Table(title="nuclei findings (leads — not auto-exploited)")
                t.add_column("severity"); t.add_column("template"); t.add_column("matched")
                for nf in data["nuclei"]:
                    t.add_row(nf.get("severity", "?"), nf.get("template", ""), nf.get("matched", ""))
                console.print(t)
            console.print(f"[green]{res.detail}[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@attack_app.command("privesc")
def attack_privesc(
    host: str = typer.Argument(..., help="Authorized opponent host to enumerate."),
    port: int = typer.Option(None, "--port", "-p", help="Target port (default: from scope)."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    recon: bool = typer.Option(True, "--recon/--no-recon", help="Crawl first to find the "
                                                                "injection point."),
    login: bool = typer.Option(True, "--login/--no-login", help="Log in first."),
    cred: list[str] = typer.Option(None, "--cred", help="Credential user:pass (repeatable)."),
) -> None:
    """Read-only local priv-esc ENUMERATION via command injection (operator escalates by hand).

    Runs id / sudo -l / SUID / capabilities / cron through the injection vector and prints what
    came back. It never escalates on its own — it hands you the intel to decide the next step.
    """
    import asyncio

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    from ..attack.engine import AttackEngine
    from ..attack.flags.inbox import FlagInbox
    from ..attack.flags.validator import FlagValidator
    from ..attack.sweep import AttackSweep
    from ..core.orchestrator import Orchestrator
    from ..core.plugin import RunContext

    matches = [t for t in cfg.scope.targets if t.host == host]
    p = port or (matches[0].ports[0] if matches and matches[0].ports else 80)

    async def _run():
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            if not orch.scope.check(host, p).allowed:
                err_console.print(f"[red]✗ {host}:{p} is NOT in authorized scope (fail closed).[/]")
                raise typer.Exit(1)
            inbox = FlagInbox(orch.state, FlagValidator(cfg.flags.pattern), events=orch.events)
            sweep = AttackSweep(AttackEngine(orch, inbox))
            extra = {}
            if cred:
                extra["credentials"] = list(cred)
            ctx = RunContext(target_host=host, target_port=p, service="web", extra=extra)
            if recon:
                eps, params = await sweep._recon(ctx)
                if eps:
                    ctx.extra["discovered_endpoints"] = eps
                if params:
                    ctx.extra["discovered_params"] = params
            if login:
                cookies, who, ep = await sweep._login(ctx)
                if cookies:
                    ctx.extra["cookies"] = cookies
                    console.print(f"[green]✓ logged in as {who} at {ep}[/]")
            console.print(f"[cyan]▶ enumerating {host}:{p} for priv-esc …[/]")
            run = await sweep.privesc(ctx)
            intel = run.result.data.get("intel", {})
            if intel:
                table = Table(title="priv-esc intel (read-only — you escalate manually)")
                table.add_column("what", style="bold cyan")
                table.add_column("observed")
                for k, v in intel.items():
                    table.add_row(k, v)
                console.print(table)
                console.print("[dim]Next step is yours: pick a SUID/sudo/cron/cap path and "
                              "exploit it by hand. AETHER never escalates on its own.[/]")
            else:
                console.print(f"[yellow]{run.result.detail}[/]")
        finally:
            await orch.shutdown()

    asyncio.run(_run())


@attack_app.command("loop")
def attack_loop(
    host: str = typer.Argument(None, help="Authorized opponent host. Omit to sweep all "
                                          "in-scope opponent web targets each round."),
    port: int = typer.Option(None, "--port", "-p", help="Target port (default: from scope)."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    interval: float = typer.Option(60.0, "--interval",
                                   help="Seconds between rounds (set to the tick length)."),
    duration: float = typer.Option(0.0, "--duration", help="Total seconds (0 = until stopped)."),
    once: bool = typer.Option(False, "--once", help="Run a single round and exit."),
    max_probes: int = typer.Option(None, "--max-probes", help="Cap probes per module."),
    recon: bool = typer.Option(True, "--recon/--no-recon",
                               help="Crawl each target first to aim payloads (smarter)."),
    login: bool = typer.Option(True, "--login/--no-login",
                               help="Auto-login each round, then attack behind the session."),
    tools: bool = typer.Option(False, "--tools/--no-tools",
                               help="Drive external scanners (nmap/rustscan/gobuster/ffuf/"
                                    "whatweb) on the FIRST round to widen the surface."),
    cred: list[str] = typer.Option(None, "--cred",
                                   help="Credential user:pass to try (repeatable)."),
) -> None:
    """Continuously re-sweep authorized targets each round (flags rotate per tick).

    Foreground loop; stop with Ctrl-C or `aether attack stop`. Every genuine flag is stamped
    with the current tick and lands in the MANUAL inbox as PENDING. AETHER never submits.
    """
    import asyncio
    import time

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    from ..attack.engine import AttackEngine
    from ..attack.flags.inbox import FlagInbox
    from ..attack.flags.validator import FlagValidator
    from ..attack.memory import ExploitMemory
    from ..attack.sweep import AttackSweep
    from ..core.orchestrator import Orchestrator
    from ..core.plugin import RunContext

    opp_targets = [t for t in cfg.scope.targets if t.owner == "opponent"]
    if host:
        matches = [t for t in opp_targets if t.host == host]
        if port:
            targets = [(host, port)]
        elif matches:
            targets = list(
                dict.fromkeys(
                    (host, p) for m in matches for p in (m.ports if m.ports else (80,))
                )
            )
        else:
            targets = [(host, 80)]
    elif opp_targets:
        if port:
            targets = [(t.host, port) for t in opp_targets]
        else:
            targets = [
                (t.host, p)
                for t in opp_targets
                for p in (t.ports if t.ports else (80,))
            ]
    else:
        err_console.print("[red]✗ no in-scope opponent targets. Configure scope or pass "
                          "a host.[/]")
        raise typer.Exit(1)

    Path("runtime").mkdir(exist_ok=True)
    if _ATTACK_STOP_FLAG.exists():
        _ATTACK_STOP_FLAG.unlink()

    async def _run():
        orch = Orchestrator(cfg)
        await orch.start()
        authorized = [(h, p) for h, p in targets if orch.scope.check(h, p).allowed]
        for h, p in targets:
            if (h, p) not in authorized:
                err_console.print(f"[red]✗ {h}:{p} not in scope — skipped[/]")
        if not authorized:
            await orch.shutdown()
            err_console.print("[red]✗ nothing authorized to sweep. Aborting (fail closed).[/]")
            raise typer.Exit(1)

        from ..scoring.tick_info import TickInfoClient

        inbox = FlagInbox(orch.state, FlagValidator(cfg.flags.pattern), events=orch.events)
        eng = AttackEngine(orch, inbox)
        sweep = AttackSweep(eng, memory=ExploitMemory(orch.state))
        tick_info = TickInfoClient(cfg.scoring.flag_id_endpoint)
        extra = {"max_probes": max_probes} if max_probes else {}
        if cred:
            extra["credentials"] = list(cred)
        start = time.time()
        rounds = 0
        try:
            while True:
                rounds += 1
                new_flags = 0
                kind_by_host = {t.host: t.kind for t in cfg.scope.targets}
                kind_by_hp = {(t.host, p): t.kind for t in cfg.scope.targets for p in t.ports}
                for h, p in authorized:
                    svc_kind = kind_by_hp.get((h, p), kind_by_host.get(h, "web"))
                    run_extra = dict(extra)
                    fids = await tick_info.fetch_for(h, svc_kind)
                    if fids:
                        run_extra["flag_ids"] = fids
                    report = await sweep.run(
                        RunContext(target_host=h, target_port=p,
                                   service=svc_kind,
                                   extra=run_extra),
                        recon=recon,
                        login=login,
                        tools=(tools and rounds == 1),   # heavy scans once, not every tick
                    )
                    new_flags += len(report.flags_found)
                total = len(await inbox.list())
                console.print(f"[cyan]round {rounds}[/]: swept {len(authorized)} target(s), "
                              f"{new_flags} flag hit(s) this round, {total} unique in inbox")
                if once or (duration and (time.time() - start) >= duration):
                    break
                if _ATTACK_STOP_FLAG.exists():
                    console.print("[yellow]stop flag detected — shutting down[/]")
                    _ATTACK_STOP_FLAG.unlink()
                    break
                await asyncio.sleep(interval)
        finally:
            await orch.shutdown()
        console.print(f"attack loop finished after {rounds} round(s). "
                      "Review `aether flags inbox` and submit manually.")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]attack loop interrupted by operator[/]")


@attack_app.command("stop")
def attack_stop() -> None:
    """Signal a running `attack loop` to stop at its next round."""
    Path("runtime").mkdir(exist_ok=True)
    _ATTACK_STOP_FLAG.write_text("stop", encoding="utf-8")
    console.print("[green]✓ stop signal written (runtime/attack.stop)[/]")


@attack_app.command("oast")
def attack_oast(
    port: int = typer.Option(0, "--port", "-p", help="Listen port (0 = auto)."),
    pub_host: str = typer.Option("127.0.0.1", "--pub-host",
                                 help="IP to advertise in callback URLs (your team IP)."),
    listen: str = typer.Option("0.0.0.0", "--listen", help="Bind address."),
) -> None:
    """Start a self-hosted OAST listener to catch blind SSRF/RCE/XXE callbacks.

    Mints a unique callback URL; inject it into a blind payload. A ping-back confirms the bug
    (and may carry exfiltrated data). Ctrl-C to stop. Receives only — never attacks.
    """
    import time as _time

    from ..attack.oast import OastListener

    oast = OastListener(pub_host=pub_host)
    bound = oast.start(listen_host=listen, listen_port=port, pub_host=pub_host)
    token = oast.new_token()
    console.print(f"[bold green]OAST listener[/] on [cyan]{listen}:{bound}[/] "
                  f"(advertising [cyan]{pub_host}[/])")
    console.print(f"[bold]Inject this callback URL into a blind payload:[/] "
                  f"[yellow]{oast.payload_url(token)}[/]")
    console.print("[dim]waiting for callbacks • Ctrl-C to stop[/]")
    seen = 0
    try:
        while True:
            _time.sleep(1.0)
            its = oast.interactions(limit=100)
            if len(its) > seen:
                for it in reversed(its[:len(its) - seen]):
                    console.print(f"[green]● HIT[/] {it['ts']} {it['method']} "
                                  f"[cyan]{it['path']}[/] token=[bold]{it['token']}[/] "
                                  f"src={it['src_ip']}")
                seen = len(its)
    except KeyboardInterrupt:
        oast.stop()
        console.print("\n[dim]OAST listener stopped[/]")


@flags_app.command("inbox")
def flags_inbox(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    show: bool = typer.Option(False, "--show-values", help="Reveal flag values."),
) -> None:
    """Show PENDING flags awaiting operator submission."""
    import asyncio

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run():
        state, inbox = _open_state_and_inbox(cfg)
        await state.open()
        try:
            rows = await inbox.pending()
            _render_flag_table(rows, "PENDING flags (operator submits manually)", show)
        finally:
            await state.close()

    asyncio.run(_run())


@flags_app.command("history")
def flags_history(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    show: bool = typer.Option(False, "--show-values", help="Reveal flag values."),
) -> None:
    """Show all flags ever discovered (any submission status)."""
    import asyncio

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run():
        state, inbox = _open_state_and_inbox(cfg)
        await state.open()
        try:
            rows = await inbox.list()
            _render_flag_table(rows, "Flag history", show)
        finally:
            await state.close()

    asyncio.run(_run())


@flags_app.command("copy")
def flags_copy(
    dedup_key: str = typer.Argument(..., help="Flag dedup key (prefix ok) to copy."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Print a single flag value to stdout for easy copy (operator convenience)."""
    import asyncio

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run():
        state, inbox = _open_state_and_inbox(cfg)
        await state.open()
        try:
            rows = await inbox.list()
            matches = [r for r in rows if r["dedup_key"].startswith(dedup_key)]
            if not matches:
                err_console.print("[red]no matching flag[/]")
                raise typer.Exit(1)
            if len(matches) > 1:
                err_console.print(f"[yellow]{len(matches)} matches — be more specific[/]")
                raise typer.Exit(1)
            # Print bare value only (for piping to clipboard, e.g. | xclip).
            print(matches[0]["value"])
        finally:
            await state.close()

    asyncio.run(_run())


@flags_app.command("mark-submitted")
def flags_mark_submitted(
    dedup_key: str = typer.Argument(..., help="Flag dedup key (prefix ok)."),
    status: str = typer.Option("SUBMITTED", "--status",
                               help="SUBMITTED | ACCEPTED | REJECTED | EXPIRED."),
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Operator action: record that YOU submitted a flag. AETHER never does this itself."""
    import asyncio

    from ..core.models import SubmissionStatus

    try:
        cfg, _ = load_cli_config(config)
        st = SubmissionStatus(status.upper())
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)
    if st == SubmissionStatus.PENDING:
        err_console.print("[red]✗ cannot set status back to PENDING[/]")
        raise typer.Exit(1)

    async def _run():
        state, inbox = _open_state_and_inbox(cfg)
        await state.open()
        try:
            rows = await inbox.list()
            matches = [r for r in rows if r["dedup_key"].startswith(dedup_key)]
            if len(matches) != 1:
                err_console.print(f"[red]✗ need exactly one match, found {len(matches)}[/]")
                raise typer.Exit(1)
            ok = await inbox.mark_submitted(matches[0]["dedup_key"], st)
            console.print(f"[green]✓ marked {st.value}[/]" if ok else "[red]✗ not updated[/]")
        finally:
            await state.close()

    asyncio.run(_run())


@flags_app.command("submit")
def flags_submit(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    limit: int = typer.Option(None, "--limit", help="Max flags to submit this run."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Submit VALIDATED+PENDING flags to the OFFICIAL organizer endpoint (submission.* config).

    Fail-closed: does nothing unless submission.enabled=true and an endpoint is configured.
    This is the ONLY automated submission path; it sends only to the configured game server,
    never to a scope target, and marks each flag so it is never submitted twice.
    """
    import asyncio

    from ..scoring.submitter import FlagSubmitter, submit_config_from

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    scfg = submit_config_from(cfg.submission)
    ok, reason = scfg.ready()
    if not ok:
        err_console.print(f"[yellow]⚠ submission not armed:[/] {reason}")
        err_console.print("  Set submission.enabled=true and the endpoint in your config first.")
        raise typer.Exit(1)

    dest = scfg.endpoint if scfg.protocol == "http" else f"{scfg.tcp_host}:{scfg.tcp_port}"
    if not yes:
        confirm = typer.confirm(
            f"Submit VALIDATED flags to organizer [{scfg.protocol}] {dest}?", default=False)
        if not confirm:
            console.print("[dim]aborted — nothing submitted[/]")
            raise typer.Exit(0)

    async def _run():
        state, inbox = _open_state_and_inbox(cfg)
        await state.open()
        try:
            report = await FlagSubmitter(inbox, scfg).submit_pending(limit=limit)
            if report.refused:
                err_console.print(f"[red]✗ refused: {report.refused}[/]")
                raise typer.Exit(1)
            console.print(f"[green]✓ {report.summary()}[/]")
            if report.errors:
                err_console.print(f"[yellow]  {len(report.errors)} error(s):[/] "
                                  + "; ".join(report.errors[:5]))
        finally:
            await state.close()

    asyncio.run(_run())


@scoring_app.command("show")
def scoring_show(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
) -> None:
    """Show tick/round timing and recorded score history (if any)."""
    import asyncio

    from ..scoring.timing import TickClock
    from ..scoring.tracker import ScoreTracker
    from ..core.state_manager import StateManager

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    clock = TickClock(cfg.scoring.tick_seconds, cfg.scoring.epoch)
    table = Table(title="Scoring / timing")
    table.add_column("Metric")
    table.add_column("Value")
    if clock.configured:
        info = clock.info()
        table.add_row("tick length", f"{cfg.scoring.tick_seconds}s")
        table.add_row("current tick", str(info.tick))
        table.add_row("seconds to next tick", f"{info.seconds_to_next:g}")
    else:
        table.add_row("tick length", "[yellow]unconfigured[/]")
    table.add_row("flag expiry (ticks)", str(cfg.scoring.expiry_ticks or "unconfigured"))
    table.add_row("scoreboard endpoint", cfg.scoring.scoreboard_endpoint or "unconfigured")
    console.print(table)

    async def _hist():
        state = StateManager(cfg.engine.state_db)
        await state.open()
        try:
            latest = await ScoreTracker(state).latest()
            if latest:
                console.print(f"latest snapshot: {latest}")
            else:
                console.print("[dim]no score history recorded yet[/]")
        finally:
            await state.close()

    asyncio.run(_hist())


@report_app.command("generate")
def report_generate(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    include_values: bool = typer.Option(False, "--include-flag-values",
                                        help="Include raw flag values (sensitive!)."),
) -> None:
    """Generate a Markdown operator report under runtime/reports/."""
    import asyncio

    from ..core.state_manager import StateManager
    from ..reporting.report import write_report

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    async def _run():
        state = StateManager(cfg.engine.state_db)
        await state.open()
        try:
            path = await write_report(cfg, state, include_flag_values=include_values)
            console.print(f"[green]✓ report written:[/] {path}")
        finally:
            await state.close()

    asyncio.run(_run())


@monitor_app.command("start")
def monitor_start(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    interval: float = typer.Option(10.0, "--interval", help="Seconds between sweeps."),
    duration: float = typer.Option(0.0, "--duration",
                                   help="Total seconds to run (0 = until stopped)."),
    once: bool = typer.Option(False, "--once", help="Run a single sweep and exit."),
) -> None:
    """Run the defense monitoring loop (foreground). Stop with Ctrl-C or `aether monitor stop`."""
    import asyncio

    from ..core.orchestrator import Orchestrator
    from ..defense.engine import DefenseEngine

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    Path("runtime").mkdir(exist_ok=True)
    if _MONITOR_STOP_FLAG.exists():
        _MONITOR_STOP_FLAG.unlink()

    async def _run():
        import time

        orch = Orchestrator(cfg)
        await orch.start()
        engine = DefenseEngine(orch)
        # Watch any self-owned target whose notes name a local path.
        for t in cfg.scope.targets:
            if t.owner == "self" and t.notes and Path(t.notes).exists():
                engine.watch_path(t.name, t.notes)
        start = time.time()
        sweeps = 0
        try:
            while True:
                incidents = await engine.sweep()
                sweeps += 1
                if incidents:
                    for inc in incidents:
                        console.print(f"[red]INCIDENT[/] {inc.severity.value}: {inc.summary}")
                else:
                    console.print(f"[green]sweep {sweeps}: clean[/]")
                if once:
                    break
                if duration and (time.time() - start) >= duration:
                    break
                if _MONITOR_STOP_FLAG.exists():
                    console.print("[yellow]stop flag detected — shutting down[/]")
                    _MONITOR_STOP_FLAG.unlink()
                    break
                await asyncio.sleep(interval)
        finally:
            await orch.shutdown()
        console.print(f"monitor finished after {sweeps} sweep(s)")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]monitor interrupted by operator[/]")


@monitor_app.command("dashboard")
def monitor_dashboard(
    config: str = typer.Option(None, "--config", "-c", help="Config path."),
    interval: float = typer.Option(5.0, "--interval", help="Seconds between sweeps."),
    duration: float = typer.Option(0.0, "--duration", help="Total seconds (0 = until stopped)."),
    once: bool = typer.Option(False, "--once", help="Render a single snapshot and exit."),
    log_text: str = typer.Option(None, "--log-text", help="Feed a log sample to the analyzer."),
) -> None:
    """Live defense dashboard: real service health, integrity, incidents, flag & patch stats."""
    import asyncio

    from .dashboard import run_dashboard

    try:
        cfg, _ = load_cli_config(config)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(1)

    Path("runtime").mkdir(exist_ok=True)
    if _MONITOR_STOP_FLAG.exists():
        _MONITOR_STOP_FLAG.unlink()
    try:
        asyncio.run(run_dashboard(cfg, interval=interval, duration=duration, once=once,
                                  log_text=log_text, stop_flag=_MONITOR_STOP_FLAG))
    except KeyboardInterrupt:
        console.print("\n[yellow]dashboard interrupted by operator[/]")


@monitor_app.command("stop")
def monitor_stop() -> None:
    """Signal a running `monitor start` loop to stop at its next sweep."""
    Path("runtime").mkdir(exist_ok=True)
    _MONITOR_STOP_FLAG.write_text("stop", encoding="utf-8")
    console.print("[green]✓ stop signal written (runtime/monitor.stop)[/]")


@lab_app.command("serve")
def lab_serve(
    host: str = typer.Option("127.0.0.1", "--host",
                             help="Bind address. Use 0.0.0.0 to reach it from another VM."),
    port: int = typer.Option(8098, "--port", help="Port to listen on."),
    flag: str = typer.Option("IONIC{vuln_lab_demo}", "--flag", help="Flag the service hides."),
    only: str = typer.Option(None, "--only",
                             help="Comma list of vuln classes to enable (default: all)."),
) -> None:
    """Run the deliberately-vulnerable lab web service as a LIVE target (Ctrl-C to stop).

    Use this to practice the full Attack & Defense loop with your own VMs: run it on one VM
    (``--host 0.0.0.0``), then from another machine point AETHER at it
    (``aether attack sweep <that-ip>``) to practice ATTACK, and edit ``lab/web/vuln_service.py``
    to practice DEFENSE (patch a class, restart, confirm the sweep no longer finds the flag).

    SAFETY: this is intentionally vulnerable — only ever run it on an isolated lab network you
    control, NEVER on the real competition network or a public interface.
    """
    import sys as _sys
    import threading as _th

    lab_dir = Path(__file__).resolve().parents[3] / "lab" / "web"
    _sys.path.insert(0, str(lab_dir))
    try:
        from vuln_service import ALL_VULNS, VulnLabService  # type: ignore
    except ImportError:
        err_console.print("[red]✗ lab service not found[/]")
        raise typer.Exit(1)

    enabled = ALL_VULNS
    if only:
        wanted = frozenset(x.strip() for x in only.split(",") if x.strip())
        unknown = wanted - ALL_VULNS
        if unknown:
            err_console.print(f"[red]✗ unknown vuln class(es): {sorted(unknown)}[/]")
            err_console.print(f"[dim]valid: {sorted(ALL_VULNS)}[/]")
            raise typer.Exit(1)
        enabled = wanted

    if host not in ("127.0.0.1", "localhost"):
        console.print("[yellow]⚠ binding beyond localhost — isolated lab network ONLY, "
                      "never the competition or a public network.[/]")
    svc = VulnLabService(flag, host=host, port=port, enabled=enabled).start()
    console.print(f"[bold red]VULN lab target[/] → [cyan]http://{svc.host}:{svc.port}/[/]  "
                  f"[dim]({len(enabled)} vuln class(es))[/]")
    console.print(f"[dim]attack it:  aether attack sweep {svc.host if host!='0.0.0.0' else '<this-vm-ip>'}"
                  f" --cred admin:admin[/]")
    console.print("[dim]Ctrl-C to stop[/]")
    try:
        _th.Event().wait()
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping lab target…[/]")
    finally:
        svc.stop()


@lab_app.command("test")
def lab_test(
    flag: str = typer.Option("CTF{aether_lab_selftest}", "--flag", help="Lab flag value."),
) -> None:
    """Self-test: spin up an isolated local lab service and run the full attack pipeline.

    Proves end-to-end that a genuine flag flows recon->exploit->verify->MANUAL inbox,
    validated and PENDING, without touching any external infrastructure.
    """
    import asyncio
    import sys as _sys

    lab_dir = Path(__file__).resolve().parents[3] / "lab" / "web"
    _sys.path.insert(0, str(lab_dir))
    try:
        from flag_service import LabWebService  # type: ignore
    except ImportError:
        err_console.print("[red]✗ lab service not found[/]")
        raise typer.Exit(1)

    from ..attack.engine import AttackEngine
    from ..attack.exploits.lab_http_flag import LabHttpFlagExploit
    from ..attack.flags.inbox import FlagInbox, render_detection
    from ..attack.flags.validator import FlagValidator
    from ..core.config_manager import (
        AetherConfig,
        EngineConfig,
        FlagConfig,
        ScopeConfig,
    )
    from ..core.models import Target
    from ..core.orchestrator import Orchestrator
    from ..core.plugin import RunContext

    pattern = r"CTF\{[^}]+\}"
    svc = LabWebService(flag, host="127.0.0.1", port=0).start()

    async def _run():
        cfg = AetherConfig(
            engine=EngineConfig(state_db=":memory:", log_file=None, log_level="WARNING"),
            scope=ScopeConfig(
                enforce=True,
                targets=[Target(name="lab", host="127.0.0.1", ports=(svc.port,),
                                kind="web", owner="opponent")],
            ),
            flags=FlagConfig(pattern=pattern),
        )
        orch = Orchestrator(cfg)
        await orch.start()
        try:
            inbox = FlagInbox(orch.state, FlagValidator(pattern), events=orch.events)
            engine = AttackEngine(orch, inbox)
            console.print(f"[cyan]lab service up on 127.0.0.1:{svc.port}[/]")
            run = await engine.run_exploit(
                LabHttpFlagExploit(),
                RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
            )
            if run.confirmed and run.ingested:
                console.print("[green]✓ end-to-end pipeline OK[/]")
                console.print(render_detection(run.ingested[0].flag))
            else:
                console.print(f"[red]✗ pipeline did not confirm: {run.verification.reason}[/]")
                raise typer.Exit(1)
        finally:
            await orch.shutdown()

    try:
        asyncio.run(_run())
    finally:
        svc.stop()


def _render_flag_table(rows: list[dict], title: str, show_values: bool) -> None:
    if not rows:
        console.print(f"[yellow]{title}: (none)[/]")
        return
    table = Table(title=f"{title} — {len(rows)}")
    for col in ("key", "target", "service", "module", "valid", "submit", "seen", "flag"):
        table.add_column(col)
    for r in rows:
        valid_style = {"VALIDATED": "green", "UNVERIFIED": "yellow", "INVALID": "red"}.get(
            r["validation"], "white"
        )
        value = r["value"] if show_values else "••••••(use --show-values)"
        table.add_row(
            r["dedup_key"][:10],
            r["target"],
            r["service"],
            r["module"],
            f"[{valid_style}]{r['validation']}[/]",
            r["submission"],
            str(r["seen_count"]),
            value,
        )
    console.print(table)
    if not show_values:
        console.print("[dim]Flag values hidden by default. Use --show-values to reveal.[/]")


if __name__ == "__main__":
    app()
