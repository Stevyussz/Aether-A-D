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
    no_args_is_help=True,
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

app.add_typer(system_app, name="system")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")
app.add_typer(modules_app, name="modules")
app.add_typer(defense_app, name="defense")
app.add_typer(attack_app, name="attack")
app.add_typer(flags_app, name="flags")
app.add_typer(scoring_app, name="scoring")


def _build_loader() -> ModuleLoader:
    loader = ModuleLoader()
    # Discover built-in modules from attack/defense packages as they are implemented.
    for pkg in ("aether.attack", "aether.defense"):
        loader.discover(pkg)
    return loader


@app.command()
def version() -> None:
    """Print the AETHER version."""
    console.print(f"AETHER A&D v{__version__}")


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
