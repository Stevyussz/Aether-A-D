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

app.add_typer(system_app, name="system")
app.add_typer(config_app, name="config")
app.add_typer(scope_app, name="scope")
app.add_typer(modules_app, name="modules")
app.add_typer(defense_app, name="defense")


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


if __name__ == "__main__":
    app()
