"""Interactive operator console: ASCII home banner + a guided control menu.

A friendly front-end over the existing commands so the team can drive AETHER by selecting
options instead of memorising flags. It never bypasses any safety rule: every action runs the
same scope-enforced, manual-inbox, never-auto-submit command the CLI exposes.
"""

from __future__ import annotations

from rich.align import Align
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .. import __version__
from .context import DEFAULT_CONFIG, EXAMPLE_CONFIG, console, resolve_config_path

_BANNER = r"""
 █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗      █████╗    ██████╗
██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗    ██╔══██╗   ██╔══██╗
███████║█████╗     ██║   ███████║█████╗  ██████╔╝    ███████║   ██║  ██║
██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗    ██╔══██║   ██║  ██║
██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║    ██║  ██║██╗██████╔╝
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝╚═════╝
"""

_TAGLINE = "Attack & Defense CTF framework  •  no AI runtime  •  flags are submitted by YOU"


def render_home() -> None:
    """Print the ASCII banner, version, and a one-line readiness status."""
    banner = Text(_BANNER, style="bold cyan")
    sub = Text(_TAGLINE, style="dim italic")
    console.print(Align.center(banner))
    console.print(Align.center(sub))

    # Best-effort readiness strip (never crashes the console).
    status = Text()
    status.append("  v", style="dim")
    status.append(__version__, style="bold")
    path = resolve_config_path(None)
    if path is None:
        status.append("   config: ", style="dim")
        status.append("none — run Init", style="yellow")
    elif path == EXAMPLE_CONFIG:
        status.append("   config: ", style="dim")
        status.append("example placeholders (fail-closed)", style="yellow")
    else:
        status.append("   config: ", style="dim")
        status.append(str(path), style="green")
    console.print(Align.center(status))
    console.print()


# (label, description, builder) — builder returns the argv for the aether CLI, or None to skip.
def _menu_items():
    return [
        ("1", "System health", "verify Python/deps and the no-AI invariant", _a_system_health),
        ("2", "Validate config", "check scope/flags; READY or fail-closed reasons", _a_config_validate),
        ("3", "Show scope", "list authorized targets (opponents vs self)", _a_scope_show),
        ("4", "Attack · sweep target", "run the whole exploit arsenal once", _a_attack_sweep),
        ("5", "Attack · loop (rounds)", "auto re-sweep every tick (exploit farm)", _a_attack_loop),
        ("6", "Flag inbox", "PENDING flags awaiting YOUR manual submission", _a_flags_inbox),
        ("7", "Copy a flag value", "print one flag value for the portal", _a_flags_copy),
        ("8", "Mark flag submitted", "record that you submitted/accepted a flag", _a_flags_mark),
        ("9", "Defense · status", "services/integrity watched", _a_defense_status),
        ("10", "Defense · live dashboard", "real health/integrity/incidents/stats screen", _a_monitor_dashboard),
        ("16", "Web console (browser UI)", "dashboard + controls + config in your browser", _a_web),
        ("15", "Defense · plain monitor", "simple text sweep loop (Ctrl-C to stop)", _a_monitor_start),
        ("11", "Scoring status", "tick clock + score history (if configured)", _a_scoring_show),
        ("12", "Generate report", "operator report (flag values hidden)", _a_report),
        ("13", "Lab self-test", "safe end-to-end pipeline on a local lab", _a_lab_test),
        ("14", "List modules", "all loaded recon/exploit/defense modules", _a_modules_list),
    ]


def _ask(label: str, default: str | None = None) -> str:
    return Prompt.ask(f"[cyan]{label}[/]", default=default) if default is not None \
        else Prompt.ask(f"[cyan]{label}[/]")


# --- action builders: return argv list for the CLI, or None to cancel --------------------

def _a_system_health(): return ["system", "health"]
def _a_config_validate(): return ["config", "validate"]
def _a_scope_show(): return ["scope", "show"]
def _a_defense_status(): return ["defense", "status"]
def _a_scoring_show(): return ["scoring", "show"]
def _a_report(): return ["report", "generate"]
def _a_lab_test(): return ["lab", "test"]
def _a_modules_list(): return ["modules", "list"]
def _a_web(): return ["web"]


def _a_attack_sweep():
    host = _ask("Target host (blank = all in-scope opponents)", default="")
    args = ["attack", "sweep"]
    if host.strip():
        args.append(host.strip())
    if Prompt.ask("  Reveal flag values?", choices=["y", "n"], default="n") == "y":
        args.append("--show-values")
    if Prompt.ask("  Smart recon first?", choices=["y", "n"], default="y") == "n":
        args.append("--no-recon")
    return args


def _a_attack_loop():
    host = _ask("Target host (blank = all in-scope opponents)", default="")
    interval = _ask("  Seconds between rounds (tick length)", default="60")
    args = ["attack", "loop"]
    if host.strip():
        args.append(host.strip())
    args += ["--interval", interval.strip() or "60"]
    return args


def _a_flags_inbox():
    args = ["flags", "inbox"]
    if Prompt.ask("  Reveal flag values?", choices=["y", "n"], default="n") == "y":
        args.append("--show-values")
    return args


def _a_flags_copy():
    key = _ask("Flag key (prefix is fine)")
    if not key.strip():
        return None
    return ["flags", "copy", key.strip()]


def _a_flags_mark():
    key = _ask("Flag key (prefix is fine)")
    if not key.strip():
        return None
    status = Prompt.ask("  New status", choices=["SUBMITTED", "ACCEPTED", "REJECTED"],
                        default="SUBMITTED")
    return ["flags", "mark-submitted", key.strip(), "--status", status]


def _a_monitor_start():
    interval = _ask("Seconds between defense sweeps", default="10")
    return ["monitor", "start", "--interval", interval.strip() or "10"]


def _a_monitor_dashboard():
    interval = _ask("Seconds between sweeps", default="5")
    return ["monitor", "dashboard", "--interval", interval.strip() or "5"]


def run_menu() -> None:
    """Launch the interactive control console (loops until the operator exits)."""
    from typer.main import get_command

    from .main import app

    root = get_command(app)
    render_home()

    items = _menu_items()
    while True:
        table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
        table.add_column(justify="right", style="bold cyan", no_wrap=True)
        table.add_column(style="bold")
        table.add_column(style="dim")
        for key, label, desc, _ in items:
            table.add_row(key, label, desc)
        table.add_row("0", "Exit", "leave the console")
        console.print(Panel(table, title="[bold]AETHER control menu[/]",
                            border_style="cyan", padding=(1, 2)))

        choice = Prompt.ask("[bold cyan]Select[/]",
                            choices=[k for k, *_ in items] + ["0"], default="0",
                            show_choices=False)
        if choice == "0":
            console.print("[dim]bye — good hunting, submit those flags yourself![/]")
            return

        builder = next(b for k, _, _, b in items if k == choice)
        try:
            argv = builder()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]cancelled[/]")
            continue
        if argv is None:
            console.print("[yellow]cancelled[/]")
            continue

        console.rule(f"[dim]aether {' '.join(argv)}[/]")
        try:
            root.main(args=argv, prog_name="aether", standalone_mode=False)
        except SystemExit:
            pass  # typer.Exit / ctx.exit from a command — not fatal to the menu
        except KeyboardInterrupt:
            console.print("\n[yellow]interrupted[/]")
        except Exception as exc:  # noqa: BLE001 - keep the console alive
            console.print(f"[red]error: {type(exc).__name__}: {exc}[/]")
        console.rule(style="dim")
        Prompt.ask("[dim]press Enter to return to the menu[/]", default="")
