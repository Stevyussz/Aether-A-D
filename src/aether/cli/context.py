"""CLI helpers: locating/loading config and a shared Rich console."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ..core.config_manager import AetherConfig, load_config

console = Console()
err_console = Console(stderr=True)

DEFAULT_CONFIG = Path("config/aether.yaml")
EXAMPLE_CONFIG = Path("config/aether.example.yaml")


def resolve_config_path(explicit: str | None = None) -> Path | None:
    """Return the config path to use, or None if nothing is available."""
    if explicit:
        return Path(explicit)
    if DEFAULT_CONFIG.exists():
        return DEFAULT_CONFIG
    if EXAMPLE_CONFIG.exists():
        return EXAMPLE_CONFIG
    return None


def load_cli_config(explicit: str | None = None) -> tuple[AetherConfig, Path]:
    """Load config, raising a friendly error if missing."""
    path = resolve_config_path(explicit)
    if path is None:
        raise FileNotFoundError(
            "no configuration found. Run `aether init` or create config/aether.yaml"
        )
    return load_config(path), path
