"""Module/plugin registry and loader.

Supports two registration paths:
- explicit registration (used by built-in modules and tests), and
- package discovery: import all submodules of a package and collect Module subclasses.

Discovery is import-based (no eval, no dynamic code download). Duplicate identifiers are a
hard error — silent shadowing of a module is never allowed.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from .logger import get_logger
from .plugin import Module

log = get_logger("module_loader")


class ModuleLoader:
    def __init__(self) -> None:
        self._registry: dict[str, type[Module]] = {}

    def register(self, module_cls: type[Module]) -> type[Module]:
        """Register a Module subclass. Usable as a decorator."""
        if not (inspect.isclass(module_cls) and issubclass(module_cls, Module)):
            raise TypeError(f"{module_cls!r} is not a Module subclass")
        ident = module_cls.meta.identifier
        if ident in self._registry and self._registry[ident] is not module_cls:
            raise ValueError(f"duplicate module identifier: {ident!r}")
        self._registry[ident] = module_cls
        return module_cls

    def discover(self, package_name: str) -> int:
        """Import every submodule of a package so decorators run. Returns count discovered."""
        try:
            pkg = importlib.import_module(package_name)
        except ModuleNotFoundError:
            log.warning("discover: package not found", extra={"ctx": {"pkg": package_name}})
            return 0
        found_before = len(self._registry)
        if not hasattr(pkg, "__path__"):
            return 0
        for mod in pkgutil.walk_packages(pkg.__path__, prefix=f"{package_name}."):
            try:
                imported = importlib.import_module(mod.name)
            except Exception:  # noqa: BLE001
                log.exception("discover: import failed", extra={"ctx": {"mod": mod.name}})
                continue
            for _, obj in inspect.getmembers(imported, inspect.isclass):
                if (
                    issubclass(obj, Module)
                    and obj is not Module
                    and not getattr(obj, "__abstractmethods__", None)
                    and obj.__module__ == imported.__name__
                ):
                    try:
                        self.register(obj)
                    except ValueError:
                        pass  # already registered under same identifier
        return len(self._registry) - found_before

    def get(self, identifier: str) -> type[Module]:
        return self._registry[identifier]

    def create(self, identifier: str) -> Module:
        return self._registry[identifier]()

    def list_modules(self) -> list[type[Module]]:
        return list(self._registry.values())

    def __contains__(self, identifier: str) -> bool:
        return identifier in self._registry

    def __len__(self) -> int:
        return len(self._registry)
