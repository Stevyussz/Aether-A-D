"""Generic module/plugin protocol.

Every runnable unit in AETHER (recon, assessment, exploit, defense check) implements this
protocol so the loader, scheduler, and guards can treat them uniformly. The attack engine
extends ExploitPlugin with the extra metadata the blueprint requires (prerequisites,
verification method, expected result, etc.).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from .models import ModuleResult


@dataclass(frozen=True)
class ModuleMeta:
    identifier: str
    description: str = ""
    supported_kinds: tuple[str, ...] = ()  # e.g. ("web",) ("linux",)
    requires_scope: bool = True
    timeout: float = 30.0
    category: str = "generic"  # recon | assessment | exploit | defense
    tags: tuple[str, ...] = field(default_factory=tuple)


class Module(abc.ABC):
    """Base class for all runnable modules."""

    meta: ModuleMeta

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Enforce that *concrete* subclasses declare metadata (no silent/anonymous
        # modules). A class is concrete here iff its `run` is not still abstract.
        # (__abstractmethods__ is not yet populated at __init_subclass__ time.)
        run = cls.__dict__.get("run") or getattr(cls, "run", None)
        if run is not None and not getattr(run, "__isabstractmethod__", False):
            if not hasattr(cls, "meta") or not isinstance(getattr(cls, "meta"), ModuleMeta):
                raise TypeError(f"{cls.__name__} must define a class-level `meta: ModuleMeta`")

    @property
    def identifier(self) -> str:
        return self.meta.identifier

    @abc.abstractmethod
    async def run(self, context: "RunContext") -> ModuleResult:
        """Execute the module against the given context and return a normalized result."""


@dataclass
class RunContext:
    """Everything a module may need at run time, injected by the orchestrator.

    The module must call ``context.scope.enforce(host, port)`` before touching any target.
    """

    target_host: str | None = None
    target_port: int | None = None
    service: str = "unknown"
    scope: object = None  # ScopeGuard (duck-typed to avoid import cycle)
    config: object = None  # AetherConfig
    tick: str | None = None
    extra: dict = field(default_factory=dict)
