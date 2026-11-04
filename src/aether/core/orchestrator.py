"""The orchestrator wires core components together and owns their lifecycle.

It is intentionally thin: construct from config, start (open state, load scope, start
scheduler), expose helpers to run modules under scope + execution guards, and shut down
gracefully. Attack and defense engines build on top of this.
"""

from __future__ import annotations

import asyncio

from .config_manager import AetherConfig
from .event_bus import Event, EventBus
from .execution_guard import ExecutionGuard
from .logger import configure_logging, get_logger
from .models import ModuleResult, TaskState
from .module_loader import ModuleLoader
from .plugin import Module, RunContext
from .scheduler import Scheduler
from .scope_guard import ScopeGuard, ScopeViolation
from .state_manager import StateManager

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(self, config: AetherConfig) -> None:
        self.config = config
        configure_logging(level=config.engine.log_level, log_file=config.engine.log_file)
        self.events = EventBus()
        self.guard = ExecutionGuard(
            max_concurrency=config.engine.max_concurrency,
            default_timeout=config.engine.default_timeout,
        )
        self.scheduler = Scheduler(self.guard)
        self.scope = ScopeGuard(enforce=config.scope.enforce)
        self.state = StateManager(config.engine.state_db)
        self.loader = ModuleLoader()
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        await self.state.open()
        self.scope.load_targets(list(self.config.scope.targets))
        await self.scheduler.start()
        self._started = True
        await self.events.publish(Event("orchestrator.started", source="orchestrator"))
        log.info("orchestrator started", extra={"ctx": self.scope.summary})

    async def shutdown(self) -> None:
        if not self._started:
            return
        await self.events.publish(Event("orchestrator.stopping", source="orchestrator"))
        await self.scheduler.stop()
        await self.state.close()
        self._started = False
        log.info("orchestrator shut down")

    async def run_module(self, module: Module, context: RunContext) -> ModuleResult:
        """Run a single module, enforcing scope before execution.

        If the module requires scope and the target is out of scope, the module never
        executes — the result is a FAILED state with a scope reason (fail closed).
        """
        context.scope = self.scope
        context.config = self.config

        if module.meta.requires_scope and context.target_host is not None:
            try:
                self.scope.enforce(context.target_host, context.target_port)
            except ScopeViolation as exc:
                await self.events.publish(
                    Event(
                        "scope.denied",
                        payload={"module": module.identifier, "host": context.target_host},
                        source="orchestrator",
                    )
                )
                return ModuleResult(
                    module=module.identifier,
                    target=context.target_host,
                    state=TaskState.FAILED,
                    detail="scope enforcement denied execution",
                    error=str(exc),
                )

        result = await self.guard.run_module(
            module.identifier,
            lambda: module.run(context),
            target=context.target_host,
            timeout=module.meta.timeout,
        )
        await self.events.publish(
            Event(
                "module.finished",
                payload={"module": module.identifier, "state": result.state.value},
                source="orchestrator",
            )
        )
        return result

    async def run_modules(
        self, items: list[tuple[Module, RunContext]]
    ) -> list[ModuleResult]:
        """Run many modules concurrently (bounded by the ExecutionGuard semaphore)."""
        return await asyncio.gather(*(self.run_module(m, c) for m, c in items))

    @property
    def status(self) -> dict:
        return {
            "started": self._started,
            "scope": self.scope.summary,
            "scheduler": self.scheduler.stats,
            "execution": self.guard.stats,
            "events": self.events.stats,
            "modules_loaded": len(self.loader),
        }
