"""AttackEngine — recon + validated exploit execution + flag pipeline.

Flow for an exploit run:
  prerequisites -> scope-enforced execution -> flag extraction (from genuine output)
  -> independent verification -> ingest into the MANUAL Flag Inbox (PENDING, never submitted).

The engine never submits flags and never fabricates them: flags are only those actually
present in (or extracted from) the real execution result.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.logger import get_logger
from ..core.models import Flag, ModuleResult, TaskState
from ..core.orchestrator import Orchestrator
from ..core.plugin import Module, RunContext
from .exploits.base import ExploitPlugin
from .flags.extractor import FlagExtractor
from .flags.inbox import FlagInbox, IngestOutcome
from .flags.validator import FlagValidator
from .verification.verifier import ExploitVerifier, VerificationReport

log = get_logger("attack_engine")


@dataclass
class ExploitRun:
    result: ModuleResult
    verification: VerificationReport
    ingested: list[IngestOutcome] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.verification.verified


class AttackEngine:
    def __init__(self, orch: Orchestrator, inbox: FlagInbox) -> None:
        self.orch = orch
        self.inbox = inbox
        pattern = orch.config.flags.pattern
        self._extractor = FlagExtractor(pattern)
        self._validator = FlagValidator(pattern)
        self._verifier = ExploitVerifier(self._validator)

    async def recon(self, module: Module, context: RunContext) -> ModuleResult:
        """Run a recon/assessment module (scope enforced by the orchestrator)."""
        return await self.orch.run_module(module, context)

    def _extract_candidates(self, result: ModuleResult) -> list[str]:
        """Collect flag strings from genuine result output (detail + data text)."""
        texts: list[str] = [result.detail or ""]
        for v in result.data.values():
            if isinstance(v, str):
                texts.append(v)
            elif isinstance(v, (list, dict)):
                texts.append(str(v))
        found: list[str] = []
        for t in texts:
            found.extend(self._extractor.extract(t))
        # dedup, preserve order
        return list(dict.fromkeys(found))

    async def run_exploit(self, plugin: ExploitPlugin, context: RunContext) -> ExploitRun:
        # 1. Prerequisites (don't even attempt if unmet).
        ok, reason = plugin.prerequisites_met(context)
        if not ok:
            res = ModuleResult(module=plugin.identifier, target=context.target_host,
                               state=TaskState.FAILED, detail=f"prerequisites unmet: {reason}")
            return ExploitRun(result=res, verification=VerificationReport(False, reason))

        # 2. Scope-enforced, timeout-bounded execution.
        result = await self.orch.run_module(plugin, context)

        # 3. Extract any flags from genuine output not already attached by the plugin.
        if result.state == TaskState.SUCCEEDED:
            existing = {f.value for f in result.flags}
            for value in self._extract_candidates(result):
                if value not in existing:
                    result.flags.append(
                        Flag(
                            value=value,
                            target=context.target_host or "unknown",
                            service=context.service,
                            module=plugin.identifier,
                            tick=context.tick,
                        )
                    )

        # 4. Independent verification.
        verification = self._verifier.verify(result)

        # 5. Ingest genuine flags into the MANUAL inbox (PENDING). Even unverified flags
        #    are surfaced so the operator sees them — but clearly marked by validation.
        ingested: list[IngestOutcome] = []
        for flag in result.flags:
            # ensure provenance fields are set
            flag.target = flag.target or (context.target_host or "unknown")
            flag.module = flag.module or plugin.identifier
            flag.tick = flag.tick or context.tick
            ingested.append(await self.inbox.ingest(flag))

        return ExploitRun(result=result, verification=verification, ingested=ingested)
