"""AttackSweep — run the whole validated exploit arsenal against one authorized target.

This is the "just point it and it finds flags" entry point. It runs every validated web
exploit module against a single authorized target, extracts genuine flags, and lands them in
the MANUAL Flag Inbox (PENDING — the operator submits). It never attacks out of scope (each
run is scope-enforced by the engine/orchestrator) and never fabricates flags.

Honesty note: a sweep only finds a flag if the target genuinely has the corresponding
vulnerability. Empty results mean "nothing matched", never a fabricated success.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.logger import get_logger
from ..core.plugin import RunContext
from .engine import AttackEngine, ExploitRun
from .exploits.base import ExploitPlugin
from .exploits.memcached_unauth import MemcachedUnauthExploit
from .exploits.redis_unauth import RedisUnauthExploit
from .exploits.tcp_vault import TcpVaultExploit
from .exploits.web_command_injection import CommandInjectionExploit
from .exploits.web_default_creds import DefaultCredsExploit
from .exploits.web_deserialization import DeserializationExploit
from .exploits.web_elasticsearch import ElasticsearchExploit
from .exploits.web_exposed_files import ExposedFilesExploit
from .exploits.web_graphql import GraphqlExploit
from .exploits.web_idor import IdorExploit
from .exploits.web_jwt import JwtWeaknessExploit
from .exploits.web_nosqli import NoSqlInjectionExploit
from .exploits.web_path_traversal import PathTraversalExploit
from .exploits.web_sqli import SqlInjectionExploit
from .exploits.web_ssrf import SsrfExploit
from .exploits.web_ssti import SstiExploit
from .exploits.web_xxe import XxeExploit

log = get_logger("attack_sweep")

# Validated web (HTTP) exploits, ordered cheapest/highest-yield first.
WEB_EXPLOITS: tuple[type[ExploitPlugin], ...] = (
    ExposedFilesExploit,
    PathTraversalExploit,
    SqlInjectionExploit,
    CommandInjectionExploit,
    SstiExploit,
    NoSqlInjectionExploit,
    DefaultCredsExploit,
    IdorExploit,
    JwtWeaknessExploit,
    DeserializationExploit,
    SsrfExploit,
    XxeExploit,
    GraphqlExploit,
    ElasticsearchExploit,
)

# Raw-TCP / data-store exploits for non-HTTP competition services.
NETWORK_EXPLOITS: tuple[type[ExploitPlugin], ...] = (
    RedisUnauthExploit,
    MemcachedUnauthExploit,
    TcpVaultExploit,
)

ALL_EXPLOITS: tuple[type[ExploitPlugin], ...] = WEB_EXPLOITS + NETWORK_EXPLOITS

_WEB_KINDS = {"web", "http", "https", "elasticsearch", "elastic", ""}


def default_web_exploits() -> list[ExploitPlugin]:
    """Instantiate one of each validated web exploit module."""
    return [cls() for cls in WEB_EXPLOITS]


def exploits_for(kind: str | None) -> list[ExploitPlugin]:
    """Pick the right exploit set for a target's service kind.

    Web/HTTP kinds get the HTTP arsenal; a specific datastore kind gets its module; any other
    (custom TCP) kind gets the full network set. Unknown → web (the common case).
    """
    k = (kind or "web").lower()
    if k in _WEB_KINDS:
        return default_web_exploits()
    if k == "redis":
        return [RedisUnauthExploit()]
    if k == "memcached":
        return [MemcachedUnauthExploit()]
    # custom TCP / unknown non-web service: try the whole network set.
    return [cls() for cls in NETWORK_EXPLOITS]


@dataclass
class SweepReport:
    target: str
    runs: list[ExploitRun] = field(default_factory=list)
    discovered_endpoints: list[str] = field(default_factory=list)
    discovered_params: list[str] = field(default_factory=list)
    fast_path: list[str] = field(default_factory=list)

    @property
    def modules_run(self) -> int:
        return len(self.runs)

    @property
    def confirmed_modules(self) -> list[str]:
        return [r.result.module for r in self.runs if r.confirmed]

    @property
    def flags_found(self) -> list[str]:
        seen: dict[str, None] = {}
        for r in self.runs:
            for f in r.result.flags:
                seen.setdefault(f.value, None)
        return list(seen)

    @property
    def any_flag(self) -> bool:
        return bool(self.flags_found)

    def summary(self) -> str:
        return (f"swept {self.target}: {self.modules_run} module(s), "
                f"{len(self.confirmed_modules)} confirmed, {len(self.flags_found)} flag(s)")


class AttackSweep:
    """Run many exploit modules against a single authorized target."""

    def __init__(self, engine: AttackEngine, memory=None) -> None:
        self.engine = engine
        self.memory = memory  # optional ExploitMemory for the learned fast path

    async def _recon(self, context: RunContext) -> tuple[list[str], list[str]]:
        """Crawl the target and return (endpoints, params). Best-effort; empty on failure."""
        from .recon.web_crawl import WebCrawlModule

        res = await self.engine.recon(WebCrawlModule(), context)
        if not res.ok:
            return [], []
        return list(res.data.get("endpoints", [])), list(res.data.get("params", []))

    async def run(
        self,
        context: RunContext,
        plugins: list[ExploitPlugin] | None = None,
        recon: bool = False,
    ) -> SweepReport:
        plugins = plugins if plugins is not None else exploits_for(context.service)
        report = SweepReport(target=context.target_host or "unknown")

        # Exploit farm: run modules that previously confirmed on this target FIRST.
        if self.memory is not None:
            learned = await self.memory.learned(report.target, context.service)
            if learned:
                order = {m: i for i, m in enumerate(learned)}
                plugins = sorted(plugins, key=lambda p: order.get(p.identifier, len(order)))
                report.fast_path = [p.identifier for p in plugins
                                    if p.identifier in order]

        # Smart mode: learn the real attack surface first, then aim payloads at it.
        if recon and (context.service or "web").lower() in _WEB_KINDS:
            endpoints, params = await self._recon(context)
            report.discovered_endpoints = endpoints
            report.discovered_params = params
            if endpoints:
                context.extra["discovered_endpoints"] = endpoints
                context.extra["discovered_paths"] = endpoints
            if params:
                context.extra["discovered_params"] = params
            log.info("sweep.recon", extra={"extra_fields": {
                "target": report.target, "endpoints": len(endpoints), "params": len(params),
            }})

        # Sequential by design: bounded, predictable load on the target (no accidental DoS).
        for plugin in plugins:
            run = await self.engine.run_exploit(plugin, context)
            report.runs.append(run)
            flags = len(run.result.flags)
            log.info("sweep.module", extra={"extra_fields": {
                "module": plugin.identifier, "state": run.result.state.value,
                "confirmed": run.confirmed, "flags": flags, "target": report.target,
            }})
        # Remember what worked so the next round runs it first.
        if self.memory is not None and report.confirmed_modules:
            await self.memory.record(report.target, context.service,
                                     report.confirmed_modules)
        log.info("sweep.done", extra={"extra_fields": {
            "target": report.target, "modules": report.modules_run,
            "confirmed": report.confirmed_modules, "flags": len(report.flags_found),
            "fast_path": report.fast_path,
        }})
        return report
