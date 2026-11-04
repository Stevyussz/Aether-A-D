"""Service health monitoring and functional checking.

Both are built around injectable async probes so they are environment-neutral: a lab test
supplies in-memory probes; in competition an adapter supplies real HTTP/TCP probes. The
functionality checker is what the patch workflow uses to confirm a service still behaves
correctly *after* a patch (preserving service interfaces and expected behavior).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..core.logger import get_logger

log = get_logger("service_monitor")

# A probe returns (ok, detail).
Probe = Callable[[], Awaitable[tuple[bool, str]]]


@dataclass
class HealthResult:
    service: str
    up: bool
    latency_ms: float
    detail: str = ""


@dataclass
class FunctionalResult:
    service: str
    passed: bool
    checks: dict[str, bool] = field(default_factory=dict)
    detail: str = ""

    @property
    def failed_checks(self) -> list[str]:
        return [name for name, ok in self.checks.items() if not ok]


class ServiceHealthMonitor:
    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, service: str, probe: Probe) -> None:
        self._probes[service] = probe

    async def check(self, service: str) -> HealthResult:
        probe = self._probes[service]
        start = time.perf_counter()
        try:
            up, detail = await probe()
        except Exception as exc:  # noqa: BLE001
            up, detail = False, f"probe error: {type(exc).__name__}: {exc}"
        latency = (time.perf_counter() - start) * 1000
        result = HealthResult(service=service, up=up, latency_ms=round(latency, 2), detail=detail)
        if not up:
            log.warning("service DOWN", extra={"ctx": {"service": service, "detail": detail}})
        return result

    async def check_all(self) -> list[HealthResult]:
        return [await self.check(s) for s in self._probes]


class ServiceFunctionalityChecker:
    """Runs a suite of named functional checks for a service; all must pass."""

    def __init__(self) -> None:
        self._suites: dict[str, dict[str, Probe]] = {}

    def register_check(self, service: str, name: str, probe: Probe) -> None:
        self._suites.setdefault(service, {})[name] = probe

    async def verify(self, service: str) -> FunctionalResult:
        suite = self._suites.get(service, {})
        checks: dict[str, bool] = {}
        details: list[str] = []
        for name, probe in suite.items():
            try:
                ok, detail = await probe()
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            checks[name] = ok
            if not ok:
                details.append(f"{name}: {detail}")
        passed = all(checks.values()) if checks else False
        return FunctionalResult(
            service=service,
            passed=passed,
            checks=checks,
            detail="; ".join(details) if details else ("ok" if passed else "no checks registered"),
        )
