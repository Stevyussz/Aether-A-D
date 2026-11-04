"""Scope enforcement — the single most safety-critical component.

Rules (blueprint §2):
- Explicit target allowlisting is mandatory.
- Never touch anything outside the authorized competition scope.
- Fail *closed*: if scope is empty, unconfigured, or the target identity is uncertain, deny.

The guard matches on host (IP or hostname) + optional port. It understands individual IPs,
CIDR ranges, and exact hostnames. It never does fuzzy/substring matching — a host is either
explicitly allowed or it is denied.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .logger import get_logger
from .models import Target

log = get_logger("scope_guard")


class ScopeViolation(Exception):
    """Raised when an operation is attempted against an out-of-scope target."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    port: int | None = None


class ScopeGuard:
    """Holds the authorized allowlist and arbitrates every target access."""

    def __init__(self, enforce: bool = True) -> None:
        # enforce=False is ONLY for isolated local-lab fixtures; never in competition.
        self._enforce = enforce
        self._hosts: set[str] = set()
        self._networks: list[ipaddress._BaseNetwork] = []
        self._ports: dict[str, set[int]] = {}  # host -> allowed ports (empty set = any)
        self._targets: dict[str, Target] = {}

    @property
    def enforced(self) -> bool:
        return self._enforce

    def load_targets(self, targets: list[Target]) -> None:
        """Replace the allowlist with the given explicitly-authorized targets."""
        self._hosts.clear()
        self._networks.clear()
        self._ports.clear()
        self._targets.clear()
        for t in targets:
            self.allow(t.host, ports=t.ports, name=t.name)
            self._targets[t.host] = t
        log.info(
            "scope loaded",
            extra={"ctx": {"hosts": len(self._hosts), "networks": len(self._networks)}},
        )

    def allow(self, host: str, ports: tuple[int, ...] = (), name: str = "") -> None:
        host = host.strip()
        if not host:
            raise ValueError("empty host cannot be added to scope")
        # Try to interpret as a network/CIDR first, then a bare IP, else a hostname.
        try:
            if "/" in host:
                self._networks.append(ipaddress.ip_network(host, strict=False))
            else:
                ipaddress.ip_address(host)  # validate it is an IP
                self._hosts.add(host)
        except ValueError:
            # Not an IP/CIDR -> treat as an exact hostname (lowercased).
            self._hosts.add(host.lower())
        if ports:
            self._ports.setdefault(host.lower() if not _is_ip(host) else host, set()).update(ports)

    def is_empty(self) -> bool:
        return not self._hosts and not self._networks

    def check(self, host: str, port: int | None = None) -> ScopeDecision:
        """Return a ScopeDecision. Fail-closed on every uncertainty."""
        host = (host or "").strip()
        if not self._enforce:
            return ScopeDecision(True, "enforcement disabled (lab mode)", host, port)
        if not host:
            return ScopeDecision(False, "empty/unknown target host", host, port)
        if self.is_empty():
            return ScopeDecision(False, "scope is empty — fail closed", host, port)

        matched = self._host_in_scope(host)
        if not matched:
            return ScopeDecision(False, "host not in authorized allowlist", host, port)

        if port is not None:
            allowed_ports = self._ports.get(host.lower() if not _is_ip(host) else host, set())
            if allowed_ports and port not in allowed_ports:
                return ScopeDecision(
                    False, f"port {port} not authorized for host", host, port
                )
        return ScopeDecision(True, "authorized", host, port)

    def enforce(self, host: str, port: int | None = None) -> None:
        """Raise ScopeViolation if not allowed. Use before any target access."""
        decision = self.check(host, port)
        if not decision.allowed:
            log.warning(
                "scope DENIED",
                extra={"ctx": {"host": host, "port": port, "reason": decision.reason}},
            )
            raise ScopeViolation(
                f"out-of-scope access denied: {host}"
                + (f":{port}" if port is not None else "")
                + f" — {decision.reason}"
            )

    def _host_in_scope(self, host: str) -> bool:
        if _is_ip(host):
            if host in self._hosts:
                return True
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._networks)
        return host.lower() in self._hosts

    def target_for(self, host: str) -> Target | None:
        return self._targets.get(host)

    @property
    def summary(self) -> dict:
        return {
            "enforced": self._enforce,
            "hosts": sorted(self._hosts),
            "networks": [str(n) for n in self._networks],
            "empty": self.is_empty(),
        }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
