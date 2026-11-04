"""Web/HTTP adapter — scope-gated HTTP client over httpx.

Provides a thin, reusable async HTTP surface for web modules (attack recon/assessment and
defense health probes). Every request host is scope-checked. Connection pooling is handled
by the underlying httpx.AsyncClient, which the adapter owns and reuses.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..core.logger import get_logger
from ..core.scope_guard import ScopeGuard

log = get_logger("adapter.web")


@dataclass
class HttpResponse:
    status: int
    headers: dict
    text: str
    url: str


class WebAdapter:
    def __init__(
        self,
        scope: ScopeGuard | None = None,
        timeout: float = 15.0,
        verify_tls: bool = False,  # CTF services often use self-signed certs
    ) -> None:
        self._scope = scope
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def __aenter__(self) -> "WebAdapter":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    def _host_port(self, url: str) -> tuple[str, int | None]:
        parsed = httpx.URL(url)
        return parsed.host, parsed.port

    async def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        host, port = self._host_port(url)
        if self._scope is not None:
            self._scope.enforce(host, port)
        resp = await self._client.request(method, url, **kwargs)
        return HttpResponse(
            status=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            url=str(resp.url),
        )

    async def get(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    def health_probe(self, url: str, expect_status: int = 200):
        """Return an async probe (for ServiceHealthMonitor) that GETs url."""

        async def _probe() -> tuple[bool, str]:
            try:
                r = await self.get(url)
                ok = r.status == expect_status
                return ok, f"HTTP {r.status}"
            except Exception as exc:  # noqa: BLE001
                return False, f"{type(exc).__name__}: {exc}"

        return _probe
