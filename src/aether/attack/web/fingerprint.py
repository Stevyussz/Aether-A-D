"""Web assessment — safe, scope-gated HTTP fingerprinting.

Non-destructive: issues a small number of ordinary GET requests to the target and records
status, server header, title, and detected technologies. No fuzzing, no injection, no
destructive payloads. This is reconnaissance of an authorized target, nothing more.
"""

from __future__ import annotations

import re

import httpx

from ...core.logger import get_logger
from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext

log = get_logger("web.fingerprint")

_TITLE_RX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class WebFingerprintModule(Module):
    meta = ModuleMeta(
        identifier="web.fingerprint",
        description="Safe HTTP fingerprint (status, server, title) of an authorized target.",
        supported_kinds=("web",),
        category="recon",
        timeout=15.0,
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        if not host:
            return ModuleResult(module=self.identifier, state=TaskState.FAILED, detail="no host")
        port = context.target_port or int(context.extra.get("port", 80))
        scheme = context.extra.get("scheme", "https" if port == 443 else "http")
        path = context.extra.get("path", "/")
        url = f"{scheme}://{host}:{port}{path}"

        if context.scope is not None and not context.scope.check(host, port).allowed:
            return ModuleResult(module=self.identifier, target=host, state=TaskState.FAILED,
                                detail="target out of scope")

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.meta.timeout,
                                         follow_redirects=True) as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            return ModuleResult(module=self.identifier, target=host, state=TaskState.FAILED,
                                detail=f"request failed: {type(exc).__name__}: {exc}")

        body = resp.text or ""
        title_m = _TITLE_RX.search(body)
        data = {
            "url": url,
            "status": resp.status_code,
            "server": resp.headers.get("server", ""),
            "powered_by": resp.headers.get("x-powered-by", ""),
            "title": (title_m.group(1).strip()[:120] if title_m else ""),
            "content_length": len(body),
        }
        return ModuleResult(
            module=self.identifier, target=host, state=TaskState.SUCCEEDED,
            detail=f"HTTP {resp.status_code} {data['server']}".strip(), data=data,
        )
