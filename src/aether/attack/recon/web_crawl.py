"""Adaptive web crawler — discovers the real attack surface of a target.

Instead of firing blind wordlists, AETHER first crawls the authorized target to learn its
actual endpoints, query parameters, and form fields, then feeds those into the exploit
modules (via ``discovered_endpoints`` / ``discovered_params``) so payloads hit real injection
points first. Read-only GET crawl, same-host only, bounded in pages and depth. Scope is
enforced by the orchestrator before this runs.
"""

from __future__ import annotations

import asyncio
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext


class _LinkFormParser(HTMLParser):
    """Collect hrefs/srcs/actions and form field names from an HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.field_names: set[str] = set()
        self._cur: dict | None = None

    def handle_starttag(self, tag: str, attrs_list: list) -> None:
        attrs = dict(attrs_list)
        if tag in ("a", "link", "script", "img", "iframe"):
            url = attrs.get("href") or attrs.get("src")
            if url:
                self.links.append(url)
        elif tag == "form":
            self._cur = {"action": attrs.get("action", ""),
                         "method": (attrs.get("method") or "GET").upper(), "fields": []}
        elif tag in ("input", "textarea", "select"):
            name = attrs.get("name")
            if name:
                self.field_names.add(name)
                if self._cur is not None:
                    self._cur["fields"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


class WebCrawlModule(Module):
    meta = ModuleMeta(
        identifier="recon.web_crawl",
        description="Crawl an authorized web target to discover endpoints, parameters, and "
                    "form fields (read-only).",
        supported_kinds=("web", "http"),
        requires_scope=True,
        timeout=25.0,
        category="recon",
        tags=("web", "recon", "crawl"),
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        port = context.target_port or int(context.extra.get("port", 80))
        scheme = context.extra.get("scheme") or ("https" if port in (443, 8443) else "http")
        base = f"{scheme}://{host}:{port}"
        if context.scope is not None:
            context.scope.enforce(host, port)

        max_pages = int(context.extra.get("max_pages", 40))
        max_depth = int(context.extra.get("max_depth", 2))
        seeds = context.extra.get("seeds") or ["/"]

        seen: set[str] = set()
        endpoints: set[str] = set()
        params: set[str] = set()
        forms: list[dict] = []
        queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
        verify = bool(context.extra.get("tls_verify", False))

        try:
            async with httpx.AsyncClient(timeout=self.meta.timeout, follow_redirects=True,
                                         verify=verify) as client:
                while queue and len(seen) < max_pages:
                    path, depth = queue.popleft()
                    if path in seen:
                        continue
                    seen.add(path)
                    if not path.startswith("/"):
                        path = "/" + path
                    endpoints.add(path.split("?", 1)[0] or "/")
                    for k in parse_qs(urlparse(path).query):
                        params.add(k)
                    try:
                        resp = await client.get(base + path)
                    except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError):
                        continue
                    ctype = resp.headers.get("content-type", "")
                    if "html" not in ctype and "xml" not in ctype:
                        continue
                    parser = _LinkFormParser()
                    try:
                        parser.feed(resp.text)
                    except Exception:  # noqa: BLE001 - never let malformed HTML crash recon
                        continue
                    params.update(parser.field_names)
                    for form in parser.forms:
                        action = urljoin(base + path, form["action"] or path)
                        ap = urlparse(action)
                        if ap.netloc == urlparse(base).netloc:
                            form_path = ap.path or "/"
                            endpoints.add(form_path)
                            forms.append({"path": form_path, "method": form["method"],
                                          "fields": form["fields"]})
                    if depth >= max_depth:
                        continue
                    for link in parser.links:
                        # Skip non-navigable schemes (data:/javascript:/mailto:/tel:/blob:) —
                        # e.g. a phpinfo page's data: logo would otherwise queue a pathless
                        # "image/..." that fuses into the authority and breaks URL parsing.
                        low = link.strip().lower()
                        if low.split(":", 1)[0] in ("data", "javascript", "mailto", "tel",
                                                    "blob", "about", "file") and ":" in low:
                            continue
                        absu = urljoin(base + path, link)
                        pu = urlparse(absu)
                        if pu.scheme and pu.scheme not in ("http", "https"):
                            continue
                        if pu.netloc and pu.netloc != urlparse(base).netloc:
                            continue  # same-host only
                        np = pu.path or "/"
                        if not np.startswith("/"):
                            np = "/" + np   # never let a path fuse into host:port
                        for k in parse_qs(pu.query):
                            params.add(k)
                        npq = np + (("?" + pu.query) if pu.query else "")
                        if np not in {s.split("?", 1)[0] for s in seen}:
                            queue.append((npq, depth + 1))
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError) as exc:
            # Return what we crawled so far rather than failing recon outright.
            if endpoints:
                return ModuleResult(
                    module=self.identifier, target=host, state=TaskState.SUCCEEDED,
                    detail=f"crawled {len(seen)} page(s) (stopped early: {type(exc).__name__})",
                    data={"endpoints": sorted(endpoints), "params": sorted(params),
                          "forms": forms})
            return ModuleResult(module=self.identifier, target=host, state=TaskState.FAILED,
                                detail=f"crawl error: {type(exc).__name__}: {exc}")

        return ModuleResult(
            module=self.identifier, target=host, state=TaskState.SUCCEEDED,
            detail=f"crawled {len(seen)} page(s): {len(endpoints)} endpoint(s), "
                   f"{len(params)} param(s), {len(forms)} form(s)",
            data={"endpoints": sorted(endpoints), "params": sorted(params), "forms": forms},
        )
