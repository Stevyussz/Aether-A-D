"""ToolReconModule — run installed external scanners and feed results into the sweep.

Drives :mod:`toolscan` (rustscan/nmap, gobuster/ffuf, whatweb) against ONE authorized target,
merges what it finds into ``context.extra`` so the exploit arsenal attacks a bigger, more
accurate surface:

- ``open_ports``        — every open port+service (so you notice extra web/data-store ports).
- ``discovered_endpoints`` — extra paths found by content discovery (added to the crawl's).
- ``fingerprints``      — detected tech stack (informs which exploits matter).

Read-only discovery; scope is enforced before anything runs.
"""

from __future__ import annotations

from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext
from . import toolscan


class ToolReconModule(Module):
    meta = ModuleMeta(
        identifier="recon.tools",
        description="Drive installed external scanners (rustscan/nmap, gobuster/ffuf, whatweb) "
                    "to discover ports, endpoints, and tech — read-only.",
        supported_kinds=("web", "http", "https", "tcp", "unknown", ""),
        requires_scope=True,
        timeout=180.0,
        category="recon",
        tags=("recon", "nmap", "rustscan", "gobuster", "ffuf", "whatweb"),
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        port = context.target_port or int(context.extra.get("port", 80))
        if context.scope is not None:
            context.scope.enforce(host, port)

        scheme = context.extra.get("scheme") or ("https" if port in (443, 8443) else "http")
        base = f"{scheme}://{host}:{port}"
        want_ports = context.extra.get("tool_ports", True)
        want_content = context.extra.get("tool_content", True)
        want_fp = context.extra.get("tool_fingerprint", True)
        want_nuclei = context.extra.get("tool_nuclei", False)   # slower; opt-in

        tools = toolscan.detect_tools()
        data: dict = {"tools_available": tools}
        summary_bits: list[str] = []

        # 1) Ports + services.
        if want_ports:
            ps = await toolscan.port_scan(host, timeout=float(context.extra.get("port_timeout", 90)))
            services = ps.get("services", [])
            data["open_ports"] = services
            data["port_tool"] = ps.get("tool")
            context.extra["open_ports"] = services
            http_ports = [s["port"] for s in services
                          if s.get("service", "").startswith("http") or "http" in s.get("service", "")
                          or s["port"] in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000)]
            if http_ports:
                context.extra["http_ports"] = sorted(set(http_ports))
            summary_bits.append(f"{len(services)} open port(s) via {ps.get('tool')}")

        # 2) Content discovery (web only).
        if want_content and (context.service or "web").lower() in ("web", "http", "https", ""):
            cd = await toolscan.content_discovery(base, timeout=float(context.extra.get("content_timeout", 45)))
            paths = [p["path"] for p in cd.get("paths", [])]
            data["discovered_paths"] = cd.get("paths", [])
            data["content_tool"] = cd.get("tool")
            if paths:
                merged = list(dict.fromkeys([*(context.extra.get("discovered_endpoints") or []), *paths]))
                context.extra["discovered_endpoints"] = merged
                context.extra["discovered_paths"] = merged
            if cd.get("tool"):
                summary_bits.append(f"{len(paths)} path(s) via {cd.get('tool')}")

        # 3) Fingerprint (web only).
        if want_fp and (context.service or "web").lower() in ("web", "http", "https", ""):
            fp = await toolscan.fingerprint(base, timeout=float(context.extra.get("fp_timeout", 30)))
            if fp.get("tech"):
                data["fingerprints"] = fp["tech"]
                context.extra["fingerprints"] = fp["tech"]
                summary_bits.append(f"{len(fp['tech'])} tech token(s) via whatweb")

        # 4) nuclei templated CVE checks (opt-in) — detection leads for the operator; AETHER
        #    does not auto-exploit these, it surfaces them (works across all service types).
        if want_nuclei and (context.service or "web").lower() in ("web", "http", "https", ""):
            nf = await toolscan.nuclei_scan(base, timeout=float(context.extra.get("nuclei_timeout", 180)))
            findings = nf.get("findings", [])
            if findings:
                data["nuclei"] = findings
                context.extra["nuclei_findings"] = findings
                sev = {}
                for f in findings:
                    sev[f.get("severity", "unknown")] = sev.get(f.get("severity", "unknown"), 0) + 1
                summary_bits.append(f"{len(findings)} nuclei finding(s) ({sev})")

        installed = [t for t, ok in tools.items() if ok]
        detail = ("; ".join(summary_bits) if summary_bits
                  else f"no external recon tools installed ({', '.join(installed) or 'none'})")
        return ModuleResult(module=self.identifier, target=host,
                            state=TaskState.SUCCEEDED, detail=detail, data=data)
