"""External tool integration — make AETHER smarter by driving best-of-breed scanners.

If the operator's machine has industry-standard tools installed (``rustscan``/``nmap`` for
port+service discovery, ``gobuster``/``ffuf`` for content discovery, ``whatweb`` for tech
fingerprinting, ``nuclei`` for templated vuln checks), AETHER shells out to them, parses their
output into structured data, and feeds it back into the sweep (open ports, extra endpoints,
fingerprints). When a tool is absent it degrades gracefully (a pure-Python TCP connect scan is
the fallback for ports). Nothing here is destructive: all invocations are discovery/read-only.

Safety: the caller MUST enforce scope before running any of these against a host. Every
subprocess is launched with an explicit argv (never a shell string), a bounded timeout, and
captured output.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path

from ...core.logger import get_logger

log = get_logger("toolscan")

# Small, high-signal path list for content discovery (keeps gobuster/ffuf fast and bounded).
COMMON_PATHS: tuple[str, ...] = (
    "admin", "administrator", "login", "login.php", "dashboard", "panel", "api", "api/v1",
    "uploads", "upload", "files", "backup", "backups", "config", "config.php", "db",
    "phpinfo.php", "info.php", "test", "dev", "debug", "flag", "flag.txt", "flags", "secret",
    ".git", ".git/HEAD", ".env", "robots.txt", "server-status", "wp-admin", "wp-login.php",
    "console", "shell", "cmd", "status", "health", "metrics", "graphql", "swagger",
    "swagger.json", "openapi.json", "static", "assets", "images", "tmp", "data", "logs",
    "user", "users", "account", "profile", "search", "home", "index.php", "server-info",
)


def available(tool: str) -> bool:
    """True if *tool* is on PATH."""
    return shutil.which(tool) is not None


def detect_tools() -> dict[str, bool]:
    """Report which supported external tools are installed."""
    return {t: available(t) for t in
            ("rustscan", "nmap", "gobuster", "ffuf", "whatweb", "nuclei", "nikto")}


async def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    """Run an argv (no shell), capture (returncode, stdout, stderr). Never raises on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except (OSError, ValueError) as exc:
        return 127, "", f"spawn failed: {exc}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "", f"timeout after {timeout}s"
    return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


# --------------------------- parsers (pure, unit-testable) ---------------------------------
def parse_rustscan_ports(text: str) -> list[int]:
    """Parse rustscan greppable output: ``127.0.0.1 -> [22,80,8080]``."""
    ports: set[int] = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                ports.add(int(p))
    return sorted(ports)


def parse_nmap_grepable(text: str) -> list[dict]:
    """Parse ``nmap -oG -`` output into [{port, proto, service, product}]."""
    services: list[dict] = []
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        portspart = line.split("Ports:", 1)[1]
        for entry in portspart.split(","):
            fields = entry.strip().split("/")
            # port / state / proto / owner / service / rpc / version
            if len(fields) < 5:
                continue
            port, state, proto = fields[0].strip(), fields[1].strip(), fields[2].strip()
            if state != "open" or not port.isdigit():
                continue
            service = fields[4].strip()
            product = fields[6].strip().replace("|", " ") if len(fields) > 6 else ""
            services.append({"port": int(port), "proto": proto,
                             "service": service or "unknown", "product": product})
    return services


def parse_gobuster(text: str) -> list[dict]:
    """Parse gobuster dir output lines: ``/admin (Status: 200) [Size: 1234]``."""
    found: list[dict] = []
    for line in text.splitlines():
        m = re.search(r"(/\S*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            found.append({"path": m.group(1), "status": int(m.group(2))})
    return found


def parse_ffuf_json(text: str) -> list[dict]:
    """Parse ffuf JSON (``-of json``) into [{path, status}]."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    out: list[dict] = []
    for r in doc.get("results", []) or []:
        word = r.get("input", {}).get("FUZZ") or r.get("url", "")
        path = word if str(word).startswith("/") else "/" + str(word)
        out.append({"path": path, "status": int(r.get("status", 0) or 0)})
    return out


def parse_whatweb(text: str) -> list[str]:
    """Extract technology tokens from whatweb plain output."""
    techs: set[str] = set()
    # whatweb prints: URL [200 OK] Apache[2.4.7], PHP[5.5.9], Country[...], ...
    for m in re.finditer(r"([A-Za-z][\w\-]+)(?:\[([^\]]*)\])?", text):
        name, ver = m.group(1), m.group(2)
        if name in ("http", "https", "OK", "URL", "Country", "IP", "GET"):
            continue
        techs.add(f"{name}[{ver}]" if ver else name)
    return sorted(techs)


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse nuclei ``-jsonl`` output into [{template, severity, matched}]."""
    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        findings.append({
            "template": o.get("template-id") or o.get("templateID") or "",
            "severity": (o.get("info", {}) or {}).get("severity", "unknown"),
            "matched": o.get("matched-at") or o.get("host") or "",
            "name": (o.get("info", {}) or {}).get("name", ""),
        })
    return findings


# --------------------------- high-level scans ----------------------------------------------
async def _python_connect_scan(host: str, ports: list[int], timeout: float) -> list[dict]:
    """Fallback: plain TCP connect scan (no external tool, no service version)."""
    open_ports: list[dict] = []

    async def _check(p: int) -> None:
        try:
            fut = asyncio.open_connection(host, p)
            reader, writer = await asyncio.wait_for(fut, timeout=1.5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            open_ports.append({"port": p, "proto": "tcp", "service": "unknown", "product": ""})
        except (OSError, asyncio.TimeoutError):
            pass

    await asyncio.gather(*[_check(p) for p in ports])
    return sorted(open_ports, key=lambda d: d["port"])


_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008,
                 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017]


async def port_scan(host: str, *, timeout: float = 90.0) -> dict:
    """Discover open ports + services. Uses rustscan→nmap, else nmap, else a Python fallback."""
    tool = None
    services: list[dict] = []
    if available("rustscan"):
        tool = "rustscan"
        rc, out, _ = await _run(
            ["rustscan", "-a", host, "-g", "--no-config", "-t", "2000", "--ulimit", "5000"],
            timeout=timeout * 0.5)
        ports = parse_rustscan_ports(out)
        if ports and available("nmap"):
            rc, out, _ = await _run(
                ["nmap", "-sV", "-Pn", "-T4", "-p", ",".join(map(str, ports)), "-oG", "-", host],
                timeout=timeout * 0.5)
            services = parse_nmap_grepable(out)
            tool = "rustscan+nmap"
        else:
            services = [{"port": p, "proto": "tcp", "service": "unknown", "product": ""}
                        for p in ports]
    elif available("nmap"):
        tool = "nmap"
        rc, out, _ = await _run(
            ["nmap", "-sV", "-Pn", "-T4", "--top-ports", "200", "-oG", "-", host],
            timeout=timeout)
        services = parse_nmap_grepable(out)
    else:
        tool = "python-connect"
        services = await _python_connect_scan(host, _COMMON_PORTS, timeout)
    log.info("port_scan", extra={"ctx": {"host": host, "tool": tool, "open": len(services)}})
    return {"tool": tool, "services": services}


def _wordlist_file() -> str:
    """Write the built-in COMMON_PATHS to a temp wordlist (for gobuster/ffuf)."""
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    f.write("\n".join(COMMON_PATHS))
    f.close()
    return f.name


async def content_discovery(base_url: str, *, timeout: float = 45.0) -> dict:
    """Find extra endpoints with ffuf→gobuster (bounded by a built-in wordlist)."""
    wl = _wordlist_file()
    try:
        if available("ffuf"):
            outp = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False).name
            rc, _out, _err = await _run(
                ["ffuf", "-u", base_url.rstrip("/") + "/FUZZ", "-w", wl, "-mc",
                 "200,201,204,301,302,307,401,403", "-of", "json", "-o", outp, "-s"],
                timeout=timeout)
            try:
                text = Path(outp).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            Path(outp).unlink(missing_ok=True)
            return {"tool": "ffuf", "paths": parse_ffuf_json(text)}
        if available("gobuster"):
            rc, out, _ = await _run(
                ["gobuster", "dir", "-u", base_url, "-w", wl, "-q", "-t", "20",
                 "-s", "200,201,204,301,302,307,401,403", "-b", ""], timeout=timeout)
            return {"tool": "gobuster", "paths": parse_gobuster(out)}
        return {"tool": None, "paths": []}
    finally:
        Path(wl).unlink(missing_ok=True)


async def fingerprint(base_url: str, *, timeout: float = 30.0) -> dict:
    """Fingerprint the web tech stack with whatweb (informs which exploits to prioritise)."""
    if not available("whatweb"):
        return {"tool": None, "tech": []}
    rc, out, _ = await _run(["whatweb", "--color=never", "-a", "1", base_url], timeout=timeout)
    return {"tool": "whatweb", "tech": parse_whatweb(out)}


async def nuclei_scan(base_url: str, *, timeout: float = 180.0) -> dict:
    """Run nuclei templated checks (opt-in; heavier/slower). Returns parsed findings."""
    if not available("nuclei"):
        return {"tool": None, "findings": []}
    rc, out, _ = await _run(
        ["nuclei", "-u", base_url, "-silent", "-jsonl", "-timeout", "5",
         "-rate-limit", "50", "-severity", "low,medium,high,critical"], timeout=timeout)
    return {"tool": "nuclei", "findings": parse_nuclei_jsonl(out)}
