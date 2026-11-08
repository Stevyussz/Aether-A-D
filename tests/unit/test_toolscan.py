"""Parsers for external-tool output are pure and robust (no tools/sockets needed)."""

from aether.attack.recon import toolscan


def test_parse_rustscan_ports():
    assert toolscan.parse_rustscan_ports("127.0.0.1 -> [22,80, 8080]") == [22, 80, 8080]
    assert toolscan.parse_rustscan_ports("no ports here") == []


def test_parse_nmap_grepable():
    line = ("Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2/, "
            "80/open/tcp//http//Apache httpd 2.4.41/, 3306/closed/tcp//mysql///\n")
    svc = toolscan.parse_nmap_grepable(line)
    ports = {s["port"]: s for s in svc}
    assert 22 in ports and ports[22]["service"] == "ssh"
    assert 80 in ports and "Apache" in ports[80]["product"]
    assert 3306 not in ports                      # closed is skipped


def test_parse_gobuster():
    out = "/admin (Status: 200) [Size: 10]\n/secret (Status: 301)\nnope\n"
    found = {f["path"]: f["status"] for f in toolscan.parse_gobuster(out)}
    assert found == {"/admin": 200, "/secret": 301}


def test_parse_ffuf_json():
    doc = '{"results":[{"input":{"FUZZ":"admin"},"status":200},{"url":"/x","status":403}]}'
    paths = {f["path"]: f["status"] for f in toolscan.parse_ffuf_json(doc)}
    assert paths["/admin"] == 200 and paths["/x"] == 403
    assert toolscan.parse_ffuf_json("not json") == []


def test_parse_whatweb():
    tech = toolscan.parse_whatweb("http://x [200 OK] Apache[2.4.7], PHP[5.5.9], JQuery")
    assert any(t.startswith("Apache") for t in tech)
    assert any(t.startswith("PHP") for t in tech)


def test_parse_nuclei_jsonl():
    jsonl = ('{"template-id":"git-config","info":{"severity":"medium","name":"Git"},'
             '"matched-at":"http://x/.git/config"}\n\n'
             'garbage line\n')
    f = toolscan.parse_nuclei_jsonl(jsonl)
    assert len(f) == 1 and f[0]["template"] == "git-config" and f[0]["severity"] == "medium"


def test_detect_tools_shape():
    d = toolscan.detect_tools()
    assert isinstance(d, dict) and "nmap" in d and all(isinstance(v, bool) for v in d.values())


async def test_tool_recon_module_merges_into_context(monkeypatch):
    # With tools "installed" (stubbed), the module feeds ports/endpoints/tech into extra.
    from aether.attack.recon import tool_recon
    from aether.core.plugin import RunContext

    async def fake_ports(host, **kw):
        return {"tool": "nmap", "services": [
            {"port": 80, "proto": "tcp", "service": "http", "product": "Apache"},
            {"port": 8080, "proto": "tcp", "service": "http-proxy", "product": ""}]}

    async def fake_content(base, **kw):
        return {"tool": "ffuf", "paths": [{"path": "/admin", "status": 200},
                                          {"path": "/backup", "status": 403}]}

    async def fake_fp(base, **kw):
        return {"tool": "whatweb", "tech": ["Apache[2.4]", "PHP[7.4]"]}

    monkeypatch.setattr(tool_recon.toolscan, "port_scan", fake_ports)
    monkeypatch.setattr(tool_recon.toolscan, "content_discovery", fake_content)
    monkeypatch.setattr(tool_recon.toolscan, "fingerprint", fake_fp)

    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web")
    res = await tool_recon.ToolReconModule().run(ctx)
    assert res.ok
    assert [s["port"] for s in ctx.extra["open_ports"]] == [80, 8080]
    assert "/admin" in ctx.extra["discovered_endpoints"]
    assert ctx.extra["fingerprints"] == ["Apache[2.4]", "PHP[7.4]"]
    assert 8080 in ctx.extra["http_ports"]


async def test_tool_recon_degrades_without_tools(monkeypatch):
    # No external tools at all: the fallback connect-scan is used and nothing crashes.
    from aether.attack.recon import tool_recon
    from aether.core.plugin import RunContext

    monkeypatch.setattr(tool_recon.toolscan, "available", lambda t: False)

    async def empty_ports(host, **kw):
        return {"tool": "python-connect", "services": []}

    monkeypatch.setattr(tool_recon.toolscan, "port_scan", empty_ports)
    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web")
    res = await tool_recon.ToolReconModule().run(ctx)
    assert res.ok                       # graceful, no exception
