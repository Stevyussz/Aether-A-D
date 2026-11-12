"""sqlmap deep-SQLi integration: opt-in gating, candidate URL building, injection detection,
and that a dumped flag flows through the normal flag-extraction path.
"""

from __future__ import annotations

from aether.attack.exploits.web_sqlmap import SqlmapExploit
from aether.attack.flags.extractor import FlagExtractor
from aether.attack.recon.toolscan import _sqlmap_injectable
from aether.core.plugin import RunContext
from aether.core.scope_guard import ScopeGuard


def test_injectable_detection():
    assert _sqlmap_injectable("GET parameter 'id' is vulnerable. Do you want to keep testing")
    assert _sqlmap_injectable("the back-end DBMS is MySQL")
    assert not _sqlmap_injectable("all tested parameters do not appear to be injectable")
    assert not _sqlmap_injectable("")


def test_candidate_urls_use_discovered_surface():
    mod = SqlmapExploit()
    ctx = RunContext(target_host="10.0.0.1", target_port=80, service="web",
                     extra={"discovered_endpoints": ["/item.php"],
                            "discovered_params": ["pid"]})
    urls = mod._candidate_urls(ctx, "http://10.0.0.1:80")
    # Discovered endpoint+param produce a probe URL (discovered-first via merge_list).
    assert "http://10.0.0.1:80/item.php?pid=1" in urls


async def test_disabled_by_default_runs_nothing(tmp_path):
    # Without use_sqlmap the module is a no-op (keeps normal sweeps fast).
    mod = SqlmapExploit()
    g = ScopeGuard(enforce=True)
    g.allow("127.0.0.1", ports=(80,))
    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web", scope=g, extra={})
    res = await mod.run(ctx)
    assert res.data["responses"] == {} and "not requested" in res.detail


def test_dumped_flag_is_extractable():
    # A realistic sqlmap table dump; the engine's extractor must find the flag inside it.
    dump = (
        "Database: ctf\nTable: secrets\n[1 entry]\n"
        "+----+----------------------------+\n"
        "| id | flag                       |\n"
        "+----+----------------------------+\n"
        "| 1  | IONIC{sqlmap_dumped_flag}  |\n"
        "+----+----------------------------+\n"
    )
    flags = FlagExtractor(r"IONIC\{[^}]+\}").extract(dump)
    assert "IONIC{sqlmap_dumped_flag}" in flags
