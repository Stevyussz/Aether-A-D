"""PathTraversal off-by-slash / alias traversal probes: the payload is appended DIRECTLY to a
directory path (no separating slash), covering nginx `alias` misconfigs the param-based LFI
sweep can't express. Discovered directories are prioritised so they're covered within budget.
"""

from __future__ import annotations

from aether.attack.exploits.web_path_traversal import PathTraversalExploit
from aether.core.plugin import RunContext


def _paths(ctx):
    return [p.path for p in PathTraversalExploit().probes(ctx)]


def test_offbyslash_probe_shape_for_discovered_dir():
    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web",
                     extra={"discovered_endpoints": ["/files", "/index.html"]})
    paths = _paths(ctx)
    # The classic nginx off-by-slash request: /files + ../flag.txt (no slash between).
    assert "/files../flag.txt" in paths
    assert "/files../../etc/passwd" in paths
    # Discovered dir off-by-slash is at the FRONT (covered before the big param sweep).
    assert paths.index("/files../flag.txt") < 50


def test_offbyslash_skips_file_like_endpoints():
    # A discovered path that looks like a file (has an extension) is not treated as a dir.
    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web",
                     extra={"discovered_endpoints": ["/app.php"]})
    paths = _paths(ctx)
    assert not any(p.startswith("/app.php..") for p in paths)
    # Common dir names are still tried (as the tail).
    assert any(p.startswith("/static..") for p in paths)


def test_param_based_probes_still_present():
    ctx = RunContext(target_host="127.0.0.1", target_port=80, service="web", extra={})
    probes = PathTraversalExploit().probes(ctx)
    assert any(pr.params for pr in probes)      # param-based LFI still there
    assert any(not pr.params for pr in probes)  # plus off-by-slash path probes
