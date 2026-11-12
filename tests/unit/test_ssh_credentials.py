"""SSH weak-credential module: login detection, credential ordering, and service dispatch.
(The live pty-ssh path is proven against a real sshd; these cover the pure logic + wiring.)
"""

from __future__ import annotations

from aether.attack.exploits.ssh_credentials import (
    PAIRS,
    SshCredentialExploit,
    _login_ok,
)
from aether.attack.sweep import exploits_for
from aether.core.plugin import RunContext


def test_login_ok_detects_real_shell_only():
    assert _login_ok("__AE_ID__\nuid=0(root) gid=0(root)") is True
    assert _login_ok("uid=1000(ctf)") is True
    assert _login_ok("Permission denied, please try again.") is False
    assert _login_ok("root@host's password: \r\nAuthentication failed.") is False
    assert _login_ok("") is False


def test_operator_creds_tried_first_and_deduped():
    mod = SshCredentialExploit()
    ctx = RunContext(target_host="10.0.0.1", target_port=22, service="ssh",
                     extra={"ssh_user": "deploy", "ssh_pass": "s3cr3t"})
    pairs = mod._pairs(ctx)
    assert pairs[0] == ("deploy", "s3cr3t")        # operator creds first
    assert len(pairs) == len(set(pairs))           # de-duplicated
    assert ("root", "root") in pairs               # curated list still present


def test_curated_list_is_bounded():
    # Bounded on purpose — this is not a mass brute-forcer (avoids lockouts).
    assert len(PAIRS) <= 30


def test_ssh_kind_dispatches_ssh_module():
    mods = exploits_for("ssh")
    ids = [m.identifier for m in mods]
    assert "exploit.ssh.credentials" in ids
    # web kinds never pull the ssh module
    assert "exploit.ssh.credentials" not in [m.identifier for m in exploits_for("web")]
