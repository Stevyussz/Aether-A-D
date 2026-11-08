"""Regression tests for SSTI payload well-formedness.

A live test against a real Vulhub Flask/Jinja2 SSTI lab surfaced two bugs these lock in:
1. the flag-hunt command is single-quoted (grep's ERE), so embedding it inside a single-quoted
   template string literal collided quotes and the RCE never ran — payloads must wrap it in
   DOUBLE quotes;
2. the only Jinja2 RCE forms were cycler/config, which fail on a bare ``jinja2.Template``
   (jinja2.utils has no ``os``; no Flask context) — a reliable ``self``-builtins form is needed.
"""

from aether.attack.exploits._server_flags import ssti_payloads

CMD_MARK = "grep -rshoaE"   # appears inside the flag-hunt command


def test_reliable_bare_jinja2_payload_present():
    ps = ssti_payloads("IONIC{")
    assert any("self.__init__.__globals__.__builtins__" in p and "__import__" in p for p in ps)


def test_command_embedding_is_quote_safe():
    # Every payload that embeds the (single-quoted) flag-hunt command must enclose it in
    # double quotes — never `popen('... '...' ...')`, which is malformed.
    ps = ssti_payloads("IONIC{")
    for p in ps:
        if CMD_MARK not in p:
            continue
        # The grep command carries single quotes; the wrapper around it must be a double quote
        # (so for the Python/PHP/Java string forms we must see popen("/exec("/shell_exec(").
        if "popen(" in p:
            assert 'popen("' in p, f"single-quoted popen wrapper (quote collision): {p}"
        if "shell_exec(" in p:
            assert 'shell_exec("' in p, f"single-quoted shell_exec wrapper: {p}"
        if "getRuntime().exec(" in p:
            assert 'exec("' in p, f"single-quoted Java exec wrapper: {p}"


def test_markers_and_rce_both_present():
    ps = ssti_payloads("IONIC{")
    assert "{{7*7}}" in ps                                   # engine detection
    assert any("popen(" in p and CMD_MARK in p for p in ps)  # flag-reading RCE
