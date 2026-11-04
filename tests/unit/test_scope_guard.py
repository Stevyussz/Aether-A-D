"""Scope enforcement is the most safety-critical code — negative tests dominate here."""

import pytest

from aether.core.models import Target
from aether.core.scope_guard import ScopeGuard, ScopeViolation


def test_empty_scope_fails_closed():
    g = ScopeGuard(enforce=True)
    assert g.is_empty()
    assert not g.check("10.0.0.1").allowed
    with pytest.raises(ScopeViolation):
        g.enforce("10.0.0.1")


def test_empty_host_denied():
    g = ScopeGuard(enforce=True)
    g.allow("10.0.0.5")
    assert not g.check("").allowed
    assert not g.check("   ").allowed


def test_exact_ip_allowed_others_denied():
    g = ScopeGuard(enforce=True)
    g.allow("10.0.0.5")
    assert g.check("10.0.0.5").allowed
    assert not g.check("10.0.0.6").allowed
    with pytest.raises(ScopeViolation):
        g.enforce("10.0.0.6")


def test_cidr_range_membership():
    g = ScopeGuard(enforce=True)
    g.allow("10.0.10.0/24")
    assert g.check("10.0.10.200").allowed
    assert not g.check("10.0.11.1").allowed


def test_hostname_exact_match_case_insensitive():
    g = ScopeGuard(enforce=True)
    g.allow("team3.ctf.local")
    assert g.check("TEAM3.CTF.LOCAL").allowed
    assert not g.check("team4.ctf.local").allowed


def test_no_substring_matching():
    # A host that merely contains an allowed host as substring must be denied.
    g = ScopeGuard(enforce=True)
    g.allow("ctf.local")
    assert not g.check("evil-ctf.local").allowed
    assert not g.check("ctf.local.attacker.com").allowed


def test_port_restriction():
    g = ScopeGuard(enforce=True)
    g.allow("10.0.0.5", ports=(80, 443))
    assert g.check("10.0.0.5", 80).allowed
    assert not g.check("10.0.0.5", 22).allowed
    # No port given -> host-level allow still holds.
    assert g.check("10.0.0.5").allowed


def test_load_targets_replaces_allowlist():
    g = ScopeGuard(enforce=True)
    g.allow("1.1.1.1")
    g.load_targets([Target(name="t1", host="2.2.2.2", ports=(8080,))])
    assert not g.check("1.1.1.1").allowed  # old entry gone
    assert g.check("2.2.2.2", 8080).allowed


def test_lab_mode_disables_enforcement_but_is_flagged():
    g = ScopeGuard(enforce=False)
    assert g.check("8.8.8.8").allowed
    assert g.summary["enforced"] is False
