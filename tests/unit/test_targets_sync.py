"""Targets API sync: parse the live opponent roster and filter to attackable (healthy) hosts,
and confirm a custom script is a first-class ExploitPlugin so the sweep/farm engine runs it.
"""

from __future__ import annotations

from aether.attack.exploits.base import ExploitMeta, ExploitPlugin
from aether.core.custom_script import CustomScriptPlugin
from aether.core.plugin import RunContext
from aether.scoring.targets_sync import Target, parse_targets


def test_parse_targets_tccpens_shape():
    payload = {
        "currentRound": 7,
        "challenges": [
            {"challengeId": 76, "title": "nginx", "tickSeconds": 60, "teams": [
                {"teamName": "Bravo", "ip": "172.0.9.4", "port": 80, "lastCheckStatus": "Ok"},
                {"teamName": "Charlie", "ip": "172.0.9.5", "port": 80, "lastCheckStatus": "Mumble"},
                {"teamName": "Delta", "ip": "172.0.9.6", "port": 80, "lastCheckStatus": "Offline"},
            ]},
        ],
    }
    ts = parse_targets(payload)
    assert [(t.host, t.port) for t in ts] == [("172.0.9.4", 80), ("172.0.9.5", 80), ("172.0.9.6", 80)]
    assert ts[0].challenge_id == 76 and ts[0].title == "nginx" and ts[0].team == "Bravo"
    # Only the Ok target is attackable.
    healthy = [t.host for t in ts if t.healthy]
    assert healthy == ["172.0.9.4"]


def test_parse_targets_tolerates_junk():
    assert parse_targets(None) == []
    assert parse_targets({"challenges": "nope"}) == []
    # teams without ip/port are skipped
    assert parse_targets({"challenges": [{"teams": [{"teamName": "x"}]}]}) == []


def test_custom_script_is_exploit_plugin():
    # Regression: the engine (sweep/farm) runs modules via run_exploit, which needs the
    # ExploitPlugin interface. A custom script must satisfy it or every sweep crashes.
    mod = CustomScriptPlugin("scripts/custom/example_tcp_commands.py")
    assert isinstance(mod, ExploitPlugin)
    assert isinstance(mod.exploit, ExploitMeta) and mod.exploit.validated
    ok, _ = mod.prerequisites_met(RunContext(target_host="10.0.0.1", service="web"))
    assert ok
    ok2, _ = mod.prerequisites_met(RunContext(target_host=None, service="web"))
    assert not ok2
