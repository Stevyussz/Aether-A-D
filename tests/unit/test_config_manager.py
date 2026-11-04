import textwrap

import pytest

from aether.core.config_manager import assess_readiness, load_config


def _write(tmp_path, text):
    p = tmp_path / "cfg.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def test_minimal_config_loads_with_defaults(tmp_path):
    cfg = load_config(_write(tmp_path, "engine: {}\n"))
    assert cfg.engine.max_concurrency == 8
    assert cfg.flags.auto_submit is False


def test_auto_submit_forbidden(tmp_path):
    with pytest.raises(ValueError, match="never auto-submits"):
        load_config(_write(tmp_path, "flags:\n  auto_submit: true\n"))


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yaml")


def test_readiness_fails_closed_without_targets(tmp_path):
    cfg = load_config(_write(tmp_path, "scope:\n  enforce: true\n  targets: []\n"))
    r = assess_readiness(cfg)
    assert not r.ready
    assert any("no authorized targets" in i for i in r.issues)


def test_readiness_flags_placeholder_host(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            """
            scope:
              enforce: true
              targets:
                - name: opp1
                  host: CHANGEME
            """,
        )
    )
    r = assess_readiness(cfg)
    assert not r.ready
    assert any("placeholder" in i for i in r.issues)


def test_readiness_ready_with_real_target(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            """
            scope:
              enforce: true
              targets:
                - name: opp1
                  host: 10.0.10.5
                  ports: [80, 443]
                  kind: web
            flags:
              pattern: "CTF\\\\{[^}]+\\\\}"
            scoring:
              tick_seconds: 60
            """,
        )
    )
    r = assess_readiness(cfg)
    assert r.ready
    assert r.issues == []


def test_lab_mode_warns(tmp_path):
    cfg = load_config(_write(tmp_path, "scope:\n  enforce: false\n"))
    r = assess_readiness(cfg)
    assert any("LAB MODE" in w for w in r.warnings)
