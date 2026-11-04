import pytest

from aether.defense.backup_manager import BackupManager
from aether.defense.integrity_monitor import IntegrityMonitor
from aether.defense.log_analyzer import LogAnalyzer
from aether.defense.service_monitor import (
    ServiceFunctionalityChecker,
    ServiceHealthMonitor,
)
from aether.defense.vulnerability_assessment import Finding, VulnerabilityAssessment


# --- backup / restore -------------------------------------------------------
def test_backup_restore_file_roundtrip(tmp_path):
    svc = tmp_path / "svc"
    svc.mkdir()
    f = svc / "app.py"
    f.write_text("original", encoding="utf-8")
    bm = BackupManager(tmp_path / "backups")
    snap = bm.create(svc, label="pre")
    assert bm.verify(snap.snapshot_id)
    # Tamper then restore.
    f.write_text("tampered", encoding="utf-8")
    bm.restore(snap.snapshot_id)
    assert f.read_text(encoding="utf-8") == "original"


def test_backup_rejects_missing_source(tmp_path):
    bm = BackupManager(tmp_path / "b")
    with pytest.raises(FileNotFoundError):
        bm.create(tmp_path / "nope")


# --- integrity --------------------------------------------------------------
def test_integrity_detects_modification_and_protected(tmp_path):
    root = tmp_path / "web"
    root.mkdir()
    (root / "index.html").write_text("hi", encoding="utf-8")
    (root / "flags.db").write_text("FLAGSTORE", encoding="utf-8")
    mon = IntegrityMonitor(root, protected=("flags.db",))
    mon.establish_baseline()
    # Add a webshell + modify flag store.
    (root / "shell.php").write_text("<?php system($_GET[c]); ?>", encoding="utf-8")
    (root / "flags.db").write_text("TAMPERED", encoding="utf-8")
    report = mon.scan()
    assert "shell.php" in report.added
    assert "flags.db" in report.modified
    assert "flags.db" in report.protected_hits
    assert not report.clean


def test_integrity_clean_when_unchanged(tmp_path):
    root = tmp_path / "web"
    root.mkdir()
    (root / "a.txt").write_text("x", encoding="utf-8")
    mon = IntegrityMonitor(root)
    mon.establish_baseline()
    assert mon.scan().clean


# --- health / functional ----------------------------------------------------
async def test_health_monitor_up_and_down():
    hm = ServiceHealthMonitor()

    async def up():
        return True, "200 OK"

    async def boom():
        raise ConnectionError("refused")

    hm.register("web", up)
    hm.register("api", boom)
    results = {r.service: r for r in await hm.check_all()}
    assert results["web"].up
    assert not results["api"].up
    assert "refused" in results["api"].detail


async def test_functional_checker_all_must_pass():
    fc = ServiceFunctionalityChecker()
    fc.register_check("web", "homepage", lambda: _ok())
    fc.register_check("web", "login", lambda: _fail())
    res = await fc.verify("web")
    assert not res.passed
    assert "login" in res.failed_checks


# --- log analyzer -----------------------------------------------------------
def test_log_analyzer_flags_iocs():
    la = LogAnalyzer()
    text = "\n".join(
        [
            "GET /index.html 200",
            "GET /../../etc/passwd 404",
            "GET /shell.php?c=id 200",
            "User-Agent: sqlmap/1.5",
        ]
    )
    matches = la.analyze_text(text)
    rules = {m.rule for m in matches}
    assert "path_traversal" in rules
    assert "webshell_access" in rules
    assert "suspicious_useragent" in rules
    assert any(m.severity == "CRITICAL" for m in matches)


# --- vulnerability assessment ----------------------------------------------
async def test_vuln_assessment_collects_findings():
    va = VulnerabilityAssessment()

    async def weak_perms():
        return Finding("world_writable", True, "HIGH", "/srv writable", "chmod 750")

    async def ok_check():
        return Finding("debug_off", False, "INFO", "debug disabled")

    va.register("perms", weak_perms)
    va.register("debug", ok_check)
    findings = await va.run()
    vuln = [f for f in findings if f.vulnerable]
    assert len(vuln) == 1
    assert vuln[0].check == "world_writable"


async def _ok():
    return True, "ok"


async def _fail():
    return False, "500 error"
