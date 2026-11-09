"""The defensive source auditor finds exploitable sinks in our own code (and not clean code)."""

from aether.defense.source_audit import SourceAuditor


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_audit_flags_dangerous_sinks(tmp_path):
    _write(tmp_path, "lfi.php", "<?php include $_GET['file']; ?>")
    _write(tmp_path, "cmd.php", "<?php system('ping '.$_GET['host']); ?>")
    _write(tmp_path, "q.php", "<?php $r=mysqli_query($db,\"SELECT * FROM u WHERE id=\".$_GET['id']); ?>")
    _write(tmp_path, "up.php", "<?php move_uploaded_file($_FILES['f']['tmp_name'],'up/'.$_FILES['f']['name']); ?>")
    _write(tmp_path, "app.py", "from flask import request\nTemplate('Hi '+request.args.get('n')).render()\n")
    _write(tmp_path, "safe.php", "<?php echo htmlspecialchars($_GET['name']); ?>")  # clean
    (tmp_path / ".git").mkdir()

    cats = {f.category for f in SourceAuditor().audit_root(tmp_path)}
    assert "lfi-rfi" in cats
    assert "command-injection" in cats
    assert "sql-injection" in cats
    assert "file-upload" in cats
    assert "ssti" in cats
    assert "exposed-vcs" in cats


def test_audit_ignores_clean_code(tmp_path):
    _write(tmp_path, "safe.php", "<?php echo htmlspecialchars($_GET['name']); $db->prepare('SELECT 1'); ?>")
    _write(tmp_path, "index.html", "<html><body>hello</body></html>")
    findings = [f for f in SourceAuditor().audit_root(tmp_path)
                if f.category not in ("hardcoded-secret",)]
    assert findings == [], f"false positives: {[f.summary for f in findings]}"


def test_findings_have_location_and_remediation(tmp_path):
    _write(tmp_path, "lfi.php", "<?php\ninclude $_REQUEST['p'];\n?>")
    fs = SourceAuditor().audit_root(tmp_path)
    lfi = [f for f in fs if f.category == "lfi-rfi"][0]
    assert lfi.line == 2 and lfi.path == "lfi.php" and lfi.remediation
