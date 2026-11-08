"""Unit tests for the file-upload web-shell module (no network)."""

from aether.attack.exploits.web_file_upload import FileUploadExploit, _shell_variants


def test_shell_variants_cover_common_bypasses():
    cmd = "grep -rshoaE 'IONIC\\{[^}]+\\}' /tmp 2>/dev/null"   # single-quoted like the real cmd
    variants = _shell_variants(cmd)
    names = [f for f, _c, _b in variants]
    # alternate PHP extensions + double-extension + magic-byte image variants
    assert any(n.endswith(".php") for n in names)
    assert any(n.endswith(".phtml") for n in names)
    assert any(".php.jpg" in n for n in names)
    assert any(b.startswith("GIF89a;") for _f, _c, b in variants)   # magic bytes
    # the single-quoted command MUST be wrapped in double quotes (no quote collision)
    for _f, _c, body in variants:
        assert 'shell_exec("' in body and "');" not in body.replace("\\'", "")


def test_module_registered_and_probes_empty():
    m = FileUploadExploit()
    assert m.identifier == "exploit.web.file_upload"
    assert m.probes.__doc__ is None or True        # probes exists
    from aether.core.plugin import RunContext
    assert m.probes(RunContext(target_host="x", target_port=80, service="web")) == []


def test_candidate_urls_guess_common_dirs():
    urls = FileUploadExploit._candidate_urls("http://h:80", "/upload.php", "ae_x.php", "ok")
    assert "http://h:80/uploads/ae_x.php" in urls
    assert "http://h:80/ae_x.php" in urls           # web-root fallback
