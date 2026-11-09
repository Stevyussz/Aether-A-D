"""Source auditor — find exploitable sinks in OUR OWN service before opponents do.

This is the defensive mirror of the attack arsenal: it reads our service's source files and
flags the dangerous patterns AETHER (or an opponent) would exploit — LFI/RFI, OS command
injection, SSTI, SQL string-concatenation, insecure deserialization, unrestricted upload,
and exposed secrets/debug. Each finding carries a file:line, a short snippet, a severity, and
a concrete remediation hint so the team can patch fast and keep the service up.

Strictly READ-ONLY static analysis (regex over source) — it changes nothing. "Patch yourself
first" is the single highest-value A&D defensive move; this tells you exactly what to patch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger

log = get_logger("source_audit")

SOURCE_SUFFIXES: frozenset[str] = frozenset({
    ".php", ".php3", ".php4", ".php5", ".phtml", ".py", ".js", ".ts", ".rb", ".java",
    ".jsp", ".ejs", ".go", ".cgi", ".pl", ".sh", ".html", ".twig", ".tpl",
})
MAX_BYTES = 2 * 1024 * 1024
_REQ = r"\$_(?:GET|POST|REQUEST|COOKIE)"               # PHP superglobals
_PYREQ = r"(?:request\.(?:args|form|values|json|GET|POST)|flask\.request)"


@dataclass
class AuditFinding:
    category: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    path: str                # relative path
    line: int
    snippet: str
    remediation: str

    @property
    def summary(self) -> str:
        return f"{self.path}:{self.line} [{self.severity}] {self.category}"


# (category, severity, compiled regex, remediation) — matched per source line.
_RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("command-injection", "CRITICAL", re.compile(
        r"(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval)\s*\([^;]{0,160}"
        + _REQ, re.I),
     "Jangan jalankan OS command dari input. Hapus system()/exec() atau whitelist argumen + "
     "escapeshellarg(); untuk eval() pada input: hapus total."),
    ("command-injection", "CRITICAL", re.compile(
        r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\([^)]{0,160}"
        + _PYREQ, re.I),
     "Jangan pass request ke shell. Pakai argumen list + shell=False; validasi/whitelist input."),
    ("command-injection", "CRITICAL", re.compile(
        r"child_process\.(?:exec|execSync)\s*\([^)]{0,160}req\.", re.I),
     "Pakai execFile/spawn dengan array args (bukan exec string); validasi input."),
    ("lfi-rfi", "HIGH", re.compile(
        r"(?:include|include_once|require|require_once)\s*\(?\s*[^;]{0,80}" + _REQ, re.I),
     "Jangan include() path dari input. Whitelist file yang boleh; pakai basename()+realpath() "
     "dan pastikan di dalam direktori yang diizinkan."),
    ("path-traversal", "HIGH", re.compile(
        r"(?:fopen|file_get_contents|readfile|open|send_file|sendfile)\s*\([^)]{0,80}"
        + r"(?:" + _REQ + r"|" + _PYREQ + r")", re.I),
     "Validasi path: tolak '..'; resolve realpath() dan pastikan prefix di folder yang diizinkan."),
    ("ssti", "CRITICAL", re.compile(
        r"render_template_string\s*\([^)]{0,120}(?:\+|%|\.format|f[\"'])", re.I),
     "Jangan render template dari string yang digabung input. Pakai template statis + context "
     "variabel (render_template('t.html', name=name))."),
    ("ssti", "CRITICAL", re.compile(
        r"(?:Template|Environment\(\)\.from_string)\s*\([^)]{0,120}(?:\+|%|\.format|f[\"'])", re.I),
     "Jangan bangun template dari input. Pisahkan template dari data; sandbox jika perlu."),
    ("sql-injection", "HIGH", re.compile(
        r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^;\"']{0,120}(?:\.\s*" + _REQ + r"|\"\s*\.\s*\$|"
        + r"\{" + _PYREQ + r"|%\s*\(|f[\"'].*\{)", re.I),
     "Pakai prepared statement / parameterized query (PDO bind, cursor.execute(sql, params)). "
     "Jangan concat input ke SQL."),
    ("deserialization", "HIGH", re.compile(
        r"(?:unserialize\s*\(\s*" + _REQ + r"|pickle\.loads\s*\(|yaml\.load\s*\((?!.*Loader)"
        + r"|readObject\s*\(|Marshal\.load)", re.I),
     "Jangan deserialize data tak-tepercaya. Pakai format aman (JSON); yaml.safe_load; hindari "
     "pickle/unserialize atas input."),
    ("file-upload", "HIGH", re.compile(r"move_uploaded_file\s*\(|\.save\s*\(.*(?:filename|upload)",
                                       re.I),
     "Validasi upload: whitelist ekstensi/MIME, rename acak, simpan DI LUAR web-root atau matikan "
     "eksekusi skrip di folder upload (.htaccess: php_flag engine off)."),
    ("code-eval", "CRITICAL", re.compile(
        r"(?:\beval\s*\(|\bassert\s*\(|create_function\s*\(|\bexec\s*\(\s*" + _PYREQ + r")", re.I),
     "Hapus eval()/assert()/exec() atas input — tidak ada alasan sah mengeksekusi input."),
    ("debug-exposed", "MEDIUM", re.compile(
        r"(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|display_errors\s*=\s*On|"
        r"phpinfo\s*\()", re.I),
     "Matikan debug/verbose errors di produksi (DEBUG=False, display_errors=Off, hapus phpinfo)."),
    ("hardcoded-secret", "LOW", re.compile(
        r"(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{3,}[\"']", re.I),
     "Jangan hardcode kredensial di source; pakai env var / secret store."),
)

# Files/paths that must not be exposed in a web root.
_EXPOSED_NAMES = ("flag", "flag.txt", ".env", "config.php.bak", "backup.zip", "db.sql",
                  "database.sql", "dump.sql")
_EXPOSED_DIRS = (".git", ".svn", ".hg")


def _scan_text(rel: str, text: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if len(line) > 4000:
            line = line[:4000]
        for cat, sev, pat, rem in _RULES:
            if pat.search(line):
                snippet = re.sub(r"\s+", " ", line).strip()[:160]
                findings.append(AuditFinding(cat, sev, rel, i, snippet, rem))
    return findings


class SourceAuditor:
    """Static audit of our own service source for exploitable sinks (read-only)."""

    def audit_root(self, root: str | Path) -> list[AuditFinding]:
        base = Path(root)
        if not base.exists():
            return []
        findings: list[AuditFinding] = []
        for p in sorted(base.rglob("*")):
            # Exposed sensitive files / VCS dirs in the web root.
            if p.is_dir() and p.name in _EXPOSED_DIRS:
                findings.append(AuditFinding(
                    "exposed-vcs", "HIGH", str(p.relative_to(base)), 0,
                    f"{p.name}/ present in web root",
                    "Hapus direktori VCS/backup dari web-root (jangan deploy .git)."))
                continue
            if not p.is_file():
                continue
            rel = str(p.relative_to(base))
            if p.name in _EXPOSED_NAMES or p.suffix in (".bak", ".sql", ".zip", ".tar"):
                findings.append(AuditFinding(
                    "exposed-file", "HIGH", rel, 0, f"{p.name} served from web root",
                    "Pindahkan file sensitif/backup ke luar web-root; hapus dari deploy."))
            if p.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings.extend(_scan_text(rel, text))
        if findings:
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            log.warning("source audit findings",
                        extra={"ctx": {"root": str(base), "by_severity": by_sev}})
        return findings
