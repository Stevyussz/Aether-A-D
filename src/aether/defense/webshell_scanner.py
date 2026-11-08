"""Webshell scanner — detect opponent-planted web shells in our own service files.

A&D opponents who get RCE on our service usually drop a web shell (a small PHP/JSP/ASP file
that runs commands from an HTTP parameter) so they can keep access and steal our flags. This
scanner reads our watched web roots and flags files that match high-signal web-shell patterns
(code execution on user input, obfuscated eval chains, upload droppers).

It is strictly READ-ONLY: it only reads and pattern-matches file contents, never modifies
anything. Removing a detected shell is a separate, operator-gated action
(:meth:`DefenseEngine.quarantine_webshell`) that always backs up first and is reversible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core.logger import get_logger

log = get_logger("webshell_scanner")

# Files worth inspecting: server-side script extensions, plus anything containing a PHP tag.
SCRIPT_SUFFIXES: frozenset[str] = frozenset({
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht",
    ".asp", ".aspx", ".ashx", ".jsp", ".jspx", ".cgi", ".pl", ".py", ".sh",
})
# Only read reasonably small files (a shell is tiny; this also bounds the work).
MAX_BYTES = 2 * 1024 * 1024

# STRONG: a single match is enough to flag the file.
_STRONG: tuple[tuple[str, re.Pattern[str]], ...] = (
    # PHP: run a command/code taken straight from the request.
    ("php_exec_on_request", re.compile(
        r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|"
        r"`)[^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)", re.I | re.S)),
    # PHP: variable-function callback on request data ($_GET['x']($_GET['y'])).
    ("php_dynamic_call_on_request", re.compile(
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(", re.I)),
    # preg_replace with the /e modifier (classic code-exec).
    ("php_preg_replace_e", re.compile(
        r"preg_replace\s*\(\s*['\"].*?/[a-z]*e[a-z]*['\"]", re.I | re.S)),
    # JSP/Java command execution.
    ("jsp_runtime_exec", re.compile(
        r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(", re.I)),
    # Classic ASP command shell.
    ("asp_wscript_shell", re.compile(
        r"(?:CreateObject|Server\.CreateObject)\s*\(\s*['\"]WScript\.Shell", re.I)),
    ("asp_eval_request", re.compile(r"eval\s*\(\s*[Rr]equest", re.I)),
)

# WEAK: individually noisy. A file is only flagged when a dangerous primitive combines with
# attacker input or obfuscation (see the combo rules in ``scan_file``) — NOT on a lone signal
# like "<?php plus $_GET", which is ordinary in legitimate code.
_WEAK: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("obfuscation_chain", re.compile(
        r"(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uu)\s*\(", re.I)),
    ("eval_call", re.compile(r"\beval\s*\(", re.I)),
    ("exec_sink", re.compile(
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", re.I)),
    ("upload_dropper", re.compile(r"move_uploaded_file\s*\(", re.I)),
    ("request_superglobal", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I)),
    ("create_function", re.compile(r"\bcreate_function\s*\(", re.I)),
)


def _weak_combo_flags(weak: set[str]) -> bool:
    """A meaningful web-shell combination of weak signals (keeps false positives low)."""
    return (
        ("eval_call" in weak and "obfuscation_chain" in weak)        # eval(base64_decode(..))
        or ("eval_call" in weak and "request_superglobal" in weak)   # eval($_GET..)
        or ("exec_sink" in weak and "request_superglobal" in weak)   # system($_GET..)
        or ("create_function" in weak and "request_superglobal" in weak)
        or ("upload_dropper" in weak and ("exec_sink" in weak or "eval_call" in weak))
    )


@dataclass
class WebshellHit:
    path: str                       # path relative to the scanned root
    abs_path: str                   # absolute path on disk
    signatures: list[str] = field(default_factory=list)
    snippet: str = ""               # a short, sanitised excerpt of the first match

    @property
    def summary(self) -> str:
        return f"{self.path}: {', '.join(self.signatures)}"


def _looks_scripty(path: Path, head: str) -> bool:
    return path.suffix.lower() in SCRIPT_SUFFIXES or "<?php" in head.lower()


def _first_match_snippet(text: str, patterns: list[re.Pattern[str]]) -> str:
    for pat in patterns:
        m = pat.search(text)
        if m:
            start = max(0, m.start() - 20)
            frag = text[start:m.end() + 40]
            return re.sub(r"\s+", " ", frag).strip()[:160]
    return ""


def scan_file(path: Path) -> WebshellHit | None:
    """Return a :class:`WebshellHit` if *path* matches web-shell signatures, else ``None``."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if not _looks_scripty(path, text[:512]):
        return None

    strong_hits = [name for name, pat in _STRONG if pat.search(text)]
    weak_hits = [name for name, pat in _WEAK if pat.search(text)]
    # Flag if any strong signature fires, or a meaningful weak-signal combination appears.
    flagged = bool(strong_hits) or _weak_combo_flags(set(weak_hits))
    if not flagged:
        return None

    sigs = strong_hits + weak_hits
    matched_pats = [pat for name, pat in (*_STRONG, *_WEAK) if name in sigs]
    return WebshellHit(path=path.name, abs_path=str(path), signatures=sigs,
                       snippet=_first_match_snippet(text, matched_pats))


class WebshellScanner:
    """Scan a directory tree for planted web shells (read-only)."""

    def scan_root(self, root: str | Path) -> list[WebshellHit]:
        base = Path(root)
        if not base.exists():
            return []
        hits: list[WebshellHit] = []
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            hit = scan_file(p)
            if hit is not None:
                try:
                    hit.path = str(p.relative_to(base))
                except ValueError:
                    hit.path = p.name
                hits.append(hit)
        if hits:
            log.warning("webshell(s) detected",
                        extra={"ctx": {"root": str(base),
                                       "hits": [h.path for h in hits]}})
        return hits
