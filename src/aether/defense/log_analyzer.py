"""Log analyzer — scan service logs for indicators of compromise/attack.

Rule-based (regex) detection over log lines. Rules are data, not code, so new IOC patterns
can be added from config without changing logic. Returns matches with the triggering rule
and line. Used as a signal source for the incident detector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.logger import get_logger

log = get_logger("log_analyzer")


@dataclass(frozen=True)
class LogRule:
    name: str
    pattern: str
    severity: str = "WARNING"

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern)


@dataclass
class LogMatch:
    rule: str
    severity: str
    line_no: int
    line: str


# Conservative default IOC rules for common web-service attacks. These detect *patterns in
# our own logs*; they do not attack anything.
DEFAULT_RULES: tuple[LogRule, ...] = (
    LogRule("path_traversal", r"\.\./|\.\.%2f", "WARNING"),
    LogRule("sqli_probe", r"(?i)(union\s+select|' or '1'='1|sleep\(\d+\))", "WARNING"),
    LogRule("webshell_access", r"(?i)/(shell|cmd|c99|r57|backdoor)\.(php|jsp|aspx)", "CRITICAL"),
    LogRule("cmd_injection", r"(?i);\s*(cat|ls|id|whoami|nc|curl|wget)\b", "WARNING"),
    LogRule("suspicious_useragent", r"(?i)(sqlmap|nikto|nmap|masscan|hydra)", "WARNING"),
)


class LogAnalyzer:
    def __init__(self, rules: tuple[LogRule, ...] = DEFAULT_RULES) -> None:
        self._rules = [(r, r.compiled()) for r in rules]

    def analyze_lines(self, lines: list[str]) -> list[LogMatch]:
        matches: list[LogMatch] = []
        for i, line in enumerate(lines, start=1):
            for rule, rx in self._rules:
                if rx.search(line):
                    matches.append(
                        LogMatch(rule=rule.name, severity=rule.severity, line_no=i, line=line.rstrip())
                    )
        if matches:
            log.warning("log IOCs found", extra={"ctx": {"count": len(matches)}})
        return matches

    def analyze_text(self, text: str) -> list[LogMatch]:
        return self.analyze_lines(text.splitlines())
