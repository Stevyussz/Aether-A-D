"""Lightweight HTTP request parameter validation helper for defending self-owned Python web services.

Can be imported into Flask, FastAPI, or WSGI/ASGI services during competition patching
to reject requests containing directory traversal, shell metacharacter sequences, or
template/SQL control sequences while keeping legitimate SLA checker requests intact.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)),
    ("null_byte", re.compile(r"(?:\x00|%00)", re.IGNORECASE)),
    ("template_expr", re.compile(r"\{\{.*?(?:config|self|__class__|__mro__|__subclasses__|lipsum|cycler).*?\}\}", re.IGNORECASE | re.DOTALL)),
    ("command_chain", re.compile(r"(?:;|\|\||&&|\$\(|\`)\s*(?:cat|id|whoami|sh|bash|nc|curl|wget|python|perl|php)\b", re.IGNORECASE)),
    ("sql_union", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("prototype_pollution", re.compile(r"(?:__proto__|constructor\s*\"?\s*:\s*\{\s*\"?prototype)", re.IGNORECASE)),
)


def inspect_value(value: str) -> list[str]:
    """Return a list of rule names triggered by `value` (empty list if clean)."""
    if not isinstance(value, str) or not value:
        return []
    hits: list[str] = []
    for name, pat in _SUSPICIOUS_PATTERNS:
        if pat.search(value):
            hits.append(name)
    return hits


def is_safe_input(value: str) -> bool:
    """Return True if `value` does not match any suspicious input pattern."""
    return len(inspect_value(value)) == 0


def validate_params(params: Mapping[str, str | list[str]]) -> tuple[bool, list[str]]:
    """Validate a dictionary of query/form parameters. Returns `(is_safe, matched_rules)`."""
    matched: list[str] = []
    for key, val in params.items():
        for k_hit in inspect_value(str(key)):
            matched.append(f"{key}:{k_hit}")
        if isinstance(val, (list, tuple)):
            for item in val:
                for v_hit in inspect_value(str(item)):
                    matched.append(f"{key}:{v_hit}")
        else:
            for v_hit in inspect_value(str(val)):
                matched.append(f"{key}:{v_hit}")
    return (len(matched) == 0), matched
