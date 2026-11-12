"""Reusable, SLA-safe hardening recipes for common service weaknesses.

Every helper integrates with :class:`PatchManager` so that:
1. A full backup snapshot is taken before any file is touched.
2. The service functional check is run immediately after applying the fix.
3. If the service check fails, the change is rolled back automatically.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from pathlib import Path

from .patch_manager import PatchManager, PatchResult

FunctionalCheck = Callable[[], Awaitable[tuple[bool, str]]]

HTACCESS_NO_EXEC = """# AETHER Defense — disable script execution in upload directory
<FilesMatch "\\.(php|phtml|php5|php7|phar|cgi|pl|py|sh)$">
    Require all denied
</FilesMatch>
php_flag engine off
"""


async def harden_upload_dir(
    patcher: PatchManager,
    upload_dir: str | Path,
    functional_test: FunctionalCheck,
) -> PatchResult:
    """Place a strict non-execution .htaccess inside an upload directory with auto-rollback."""
    target_dir = Path(upload_dir)
    htaccess = target_dir / ".htaccess"

    async def pre_check() -> tuple[bool, str]:
        if not target_dir.is_dir():
            return False, f"directory does not exist: {target_dir}"
        return True, "upload directory ready"

    async def apply() -> tuple[bool, str]:
        try:
            existing = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
            if "php_flag engine off" not in existing:
                htaccess.write_text(existing + "\n" + HTACCESS_NO_EXEC, encoding="utf-8")
            return True, f"wrote execution lock to {htaccess}"
        except OSError as exc:
            return False, f"write failed: {exc}"

    async def verify() -> tuple[bool, str]:
        ok = htaccess.is_file() and "php_flag engine off" in htaccess.read_text(encoding="utf-8")
        return ok, ("htaccess verified" if ok else "htaccess missing expected directive")

    return await patcher.apply(
        f"harden-upload-{target_dir.name}",
        target_dir,
        apply=apply,
        functional_test=functional_test,
        pre_check=pre_check,
        verify=verify,
    )


async def apply_regex_patch(
    patcher: PatchManager,
    file_path: str | Path,
    pattern: str,
    replacement: str,
    functional_test: FunctionalCheck,
    label: str = "regex-fix",
) -> PatchResult:
    """Safely replace a vulnerable code pattern in a source file with automatic rollback."""
    target = Path(file_path)
    rx = re.compile(pattern, re.MULTILINE)

    async def pre_check() -> tuple[bool, str]:
        if not target.is_file():
            return False, f"file not found: {target}"
        text = target.read_text(encoding="utf-8", errors="replace")
        if not rx.search(text):
            return False, f"pattern not found in {target.name}"
        return True, "pattern matched"

    async def apply() -> tuple[bool, str]:
        text = target.read_text(encoding="utf-8", errors="replace")
        updated, count = rx.subn(replacement, text)
        if count == 0:
            return False, "no replacements made"
        target.write_text(updated, encoding="utf-8")
        return True, f"replaced {count} occurrence(s) in {target.name}"

    async def verify() -> tuple[bool, str]:
        text = target.read_text(encoding="utf-8", errors="replace")
        clean = not rx.search(text)
        return clean, ("vulnerable pattern removed" if clean else "pattern still present")

    return await patcher.apply(
        f"{label}-{target.name}",
        target,
        apply=apply,
        functional_test=functional_test,
        pre_check=pre_check,
        verify=verify,
    )
