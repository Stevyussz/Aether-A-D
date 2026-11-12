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

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

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
    for fid in context.extra.get("flag_ids") or []:
        u = str(fid).strip()
        if u:
            for pw in (u, "password", "123456", "admin"):
                if (u, pw) not in creds:
                    creds.append((u, pw))
    for pair in DEFAULT_CREDS:
        if pair not in creds:
            creds.append(pair)
    return creds


@dataclass
class _LoginForm:
    action: str = ""
    method: str = "POST"
    hidden: dict = field(default_factory=dict)   # hidden inputs incl. CSRF token
    user_field: str | None = None
    pass_field: str | None = None


class _FormParser(HTMLParser):
    """Find the login form (the one with a password input) and its fields/CSRF token."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_LoginForm] = []
        self._cur: _LoginForm | None = None

    def handle_starttag(self, tag: str, attrs_list: list) -> None:
        a = dict(attrs_list)
        if tag == "form":
            self._cur = _LoginForm(action=a.get("action", ""),
                                   method=(a.get("method") or "POST").upper())
        elif tag == "input" and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            itype = (a.get("type") or "text").lower()
            if itype == "hidden":
                self._cur.hidden[name] = a.get("value", "")
            elif itype == "password" or name.lower() in PASS_FIELDS:
                self._cur.pass_field = name
            elif self._cur.user_field is None and (
                    itype in ("text", "email") or name.lower() in USER_FIELDS):
                self._cur.user_field = name

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _pick_login_form(html: str) -> _LoginForm | None:
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 - never let malformed HTML crash login
        return None
    # Prefer a form that has a password field (the real login form).
    for form in parser.forms:
        if form.pass_field:
            return form
    return parser.forms[0] if parser.forms else None


def _form_data(user: str, pw: str, form: _LoginForm | None) -> dict:
    """Build POST data: CSRF/hidden fields + the detected user/pass fields, with name
    aliases sprayed as a safety net so it also works when there is no parseable form."""
    data: dict[str, str] = {}
    if form is not None:
        data.update(form.hidden)                         # keep the CSRF token etc.
        if form.user_field:
            data[form.user_field] = user
        if form.pass_field:
            data[form.pass_field] = pw
    for f in USER_FIELDS:
        data.setdefault(f, user)
    for f in PASS_FIELDS:
        data.setdefault(f, pw)
    data.setdefault("submit", "Login")
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
        cap = int(context.extra.get("max_login_attempts", 40))
        verify = bool(context.extra.get("tls_verify", False))

        # Phase 1 — discovery: one GET per endpoint to find the REAL login pages (don't spray
        # creds blindly at endpoints that aren't logins; keeps it fast and quiet). API
        # endpoints are tried as JSON logins without a discovery GET.
        candidates: list[tuple[str, _LoginForm | None, bool]] = []
        async with httpx.AsyncClient(timeout=self.meta.timeout, follow_redirects=True,
                                     verify=verify) as disco:
            for ep in endpoints:
                if ep.startswith("/api") or ep.endswith(".json"):
                    candidates.append((ep, None, True))
                    continue
                try:
                    page = await disco.get(base + ep)
                except httpx.HTTPError:
                    continue
                if page.status_code == 200 and "html" in page.headers.get("content-type", ""):
                    form = _pick_login_form(page.text)
                    if (form and form.pass_field) or "password" in page.text.lower():
                        candidates.append((ep, form, False))

        # Phase 2 — spray the weak/default (or operator) creds at the login pages only.
        attempts = 0
        for ep, disc_form, is_api in candidates:
            for user, pw in creds:
                if attempts >= cap:
                    break
                attempts += 1
                try:
                    # Fresh client per attempt so the cookie jar reflects only this login.
                    async with httpx.AsyncClient(timeout=self.meta.timeout,
                                                 follow_redirects=True, verify=verify) as client:
                        if is_api:
                            resp = await client.post(base + ep,
                                                     json={"username": user, "password": pw})
                        else:
                            # CSRF-aware: re-GET to refresh a single-use token, then POST it back.
                            form = disc_form
                            try:
                                page = await client.get(base + ep)
                                if "html" in page.headers.get("content-type", ""):
                                    form = _pick_login_form(page.text) or disc_form
                            except httpx.HTTPError:
                                pass
                            action = urljoin(base + ep, form.action) if (form and form.action) \
                                else base + ep
                            resp = await client.post(action, data=_form_data(user, pw, form))
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
            detail=f"no login succeeded ({attempts} attempt(s) across "
                   f"{len(candidates)} login page(s) of {len(endpoints)} probed)",
            data={"authenticated": False, "cookies": {}, "attempts": attempts,
                  "login_pages": len(candidates)},
        )
