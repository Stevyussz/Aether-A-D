# AETHER A&D — Operator Runbook

For a two-person team. Everything here works today against the local lab; the only thing
you add at the competition is the official scope/flag/timing in `config/aether.yaml`.

> **New to Attack & Defense?** Read **[STRATEGY.md](STRATEGY.md)** first (roles, first 5
> minutes, the per-tick loop, scoring, game-day checklist) and keep
> **[CHEATSHEET.md](CHEATSHEET.md)** open (AETHER + manual commands).
>
> **Hari-H (Bahasa Indonesia):** checklist tempur langkah-demi-langkah ada di
> **[RUNBOOK-HARI-H.md](RUNBOOK-HARI-H.md)** — scope → defense → attack → submit → capture/replay.

## 0. One-time setup (per machine)

```bash
uv venv --python 3.12 .venv
uv pip install -e ".[dev]" --python .venv/bin/python
uv tool install --editable .        # global `aether` command (no .venv/bin prefix)
aether system health                # all green, "No-AI runtime: clean"
```

**Easiest control — the interactive console.** Just type `aether` (no arguments) for the
ASCII home screen and a guided menu: system health, config/scope, attack sweep & loop, flag
inbox, copy/mark flags, defense monitor, scoring, reports, and the lab self-test — all by
selecting a number and answering prompts. Everything below is also available as direct
subcommands for speed.

**Browser UI — the Web Console.** For a clear, clickable dashboard with controls and config:

```bash
aether web                 # prints a tokenised http://127.0.0.1:8787/?token=… URL — open it
aether web --port 9000     # choose the port (localhost only, never exposed)
```

It serves six tabs — **Monitor** (live **charts** for CPU/memory, service latency, and
VALIDATED flags, plus health/integrity/incidents/web-shells/patch-log/tick, auto-refreshing),
**Attack** (one-click scope-enforced sweep per target with an "external tools" toggle and a
**live progress panel** — bar, current module, confirmed modules, flag count, streaming log),
**Defense** (the control centre for keeping your own service safe: web-shell list with one-click
**Quarantine**, incidents, file-integrity, service/SLA status, patch log, and a "Jalankan
defense sweep" button), **Flags** (review, reveal, mark submitted/accepted), **Config** (a
point-and-click **scope builder** plus raw-YAML editor under "Advanced"), and **Panduan** (the
first-5-minutes / per-tick guide in-app). UI prose is in Indonesian; cyber terms stay English.
It binds to localhost only, mutating actions require the token in the URL, scope stays
fail-closed, config save refuses to disable scope, quarantine only touches files inside our own
watched roots and backs up first, and AETHER never auto-submits — exactly like the CLI.

## 1. Before the round — configure scope (CRITICAL)

```bash
.venv/bin/aether init                       # writes config/aether.yaml from example
$EDITOR config/aether.yaml                   # fill OFFICIAL targets, flag pattern, tick
.venv/bin/aether config validate             # MUST say READY before you rely on it
.venv/bin/aether scope show                   # eyeball the allowlist — opponents in red
```

AETHER **fails closed**: if scope is empty or still has placeholders, nothing runs. That is
intentional. Do not set `scope.enforce: false` during the competition.

## 2. During the round — attack

```bash
.venv/bin/aether attack status                # modules + authorized opponent targets

# AUTO flag-finding — runs the whole validated exploit arsenal at one target:
.venv/bin/aether attack sweep <opponent-host>  # smart by default: crawls first, then aims
.venv/bin/aether attack sweep                   # omit host = sweep ALL in-scope opponents
.venv/bin/aether attack sweep <host> --no-recon # skip the crawl (blind wordlists only)
.venv/bin/aether attack sweep <host> --tools    # ALSO drive nmap/rustscan/gobuster/ffuf/whatweb
#   --tools widens the surface: discovers extra open ports/services (so you notice a second web
#   or data-store port), extra endpoints (gobuster/ffuf), and the tech stack (whatweb), then
#   feeds all of it into the exploit arsenal. Needs those tools on PATH; degrades gracefully.

# EXTERNAL RECON only (no exploitation) — ports/services, paths, tech:
.venv/bin/aether attack recon <host>            # nmap/rustscan + gobuster/ffuf + whatweb, scope-enforced
.venv/bin/aether attack recon <host> --nuclei   # ALSO run nuclei CVE checks (leads; slower)
.venv/bin/aether attack sweep <host> --nuclei   # tools + nuclei + full arsenal in one go
#   nuclei findings are DETECTION LEADS (surfaced, not auto-exploited). First nuclei run
#   downloads its templates (can take minutes) — run `nuclei -update-templates` once up front.
#   In the Web Console, tick "+ nuclei" on the Attack tab; ports/tech/paths/nuclei all render
#   in the live sweep panel.

# BEHIND A LOGIN — sweep auto-logs-in first (default/weak creds), then attacks authenticated:
.venv/bin/aether attack sweep <host>                      # --login is ON by default
.venv/bin/aether attack sweep <host> --cred admin:hunter2 # add known creds (repeatable)
.venv/bin/aether attack sweep <host> --no-login           # skip the login step
#   On success you'll see "✓ logged in as <user> … — attacking authenticated"; every exploit
#   module then carries the session cookie, so vulns hidden behind the login are reachable.
#   Login is CSRF-aware: it discovers the real login pages, reads the form's hidden CSRF token
#   and field names from a GET, and submits them — so token-protected logins work too.

# AFTER A FOOTHOLD — local priv-esc ENUMERATION (read-only; you escalate by hand):
.venv/bin/aether attack privesc <host>                    # id / sudo -l / SUID / caps / cron
#   Prints the intel it gathered through the command-injection vector. AETHER never escalates
#   on its own — pick a SUID/sudo/cron/capability path and exploit it yourself.

# CONTINUOUS — re-sweep every round (flags rotate each tick); set --interval to tick length:
.venv/bin/aether attack loop --interval 60      # Ctrl-C or `aether attack stop` to end
#   AETHER remembers which modules hit each target (the "exploit farm") and runs them FIRST
#   each round, so the fresh flag is re-pulled immediately. Knowledge persists across restarts.
.venv/bin/aether attack stop                     # graceful stop at next round

.venv/bin/aether flags inbox                   # PENDING flags, values hidden by default
.venv/bin/aether flags inbox --show-values     # reveal when you are ready to submit
.venv/bin/aether flags copy <key-prefix>       # prints the bare value (pipe to clipboard)
#   e.g.  .venv/bin/aether flags copy 1a2b3c4d5e | xclip -selection clipboard
```

**You submit flags on the official portal yourself.** AETHER never submits. After you submit:

```bash
.venv/bin/aether flags mark-submitted <key-prefix> --status SUBMITTED
#   later, if the portal accepted/rejected:
.venv/bin/aether flags mark-submitted <key-prefix> --status ACCEPTED
```

**Web gets you in — the flag lives on the SERVER.** This competition follows the A&D /
HTB / THM / VulnHub pattern: initial access is via the web, but the flag is usually on the
server filesystem (`/root/root.txt`, `/home/*/user.txt`, `proof.txt`, a web-root `flag*`, or
an env var), NOT in the HTTP response. So every module that reaches code execution (command
injection, SSTI, deserialization, LFI) actively **reads the flag off the server**: it `cat`s
the conventional flag files AND — most reliably — **greps the filesystem for the flag prefix**
(`IONIC{`, derived automatically from your configured `flags.pattern`) so the flag is found
wherever it hides, under any filename. All reads are read-only and bounded (no whole-disk
scans, no writes). If no flag pattern is configured yet, the modules fall back to `cat`-ing
the common flag files.

The arsenal auto-selects modules by the target's `kind`:

- **Web / HTTP services** (`kind: web`) — exposed flag files/backups/VCS, path traversal/LFI,
  SQLi, **OS command injection (reads `/root/root.txt`, `/home/*/user.txt`, greps the FS)**,
  **SSTI → RCE (Jinja2/Twig/Freemarker/Smarty/ERB/PHP, reads the server flag)**, NoSQLi,
  default credentials, IDOR, **weak JWT (alg:none / weak secret)**, **insecure
  deserialization** (PHP/Python/Node/Ruby), SSRF, XXE, GraphQL, and **unauthenticated
  Elasticsearch**.
- **Data stores** (`kind: redis` / `kind: memcached`) — dump an unauthenticated Redis or
  Memcached and recover flags from the values.
- **Custom TCP services** (`kind: tcp`/`vault`/`note`) — speak the common vault/note command
  vocabulary and read back flag records; the network set (Redis + Memcached + vault) is tried
  for any unknown non-web service.

**Smart recon (default on):** before firing, `sweep`/`loop` crawl the web target to learn
its real endpoints, query parameters, and form fields, then aim every injection module at
that discovered surface first (not just blind wordlists). This finds flags hidden behind
non-standard endpoints/params that a static list would miss. Use `--no-recon` to skip it.

Set each opponent target's `kind` in scope so `sweep`/`loop` picks the right set (or pass a
host and it defaults to the web arsenal). All probes are read-only/non-destructive, every run
is scope-enforced (out-of-scope targets refused), and a flag is only ever surfaced if it is
genuine output — nothing is fabricated. If the arsenal finds nothing, the target simply isn't
vulnerable to those classes; write a target-specific module (see
`src/aether/attack/exploits/web_sqli.py` or `tcp_vault.py` as templates) and it joins the
sweep automatically.

Validation legend in the inbox: **VALIDATED** (matches official pattern — submit these),
**UNVERIFIED** (no pattern configured yet — check manually), **INVALID** (does not match),
**DUPLICATE** (seen before, `seen>1`).

## 3. During the round — defend

```bash
aether defense status
aether monitor dashboard --interval 5    # LIVE dashboard: real health, integrity, incidents,
                                         # flag-inbox stats, patch log, tick clock, resources
aether monitor start --interval 10       # plain text sweep loop (lighter, scriptable)
#   another terminal / teammate:
aether monitor stop                       # graceful stop of either at the next sweep

# WEB SHELLS — if an opponent drops a shell on our service, find and remove it safely:
aether defense webshells                  # READ-ONLY scan of our watched web roots
aether defense webshells --path /var/www  # scan a specific directory
aether defense quarantine /var/www/html/uploads/shell.php
#   quarantine is operator-gated and reversible: it backs up the file, moves it out of the
#   web root, runs a functional test, and auto-rolls-back if the service breaks. The legit
#   files are never touched. Each monitor/defense sweep also raises a CRITICAL "webshell"
#   incident when a shell is detected.
```

The live dashboard (`monitor dashboard`, or menu option 10) shows only genuine data: service
health/latency from real probes, file-integrity drift from real baseline scans, incidents
fused this sweep, flag-inbox counts by validation/submission, the modification/patch log, the
competition tick clock, and live CPU/memory — refreshing every `--interval` seconds.

Monitor sweeps combine file-integrity drift, log IOCs, and service health into incidents.
Remediation (patch/recovery) is **operator-gated** — AETHER never restarts or patches a
service on its own. The patch workflow always backs up first and auto-rolls-back if the
functional test fails, so your flag store and service behavior are preserved.

## 4. Reporting

```bash
.venv/bin/aether report generate                     # runtime/reports/*.md (values hidden)
.venv/bin/aether scoring show                         # tick + score history if configured
```

## 5. Sanity checks you can run any time

```bash
.venv/bin/aether lab serve --host 0.0.0.0 --port 8080 # run the vuln target LIVE for A&D practice
#   (isolated lab network ONLY) — attack it from another VM, then patch it and re-sweep.
#   See docs/DEFENSE-AND-LAB.md for the full self-simulation + how to patch without coding.
.venv/bin/aether lab test                             # full pipeline against a local lab flag
.venv/bin/python scripts/acceptance_check.py          # BLUEPRINT §9 self-check
.venv/bin/python scripts/measure_resources.py         # real resource numbers
.venv/bin/pytest                                       # full test suite
```

## Division of labour (suggested)

- **Operator A (Attack):** watches `flags inbox`, submits on the portal, marks submitted.
- **Operator B (Defense):** runs `monitor start`, triages incidents, gates remediation.

Both can run every command; the inbox/state is shared via `runtime/aether.sqlite`.
