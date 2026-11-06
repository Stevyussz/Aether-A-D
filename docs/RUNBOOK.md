# AETHER A&D — Operator Runbook

For a two-person team. Everything here works today against the local lab; the only thing
you add at the competition is the official scope/flag/timing in `config/aether.yaml`.

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

The arsenal auto-selects modules by the target's `kind`:

- **Web / HTTP services** (`kind: web`) — exposed flag files/backups/VCS, path traversal/LFI,
  SQLi, OS command injection, SSTI, NoSQLi, default credentials, IDOR, **weak JWT
  (alg:none / weak secret)**, **insecure deserialization** (PHP/Python/Node/Ruby), SSRF, XXE,
  GraphQL, and **unauthenticated Elasticsearch**.
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
.venv/bin/aether defense status
.venv/bin/aether monitor start --interval 10        # foreground sweep loop
#   another terminal / teammate:
.venv/bin/aether monitor stop                        # graceful stop at next sweep
```

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
.venv/bin/aether lab test                             # full pipeline against a local lab flag
.venv/bin/python scripts/acceptance_check.py          # BLUEPRINT §9 self-check
.venv/bin/python scripts/measure_resources.py         # real resource numbers
.venv/bin/pytest                                       # full test suite
```

## Division of labour (suggested)

- **Operator A (Attack):** watches `flags inbox`, submits on the portal, marks submitted.
- **Operator B (Defense):** runs `monitor start`, triages incidents, gates remediation.

Both can run every command; the inbox/state is shared via `runtime/aether.sqlite`.
