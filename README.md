# AETHER A&D

**Competition-grade Attack & Defense CTF framework for a two-person team.**

AETHER is a lightweight, modular, asynchronous, event-driven CLI framework that runs two
continuous objectives during an authorized Attack & Defense competition:

1. **ATTACK** — discover vulnerabilities in *explicitly authorized* opponent services, run
   validated exploit modules, extract and validate flags, and surface them immediately to the
   human operator for **manual** submission. Initial access is via the web, but A&D flags live
   on the **server filesystem** — so the RCE-capable modules read the flag off the server
   (`/root/root.txt`, `/home/*/user.txt`, or wherever a `grep` for the flag prefix finds it).
   It **auto-logs-in** (CSRF-aware, default/weak or operator creds) to attack behind the login,
   and offers read-only **priv-esc enumeration** (`id`/`sudo -l`/SUID/caps/cron) after a
   foothold.
2. **DEFENSE** — monitor our own services, detect compromise (including **web shells** an
   opponent plants after getting RCE), perform safe and reversible remediation (web-shell
   **quarantine** backs up first and auto-rolls-back), and preserve flag data, service
   functionality, and availability.

Drive it from the terminal (`aether`, or direct subcommands), the live TUI dashboard
(`aether monitor dashboard`), or the **browser Web Console** (`aether web`) — a localhost UI
with monitoring, one-click scope-enforced sweeps, flag review, and config management.

## Non-negotiable safety rules

- **No AI runtime.** No LLMs, AI APIs, AI agents, or external AI/network dependencies at
  competition time.
- **Scope is allowlisted and fail-closed.** Nothing runs against a target that is not
  explicitly authorized in the active configuration.
- **AETHER never auto-submits flags.** Every flag lands in a manual **Flag Inbox** as
  `PENDING`. The human operator (Stev) submits.
- **No fabricated results.** A flag is only ever shown if it is genuine output of an execution
  result and passed validation. Nothing is invented.
- **No destructive exploitation**, uncontrolled scanning, stealth persistence, or data
  extraction beyond flags.

## Status

**Release candidate.** All build phases implemented; 196 automated tests passing; 13/14
acceptance criteria verified in the local lab (the last depends on the official briefing and
is deliberately left pending). See:

- `docs/PREP-4DAYS.md` — **focused 4-day study plan** (what to learn/skip within scope, exact
  THM/VulnHub rooms, skills to master, tricks) for a team new to A&D with little time
- `docs/STRATEGY.md` — **A&D game plan for a team new to Attack & Defense** (roles, first 5
  minutes, the per-tick loop, scoring model, beginner mistakes, game-day checklist)
- `docs/CHEATSHEET.md` — quick command reference: AETHER + the manual bits (enumeration,
  priv-esc, web payloads, service hardening) for authorized competition use
- `docs/STATUS.md` — per-phase build status
- `docs/RUNBOOK.md` — operator runbook (both team members)
- `docs/ACCEPTANCE.md` — acceptance-criteria evidence map (BLUEPRINT §9)
- `docs/IONIC_INTEGRATION.md` — what to configure when the official briefing arrives

Self-checks: `aether lab test`, `python scripts/acceptance_check.py`,
`python scripts/measure_resources.py`, `pytest`.

> Not declared competition-ready until the official environment is integrated and acceptance
> is re-run against it (blueprint final directive).

## Quick start

```bash
# Requires Python 3.12+. Dependencies managed with uv (or pip).
uv venv --python 3.12 .venv
uv pip install -e ".[dev]" --python .venv/bin/python

# Install the `aether` command globally (type `aether` anywhere — no prefix needed):
uv tool install --editable .     # puts `aether` on ~/.local/bin (ensure it's on PATH)

# Just run it — a bare `aether` opens the interactive console (ASCII home + control menu):
aether                            # guided menu: health, scope, sweep, inbox, monitor…
aether menu                       # same console, explicitly

# Or drive subcommands directly:
aether --help
aether init
aether system health
aether config validate
aether scope show
aether attack sweep <opponent-host>      # smart, scope-enforced; flags -> manual inbox

# Run the test suite
.venv/bin/pytest
```

## Configuration & scope

The real competition environment (IPs, topology, flag format, scoring, round timing) is
**UNKNOWN** until the organizer briefing. The framework ships with clearly marked placeholder
config in `config/aether.example.yaml` and **fails closed** until an operator fills in official
scope. Copy it to `config/aether.yaml` and edit.

## Repository layout

```
src/aether/
  core/        orchestrator, event bus, scheduler, scope/execution guards, config, state, logging
  cli/         Typer + Rich command-line interface
  attack/      recon, fingerprinting, web/linux assessment, exploit plugin iface, flags inbox
  defense/     monitoring, integrity, log analysis, patching, backup, recovery
  adapters/    web/http, linux/ssh, docker environment adapters
  reporting/   operator reports
  utils/       shared helpers
tests/         unit / integration / regression / stress / fixtures
lab/           isolated local lab services for safe testing
config/        placeholder + operator configuration
docs/          documentation and phase status
```

## License

Proprietary — authorized competition use only.
