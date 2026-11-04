# AETHER A&D

**Competition-grade Attack & Defense CTF framework for a two-person team.**

AETHER is a lightweight, modular, asynchronous, event-driven CLI framework that runs two
continuous objectives during an authorized Attack & Defense competition:

1. **ATTACK** — discover vulnerabilities in *explicitly authorized* opponent services, run
   validated exploit modules, extract and validate flags, and surface them immediately to the
   human operator for **manual** submission.
2. **DEFENSE** — monitor our own services, detect compromise, perform safe and reversible
   remediation, and preserve flag data, service functionality, and availability.

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

Built incrementally in phases (see `BLUEPRINT.md` §7). Current implemented phases are tracked
in `docs/STATUS.md`.

## Quick start

```bash
# Requires Python 3.12+. Dependencies managed with uv (or pip).
uv venv --python 3.12 .venv
uv pip install -e ".[dev]" --python .venv/bin/python

# Run the CLI
.venv/bin/aether --help
.venv/bin/aether init
.venv/bin/aether system health
.venv/bin/aether config validate
.venv/bin/aether scope show

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
