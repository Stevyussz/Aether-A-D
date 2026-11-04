# AETHER A&D — Operator Runbook

For a two-person team. Everything here works today against the local lab; the only thing
you add at the competition is the official scope/flag/timing in `config/aether.yaml`.

## 0. One-time setup (per machine)

```bash
uv venv --python 3.12 .venv
uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/aether system health      # all green, "No-AI runtime: clean"
```

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
# (recon / exploit runs are driven by the engine; flags flow to the inbox automatically)
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
