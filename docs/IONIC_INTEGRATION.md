# IONIC Competition Integration Checklist

The real IONIC environment is **UNKNOWN** until the organizer briefing. AETHER is built to
stay fully usable in the local lab until then, and to **fail closed** until you fill in the
official values. This is the checklist to run through the moment you receive the briefing.

## Do NOT invent (blueprint §10)

IPs, topology, service inventory, SSH credentials, flag format, flag expiration, submission
protocol, round duration, scoring formula, patching restrictions. Every one of these is a
config value, not a code assumption.

## When the briefing arrives

1. **Read the official rules**, especially:
   - the **AI policy** — confirm whether any automation is permitted during play. AETHER has
     **no AI runtime**, but confirm tool automation is allowed at all.
   - flag **submission** method and rate limits (you submit manually either way).
   - **patching restrictions** (what you may/may not change on your services).
   - **scoring** and **tick/round** length.

2. **Fill `config/aether.yaml`:**
   - `scope.targets`: every authorized opponent host (`owner: opponent`) and every one of
     your own services to defend (`owner: self`), with exact hosts/ports. No CIDR wider than
     the official scope.
   - `flags.pattern`: the official flag regex (e.g. `IONIC\{[A-Za-z0-9_]+\}`). Leaving it
     null means flags come in as UNVERIFIED — set it.
   - `scoring.tick_seconds`, `scoring.epoch` (tick-0 start), `scoring.expiry_ticks`.
   - `flags.auto_submit`: leave `false` (config load rejects `true`).

3. **Validate & eyeball:**
   ```bash
   aether config validate      # must be READY
   aether scope show           # confirm opponents vs self, no stray hosts
   ```

4. **Wire real adapters/probes** (code-free for web; see `docs/RUNBOOK.md`):
   - Web health probes via `WebAdapter.health_probe(url)`.
   - Linux enumeration via `SSHCommandAdapter(host, user, key_path=...)` → pass
     `.command_runner()` into the linux assessment module's context.
   - Docker service control via `DockerAdapter` for backup/restore/restart of your
     containers.

5. **Re-run acceptance against the real config:**
   ```bash
   python scripts/acceptance_check.py
   ```
   The "Official IONIC rules reviewed and incorporated" item flips to PASS only after you
   have (a) reviewed the rules and (b) configured official scope.

## Hard invariants that never change

- No AI/LLM/network-AI dependency in the runtime.
- Scope is allowlisted and fail-closed.
- AETHER never auto-submits flags.
- No destructive exploitation, no stealth persistence, no data extraction beyond flags.
- Remediation is minimal, reversible, backed-up, and operator-gated.
