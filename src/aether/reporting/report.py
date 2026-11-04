"""Operator report generation.

Produces a Markdown summary of the current competition posture: scope, modules, flag inbox
counts (by validation and submission — values are NOT included by default so reports can be
shared safely), defense modification log, and scoring. Reports go under runtime/reports/.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.config_manager import AetherConfig
from ..core.state_manager import StateManager


async def build_report(
    cfg: AetherConfig,
    state: StateManager,
    include_flag_values: bool = False,
) -> str:
    flags = await state.list_flags()
    mods = await state.list_modifications()

    by_validation = Counter(f["validation"] for f in flags)
    by_submission = Counter(f["submission"] for f in flags)

    now = datetime.now(timezone.utc).isoformat()
    lines: list[str] = []
    lines.append("# AETHER A&D — Operator Report")
    lines.append("")
    lines.append(f"- Generated: {now}")
    lines.append(f"- Scope enforcement: {'ENFORCED' if cfg.scope.enforce else 'LAB (not enforced)'}")
    lines.append(f"- Authorized targets: {len(cfg.scope.targets)}")
    lines.append("")

    lines.append("## Targets")
    if cfg.scope.targets:
        lines.append("")
        lines.append("| name | host | ports | kind | owner |")
        lines.append("|------|------|-------|------|-------|")
        for t in cfg.scope.targets:
            ports = ",".join(str(p) for p in t.ports) or "(any)"
            lines.append(f"| {t.name} | {t.host} | {ports} | {t.kind} | {t.owner} |")
    else:
        lines.append("\n_No authorized targets (fail closed)._")
    lines.append("")

    lines.append("## Flag inbox")
    lines.append("")
    lines.append(f"- Total flags discovered: **{len(flags)}**")
    lines.append(f"- By validation: " + (", ".join(f"{k}={v}" for k, v in by_validation.items()) or "none"))
    lines.append(f"- By submission: " + (", ".join(f"{k}={v}" for k, v in by_submission.items()) or "none"))
    lines.append("")
    lines.append("> AETHER never auto-submits. All flags start PENDING; the operator submits.")
    lines.append("")
    if flags:
        lines.append("| key | target | service | module | tick | valid | submit | seen |"
                     + (" flag |" if include_flag_values else ""))
        sep = "|-----|--------|---------|--------|------|-------|--------|------|"
        lines.append(sep + ("------|" if include_flag_values else ""))
        for f in flags:
            row = (f"| {f['dedup_key'][:10]} | {f['target']} | {f['service']} | {f['module']} "
                   f"| {f['tick'] or '-'} | {f['validation']} | {f['submission']} | {f['seen_count']} |")
            if include_flag_values:
                row += f" {f['value']} |"
            lines.append(row)
    lines.append("")

    lines.append("## Defense modifications")
    lines.append("")
    if mods:
        lines.append(f"- Recorded modifications: **{len(mods)}**")
        lines.append("")
        lines.append("| ts | component | action | target | reversible |")
        lines.append("|----|-----------|--------|--------|------------|")
        for m in mods[:50]:
            lines.append(f"| {m['ts']} | {m['component']} | {m['action']} "
                         f"| {m['target'] or '-'} | {'yes' if m['reversible'] else 'NO'} |")
    else:
        lines.append("_No defensive modifications recorded._")
    lines.append("")

    lines.append("## Scoring")
    lines.append("")
    lines.append(f"- Tick length: {cfg.scoring.tick_seconds or 'unconfigured'}")
    lines.append(f"- Flag expiry (ticks): {cfg.scoring.expiry_ticks or 'unconfigured'}")
    lines.append("")
    return "\n".join(lines)


async def write_report(
    cfg: AetherConfig,
    state: StateManager,
    out_dir: str | Path = "runtime/reports",
    include_flag_values: bool = False,
) -> Path:
    text = await build_report(cfg, state, include_flag_values=include_flag_values)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"aether-report-{stamp}.md"
    path.write_text(text, encoding="utf-8")
    return path
