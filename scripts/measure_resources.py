"""Measure actual resource consumption of AETHER under a representative workload.

Runs the lab attack pipeline + defense sweeps repeatedly and reports peak RSS and wall time.
This produces REAL measured numbers (acceptance criterion) — it does not assume benchmarks.

Usage:  .venv/bin/python scripts/measure_resources.py --iterations 50
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "lab" / "web"))

import psutil  # noqa: E402
from flag_service import LabWebService  # noqa: E402

from aether.attack.engine import AttackEngine  # noqa: E402
from aether.attack.exploits.lab_http_flag import LabHttpFlagExploit  # noqa: E402
from aether.attack.flags.inbox import FlagInbox  # noqa: E402
from aether.attack.flags.validator import FlagValidator  # noqa: E402
from aether.core.config_manager import (  # noqa: E402
    AetherConfig, EngineConfig, FlagConfig, ScopeConfig,
)
from aether.core.models import Target  # noqa: E402
from aether.core.orchestrator import Orchestrator  # noqa: E402
from aether.core.plugin import RunContext  # noqa: E402
from aether.defense.engine import DefenseEngine  # noqa: E402

PATTERN = r"CTF\{[^}]+\}"


async def workload(iterations: int) -> dict:
    svc = LabWebService("CTF{measure}", port=0).start()
    tmp = ROOT / "runtime" / "_measure"
    tmp.mkdir(parents=True, exist_ok=True)
    cfg = AetherConfig(
        engine=EngineConfig(state_db=":memory:", log_file=None, log_level="ERROR",
                            max_concurrency=8),
        scope=ScopeConfig(enforce=True, targets=[
            Target(name="lab", host="127.0.0.1", ports=(svc.port,), kind="web", owner="opponent"),
        ]),
        flags=FlagConfig(pattern=PATTERN),
    )
    orch = Orchestrator(cfg)
    await orch.start()
    proc = psutil.Process()
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        inbox = FlagInbox(orch.state, FlagValidator(PATTERN))
        attack = AttackEngine(orch, inbox)
        defense = DefenseEngine(orch, backup_root=tmp / "bk")
        web_root = tmp / "web"
        web_root.mkdir(exist_ok=True)
        (web_root / "index.html").write_text("home")
        defense.watch_path("web", web_root)
        for i in range(iterations):
            await asyncio.gather(
                attack.run_exploit(
                    LabHttpFlagExploit(),
                    RunContext(target_host="127.0.0.1", target_port=svc.port, service="web"),
                ),
                defense.sweep(log_text="GET /index.html 200"),
            )
        elapsed = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return {
            "iterations": iterations,
            "wall_seconds": round(elapsed, 3),
            "per_iter_ms": round(elapsed / iterations * 1000, 2),
            "rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
            "py_peak_mb": round(peak / 1024 / 1024, 1),
            "flags_in_inbox": len(await inbox.list()),
        }
    finally:
        await orch.shutdown()
        svc.stop()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=50)
    args = ap.parse_args()
    stats = asyncio.run(workload(args.iterations))
    print("AETHER resource measurement (real, measured):")
    for k, v in stats.items():
        print(f"  {k:16} {v}")


if __name__ == "__main__":
    main()
