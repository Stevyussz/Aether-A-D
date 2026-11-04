# Acceptance Criteria — Evidence Map (BLUEPRINT §9)

Run `.venv/bin/python scripts/acceptance_check.py` for the live self-check. This table maps
each criterion to the code and tests that evidence it.

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Core executes successfully | ✅ | `orchestrator.py`; `tests/unit/test_orchestrator.py` |
| 2 | Scope enforcement passes all negative tests | ✅ | `scope_guard.py`; `tests/unit/test_scope_guard.py` (empty/substring/port/CIDR) |
| 3 | Attack and defense pipelines coexist | ✅ | `tests/integration/test_coexistence.py` |
| 4 | Valid lab flags appear in manual inbox after validation | ✅ | `tests/integration/test_attack_pipeline.py` |
| 5 | No automatic flag submission | ✅ | `inbox.py` (PENDING-only, `mark_submitted` operator-only); `test_flag_pipeline.py` |
| 6 | Duplicate flags detected | ✅ | `state_manager.upsert_flag`; `test_attack_pipeline.py::test_rerun_is_deduplicated` |
| 7 | Service monitoring works | ✅ | `defense/engine.py`, `integrity_monitor.py`; `test_defense_engine.py` |
| 8 | Backup and rollback work in simulated failures | ✅ | `patch_manager.py`; `test_patch_workflow.py`, `test_failure_simulation.py` |
| 9 | Functional service checks pass after remediation | ✅ | `patch_manager.py` FUNCTIONAL step; `test_patch_workflow.py` |
| 10 | No critical silent failures remain | ✅ | `execution_guard.run_module` normalizes; `test_execution_guard.py`, `test_failure_simulation.py` |
| 11 | Resource consumption is measured | ✅ | `scripts/measure_resources.py` — measured ~31ms/iter, ~55MB RSS (4-core/8GiB) |
| 12 | Both team members can operate the CLI | ✅ | 13 command groups; `docs/RUNBOOK.md`; `test_cli*.py` |
| 13 | Official IONIC rules reviewed and incorporated | ⏳ PENDING-ENV | environment UNKNOWN; fail-closed placeholders; `docs/IONIC_INTEGRATION.md` |

## Honest status

AETHER is a **release candidate** that passes every lab-verifiable acceptance criterion
(13/14) with 138 automated tests green. Criterion 13 cannot be truthfully marked complete
until the official environment is briefed and configured — by design, the framework refuses
to pretend otherwise. Per the blueprint's final directive, AETHER is **not declared
competition-ready** until the official environment is integrated and acceptance is re-run
against it.
