# MISSION: BUILD AETHER A&D — COMPETITION-GRADE ATTACK & DEFENSE FRAMEWORK

**Role:** Senior Python Systems Engineer, Cybersecurity Engineer, A&D CTF Specialist.

**Project:** AETHER A&D  
**Version:** 1.2  
**Language:** Python 3.12+  
**Architecture:** Modular, asynchronous, event-driven  
**Interface:** CLI  
**Priority:** Balanced — Speed, Accuracy, Reliability  
**Execution:** Automatic within explicitly authorized competition scope  
**Testing:** Intensive  
**AI Runtime:** STRICTLY NONE

## 1. PRIMARY OBJECTIVE

Build a functional, lightweight, modular Attack & Defense CTF framework for a two-person team.

AETHER has two continuously operating objectives:

1. ATTACK: Discover vulnerabilities in explicitly authorized opponent services, execute validated exploit modules, retrieve flags, validate them, and display them immediately to the operator.
2. DEFENSE: Monitor our own services, identify vulnerabilities and compromises, perform safe remediation, preserve flag data and service functionality, and maintain availability.

This is a real software implementation task.

DO NOT merely generate architecture documents, pseudocode, empty directories, or placeholder modules.

Build executable components, implement tests, run them, inspect failures, and fix them.

## 2. NON-NEGOTIABLE RULES

- No AI models, LLMs, AI APIs, AI agents, or external AI dependencies in the competition runtime.
- No external AI service or network dependency.
- All operations must respect official competition rules.
- Explicit target allowlisting is mandatory.
- Never attack infrastructure outside the authorized competition scope.
- No destructive exploitation, uncontrolled scanning, stealth persistence, or unauthorized data extraction.
- Preserve service functionality and competition flag data.
- Never fabricate successful exploit results or flags.
- Every result must be verifiable.
- Fail safely when configuration, scope, or target identity is uncertain.

AI-assisted development must not be assumed permissible during the competition itself. Follow the organizer's actual AI policy.

## 3. CORE ARCHITECTURE

Implement these components:

### Core Engine
- orchestrator
- event_bus
- scheduler
- module_loader
- config_manager
- state_manager
- scope_guard
- execution_guard
- logger

Requirements:
- Async task execution.
- Independent module lifecycle.
- Timeout isolation.
- Concurrency limits.
- Structured logging.
- Graceful shutdown.
- Persistent state.
- Error isolation.
- No silent failures.

### Attack Engine
- reconnaissance
- service fingerprinting
- web assessment
- Linux service assessment
- validated exploit plugin interface
- exploit verification
- flag extraction
- flag validation
- flag deduplication
- flag notification

Exploit plugins must include:
- Module identifier.
- Supported target/service.
- Prerequisites.
- Scope requirements.
- Execution timeout.
- Expected result.
- Verification method.
- Error handling.

Separate vulnerability research from repeated execution of validated exploit modules.

Never assume that a detected vulnerability automatically means a successful exploit.

### MANUAL FLAG SUBMISSION — CRITICAL REQUIREMENT

AETHER MUST NEVER AUTOMATICALLY SUBMIT FLAGS.

The human operator, Stev, handles all official flag submissions.

Implement a dedicated real-time Flag Inbox.

Every discovered flag must display:

- Flag value.
- Source target.
- Associated service.
- Discovery timestamp.
- Round/tick identifier, if available.
- Exploit module.
- Validation status.
- Duplicate status.
- Submission status, initially PENDING.

Requirements:
- Immediate notification on successful extraction.
- Easy copy-to-clipboard.
- Clear separation between valid, unverified, duplicate, and failed results.
- Never expose flags in ordinary logs or reports unnecessarily.
- No automatic submission requests.
- No automatic marking as submitted without operator confirmation.

Example CLI presentation:

[FLAG DETECTED]
Target: authorized-target
Service: web-service
Module: validated-module
Status: VALIDATED
Submission: PENDING

FLAG: [ACTUAL DISCOVERED FLAG]

The flag must be genuine output from the execution result, never a placeholder presented as a real discovery.

### Defense Engine

Implement:
- service_health_monitor
- integrity_monitor
- log_analyzer
- vulnerability_assessment
- patch_manager
- backup_manager
- recovery_manager
- incident_detector
- service_functionality_checker

Patch workflow:

PRE-CHECK → BACKUP → PATCH → FUNCTIONAL TEST → VERIFY → COMMIT / ROLLBACK

Requirements:
- Preserve competition flag storage.
- Preserve service interfaces and expected behavior.
- Prefer minimal, reversible remediation.
- Apply only authorized changes.
- Automatically rollback failed remediation when safe.
- Do not restart or modify critical services blindly.
- Record every modification.
- Alert the operator when automated remediation is unsafe or unsuccessful.

### Environment Adapters

Support modular adapters for:

1. Web applications and HTTP APIs.
2. Linux servers and authorized SSH environments.
3. Docker containers.

The core must not depend on any specific environment.

Do not invent environment-specific assumptions before official technical information is provided.

### Scoring and Competition Intelligence

Implement configurable interfaces for:
- Round/tick synchronization.
- Flag expiration metadata.
- Official submission status, if accessible.
- Attack points.
- Defense points.
- Service SLA.
- Score history.

Never hardcode an assumed IONIC scoring system.

Use official competition documentation and configuration only.

## 4. PERFORMANCE REQUIREMENTS

Optimize for balanced speed, accuracy, and reliability.

Implement:
- asyncio-based I/O concurrency.
- Configurable worker limits.
- Per-task timeouts.
- Connection pooling where appropriate.
- Result caching with correct expiration.
- Deduplication.
- Priority queues.
- Bounded memory usage.
- Efficient polling based on official competition timing.
- Resource-aware operation.

Avoid:
- Unbounded concurrency.
- Repeated unnecessary scans.
- Blocking operations inside async workers.
- Excessive dependencies.
- Heavy dashboards or unnecessary background processes.

Target development hardware may have only 8 GB RAM and older Intel integrated graphics. Keep the framework lightweight.

Do not claim performance benchmarks without actually running them.

## 5. CLI DESIGN

Use Typer and Rich.

Commands:

aether init
aether system health
aether config validate
aether scope show
aether modules list
aether modules test
aether attack status
aether defense status
aether monitor start
aether monitor stop
aether flags inbox
aether flags history
aether flags copy
aether flags mark-submitted
aether report generate
aether lab test

Provide:
- Clear status indicators.
- Readable error messages.
- Real-time event output.
- Critical notifications.
- Minimal operator interaction.
- No fake or simulated production results.

## 6. TESTING REQUIREMENTS

Use pytest and pytest-asyncio.

Implement:

UNIT TESTS
- Core components.
- Plugin loading.
- Scope validation.
- Flag parser.
- Deduplication.
- State management.

INTEGRATION TESTS
- Attack and defense coexistence.
- Adapter integration.
- Flag inbox.
- Monitoring pipeline.
- Patch verification.

REGRESSION TESTS
- Previously fixed bugs.
- Invalid configuration.
- Duplicate flags.
- Timeout handling.
- Unexpected service responses.

STRESS TESTS
- Concurrent task execution.
- Large event volumes.
- Memory consumption.
- Long-running monitoring.
- Graceful shutdown.

FAILURE SIMULATION
- Network interruptions.
- Service crashes.
- Exploit failures.
- Invalid flags.
- Patch failures.
- Rollback failures.
- Database interruptions.

Use isolated local lab fixtures. Never run destructive tests against competition infrastructure.

## 7. DEVELOPMENT PROCESS

Work incrementally.

PHASE 0 — Inspect environment and initialize repository.

PHASE 1 — Implement core engine and scope enforcement.

PHASE 2 — Implement CLI, configuration, state persistence, and event handling.

PHASE 3 — Implement defense monitoring, backup, patching, and recovery.

PHASE 4 — Implement attack plugin interface, validated assessment modules, flag extraction, and manual flag inbox.

PHASE 5 — Implement web, Linux, and Docker adapters.

PHASE 6 — Implement scoring integration and competition timing.

PHASE 7 — Intensive integration, regression, stress, and endurance testing.

PHASE 8 — Prepare competition release candidate.

Do not build all phases in one uncontrolled code-generation operation.

At each phase:
1. Implement.
2. Run tests.
3. Inspect output.
4. Fix failures.
5. Update documentation.
6. Commit a stable milestone.

## 8. REPOSITORY STRUCTURE

Use a clean src-layout Python project:

aether-ad/
  pyproject.toml
  README.md
  config/
  src/aether/
    core/
    cli/
    attack/
      recon/
      web/
      linux/
      exploits/
      verification/
      flags/
    defense/
      monitoring/
      integrity/
      analysis/
      patching/
      recovery/
    adapters/
    reporting/
    utils/
  tests/
    unit/
    integration/
    regression/
    stress/
    fixtures/
  lab/
    web/
    linux/
    docker/
  docs/

Adapt the structure if implementation needs justify it.

## 9. ACCEPTANCE CRITERIA

AETHER is not complete until:

- Core executes successfully.
- Scope enforcement passes all negative tests.
- Attack and defense pipelines can coexist.
- Valid lab flags appear in the manual inbox immediately after validation.
- No automatic flag submission exists.
- Duplicate flags are detected.
- Service monitoring works.
- Backup and rollback work in simulated failures.
- Functional service checks pass after remediation.
- No critical silent failures remain.
- Resource consumption is measured.
- Both team members can operate the CLI.
- Official IONIC rules have been reviewed and incorporated.

## 10. COMPETITION CONFIGURATION

The actual IONIC environment is currently UNKNOWN.

DO NOT invent:
- IP addresses.
- Target topology.
- Service inventory.
- SSH credentials.
- Flag format.
- Flag expiration.
- Submission protocol.
- Round duration.
- Scoring formula.
- Patching restrictions.

Use clearly marked configuration placeholders and fail closed until official scope is configured.

Keep the core usable through local lab simulations while waiting for the organizer's technical briefing.

## 11. FINAL DIRECTIVE

Your mission is to produce working, testable, maintainable software—not an impressive-looking empty architecture.

Prioritize:

1. Correctness.
2. Scope safety.
3. Flag discovery and delivery to the human operator.
4. Service availability.
5. Reliable remediation.
6. Execution speed.
7. Resource efficiency.

Never sacrifice correctness for speed.

Never claim a module is finished without tests.

Never claim AETHER is competition-ready until the official environment has been integrated and the complete system has passed its acceptance tests.

Begin with PHASE 0. Inspect the actual development environment, create the repository, and implement PHASE 1.

Report actual files created, commands executed, test results, failures, and remaining work after each milestone.