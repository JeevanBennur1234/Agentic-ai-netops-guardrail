# Agentic AI-NetOps Guardrail - Implementation Status

> Before running these examples, set NETOPS_HOME to the repository root and activate the Python environment: export NETOPS_HOME="$(pwd)" followed by source "$NETOPS_HOME/.venv/bin/activate".

Date: 2026-10-27
Branch: master

## Executive status

The repository contains a functional prototype pipeline made from an Ollama-backed intent proposer, a NetworkX topology safety checker, a decision gate, a constrained Open vSwitch executor, tamper-evident auditing, observability, and test/benchmark utilities.

This is a research prototype, not a production-ready autonomous network controller. The strongest remaining limitation is live failover after a forwarding trunk fails. Current live lab experiments showed 0% baseline ping loss, 100% loss after the active trunk was disabled, and successful restoration of connectivity after the original trunk was re-enabled. This is a failover failure with a successful rollback, not a successful failover.

## Mapping to the five presentation objectives

### Objective 1: Analyze existing AI-NetOps and SDN verification approaches
Status: literature survey drafted; reference verification and final gap wording documented in docs/literature_and_research_gap.md.

The comparison covers Header Space Analysis, VeriFlow, NetKAT, intent-correctness testing, intent-based networking and an LLM-based network assistant. Avoid claiming that no existing open framework can do this without a wider, defensible literature review. The project contribution should be described narrowly as the prototype integration of an LLM intent proposer, a separate topology-aware safety gate and a bounded executor, with empirical evaluation in Mininet.

### Objective 2: Design an invariant-checking framework
Status: core graph-based prototype implemented.

Relevant code:
- verifier/safety_verifier.py
- controller/decision_gate.py
- tests/test_guardrail.py

Checks include topology existence, graph connectivity, loop detection/policy, endpoint reachability and simulated port removal. A recent change makes inter-switch links respect observed STP state when that telemetry is available: if either endpoint is not reported FORWARD, the physical edge is not counted as a usable path for safety checks. Missing STP state is conservative once STP-state telemetry exists.

Limitations:
- This is a graph abstraction, not a full symbolic model of OpenFlow match/action semantics.
- Graph reachability does not prove all packet/header-level policies.
- Reroute is deliberately rejected because forwarding-aware verification is not implemented.
- Results depend on telemetry completeness and correctness.

### Objective 3: Develop an AI remediation agent
Status: intent-proposal component implemented; anomaly detection is not yet comprehensive.

Relevant code: agent/remediation_agent.py.

The agent calls local Ollama (default model qwen2.5-coder:1.5b), receives sanitized telemetry plus a valid physical-port list, requests structured JSON and validates the result against a schema. Invalid output and service errors default to no_action; target ports are validated against telemetry.

Limitations:
- The input is mainly port/flow counters, discovered links and controller telemetry.
- This is not yet a calibrated anomaly detector with a labelled congestion/loss dataset.
- Synthetic intent experiments do not measure LLM accuracy; separate model-decision evaluation is needed.

### Objective 4: Integrate agent and safety gate with Ryu
Status: integration components exist; controlled pipeline can be invoked, but autonomous failover behavior is incomplete.

Relevant code:
- controller/telemetry_controller.py: OpenFlow statistics, link discovery, STP-state telemetry and atomic telemetry snapshots.
- controller/decision_gate.py: agent -> safety check -> REJECTED or PENDING_HUMAN_APPROVAL; approved proposals are freshly revalidated before execution.
- controller/human_verifier.py and observability/server.py: authenticated human approval queue/API, expiring action/topology-bound fingerprints, reasoned approve/reject/request-changes decisions, single-use consumption, and signed-audit-backed execution.
- executor/remediation_executor.py: requires human approval and a live connectivity checker by default, validates targets, restricts block to eligible inter-switch trunks, installs cookie-scoped rules at both trunk ends, verifies installed flow entries and attempts transaction-scoped rollback.
- audit/audit_trail.py: hash/signature audit records.
- observability/server.py and observability/metrics.py: API/metrics.
- controller/remediation_service.py: polling supervisor that runs the decision pipeline only when the telemetry file changes.

The supervisor defaults to dry-run. Using --execute requires a caller-supplied --connectivity-checker module:function; live block execution is fail-closed if a checker is required but missing. The project does not install or run this supervisor as a persistent OS service; it is a manually launched component.

Limitations:
- The previous live trunk-rule test blocks a trunk already blocked by STP. That test verifies paired flow changes, access-port rejection and continued connectivity, but it does not prove failover after loss of the active trunk.
- The latest Mininet configLinkStatus(..., "down") experiment on the active s1-eth2 <-> s2-eth1 link started with 0.0% packet loss but did not produce a DOWN/MISSING event in Ryu's telemetry. STP therefore left the alternate blocked and packet loss reached 100% through the 30-second window. Re-enabling the original link restored connectivity in 0.017 seconds in the saved triangle experiment. The telemetry-path mismatch under sudo was fixed, but this latest post-fix run still did not fail over. The remote tooling blocked an attempt to remove OVS ports to emulate a true cable unplug, so physical link-down behavior remains untested.
- Experimental custom Ryu STP hooks were removed after they produced STP-state-machine exceptions. Do not treat any run performed with those hooks enabled as a valid performance or failover result.
- A live connectivity callback must be specific to the emulated/deployed environment; a generic callback must not be used to claim production safety.

### Objective 5: Evaluate latency, rejection quality and remediation effectiveness
Status: tests and a reproducible evaluation harness exist; broad empirical evaluation remains incomplete.

Current evidence produced on 2026-10-27:
- Full pytest suite after Phase 1–3 changes: 155 tests passed (one upstream eventlet/distutils deprecation warning).
- Labelled synthetic safety cases: 12/12 predictions matched their hand-written labels; false-accept rate 0/9 = 0%; false-reject rate 0/3 = 0%.
- Simulated executor transaction benchmark: 30/30 transactions passed using an in-memory OVS command runner; the latest rerun measured mean 0.277 ms (median 0.221 ms; p95 0.380 ms).
- The benchmark and safety data are written to experiments/results/recommended_evaluation_20261027.json and experiments/results/recommended_evaluation_20261027.md.

Fresh live tests run on 2026-10-27:
- testbed/validate_redundant_topology.py: PASS. The two-switch/two-trunk Mininet topology reached STP convergence; s2-p2 was BLOCK while host access ports forwarded; baseline pingall packet loss was 0.0%.
- testbed/validate_trunk_remediation.py: PASS. The executor installed and verified a cookie-scoped drop rule on both ends of standby trunk B (s1-p3 and s2-p2), a live pingall callback returned 0% loss, the access-port block was rejected without changing the checked flow rules, and a two-record audit chain verified. The same live test also confirmed that both the gate and executor reject a block request on the currently forwarding trunk when the alternate is STP-blocked, without changing flow rules or losing connectivity.
- testbed/validate_triangle_failover.py: FAILOVER_FAILED_ROLLBACK_PASS. After correcting the root-vs-project telemetry path and making the ring STP priority deterministic, the test used Mininet configLinkStatus(..., "down") on active trunk s1-eth2 <-> s2-eth1. Baseline pingall loss was 0.0%; Ryu did not report that port as DOWN/MISSING, STP left the alternate blocked, and loss remained 100% through the 30-second window. Re-enabling the original trunk restored 0.0% loss in 0.017 seconds. This emulates an interface link-down, not a physical cable unplug. The result is in experiments/results/live_triangle_failover_latest.json.
- The live trunk-remediation pass is a standby-trunk rule-installation test, not proof of active-link failover.
- Follow-up diagnostic testbed/diagnose_link_down.py (2026-10-27): baseline ping loss was 0.0%; after Mininet.configLinkStatus(s1, s2, "down"), Linux interfaces showed DOWN/M-DOWN, but OpenFlow port-description state remained LIVE after two seconds (config: NO_PACKET_IN), ping loss reached 100.0%, and restoring the link returned loss to 0.0%. This supports the finding that this injection does not generate the OpenFlow LINK_DOWN signal Ryu STP needs; it does not prove behavior for a physical cable unplug.

These numbers have narrow meanings:
- The 12 cases are synthetic and manually labelled; they are not statistically representative and do not establish LLM decision quality.
- The benchmark does not execute real OVS commands or measure live connectivity; it measures the executor software path with a fake command runner and stub connectivity callback.
- The old report dated 2026-10-08 is historical and does not represent the current tree.
- The active-trunk administrative-down tests did not fail over; successful rollback is recorded separately. A physical cable-unplug event was not tested.

## Threat model and controls

| Threat or failure | Existing control | Remaining gap |
|---|---|---|
| Malformed/unsupported AI intent | JSON Schema and action validation | Add broader fuzz and model-output tests |
| Invalid switch/port | Telemetry-derived physical-port validation | Validate against a fresh, coherent topology snapshot at execution time |
| AI tries access-port isolation | Gate and executor independently reject access-port block | Add more topology and policy scenarios |
| Shell/command injection | Executor uses argument arrays and shell=False | Keep all new command paths under the same rule |
| Failed flow install or mismatched rule | Cookie-scoped rule identity and rule-table checks | Fault-inject one-sided partial writes and rollback failures |
| Actual host connectivity is lost | Live connectivity checker is required by default for block actions; failed postcondition triggers scoped rollback | Integrate a real lab-specific checker and fault-inject rollback failure under loss |
| Telemetry read during write | Atomic JSON snapshot replacement in controller | Add atomic-write regression coverage |
| Audit log alteration | Hash/signature validation | Document key custody, rotation and protected storage |
| Active trunk fails / alternate remains blocked | Live failover harness, explicit OpenFlow port-status telemetry, deterministic STP priorities, and rollback evidence | Not solved: the current Mininet failure injection does not yield a DOWN/MISSING event at Ryu; find and validate a reliable failure-detection/reconvergence mechanism |

## Reproducible commands

From $NETOPS_HOME:

    $VIRTUAL_ENV/bin/python -m pytest -q
    $VIRTUAL_ENV/bin/python experiments/evaluate_guardrail_cases.py
    $VIRTUAL_ENV/bin/python -m py_compile controller/telemetry_controller.py controller/decision_gate.py controller/remediation_service.py executor/remediation_executor.py verifier/safety_verifier.py

Live Mininet tests must only run in the project's isolated testbed. They require Ryu listening at 127.0.0.1:6653 and root privileges for Mininet. They refuse to take over pre-existing bridges and clean up the Mininet instance that they create.

## Readiness verdict

Prototype integration: advanced; Human Verifier and fail-closed approval flow implemented.
Automated regression testing: 155 tests passing after Phase 1–3 changes.
Synthetic verifier evaluation: green on the defined 12 cases only.
Real OVS transaction latency: not freshly measured by the new benchmark.
Active-link failover: failed in current live experiment; rollback restored connectivity.
Production readiness: not established.
