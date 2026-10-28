# System Design and Threat Model
Prepared: 2026-10-27

## 1. System goal

The prototype investigates a safe boundary between an AI-proposed network change and changes made to an SDN data plane. The AI component proposes an intent; deterministic code checks a limited set of topology invariants; a bounded executor validates approval, applies a constrained operation, checks the resulting state and records the outcome.

The current implemented action set is deliberately limited. no_action is supported; block is restricted to inter-switch trunks with an alternate topology path; reroute is rejected because packet-forwarding-aware safety verification is not implemented.

## 2. Component architecture

1. Telemetry collection: controller/telemetry_controller.py obtains OpenFlow flow/port counters and discovered links, and records STP port states. Telemetry JSON publication uses a temporary file and atomic replacement.
2. Intent proposal: agent/remediation_agent.py sanitizes telemetry, enumerates valid physical ports and asks a local Ollama model for a structured JSON intent.
3. Validation and gate: JSON Schema/physical-port checks and controller/decision_gate.py reject unsafe actions. A safe block creates PENDING_HUMAN_APPROVAL and cannot mutate OVS until the exact action is reviewed. The verifier builds a NetworkX graph and checks connectivity/reachability and loop policy; STP-blocked and reported down/missing links do not count as forwarding paths.
4. Human approval and controlled execution: controller/human_verifier.py stores an expiring proposal bound to intent, verifier result, current topology/port states and a fingerprint. The /approvals UI requires a configured bearer-token identity, and each approve/reject requires a reason. executor/remediation_executor.py consumes the matching approval once, independently validates physical targets and confines block operations to an inter-switch trunk. It requires a live connectivity callback by default, uses argument arrays with shell=False, adds transaction-tagged rules at both ends and verifies rules by cookie.
5. Post-check and rollback: the executor inspects flow tables and topology safety. An optional environment-specific callback checks live host reachability; callers can require this callback for block operations. Failed transactions attempt to remove only their own cookie-tagged rules.
6. Audit and visibility: audit/audit_trail.py writes signed/hash-chained records; observability/ exposes metrics/trace views; experiments/evaluate_guardrail_cases.py records synthetic safety-case outcomes and a simulated executor benchmark.
7. Supervisor: controller/remediation_service.py watches the telemetry snapshot for changes and invokes the gate. It is dry-run by default. Execute mode requires an explicit live connectivity checker. It is a manually launched service script, not installed as a persistent system service.

## 3. Trust boundaries

- The LLM output is untrusted input. It must never select an arbitrary command or directly access OVS.
- Telemetry can be stale, incomplete or inconsistent. Atomic file replacement prevents partial JSON reads but does not guarantee that all switch/link/STP observations are from the same instant.
- The decision gate, human verifier and executor are separate boundaries. A supplied APPROVED string is insufficient; block execution requires a stored, authenticated, exact-action approval and a matching signed audit record. The executor revalidates actions and targets independently.
- A successful ovs-ofctl command is not proof of host reachability. Live connectivity must be measured in the test environment if it is a required postcondition.
- Telemetry freshness is enforced for block approvals: snapshots must carry updated_at_utc and be no older than 30 seconds at proposal/approval/execution validation time. Approval store writes are atomic and process-locked; pending duplicate proposals are deduplicated.
- The audit path is evidence of what the application recorded, not an independent hardware attestation of network state.

## 4. Assets and security objectives

Assets:
- host-to-host reachability and service availability;
- switch flow-table state and controller connectivity;
- topology and port-state telemetry;
- approval/decision records and audit signing key;
- operator trust in experiment results.

Security objectives:
- reject malformed, unsupported and topology-unsafe actions before changes;
- prevent access-port isolation by a trunk-block intent;
- avoid arbitrary shell execution from model output;
- detect failed or partial flow installation and attempt scoped rollback;
- preserve a verifiable record of decisions;
- measure data-plane connectivity after a network mutation where configured.

## 5. Threats, mitigations and residual risk

| Threat | Current control | Residual risk / next test |
|---|---|---|
| Prompt injection or hallucinated port/action | JSON schema, enum validation, telemetry-derived physical ports | Expand adversarial corpus; measure generated model intent quality separately |
| Invalid target or reserved OpenFlow port | Gate and executor target validation | Add fuzzing for unusual IDs, data types and stale topology |
| Isolation of a host access port | Access endpoint classification; gate and executor reject such block operations | Validate multiple VLANs and host attachment patterns |
| Only physical alternate exists but is STP-blocked | Verifier checks STP forwarding state and explicit OpenFlow port-status telemetry | The live triangle experiment still fails over: Ryu did not report the injected link-down as DOWN/MISSING; refine switch/OS link-state detection and STP recovery |
| Shell injection | subprocess argument list and shell=False | Maintain this invariant in every new execution path |
| One-sided paired flow install | Cookie-scoped transaction and rollback | Inject command failure on each side and verify failed rollback is surfaced |
| Loss of live connectivity after mutation | Executor requires a live connectivity callback by default; failed postcondition attempts transaction-scoped rollback | Real failover currently fails; callback must be deployment/testbed-specific, and rollback failure must be surfaced |
| Audit log alteration | Hash chain/signature verification | Key storage/rotation/access control and backups need operational policy |
| Partial telemetry JSON | Atomic temp-file replacement and os.replace | Telemetry from multiple switches is not a cross-switch atomic snapshot |
| Duplicate/rapid remediation decisions | Supervisor fingerprints unchanged telemetry; approval store deduplicates pending fingerprints and serializes lifecycle changes across worker processes | Controller event queue/debounce for concurrent network changes remains future work |

## 6. Safety invariants currently in scope

- A requested block must target an existing physical port.
- Access ports cannot be blocked.
- A block request must refer to an inter-switch trunk and not a fabricated host-facing target.
- Required access endpoints must remain connected in the modeled forwarding graph.
- An inter-switch link is counted as a forwarding path only if both endpoints report STP FORWARD when STP telemetry is present.
- A block is refused in strict mode if no live connectivity checker is configured.
- Reroute is rejected until forwarding-aware proof/verification exists.
- An approved execution is not considered successful unless expected rule changes and configured postconditions are verified.

These are prototype invariants, not a complete proof of all OpenFlow or Ethernet behavior.

## 7. Known live finding: failover is unresolved

The two-switch topology baseline and standby-trunk blocking test pass. The same live test safely rejected a block request on active trunk A when the alternate was STP-blocked, from both the gate and executor, with no flow changes and 0% ping loss. The latest three-switch ring experiment used Mininet configLinkStatus(..., "down") on the active s1-s2 trunk. Baseline packet loss was 0%; after injection, ping loss remained 100% for the 30-second window, the alternate stayed blocked, and Ryu did not record an OpenFlow port DOWN/MISSING event for the failed trunk. Re-enabling the original trunk restored 0% loss in about 0.009 seconds. This is rollback/recovery from explicit restoration, not automatic resilience. It is not a physical cable-unplug test. Automatic link failover remains unresolved and must not be presented as working.

## 8. Validation commands

From the repository root:

    /home/bennurjeevan/venvs/netops/bin/python -m pytest -q
    /home/bennurjeevan/venvs/netops/bin/python experiments/evaluate_guardrail_cases.py
    sudo env PYTHONPATH=/home/bennurjeevan/venvs/netops/lib/python3.10/site-packages python3 testbed/validate_redundant_topology.py
    sudo env PYTHONPATH=/home/bennurjeevan/venvs/netops/lib/python3.10/site-packages python3 testbed/validate_trunk_remediation.py
    sudo env PYTHONPATH=/home/bennurjeevan/venvs/netops/lib/python3.10/site-packages python3 testbed/validate_triangle_failover.py

The live test scripts require Ryu listening on 127.0.0.1:6653, sudo/root access, and an isolated Mininet environment. They refuse to modify pre-existing bridges and stop only the network they create.

## 9. Research-report cautions

- Describe the graph checker as topology-aware verification, not as equivalent to HSA, VeriFlow or NetKAT.
- Report 12/12 only as accuracy on the 12 manually labelled synthetic cases.
- Report the 0.259 ms mean only as the current executor software-path latency under an in-memory fake OVS runner; it is not live OVS performance.
- State that automatic active-trunk failover failed in the current experiment even though rollback after restoring the original trunk succeeded.
- Do not state production readiness until the failover gap, telemetry consistency, fault-injected rollback and larger evaluation are addressed.
