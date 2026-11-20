# Continuous NetOps Incident Monitor

## Run

From the repository root with the project virtual environment active:

```bash
.venv/bin/python -m netops_guardrail.controller.monitor
```

The monitor reads the Ryu telemetry snapshot, debounces deterministic detections, persists incidents under `$NETOPS_HOME/observability/data/incidents/`, and submits eligible incidents to the existing `decision_gate.decide(..., execute_approved=False)` pipeline. It does not call a network executor.

Useful options:

```bash
.venv/bin/python -m netops_guardrail.controller.monitor --help
.venv/bin/python -m netops_guardrail.controller.monitor --no-ai
.venv/bin/python -m netops_guardrail.controller.monitor --telemetry telemetry/data/latest.json --interval 5 --debounce 2 --cooldown 60 --max-ai-calls-per-hour 12
```

The monitor is a separate process. Run it under a service manager in deployments and supervise its restart policy/logs. Keep the observability server and monitor under the same `NETOPS_HOME`.

On each polling cycle the monitor atomically writes `monitor_status.json` beside `incidents.json`. The `/api/status` response exposes this heartbeat as `monitor.status` (`running`, `degraded`, or `stopped`) and `monitor.ai_enabled`. The dashboard displays both values so saved incidents cannot be mistaken for proof that the monitor is currently running. A heartbeat older than the liveness threshold is reported as stopped.

## Incident semantics

- `live_telemetry`: a current controller telemetry snapshot with no explicit non-live provenance.
- `lab_injected_live`: only accepted when the telemetry producer itself writes this provenance into the snapshot.
- `simulation`: only accepted from trusted telemetry-pipeline provenance. Simulation incidents are persisted but are never dispatched to AI or marked executable.
- `telemetry_stale`: always non-remediable; the monitor does not invoke the agent for stale evidence.
- `topology_offline`: emitted when all known physical ports are reported MISSING and no active inter-switch links remain. This is non-remediable and is not dispatched to Ollama; reconnect Mininet/OVS before evaluating network faults.
- Link-event detections use a 30-second event window and the latest event per link, so an old DELETE cannot keep a recovered link marked as failed.
- Flow drift currently detects the project's known marker cookie/priority only. It is not a general desired-state flow policy engine. This path returns a deterministic `no_action` without invoking Ollama because no policy-safe flow-specific remediation is wired through the guarded executor path.
- Link failures are detected from explicit DOWN/MISSING port state or DELETE link events. The model is restricted to `no_action` until an approved link-remediation intent is supported by the existing human-approval path; if telemetry already shows recovery, the agent short-circuits without invoking Ollama.
- Standby-forwarding anomalies can produce a constrained AI recommendation using Ollama. The existing safety verifier and decision gate run, and a block recommendation requires human approval. The monitor never executes it.
- The polling monitor invokes `standby_forwarding_anomaly`, `flow_rule_drift`, `link_flapping`, and `mac_flooding` detectors. MAC-flood detection is passive and reads recent controller MAC-learning events; its live injector is exposed only when both an explicit traffic-generator callback and a MAC-table recovery callback are configured.
- Each agent result records whether the LLM was actually invoked and why it was skipped or failed. The incident pipeline stage uses this metadata rather than marking every deterministic no-action as an AI completion.

## Persistence and controls

- `incidents.json` stores evidence, provenance, lifecycle, stage outcomes, human proposal metadata, and audit record reference.
- `ai_dispatches.json` persists a rolling one-hour dispatch ledger to enforce the configured AI-call cap across restarts.
- Repeated evidence is debounced and deduplicated. An incident is resolved when its deterministic condition disappears.
- A failed AI/safety pipeline is recorded as failed-closed; there is no fallback execution path.
- The Issue 2 controlled demo endpoint now returns a simulation-only observation and does not create a proposal that could later be approved against a real network.

## Validation boundaries

Unit tests, mocked decision-pipeline integration tests, Flask dashboard/API tests, and a one-shot CLI replay test cover the continuous-monitor software path. Separately, the Phase B3 ring4 harness has recorded a live Mininet/OVS verification; that evidence validates the B3 executor scenarios, not the continuous monitor's end-to-end detector-to-approval path. Live monitor-driven incident validation and production deployment checks remain outstanding.


## Phase C live-fault target policy

All live injector targets are resolved from a controller-produced telemetry snapshot no older than 30 seconds. Injection fails closed when provenance, timestamp, physical ports, or the scenario-specific topology evidence is missing. The injector records the resolved target with the run evidence. The current target resolver supports primary-trunk shutdown, standby-trunk flapping, flow-table drift, restoration of a recently deleted/down inter-switch link, and MAC flooding on a discovered host access attachment. `standby_forwarding` remains passive-only.

The monitor polls `trunk_down`, `redundant_trunk_restored`, `flow_rule_drift`, `link_flapping`, `mac_flooding`, and `standby_forwarding_anomaly`. These detectors are telemetry-driven; fixture provenance is not eligible for AI dispatch or live remediation. A passing unit test does not constitute a live lab run. Live execution still requires fresh ring4 telemetry, healthy baseline connectivity, monitor heartbeat, an operator token, and the existing approval/safety gates.

The manual LAB RESET now follows the same target rule: it requires a controller-produced telemetry snapshot no older than 30 seconds, enumerates discovered physical switch ports, restores those ports, and deletes only the NetOps marker-cookie flows on discovered bridges. It does not flush unrelated flows, remove bridges, clear telemetry/approval/audit files, or run global Mininet cleanup. Stale or missing telemetry causes reset to fail closed; restart the controller/monitor and refresh telemetry before retrying.
