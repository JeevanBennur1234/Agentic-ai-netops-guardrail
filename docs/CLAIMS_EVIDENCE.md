# Claims-to-Evidence Matrix

Date: 2026-11-13
Branch at review: `p2/experimental-evidence`
HEAD recorded in the five failover artifacts: `c6831e2a86da7fccb81b9c03c9ffed3ad7144135`
Important: the tested controller and failover-harness changes were present in the local working tree but were **uncommitted**. The artifact commit hash identifies HEAD, not a clean snapshot of every tested file. Preserve the JSON artifacts and corresponding local diff together.

## Evidence labels

- **LIVE** — execution against the Mininet/Open vSwitch/Ryu testbed. It is still emulated lab evidence, not production hardware evidence.
- **SIMULATED** — controlled simulation or in-memory/fake OVS runner.
- **SYNTHETIC** — unit/API tests, manually authored cases, or deterministic fixtures.
- **UNSUPPORTED** — no evidence supports the claim at the stated strength.

## Current project status

The project is a research prototype for AI-assisted NetOps with a separated intent proposer, deterministic topology safety gate, human approval workflow, constrained executor, post-check/rollback path, audit trail, and observability. The current full test suite passes **176 tests**. The strongest recent P2 result is five successful 90-second active-trunk failover trials in Mininet + OVS + Ryu.

## Claims supported by current evidence

| Claim | Supporting evidence | Evidence label | Qualification |
|---|---|---|---|
| A local AI intent proposer is integrated with a separate topology-aware safety gate. | `src/netops_guardrail/agent/remediation_agent.py`; `src/netops_guardrail/controller/decision_gate.py`; agent/observability tests | SYNTHETIC | Claim the integration path exists. Do not infer model accuracy. |
| The graph verifier checks a limited set of topology and reachability invariants with STP-aware forwarding. | `src/netops_guardrail/verifier/safety_verifier.py`; `tests/test_guardrail.py` | SYNTHETIC | This is graph/topology checking, not formal proof of arbitrary packet behavior. |
| Human approval is authenticated, reasoned, expiring, fingerprint-bound, and single-use in tested software paths. | `tests/test_human_verifier.py`; `tests/test_observability.py` | SYNTHETIC | Production identity/access-control assurance is not established. |
| Executor actions are constrained, cookie-tagged, post-checked, and have scoped rollback attempts. | `src/netops_guardrail/executor/remediation_executor.py`; `tests/test_remediation_executor.py`; `experiments/results/live_integration_summary_20261027.json` | SYNTHETIC + LIVE (historical) | The live integration evidence is a standby-trunk rule test, not active-link failover. |
| Audit records are signed/hash-linked and tamper tests exist. | `src/netops_guardrail/audit/audit_trail.py`; `tests/test_audit_trail.py` | SYNTHETIC | Does not establish that every deployment is tamper-proof. |
| Five 90-second active-trunk failover trials passed in the Mininet + OVS + Ryu testbed. | `experiments/results/2026-11-13_live_active_failover_trial_02.json`, `_03.json`, `_06.json`, `_07.json`, `_08.json` | LIVE (emulated lab) | All five began at 0% baseline loss, recovered over the alternate STP path, completed 90 seconds of observation, and recorded zero post-recovery packet-loss samples. Fault injection was OpenFlow 1.3 administrative port-down, not physical cable unplug. |
| The five successful failover trials recovered in 9.042–10.131 seconds. | The five JSON artifacts listed above and `experiments/results/2026-11-13_live_active_failover_summary.json` | LIVE (emulated lab) | Median 9.048 seconds; n=5. This is a small lab sample, not a production SLA or general performance guarantee. |
| Qwen structured-output evaluation returned valid JSON and passed the intent schema for all 30 defined synthetic scenarios. | `experiments/results/2026-11-10_qwen_structured_full.json` | SYNTHETIC | 30/30 valid JSON, 30/30 schema pass, 0 fallbacks. The run had 3 mutating proposals; 2 unsafe mutating proposals were blocked by the independent guardrail and 0 passed. This is a result on a deterministic synthetic topology profile, not a general model-accuracy claim or live OVS evaluation. |
| The latest full regression suite passed 176 tests. | Latest local run: `.venv/bin/pytest -q` → `176 passed` | SYNTHETIC | Tests passed after the controller/harness changes; this is a local run, not a CI run on a pushed commit. |
| Live OVS executor latency was measured in five successful transactions. | `experiments/results/2026-10-30_952e9e7_real_ovs_latency_summary.json` and samples | LIVE (emulated lab) | Median 86.863 ms; n=5. p95/p99 estimates are weak at this sample size and exclude human approval latency and topology startup. |

## Claims to avoid

| Claim | Why it is unsupported |
|---|---|
| Production readiness or production SLA. | No production deployment, operational acceptance, or physical-network validation exists. |
| Formal proof of the whole network. | The verifier covers finite graph/topology invariants, not arbitrary packet/header-level behavior. |
| General 100% AI accuracy. | The Qwen run achieved 30/30 valid JSON and schema passes on the defined synthetic set, but that measures structured-output compliance on this dataset, not general decision accuracy or live network performance. |
| AI autonomously performed the successful failover. | The successful experiment demonstrates STP reconvergence after an OpenFlow administrative port-down event. It does not demonstrate an LLM proposing or executing a remediation. |
| Physical cable-unplug failover. | The recorded failure injection used OpenFlow 1.3 administrative port-down, not a verified physical cable unplug. |
| A formal guarantee that failover always completes within 10 seconds. | Only five trials were recorded in one emulated topology/environment. |
| A verifier result equals human approval or successful execution. | Verification, authorization, execution, and post-check remain separate lifecycle states. |
| A real Issue 2 anomaly when mode is `controlled_simulation`. | The controlled-simulation path is explicitly simulated. |
| That no other network verifiers exist. | No exhaustive literature review can establish this negative claim. |

## Failover experiment details

- Trials counted as PASS: **02, 03, 06, 07, 08**.
- Trial 01: do not count; it is not part of the five validated 90-second results.
- Trials 04 and 05: **INCONCLUSIVE** because baseline connectivity was 100% packet loss before fault injection. They are not failover failures and are not counted as passes.
- Each successful trial had 0.0% baseline ping loss, observed the primary trunk administrative-down event, saw the alternate trunk transition to FORWARD, recovered host connectivity, and completed the 90-second window.
- Successful trial metrics:

| Trial | Recovery (seconds) | Ping samples | Post-recovery loss samples |
|---|---:|---:|---:|
| 02 | 9.048 | 165 | 0 |
| 03 | 9.058 | 164 | 0 |
| 06 | 10.131 | 162 | 0 |
| 07 | 9.042 | 165 | 0 |
| 08 | 9.042 | 165 | 0 |

- Baseline harness fix: controller clears stale per-switch STP states on datapath reconnect; validator waits for fresh telemetry, expected initial STP state, and three consecutive 0%-loss baseline probes before injecting the fault.
- The tested controller and harness edits are currently local/uncommitted. Do not cite the HEAD hash alone as an immutable reproduction snapshot; retain the source diff with these artifacts.

## Remaining limitations / final-day priorities

1. Keep claims scoped to the Mininet + OVS + Ryu emulation. Do not imply physical or production validation.
2. Preserve the current local source changes and all five PASS JSON artifacts together.
3. Before submission, review the report and slides for stale statements that active failover is unresolved or failed; update them to the five-trial result with the administrative-down qualification.
4. Keep the Qwen model-output limitation explicit: 0/30 strict JSON, 30/30 fallback.
5. Do not claim production readiness, formal verification, or autonomous AI failover.
6. The working tree is not clean and the latest changes have not been committed or pushed. If source delivery through GitHub is required, review the diff, commit only after approval, and push the intended branch separately.
