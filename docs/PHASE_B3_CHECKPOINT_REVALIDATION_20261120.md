# Phase B3 checkpoint revalidation — 2026-11-20

## Scope and source revision

- Code commit tested live: `f18845f0544423d657740c49e663ac1357c96d66`
- Branch: `feature/continuous-netops-monitoring`
- Live harness: `scripts/run_phase_b3_live_ring4.py`
- Raw run record: `experiments/results/phase_b3/20261120T134732Z_phase_b3_live_ring4.json`
- Provenance: live Mininet + Open vSwitch + Ryu. No simulated result was used as live evidence.

This revalidation follows the rate-limit rollback correction in `f18845f`. The correction keeps the transaction cookie active in the guardrail ledger unless OVS read-back confirms that both the transaction flow and meter are absent. It also removes the missing-priority fallback when selecting a candidate flow for `remove_flow`.

## Live baseline

The harness required three clean baseline snapshots. On initial startup:

- STP converged in 3.31 seconds with `s4-p4` blocked.
- `pingall` loss was 0%.
- Baselines were checked between scenarios, with all expected physical links up and no guardrail/meter priority flows.

## Live results

### 7a — disable an active trunk

- Verified `s1-p3` was FORWARD and `s4-p4` was BLOCK before the change.
- A real `HumanApprovalStore` approval was consumed for `disable_port`.
- Execution succeeded; standby `s4-p4` transitioned to FORWARD.
- Executor-reported convergence: **13.045 seconds**.
- Continuous h1→h4 ping recorded **62 missing sequence numbers** and a **12.86-second** reply-to-reply gap.
- Interval estimate: **12.636 seconds**; median normal interval: **0.2038 seconds**.
- The active port was restored and the clean baseline recovered.

### 7b — restore a missing link safely

- The attempt to restore absent standby link `s4-p4` while an alternate path was active was rejected because the resulting topology contained a forwarding loop.
- The harness then disabled both s4 uplinks and verified h1 could not reach h4.
- `s4-p3` was absent from live links but found in `telemetry/topology_spec.json` through the topology inventory merge.
- A real approval was consumed for `restore_port`; execution succeeded and connectivity was verified.
- Executor-reported convergence: **8.529 seconds**.
- STP reconverged with `s4-p4` returned to BLOCK; the third baseline snapshot passed.

### 7c — meter under broadcast load

- A real approved `rate_limit_port` action installed a **2,000-kbps** meter on `s1-p1`.
- h1 generated 1,400-byte UDP broadcasts for **15.04 seconds**.
- OpenFlow meter drop counters increased by **11,081 packets** and **15,978,802 bytes**.
- STP-blocked `s4-p4` counter deltas: **2,784 RX**, **1 TX** (kernel and OpenFlow counters agreed).
- RX growth alone is not evidence of forwarding; the accurate observation is that no broadcast/data packet was transmitted out of the blocked port (the single TX packet is within the harness's allowance for STP control traffic).
- h1→h4 RTT summary during load: **0.026 / 0.041 / 0.089 / 0.014 ms** (min/avg/max/mdev).
- Independent h2→h4 ping: **32/32 replies, 0% loss**.

### 7d — human approvals

The harness used `require_human_approval=True` and the real persisted `HumanApprovalStore`. Three approved proposals were consumed by `live-network-admin`: `disable_port`, `restore_port`, and `rate_limit_port`. The unsafe redundant restore proposal was rejected and was not consumed.

## Automated validation

On this revision and its source/test changes:

- Focused `tests/test_phase_b_actions.py`: **52 passed**.
- Full `pytest -q`: **335 passed**.
- `ruff check src tests`: **All checks passed**.
- `python -m compileall -q src tests`: passed.
- `git diff --check`: passed.

## Teardown verification

The raw run record reports `status=passed`, three baseline snapshots, and `cleanup.lab_bridges_remaining=[]`. A separate post-run root check confirmed:

- No OVS bridges remained.
- No Ryu/Mininet/mnexec process remained.
- Nothing was listening on OpenFlow TCP port 6653.

The dedicated B3 ledger had one active cookie retired after bridge teardown. The script did not delete the shared production guardrail ledger.

## Boundary of this evidence

This is a B3 live-lab revalidation, not production-readiness certification. It does not prove resilience under production traffic, multi-tenant authorization, real identity-provider integration, long-duration restarts, durable backup/restore, or Phase C AI/detector performance. Phase C remains gated on independent review of the pushed checkpoint. Do not describe this project as production-ready until those gates are completed and the operational security review is signed off.
