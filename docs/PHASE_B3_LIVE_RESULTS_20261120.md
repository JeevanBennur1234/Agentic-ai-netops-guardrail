# Phase B3 — live ring4 verification

**Date:** 2026-11-20
**Repository:** `JeevanBennur1234/Agentic-ai-netops-guardrail`
**Branch:** `feature/continuous-netops-monitoring`
**Base HEAD recorded by the run:** `8f64f094a25fdf2b35aff18c1f6ba823d282a09a`
**Model:** Not used by this B3 executor-verification harness (`null` in the raw JSON).
**Command:** `wsl.exe -d Ubuntu-22.04 -u root -- bash -lc "cd /home/bennurjeevan/netops_guardrail && .venv/bin/python scripts/run_phase_b3_live_ring4.py"`
**Final raw result:** `experiments/results/phase_b3/20261120T131540Z_phase_b3_live_ring4.json`

The recorded HEAD is the base commit at execution time. The checkout was dirty during the experiment; the source changes and harness are included in the subsequent checkpoint. The result JSON and the script/log files are retained for auditability.

## Baselines

Three explicit baseline snapshots were saved:
- `before_7a_active_trunk`
- `after_7a_before_7b`
- `after_7b_before_7c`

Each snapshot requires `pingall=0%`, STP convergence with `s4-p4` blocked, no administratively down physical ports, and no pre-existing priority-65000/65500 guardrail or meter flows. The OpenFlow `LOCAL` pseudo-port is deliberately excluded from the physical-port check.

## Live results

### 7a — active trunk disable

- Verified `s1-p3` was FORWARD and the standby `s4-p4` was BLOCK before injection.
- A real human-approved `disable_port` was executed successfully.
- STP moved `s4-p4` to FORWARD to preserve reachability.
- Executor-reported convergence: **13.042 s**.
- Continuous ping: **62 sequence numbers missed**, **12.86 s** measured reply-to-reply gap.
- Median normal reply interval: **0.2025 s**; interval-estimated loss duration: **12.554 s**; residual between the two measurements: **0.306 s**.
- The active trunk was restored and the full ring baseline recovered.

The earlier 16.1-second outage report was not reproduced in this run. This run gives a separate, timestamped measurement; it does not retroactively prove the earlier 16.1-second value.

### 7b — redundant restore rejection and genuine edge partition

- Attempting to restore the absent standby link `s4-p4` while the redundant path through `s4-p3` was present was **rejected** by the loop-safety verifier.
- For the positive partition test, **both** `s4-p3` and `s4-p4` were administratively disabled and both links were removed from live telemetry.
- The h1→h4 connectivity probe confirmed the edge partition.
- The union with `telemetry/topology_spec.json` recovered the missing link identity.
- The human-approved `restore_port` action restored `s4-p3`; execution succeeded and connectivity verification passed. Executor convergence: **8.526 s**.
- `s4-p4` was brought back up; STP returned it to BLOCK and baseline pingall returned to 0% loss.

### 7c — rate limit under broadcast load

- `rate_limit_port` installed a 2,000-kbps meter on `s1-p1`.
- h1 generated 1,400-byte UDP broadcasts for **15.05 s** with a 1-ms requested send interval.
- OpenFlow meter band drop counters increased by **11,153 packets** and **16,082,626 bytes**.
- STP-blocked `s4-p4` counters: **2,803 RX packets**, **1 TX packet** (kernel and OpenFlow deltas agree). RX growth is not proof of forwarding: frames can arrive at a blocked port and be discarded. The accurate claim is that no broadcast/data packets were transmitted out of the blocked port.
- h1→h4 RTT summary during the flood: **0.028 / 0.057 / 0.106 / 0.021 ms** (min/avg/max/mdev).
- Independent h2→h4 ping: **32/32 replies, 0% loss**.

### 7d — real human approval store

The harness confirmed `require_human_approval=True`. Three proposals were consumed by the real `HumanApprovalStore`, with approver `live-network-admin`:
- `disable_port`
- `restore_port`
- `rate_limit_port`

The unsafe redundant `restore_port` proposal was rejected and was not consumed.

## Harness attempts retained

The result directory also retains aborted runs rather than hiding them:
- `20261120T130049Z_...`: baseline parser incorrectly attributed OVS `LOCAL(s1)` pseudo-port state to physical port 4.
- `20261120T130147Z_...`: same preflight parser issue with the raw port dump captured for diagnosis.
- `20261120T130214Z_...`: 7a and 7b completed; 7c stopped before flood generation because the `ovs-ofctl meter-stats` selector syntax was wrong.

The parser and meter-stat collection were corrected before the successful runs. The final rerun additionally verified that the B3-specific cookie ledger is isolated from the shared guardrail ledger and that its teardown restores runtime ownership. All five JSON results are preserved.

## Validation

- Full pytest suite: **334 passed**.
- Ruff: **All checks passed**.
- Live result: **passed**.
- Mininet/Ryu cleanup completed; the OVS ring bridges were absent after teardown.
- The harness uses a dedicated B3 cookie ledger and does not delete the shared guardrail ledger. On teardown it verifies that ring bridges are gone, retires only the B3 ledger cookies, persists the final result, and restores runtime file ownership. The final rerun verified result JSON and ledger ownership as the checkout user, with no ring bridges or Ryu/Mininet processes left running.

This is a B3 verification result, not a claim that the system is production-ready. Phase C and the separate production-hardening review remain gated on independent review of the checkpoint.
