# Phase 2 Live Fault Experiment Results — 2026-11-15

## Outcome

**PASS — all requested live experiments completed in the isolated Mininet/OVS testbed.**

- Initial topology baseline: 0.0% packet loss.
- Flow-rule drift: detected, scoped marker removal verified, connectivity retained.
- Link flapping: 5/5 trials detected and recovered; every post-recovery connectivity check reported 0.0% packet loss.
- MAC-learning flood: 32 distinct-source frames generated and detected; controller learning state reset; independent table and connectivity checks passed.

Evidence type: `LIVE_MININET_OVS`
Repository branch: `p2/experimental-evidence`
Topology: two Mininet hosts, two OVS switches, and two redundant inter-switch trunks.
Controller: Ryu on `127.0.0.1:6653`.

## 1. Flow-rule drift

- Installed a marker drop rule on `s1` with cookie `0x4e45544f5053`, priority `65000`, and reserved EtherType `0x88b5`.
- The controller's flow telemetry detected the marker.
- Restoration deleted only the marker cookie; it did not flush the switch flow table.
- An independent `ovs-ofctl dump-flows s1` check confirmed the marker was absent.
- Post-restoration host connectivity: **0.0% packet loss**.

**Result: PASS.**

## 2. Link flapping

- Target: standby trunk interface `s1-eth3`.
- Each trial injected two down/up cycles.
- The detector observed new link and/or OpenFlow port-status evidence in every trial.
- Independent recovery checks confirmed the interface returned UP, STP reconverged, and host connectivity recovered.

| Trial | New detector events | Post-recovery packet loss | Result |
|---:|---:|---:|---|
| 1 | 10 | 0.0% | PASS |
| 2 | 9 | 0.0% | PASS |
| 3 | 4 | 0.0% | PASS |
| 4 | 9 | 0.0% | PASS |
| 5 | 10 | 0.0% | PASS |

**Result: PASS — 5/5 trials.**

## 3. MAC-learning flood

- Generated **32 Ethernet frames** from `h1`, each using a distinct locally administered source MAC address.
- The detector reported a flood condition with **36 unique source MACs** observed in its 30-second telemetry window.
- Recovery used the existing controller behavior: a controlled DOWN/UP transition on access port `s1-eth1` caused the port-status handler to flush the controller's L2 learning state and the associated learned flows.
- After STP reconvergence and endpoint relearning, the independent checks reported:

| Check | Observed | Expected | Result |
|---|---:|---:|---|
| Controller learned MAC count — s1 | 1 | ≤2 | PASS |
| Controller learned MAC count — s2 | 1 | ≤2 | PASS |
| Priority-1 learned flows — s1 | 2 | ≤2 | PASS |
| Priority-1 learned flows — s2 | 2 | ≤2 | PASS |
| Host connectivity loss | 0.0% | 0.0% | PASS |
| Detector after 30-second event window | Not detected | Not detected | PASS |

The MAC-table check is based on the controller's learned-MAC telemetry, the live OVS flow tables, and an independent host-connectivity test.

**Result: PASS.**

## Reproduction and raw evidence

- Runner: `experiments/run_phase2_live_faults.py`
- Raw structured evidence: `experiments/results/20261115_130257_phase2_live_faults.json`
- Human-readable run summary: `experiments/results/20261115_130257_phase2_live_faults.txt`
- The raw JSON includes timestamps, per-trial detector output, restoration outcomes, independent checks, final telemetry, and 39 recorded command executions.

The runner refuses to take ownership of pre-existing `s1`/`s2` bridges and tears down only the Mininet instance it creates. The successful run recorded no cleanup error.

## Regression verification

After the live run, the repository test suite completed with **206 passed, 0 failed**. Ruff reported **all checks passed** for the live experiment runner, and `git diff --check` reported no whitespace errors.

## Scope and limitations

- These are live experiments in the isolated local Mininet/OVS lab, not production-network tests.
- Link flapping uses Linux interface state changes on the standby trunk, not physical cable removal.
- MAC-table recovery uses the controller's existing port-status-triggered learning-state flush. It is not evidence of a generic production MAC-table management API.
- The detector's MAC-flood signal is event-window based; the report separately verifies table state and connectivity, then confirms the detector clears after the 30-second window expires.
- The results demonstrate the tested scenarios and recovery checks only. They do not establish production readiness or formal safety guarantees.
