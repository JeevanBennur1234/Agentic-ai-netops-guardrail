# Issue 2 — Standby Forwarding Anomaly

> Before running these examples, set NETOPS_HOME to the repository root and activate the Python environment: export NETOPS_HOME="$(pwd)" followed by source "$NETOPS_HOME/.venv/bin/activate".


## What this scenario checks

The standby trunk is s1-p3 <-> s2-p2; the primary trunk is s1-p2 <-> s2-p1. The live detector reads the latest Ryu telemetry and reports a real anomaly only when:

- Telemetry is fresh (30 seconds or newer).
- Both redundant trunks and all expected physical ports are discovered.
- Both primary-trunk endpoints are FORWARD.
- Both host-facing ports are FORWARD.
- Both standby-trunk endpoints are simultaneously FORWARD.

A normal STP state such as s1-p3=FORWARD, s2-p2=BLOCK is **not** treated as an anomaly.

## How to demonstrate it

1. Make sure Ryu, Mininet and the dashboard are running, and verify h1-to-h2 connectivity.
2. Open /dashboard and select **Issue 2: Standby Forwarding**.
3. The endpoint checks live connectivity, current telemetry, and existing guardrail rules.
4. If live telemetry really shows both standby endpoints forwarding, the proposal is labeled live_telemetry.
5. If the live anomaly is absent, the UI explicitly uses a controlled_simulation signal for a review-workflow demo. This does not modify OVS, port state, STP state, or telemetry. The AI reason explicitly says that the signal is simulated and states the real observed port states.
6. Review the proposed action and safety checks on /approvals. It is a human-reviewable proposal to block s1-p3. Approval does not execute it; execution remains a separate step and must revalidate the approval and current topology.

## Safety boundaries

- This Issue 2 button does not deliberately force both standby ports into FORWARD, disable STP, or create a broadcast loop.
- The real detector is telemetry-backed, but the demonstration fallback is explicitly a simulation, not proof that a live anomaly occurred.
- No network mutation is attempted when the Issue 2 proposal is created.
- Do not claim active-primary failover is implemented by this scenario.
- Proposals expire after five minutes and must be reviewed while valid.

## Useful checks

    cd "$NETOPS_HOME"
    curl -fsS http://127.0.0.1:8000/health
    $VIRTUAL_ENV/bin/python -m testbed.live_connectivity
    sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 'priority=65500' || true
    sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep 'priority=65500' || true

A healthy baseline should report connectivity_ok=true. Existing priority-65500 standby drop rules prevent creating a duplicate Issue 2 proposal; inspect/reconcile an existing action rather than deleting it blindly.
