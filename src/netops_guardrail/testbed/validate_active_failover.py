#!/usr/bin/env python3
"""Validate STP recovery after a physical active-trunk failure in isolated Mininet."""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from netops_guardrail.netops_paths import NETOPS_HOME

PROJECT_ROOT = NETOPS_HOME
from netops_guardrail.testbed.redundant_topo import RedundantTopo

TELEMETRY_PATH = PROJECT_ROOT / "telemetry/data/latest.json"
RESULT_PATH = Path(os.environ.get("NETOPS_FAILOVER_RESULT_PATH", str(PROJECT_ROOT / "experiments/results/live_active_failover_latest.json")))
TRUNK_PORTS = {("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")}
ACCESS_PORTS = {("1", "1"), ("2", "3")}
ACTIVE_TRUNK = (("s1", "s1-eth2", "1", "2"), ("s2", "s2-eth1", "2", "1"))
FAILOVER_TRUNK_STATES = {("1", "3"), ("2", "2")}


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def read_telemetry():
    try:
        with TELEMETRY_PATH.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def state_map(telemetry):
    return {
        (str(switch_id), str(port_id)): str(state).upper()
        for switch_id, data in telemetry.get("switches", {}).items()
        for port_id, state in data.get("stp_port_states", {}).items()
    }


def pingall(net):
    return float(net.pingAll(timeout=1))


def log_event(report, name, started_at, **details):
    item = {
        "event": name,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "elapsed_seconds": round(time.monotonic() - started_at, 3),
        **details,
    }
    report.setdefault("events", []).append(item)
    print(json.dumps(item, sort_keys=True), flush=True)


def main():
    if os.geteuid() != 0:
        print("ERROR: run this test as root so Mininet can configure namespaces.")
        return 2
    try:
        with socket.create_connection(("127.0.0.1", 6653), timeout=1):
            pass
    except OSError as exc:
        print(f"ERROR: Ryu is not listening at 127.0.0.1:6653: {exc}")
        return 2

    for bridge in ("s1", "s2"):
        if run(["ovs-vsctl", "br-exists", bridge]).returncode == 0:
            print(f"ERROR: OVS bridge {bridge} already exists; refusing to touch it.")
            return 2

    commit_result = run(["git", "-C", str(PROJECT_ROOT), "rev-parse", "HEAD"])
    report = {
        "metadata": {
            "date": datetime.now().astimezone().isoformat(timespec="seconds"),
            "commit_hash": commit_result.stdout.strip() or "unknown",
            "model_name": "none (live OVS/Mininet experiment)",
            "command": os.environ.get("NETOPS_EXPERIMENT_COMMAND", " ".join(sys.argv)),
            "observation_window_seconds": float(os.environ.get("NETOPS_FAILOVER_OBSERVATION_SECONDS", "90")),
            "testbed": "LIVE Mininet + OVS + Ryu",
        },
        "events": [],
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "test": "Mininet-emulated active-trunk link failure and STP failover",
        "active_trunk_interfaces": ["s1-eth2", "s2-eth1"],
        "result": "FAIL",
    }
    net = Mininet(
        topo=RedundantTopo(),
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=False,
        build=True,
        waitConnected=True,
    )
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    started = False

    try:
        setLogLevel("warning")
        print("Starting isolated dual-trunk Mininet topology...")
        net.start()
        started = True

        # Wait for fresh STP events from this Mininet instance. Datapath IDs
        # are reused between trials, so a timestamp alone is insufficient:
        # the controller also clears per-switch STP state on reconnect.
        topology_started_at = datetime.now(timezone.utc)
        deadline = time.monotonic() + 60
        initial_states = {}
        telemetry_fresh = False
        baseline_successes = 0
        baseline_attempts = 0
        baseline_loss = 100.0
        required_baseline_successes = 3

        while time.monotonic() < deadline:
            telemetry = read_telemetry()
            updated_at = telemetry.get("updated_at_utc")
            try:
                telemetry_time = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                telemetry_fresh = telemetry_time > topology_started_at
            except (AttributeError, TypeError, ValueError):
                telemetry_fresh = False

            initial_states = state_map(telemetry)
            all_stp_ports_reported = all(
                port in initial_states
                for port in {
                    ("1", "1"), ("1", "2"), ("1", "3"),
                    ("2", "1"), ("2", "2"), ("2", "3"),
                }
            )
            access_forwarding = all(
                initial_states.get(port) == "FORWARD" for port in ACCESS_PORTS
            )
            active_trunk_forwarding = all(
                initial_states.get(port) == "FORWARD"
                for port in {("1", "2"), ("2", "1")}
            )
            standby_trunk_blocked = any(
                initial_states.get(port) == "BLOCK"
                for port in {("1", "3"), ("2", "2")}
            )
            topology_converged = (
                telemetry_fresh
                and all_stp_ports_reported
                and access_forwarding
                and active_trunk_forwarding
                and standby_trunk_blocked
            )

            if topology_converged:
                baseline_loss = pingall(net)
                baseline_attempts += 1
                if baseline_loss == 0.0:
                    baseline_successes += 1
                else:
                    baseline_successes = 0
                print(
                    f"Baseline probe {baseline_attempts}: "
                    f"loss={baseline_loss:.1f}%, "
                    f"consecutive_successes={baseline_successes}/{required_baseline_successes}"
                )
                if baseline_successes >= required_baseline_successes:
                    break
            else:
                baseline_successes = 0
            time.sleep(1.0)

        report["initial_stp_states"] = {
            f"s{switch}-p{port}": state for (switch, port), state in sorted(initial_states.items())
        }
        report["baseline_ping_loss_percent"] = baseline_loss
        report["baseline_ping_attempts"] = baseline_attempts
        report["baseline_consecutive_successes"] = baseline_successes
        print(
            f"Baseline final pingall loss: {baseline_loss:.1f}% "
            f"({baseline_successes}/{required_baseline_successes} consecutive clean probes)"
        )
        if baseline_successes < required_baseline_successes:
            report["result"] = "INCONCLUSIVE"
            report["failure_reason"] = (
                "Fresh topology did not reach stable baseline: expected fresh STP state "
                "with access ports and trunk A forwarding, standby trunk blocked, and "
                f"{required_baseline_successes} consecutive 0%-loss pingall probes "
                f"within 60 seconds (telemetry_fresh={telemetry_fresh}, "
                f"baseline_attempts={baseline_attempts})."
            )
            return 1

        # Use the same OpenFlow administrative port shutdown validated
        # interactively against this Ryu/STP build. This is an emulated
        # port-failure test, not a physical cable-unplug test.
        started_at = time.monotonic()
        log_event(
            report,
            "link_down_command_started",
            started_at,
            interfaces=["s1-eth2", "s2-eth1"],
            injection_method="OpenFlow 1.3 mod-port down (administrative port failure)",
        )
        for switch_name, _intf_name, _switch_id, port_id in ACTIVE_TRUNK:
            result = run([
                "ovs-ofctl", "-O", "OpenFlow13", "mod-port",
                switch_name, port_id, "down",
            ])
            if result.returncode != 0:
                report["result"] = "INCONCLUSIVE"
                report["failure_reason"] = (
                    f"OpenFlow port shutdown failed for {switch_name} port {port_id}: "
                    f"{result.stderr.strip()}"
                )
                return 1
        log_event(
            report,
            "link_down",
            started_at,
            interfaces=["s1-eth2", "s2-eth1"],
            injection_method="OpenFlow 1.3 mod-port down (administrative port failure)",
        )
        print("Injected administrative port failure on trunk A (s1-eth2 <-> s2-eth1).")

        observation_seconds = float(os.environ.get("NETOPS_FAILOVER_OBSERVATION_SECONDS", "90"))
        deadline = time.monotonic() + observation_seconds
        recovered = False
        recovery_time_seconds = None
        recovery_loss = 100.0
        recovered_states = {}
        previous_states = dict(initial_states)
        first_ping_failure_seen = False
        first_ping_success_seen = False
        post_recovery_loss_samples = 0
        ping_samples = 0
        seen_port_down = set()
        while time.monotonic() < deadline:
            telemetry = read_telemetry()
            recovered_states = state_map(telemetry)
            telemetry_updated = telemetry.get("updated_at_utc")
            for port, state in sorted(recovered_states.items()):
                old_state = previous_states.get(port)
                if old_state != state:
                    log_event(report, "stp_port_state_change", started_at, switch=port[0], port=port[1], previous_state=old_state, new_state=state, telemetry_updated_at_utc=telemetry_updated)
            previous_states = dict(recovered_states)
            for switch_id, port_id in (("1", "2"), ("2", "1")):
                status = telemetry.get("switches", {}).get(switch_id, {}).get("port_status", {}).get(port_id, {})
                if status and (status.get("state") in {"DOWN", "MISSING"} or status.get("link_down") or status.get("admin_down")):
                    key = (switch_id, port_id, status.get("state"), status.get("reason"))
                    if key not in seen_port_down:
                        seen_port_down.add(key)
                        log_event(report, "of_port_down_event_observed", started_at, switch=switch_id, port=port_id, port_status=status, telemetry_updated_at_utc=telemetry_updated)
            recovery_loss = pingall(net)
            ping_samples += 1
            if recovery_loss > 0.0 and not first_ping_failure_seen:
                first_ping_failure_seen = True
                log_event(report, "first_ping_failure", started_at, ping_loss_percent=recovery_loss, since_link_down_seconds=round(time.monotonic() - started_at, 3))
            elif recovery_loss == 0.0 and not first_ping_success_seen:
                first_ping_success_seen = True
                success_event = "first_ping_success_after_failure" if first_ping_failure_seen else "first_ping_success_after_link_down"
                log_event(report, success_event, started_at, ping_loss_percent=recovery_loss, after_observed_failure=first_ping_failure_seen, since_link_down_seconds=round(time.monotonic() - started_at, 3))
            alt_forward = all(recovered_states.get(port) == "FORWARD" for port in FAILOVER_TRUNK_STATES)
            if alt_forward and recovery_loss == 0.0 and not recovered:
                recovered = True
                recovery_time_seconds = round(time.monotonic() - started_at, 3)
                log_event(report, "validated_recovery", started_at, since_link_down_seconds=recovery_time_seconds)
            elif recovered and recovery_loss > 0.0:
                post_recovery_loss_samples += 1
                if post_recovery_loss_samples == 1:
                    log_event(report, "packet_loss_after_recovery", started_at, ping_loss_percent=recovery_loss, since_link_down_seconds=round(time.monotonic() - started_at, 3))
            time.sleep(0.5)

        report["failover_recovered"] = recovered
        report["failover_recovery_time_seconds"] = recovery_time_seconds
        report["post_failure_ping_loss_percent"] = recovery_loss
        report["observation_window_ping_samples"] = ping_samples
        report["post_recovery_nonzero_loss_samples"] = post_recovery_loss_samples
        report["post_failure_stp_states"] = {
            f"s{switch}-p{port}": state for (switch, port), state in sorted(recovered_states.items())
        }
        stable_through_window = recovered and post_recovery_loss_samples == 0
        if stable_through_window:
            report["result"] = "PASS"
            print(f"PASS: backup path recovered in {recovery_time_seconds:.3f}s and remained loss-free for the {observation_seconds:.0f}s observation window ({ping_samples} ping samples).")
            return 0

        if recovered:
            report["failover_failure_reason"] = (
                f"Backup path recovered in {recovery_time_seconds:.3f}s but packet loss recurred "
                f"during the {observation_seconds:g}-second observation window."
            )
        else:
            report["failover_failure_reason"] = (
                f"STP did not converge the alternate trunk to FORWARD with 0% pingall loss "
                f"within {observation_seconds:g} seconds after the administrative port failure."
            )
        log_event(report, "observation_window_expired", started_at, observation_seconds=observation_seconds)
        print("FAIL: STP failover was not demonstrated; attempting explicit rollback by restoring trunk A.")

        rollback_started = time.monotonic()
        log_event(report, "rollback_started", started_at, interfaces=["s1 port 2", "s2 port 1"])
        for switch_name, _intf_name, _switch_id, port_id in ACTIVE_TRUNK:
            result = run([
                "ovs-ofctl", "-O", "OpenFlow13", "mod-port",
                switch_name, port_id, "up",
            ])
            log_event(
                report,
                "rollback_mod_port_up",
                started_at,
                switch=switch_name,
                port=port_id,
                returncode=result.returncode,
                stderr=result.stderr.strip(),
            )

        rollback_deadline = time.monotonic() + 20
        rollback_recovered = False
        rollback_loss = 100.0
        rollback_states = {}
        while time.monotonic() < rollback_deadline:
            rollback_states = state_map(read_telemetry())
            trunk_a_forward = all(
                rollback_states.get(port) == "FORWARD"
                for port in {("1", "2"), ("2", "1")}
            )
            if trunk_a_forward:
                rollback_loss = pingall(net)
                if rollback_loss == 0.0:
                    rollback_recovered = True
                    log_event(report, "rollback_connectivity_restored", started_at, ping_loss_percent=rollback_loss)
                    break
            time.sleep(0.5)

        report["rollback_recovered"] = rollback_recovered
        report["rollback_recovery_time_seconds"] = round(time.monotonic() - rollback_started, 3)
        report["rollback_ping_loss_percent"] = rollback_loss
        report["rollback_stp_states"] = {
            f"s{switch}-p{port}": state for (switch, port), state in sorted(rollback_states.items())
        }
        report["result"] = "FAILOVER_FAILED_ROLLBACK_PASS" if rollback_recovered else "FAILOVER_FAILED_ROLLBACK_FAILED"
        if rollback_recovered:
            print(f"PASS: rollback restored host reachability in {report['rollback_recovery_time_seconds']:.3f}s.")
        else:
            print("CRITICAL FAIL: failover failed and restoring the original trunk did not restore host reachability.")
        return 1

    except Exception as exc:
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
        print(f"FAIL: {report['failure_reason']}")
        return 1
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        try:
            RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
            RESULT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"Live failover evidence: {RESULT_PATH}")
        except OSError as exc:
            print(f"WARNING: could not write evidence JSON: {exc}")
        if started:
            print("Stopping only the Mininet topology created by this test...")
            net.stop()


if __name__ == "__main__":
    sys.exit(main())
