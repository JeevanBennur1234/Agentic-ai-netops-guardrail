#!/usr/bin/env python3
"""Test physical failover in an isolated three-switch ring and restore on failure."""
import json
import os
import socket
import subprocess
import time
from datetime import datetime, timezone

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo

from netops_guardrail.netops_paths import NETOPS_HOME

PROJECT_ROOT = NETOPS_HOME

class TriangleTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        # OpenFlow port map:
        # h1--s1-p1; s1-p2--s2-p1; s2-p2--s3-p1;
        # s3-p2--s1-p3; h2--s2-p3.
        # Hosts are attached to s1 and s2 so the failed s1-s2 trunk is the
        # direct path, and recovery must use s1-s3-s2 through the spare edge.
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)
        self.addLink(h2, s2)

TELEMETRY = PROJECT_ROOT / "telemetry/data/latest.json"
RESULT = PROJECT_ROOT / "experiments/results/live_triangle_failover_latest.json"
TRUNKS = [
    (("s1", "s1-eth2", ("1", "2")), ("s2", "s2-eth1", ("2", "1"))),
    (("s2", "s2-eth2", ("2", "2")), ("s3", "s3-eth1", ("3", "1"))),
    (("s3", "s3-eth2", ("3", "2")), ("s1", "s1-eth3", ("1", "3"))),
]
ACCESS = {("1", "1"), ("2", "3")}

def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)

def command_evidence(args):
    result = run(args)
    return {
        "command": args,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }

def states_from_telemetry():
    try:
        data = json.loads(TELEMETRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        (str(sw), str(port)): str(state).upper()
        for sw, item in data.get("switches", {}).items()
        for port, state in item.get("stp_port_states", {}).items()
    }

def pingall(net):
    return float(net.pingAll(timeout=1))

def port_state_report(states):
    return {f"s{sw}-p{port}": state for (sw, port), state in sorted(states.items())}

def main():
    if os.geteuid() != 0:
        print("ERROR: run this test as root.")
        return 2
    try:
        with socket.create_connection(("127.0.0.1", 6653), timeout=1):
            pass
    except OSError as exc:
        print(f"ERROR: Ryu is not listening on 127.0.0.1:6653: {exc}")
        return 2

    for bridge in ("s1", "s2", "s3"):
        if run(["ovs-vsctl", "br-exists", bridge]).returncode == 0:
            print(f"ERROR: OVS bridge {bridge} already exists; refusing to touch it.")
            return 2

    report = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "test": "three-switch ring active-path failure with host on opposite trunk endpoint",
        "failure_injection": "Mininet configLinkStatus interface link-down; emulated failure, not a physical cable unplug",
        "result": "FAIL",
        "rollback_recovered": False,
    }
    net = Mininet(topo=TriangleTopo(), controller=None, switch=OVSKernelSwitch,
                  autoSetMacs=True, autoStaticArp=False, build=True, waitConnected=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    started = False
    failed_trunk = None
    try:
        setLogLevel("warning")
        print("Starting isolated three-switch ring...")
        net.start()
        started = True

        deadline = time.monotonic() + 35
        states = {}
        while time.monotonic() < deadline:
            states = states_from_telemetry()
            access_forward = all(states.get(p) == "FORWARD" for p in ACCESS)
            any_blocked = any(states.get(p) == "BLOCK" for pair in TRUNKS for endpoint in pair for p in [endpoint[2]])
            if access_forward and any_blocked:
                break
            time.sleep(0.5)

        report["initial_stp_states"] = port_state_report(states)
        loss = pingall(net)
        report["baseline_ping_loss_percent"] = loss
        print("Initial STP state:", json.dumps(report["initial_stp_states"], sort_keys=True))
        print(f"Baseline pingall loss: {loss:.1f}%")
        if loss != 0.0:
            report["failure_reason"] = "Baseline pingall failed."
            return 1

        forwarding_links = []
        for end_a, end_b in TRUNKS:
            if states.get(end_a[2]) == "FORWARD" and states.get(end_b[2]) == "FORWARD":
                forwarding_links.append((end_a, end_b))
        if not forwarding_links:
            report["failure_reason"] = "No active trunk could be identified from observed STP state."
            return 1

        failed_trunk = forwarding_links[0]
        report["failed_trunk_interfaces"] = [failed_trunk[0][1], failed_trunk[1][1]]
        report["failed_trunk_ports"] = [list(failed_trunk[0][2]), list(failed_trunk[1][2])]
        print(f"Injecting emulated link-down on trunk: {failed_trunk[0][1]} <-> {failed_trunk[1][1]}")
        fail_time = time.monotonic()
        # Use Mininet's link status API so the Linux interfaces change state;
        # this is different from changing only the OpenFlow administrative flag.
        # The test still does not emulate removing a physical cable from hardware.
        net.configLinkStatus(failed_trunk[0][0], failed_trunk[1][0], "down")
        # Record both the Linux view and what OVS is exposing to OpenFlow.
        # This distinguishes an ineffective failure injection from a controller
        # or STP reconvergence defect without deleting ports or bypassing OVS.
        failed_interfaces = [failed_trunk[0][1], failed_trunk[1][1]]
        report["failure_injection_diagnostics"] = {
            "ovs_show_s1": command_evidence(["ovs-ofctl", "-O", "OpenFlow13", "show", "s1"]),
            "ovs_show_s2": command_evidence(["ovs-ofctl", "-O", "OpenFlow13", "show", "s2"]),
            "s1_link_state": command_evidence(["ovs-vsctl", "get", "Interface", failed_interfaces[0], "link_state"]),
            "s1_admin_state": command_evidence(["ovs-vsctl", "get", "Interface", failed_interfaces[0], "admin_state"]),
            "s2_link_state": command_evidence(["ovs-vsctl", "get", "Interface", failed_interfaces[1], "link_state"]),
            "s2_admin_state": command_evidence(["ovs-vsctl", "get", "Interface", failed_interfaces[1], "admin_state"]),
            "s1_linux_link": command_evidence(["ip", "-details", "link", "show", failed_interfaces[0]]),
            "s2_linux_link": command_evidence(["ip", "-details", "link", "show", failed_interfaces[1]]),
        }
        print("Failure injection diagnostics recorded for Linux, OVSDB and OpenFlow port state.")

        # The only initially-blocked physical edge should become the spare path.
        deadline = time.monotonic() + 30
        recovered = False
        post_states = {}
        post_loss = 100.0
        while time.monotonic() < deadline:
            post_states = states_from_telemetry()
            blocked_before = {
                port for port, state in states.items() if state == "BLOCK"
            }
            promoted = any(
                post_states.get(port) == "FORWARD" for port in blocked_before
            )
            access_forward = all(post_states.get(p) == "FORWARD" for p in ACCESS)
            if promoted and access_forward:
                post_loss = pingall(net)
                if post_loss == 0.0:
                    recovered = True
                    break
            time.sleep(0.5)

        report["failover_recovered"] = recovered
        report["failover_recovery_seconds"] = round(time.monotonic() - fail_time, 3) if recovered else None
        report["post_failure_stp_states"] = port_state_report(post_states)
        report["post_failure_ping_loss_percent"] = post_loss
        post_telemetry = json.loads(TELEMETRY.read_text(encoding="utf-8"))
        observed_port_status = {
            f"s{sw}-p{port}": details
            for sw, item in post_telemetry.get("switches", {}).items()
            for port, details in item.get("port_status", {}).items()
        }
        report["post_failure_openflow_port_status"] = observed_port_status
        failed_port_ids = {tuple(end[2]) for end in failed_trunk}
        seen_down = any(
            str(details.get("state", "")).upper() in {"DOWN", "MISSING"}
            and (key.split("-p")[0][1:], key.split("-p")[1]) in failed_port_ids
            for key, details in observed_port_status.items()
            if "-p" in key and isinstance(details, dict)
        )
        report["controller_observed_failed_port"] = seen_down
        if recovered:
            report["result"] = "PASS"
            print(f"PASS: ring failover recovered in {report['failover_recovery_seconds']:.3f}s.")
            return 0

        report["failure_reason"] = "Alternate ring edge did not become forwarding with 0% ping loss within 30 seconds."
        if not seen_down:
            report["failure_reason"] += " The controller telemetry did not record an OpenFlow port DOWN/MISSING event for the failed trunk."
        print("FAIL: ring failover did not recover; restoring original active link.")
        rollback_start = time.monotonic()
        net.configLinkStatus(failed_trunk[0][0], failed_trunk[1][0], "up")
        rollback_deadline = time.monotonic() + 25
        rollback_states = {}
        rollback_loss = 100.0
        rollback_ok = False
        while time.monotonic() < rollback_deadline:
            rollback_states = states_from_telemetry()
            trunk_forward = all(rollback_states.get(endpoint[2]) == "FORWARD"
                                for endpoint in failed_trunk)
            if trunk_forward:
                rollback_loss = pingall(net)
                if rollback_loss == 0.0:
                    rollback_ok = True
                    break
            time.sleep(0.5)
        report["rollback_recovered"] = rollback_ok
        report["rollback_recovery_seconds"] = round(time.monotonic() - rollback_start, 3)
        report["rollback_ping_loss_percent"] = rollback_loss
        report["rollback_stp_states"] = port_state_report(rollback_states)
        report["result"] = "FAILOVER_FAILED_ROLLBACK_PASS" if rollback_ok else "FAILOVER_FAILED_ROLLBACK_FAILED"
        print("Rollback:", "PASS" if rollback_ok else "FAIL")
        return 1
    except Exception as exc:
        report["failure_reason"] = f"{type(exc).__name__}: {exc}"
        print("FAIL:", report["failure_reason"])
        return 1
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        try:
            RESULT.parent.mkdir(parents=True, exist_ok=True)
            RESULT.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"Evidence written to {RESULT}")
        except OSError as exc:
            print(f"WARNING: unable to write evidence: {exc}")
        if started:
            print("Stopping only the Mininet topology created by this test.")
            net.stop()

if __name__ == "__main__":
    raise SystemExit(main())
