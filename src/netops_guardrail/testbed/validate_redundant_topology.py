#!/usr/bin/env python3
"""
Integration test for the Ryu-controlled redundant Mininet topology.

Start the project's TelemetryController first, then run this file as root.
It refuses to start if existing s1/s2 OVS bridges are present, waits for STP
convergence, validates port roles, pings both hosts, and always tears down the
Mininet instance it created.
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from netops_guardrail.netops_paths import NETOPS_HOME
PROJECT_ROOT = NETOPS_HOME
from netops_guardrail.testbed.redundant_topo import RedundantTopo  # noqa: E402

TELEMETRY_PATH = PROJECT_ROOT / "telemetry/data/latest.json"
TRUNK_PORTS = {("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")}
ACCESS_PORTS = {("1", "1"), ("2", "3")}


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def read_states():
    try:
        with TELEMETRY_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    states = {}
    for switch_id, switch_data in data.get("switches", {}).items():
        for port_id, state in switch_data.get("stp_port_states", {}).items():
            states[(str(switch_id), str(port_id))] = state
    return states


def main():
    if os.geteuid() != 0:
        print("ERROR: run under sudo so Mininet can configure network namespaces.")
        return 2

    try:
        with socket.create_connection(("127.0.0.1", 6653), timeout=1):
            pass
    except OSError as exc:
        print(f"ERROR: Ryu is not listening on 127.0.0.1:6653: {exc}")
        return 2

    # Never take over a topology owned by another process.
    for bridge in ("s1", "s2"):
        result = run(["ovs-vsctl", "br-exists", bridge])
        if result.returncode == 0:
            print(f"ERROR: OVS bridge {bridge} already exists; refusing to touch it.")
            return 2

    setLogLevel("warning")
    net = Mininet(
        topo=RedundantTopo(),
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=False,
        build=True,
        waitConnected=True,
    )
    net.addController(
        "c0", controller=RemoteController,
        ip="127.0.0.1", port=6653,
    )

    try:
        print("Starting isolated two-switch, dual-trunk Mininet topology...")
        net.start()

        # The testbed config uses a 4-second forward delay; allow margin for
        # STP role election and controller telemetry flushes.
        states = {}
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            states = read_states()
            any_trunk_blocked = any(
                states.get(port) == "BLOCK" for port in TRUNK_PORTS
            )
            access_forwarding = all(
                states.get(port) == "FORWARD" for port in ACCESS_PORTS
            )
            if any_trunk_blocked and access_forwarding:
                break
            time.sleep(1)

        print("STP port states:")
        for port in sorted(TRUNK_PORTS | ACCESS_PORTS):
            print(f"  s{port[0]}-p{port[1]}: {states.get(port, 'UNKNOWN')}")

        blocked_trunks = [
            port for port in sorted(TRUNK_PORTS)
            if states.get(port) == "BLOCK"
        ]
        if not blocked_trunks:
            print("FAIL: STP did not block a redundant trunk within 30 seconds.")
            return 1
        if not all(states.get(port) == "FORWARD" for port in ACCESS_PORTS):
            print("FAIL: one or more host access ports did not reach FORWARD.")
            return 1

        print("Running host reachability test (pingall)...")
        loss = net.pingAll(timeout=2)
        print(f"Observed packet loss: {loss:.1f}%")
        if loss != 0:
            print("FAIL: hosts remain disconnected after STP convergence.")
            return 1

        print(f"PASS: host connectivity works with redundant trunks present; STP blocked {blocked_trunks}.")
        return 0
    finally:
        print("Stopping only the Mininet topology created by this test...")
        net.stop()


if __name__ == "__main__":
    sys.exit(main())
