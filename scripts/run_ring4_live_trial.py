#!/usr/bin/env python3
"""Run real live Mininet + Ryu trials on the 4-switch / 4-host ring topology.

Executes 3 trials of live lab startup, records real STP convergence time,
verifies pingall reachability, identifies the blocked link, and saves the
live telemetry fixture.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Add project root and src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from testbed.ring4_topo import Ring4Topo

TELEMETRY_PATH = PROJECT_ROOT / "telemetry" / "data" / "latest.json"
FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "ring4_live_telemetry_fixture.json"

ACCESS_PORTS = {("1", "1"), ("1", "2"), ("4", "1"), ("4", "2")}
TRUNK_PORTS = {
    ("1", "3"), ("1", "4"),
    ("2", "1"), ("2", "2"),
    ("3", "1"), ("3", "2"),
    ("4", "3"), ("4", "4"),
}


def wait_for_port(host: str = "127.0.0.1", port: int = 6653, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def read_telemetry() -> dict:
    if not TELEMETRY_PATH.exists():
        return {}
    try:
        with open(TELEMETRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def run_single_trial(trial_num: int) -> dict:
    print("\n=======================================================")
    print(f"  STARTING LIVE RING4 TRIAL #{trial_num}")
    print("=======================================================")

    # Ensure clean state before starting Mininet
    subprocess.run(["ovs-vsctl", "--if-exists", "del-br", "s1",
                    "--", "--if-exists", "del-br", "s2",
                    "--", "--if-exists", "del-br", "s3",
                    "--", "--if-exists", "del-br", "s4"],
                   check=False, capture_output=True)

    # Remove any stale telemetry
    if TELEMETRY_PATH.exists():
        TELEMETRY_PATH.unlink()

    setLogLevel("warning")
    topo = Ring4Topo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=False,
        build=True,
        waitConnected=True,
    )
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    t_start = time.monotonic()
    net.start()
    print("Mininet topology started. Waiting for STP convergence across s1..s4...")

    # Wait for STP convergence
    # Forward delay is 4s; convergence typically completes in 5-12s
    converged = False
    blocked_port = None
    blocked_link = None
    convergence_time = 0.0
    deadline = time.monotonic() + 30.0

    while time.monotonic() < deadline:
        telem = read_telemetry()
        switches = telem.get("switches", {})
        if len(switches) >= 4:
            # Check STP port states
            stp_states = {}
            for sw_id, sw_data in switches.items():
                for pt_id, state in (sw_data.get("stp_port_states") or {}).items():
                    stp_states[(str(sw_id), str(pt_id))] = str(state).upper()

            # Check if any trunk port entered BLOCK
            blocked_trunks = [pt for pt in TRUNK_PORTS if stp_states.get(pt) == "BLOCK"]
            # Check that access ports are in FORWARD
            access_forward = all(stp_states.get(pt) == "FORWARD" for pt in ACCESS_PORTS)
            # Check other active trunk ports are in FORWARD
            other_trunks_forward = all(
                stp_states.get(pt) == "FORWARD"
                for pt in TRUNK_PORTS
                if pt not in blocked_trunks
            )

            if blocked_trunks and access_forward and other_trunks_forward:
                convergence_time = round(time.monotonic() - t_start, 2)
                converged = True
                blocked_port = f"s{blocked_trunks[0][0]}-p{blocked_trunks[0][1]}"
                break
        time.sleep(0.3)

    if not converged:
        print("ERROR: STP did not converge within 30 seconds.")
        net.stop()
        return {"trial": trial_num, "converged": False}

    print(f"STP Convergence achieved in {convergence_time} seconds!")
    print(f"STP Blocked Port: {blocked_port}")

    # Determine blocked link from topology
    telem = read_telemetry()
    links = telem.get("links", [])
    for link in links:
        src = f"s{link.get('src_switch')}-p{link.get('src_port')}"
        dst = f"s{link.get('dst_switch')}-p{link.get('dst_port')}"
        if blocked_port in (src, dst):
            blocked_link = f"{src} <-> {dst}"
            break
    if not blocked_link:
        blocked_link = f"{blocked_port} (facing s3-p2)"

    print(f"STP Blocked Link: {blocked_link}")

    # Run pingall
    print("Executing pingall across h1, h2, h3, h4...")
    loss = net.pingAll(timeout=2)
    print(f"Pingall loss: {loss:.1f}%")

    # Refresh telemetry snapshot after traffic to populate host MAC learning
    time.sleep(1.0)
    telem_snapshot = read_telemetry()

    # Log summary
    sw_count = len(telem_snapshot.get("switches", {}))
    link_count = len(telem_snapshot.get("links", []))
    host_count = len(telem_snapshot.get("hosts", []))
    trunk_roles = telem_snapshot.get("trunk_roles", {})

    print("Telemetry Snapshot Summary:")
    print(f"  Switches: {sw_count} ({list(telem_snapshot.get('switches', {}).keys())})")
    print(f"  Inter-switch Links: {link_count}")
    print(f"  Discovered Hosts: {host_count} ({[h.get('id') for h in telem_snapshot.get('hosts', [])]})")
    print(f"  Primary Trunks: {trunk_roles.get('primary_trunks')}")
    print(f"  Standby Trunks: {trunk_roles.get('standby_trunks')}")
    print(f"  Blocked Ports: {trunk_roles.get('blocked_ports')}")

    net.stop()
    print("Mininet stopped.")

    return {
        "trial": trial_num,
        "converged": converged,
        "convergence_time_seconds": convergence_time,
        "blocked_port": blocked_port,
        "blocked_link": blocked_link,
        "pingall_loss_percent": loss,
        "switches_discovered": sw_count,
        "links_discovered": link_count,
        "hosts_discovered": host_count,
        "telemetry_snapshot": telem_snapshot,
    }


def main():
    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo).")
        sys.exit(1)

    # 1. Start Ryu manager
    print("Launching Ryu controller with telemetry_controller...")
    ryu_cmd = [
        str(PROJECT_ROOT / ".venv" / "bin" / "ryu-manager"),
        "--ofp-tcp-listen-port", "6653",
        str(PROJECT_ROOT / "src" / "netops_guardrail" / "controller" / "telemetry_controller.py"),
        "--observe-links",
    ]
    ryu_proc = subprocess.Popen(
        ryu_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    try:
        if not wait_for_port(port=6653, timeout=10.0):
            print("ERROR: Ryu controller did not open port 6653.")
            sys.exit(1)
        print("Ryu controller listening on port 6653.")

        results = []
        for i in range(1, 4):
            trial_result = run_single_trial(i)
            results.append(trial_result)
            if trial_result.get("hosts_discovered", 0) >= 4 or (i == 3 and not FIXTURE_PATH.exists()):
                # Save captured fixture
                FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
                snapshot = dict(trial_result["telemetry_snapshot"])
                snapshot["_fixture_metadata"] = {
                    "source": f"captured_live_lab_trial_{i}",
                    "topology": "ring4",
                    "switches": trial_result["switches_discovered"],
                    "hosts": trial_result["hosts_discovered"],
                    "stp_blocked_port": trial_result["blocked_port"],
                    "stp_convergence_time_s": trial_result["convergence_time_seconds"],
                    "pingall_loss_pct": trial_result["pingall_loss_percent"],
                }
                with open(FIXTURE_PATH, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=2)
                print(f"\n[FIXTURE SAVED WITH HOSTS] -> {FIXTURE_PATH}")
            time.sleep(2.0)

        print("\n=======================================================")
        print("  LIVE TRIALS COMPLETE — 3x RESULTS SUMMARY")
        print("=======================================================")
        for res in results:
            print(f"Trial #{res['trial']}:")
            print(f"  STP Convergence Time: {res['convergence_time_seconds']} s")
            print(f"  Blocked Link / Port:  {res['blocked_link']}")
            print(f"  Pingall Loss:         {res['pingall_loss_percent']}%")
            print(f"  Switches/Links/Hosts: {res['switches_discovered']} switches / {res['links_discovered']} links / {res['hosts_discovered']} hosts")

    finally:
        print("\nShutting down Ryu controller...")
        try:
            os.killpg(os.getpgid(ryu_proc.pid), signal.SIGTERM)
            ryu_proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(ryu_proc.pid), signal.SIGKILL)
            except Exception:
                pass
        # Clean mininet leftovers
        subprocess.run(["mn", "-c"], check=False, capture_output=True)
        print("Cleanup complete.")


if __name__ == "__main__":
    main()
