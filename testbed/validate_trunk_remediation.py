#!/usr/bin/env python3
"""
End-to-end safety integration test for trunk isolation on the live Mininet lab.

Requirements:
  1. Run controller/telemetry_controller.py with the project venv's ryu-manager.
  2. Run this script with sudo.
  3. It refuses to touch pre-existing s1/s2 bridges and cleans up only the
     Mininet instance created here.

The test checks discovered physical links, baseline host reachability, STP
state, two-ended trunk blocking, post-change pingall, access-port rejection,
and audit-chain integrity.
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from netops_paths import NETOPS_HOME
# Mininet may run under system Python while application dependencies live in
# the active virtualenv (or the repository-local .venv used by the quickstart).
VENV_ROOT = Path(os.environ.get("VIRTUAL_ENV", str(NETOPS_HOME / ".venv")))
VENV_SITE = (
    VENV_ROOT / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages"
)
if VENV_SITE.exists():
    sys.path.insert(0, str(VENV_SITE))
from testbed.redundant_topo import RedundantTopo  # noqa: E402
sys.path.insert(0, str(PROJECT_ROOT / "controller"))
sys.path.insert(0, str(PROJECT_ROOT / "verifier"))
sys.path.insert(0, str(PROJECT_ROOT / "executor"))
sys.path.insert(0, str(PROJECT_ROOT / "audit"))
from decision_gate import apply_intent_to_graph  # noqa: E402
from remediation_executor import RemediationExecutor  # noqa: E402
from safety_verifier import build_topology  # noqa: E402
from audit_trail import AuditTrail  # noqa: E402

TELEMETRY_PATH = PROJECT_ROOT / "telemetry/data/latest.json"
TRUNK_PORTS = {("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")}
ACCESS_PORTS = {("1", "1"), ("2", "3")}
EXPECTED_LINKS = {
    tuple(sorted(("s1-p2", "s2-p1"))),
    tuple(sorted(("s1-p3", "s2-p2"))),
}


def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)


def read_telemetry():
    try:
        with TELEMETRY_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def state_map(telemetry):
    states = {}
    for sw, data in telemetry.get("switches", {}).items():
        for port, state in data.get("stp_port_states", {}).items():
            states[(str(sw), str(port))] = state
    return states


def observed_trunk_links(telemetry):
    links = set()
    for entry in telemetry.get("links", []):
        try:
            left = f"s{str(entry['src_switch'])}-p{str(entry['src_port'])}"
            right = f"s{str(entry['dst_switch'])}-p{str(entry['dst_port'])}"
        except (KeyError, TypeError):
            continue
        links.add(tuple(sorted((left, right))))
    return links


def dump_flows(bridge):
    result = run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge])
    if result.returncode != 0:
        raise RuntimeError(f"Could not read flow table for {bridge}: {result.stderr}")
    return result.stdout


def priority_65500_rules(output):
    # Ignore volatile duration and packet/byte counters; compare stable rules.
    rules = []
    for line in output.splitlines():
        if "priority=65500" not in line or "actions=" not in line:
            continue
        cookie = re.search(r"\bcookie=0x([0-9a-f]+)\b", line, re.IGNORECASE)
        in_port = re.search(r"\bin_port=(\d+)\b", line)
        action = line.split("actions=", 1)[1].strip().split()[0]
        if cookie and in_port:
            rules.append(
                f"cookie=0x{cookie.group(1).lower()},priority=65500,"
                f"in_port={in_port.group(1)},actions={action}"
            )
    return sorted(rules)


def main():
    if os.geteuid() != 0:
        print("ERROR: run this test with sudo.")
        return 2

    try:
        with socket.create_connection(("127.0.0.1", 6653), timeout=1):
            pass
    except OSError as exc:
        print(f"ERROR: Ryu is not listening at 127.0.0.1:6653: {exc}")
        return 2

    # Never take ownership of a lab already running on the user's machine.
    for bridge in ("s1", "s2"):
        if run(["ovs-vsctl", "br-exists", bridge]).returncode == 0:
            print(f"ERROR: existing OVS bridge {bridge}; refusing to modify it.")
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
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    try:
        print("Starting redundant topology and waiting for STP...")
        net.start()

        deadline = time.monotonic() + 35
        telemetry = {}
        states = {}
        links = set()
        while time.monotonic() < deadline:
            telemetry = read_telemetry()
            states = state_map(telemetry)
            links = observed_trunk_links(telemetry)
            blocked = any(states.get(p) == "BLOCK" for p in TRUNK_PORTS)
            access_ok = all(states.get(p) == "FORWARD" for p in ACCESS_PORTS)
            if blocked and access_ok and EXPECTED_LINKS.issubset(links):
                break
            time.sleep(1)

        print("STP states:")
        for port in sorted(TRUNK_PORTS | ACCESS_PORTS):
            print(f"  s{port[0]}-p{port[1]}: {states.get(port, 'UNKNOWN')}")
        print(f"Discovered trunk links: {sorted(links)}")

        if not EXPECTED_LINKS.issubset(links):
            print("FAIL: live LLDP discovery did not report both expected redundant trunks.")
            return 1
        if not any(states.get(p) == "BLOCK" for p in TRUNK_PORTS):
            print("FAIL: STP did not block a redundant trunk.")
            return 1
        if not all(states.get(p) == "FORWARD" for p in ACCESS_PORTS):
            print("FAIL: a host-facing port did not reach FORWARD.")
            return 1

        baseline_loss = net.pingAll(timeout=2)
        print(f"Baseline pingall loss: {baseline_loss:.1f}%")
        if baseline_loss != 0:
            print("FAIL: baseline host reachability must pass before remediation.")
            return 1

        # Consume the live-discovered topology rather than a hand-written graph.
        telemetry = read_telemetry()
        graph = build_topology(telemetry)
        required_hosts = ["s1-p1", "s2-p3"]
        target_node = "s1-p3"  # redundant trunk B, peer s2-p2 (STP-blocked side)
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "isolate redundant trunk B while preserving host reachability",
        }
        verifier_result = apply_intent_to_graph(graph, intent)
        decision = "APPROVED" if verifier_result.get("safe") else "REJECTED"
        if decision != "APPROVED":
            print("FAIL: safety gate did not approve the redundant trunk simulation.")
            print(json.dumps(verifier_result, indent=2))
            return 1

        post_graph = graph.copy()
        post_graph.remove_node(target_node)

        def topology_provider(phase="pre"):
            return (post_graph if phase == "post" else graph, required_hosts)

        executor = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            topology_provider=topology_provider,
            connectivity_checker=lambda: net.pingAll(timeout=2) == 0,
        )
        execution = executor.execute(intent, decision, verifier_result)
        print("Trunk remediation result:")
        print(json.dumps(execution, indent=2))

        if not (
            execution.get("success") is True
            and execution.get("change_verified") is True
            and execution.get("safety_verified") is True
            and execution.get("connectivity_verified") is True
            and execution.get("target_ports") == [(1, 3), (2, 2)]
        ):
            print("FAIL: trunk transaction did not pass all postconditions.")
            return 1

        s1_rules = priority_65500_rules(dump_flows("s1"))
        s2_rules = priority_65500_rules(dump_flows("s2"))
        if not any("in_port=3" in line and "actions=drop" in line for line in s1_rules):
            print("FAIL: no verified drop rule on s1-p3.")
            return 1
        if not any("in_port=2" in line and "actions=drop" in line for line in s2_rules):
            print("FAIL: no verified drop rule on s2-p2.")
            return 1

        # The currently forwarding trunk must be rejected when its only
        # alternate physical trunk is STP-blocked. Exercise both the gate and
        # a forged APPROVED decision presented directly to the executor.
        active_trunk_intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "test unsafe active-trunk isolation while alternate is STP-blocked",
        }
        active_gate_result = apply_intent_to_graph(graph, active_trunk_intent)
        if active_gate_result.get("safe") is not False:
            print("FAIL: safety gate did not reject active-trunk block with STP-blocked alternate.")
            print(json.dumps(active_gate_result, indent=2))
            return 1

        before_active_rules = {
            "s1": priority_65500_rules(dump_flows("s1")),
            "s2": priority_65500_rules(dump_flows("s2")),
        }
        active_bypass_result = executor.execute(
            active_trunk_intent, "APPROVED", {"safe": True}
        )
        after_active_rules = {
            "s1": priority_65500_rules(dump_flows("s1")),
            "s2": priority_65500_rules(dump_flows("s2")),
        }
        if active_bypass_result.get("success") is not False:
            print("FAIL: executor accepted forged approval for active-trunk block.")
            print(json.dumps(active_bypass_result, indent=2))
            return 1
        if before_active_rules != after_active_rules:
            print("FAIL: active-trunk rejection unexpectedly changed OVS flows.")
            return 1
        if net.pingAll(timeout=2) != 0:
            print("FAIL: connectivity changed while active-trunk action was rejected.")
            return 1
        print("PASS: active-trunk block rejected by gate and executor without flow changes; connectivity remained intact.")

        # The gate should reject an access-port block; the executor must also
        # reject a forged APPROVED decision, and neither attempt may add a rule.
        access_intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "1",
            "reason": "test access-port isolation rejection",
        }
        gate_result = apply_intent_to_graph(graph, access_intent)
        if gate_result.get("safe") is not False:
            print("FAIL: decision gate did not reject the access-port block.")
            return 1

        before_access_rules = {
            "s1": priority_65500_rules(dump_flows("s1")),
            "s2": priority_65500_rules(dump_flows("s2")),
        }
        bypass_result = executor.execute(access_intent, "APPROVED", {"safe": True})
        after_access_rules = {
            "s1": priority_65500_rules(dump_flows("s1")),
            "s2": priority_65500_rules(dump_flows("s2")),
        }
        if bypass_result.get("success") is not False or "access endpoint" not in bypass_result.get("error", ""):
            print("FAIL: executor did not independently reject the access-port block.")
            print(json.dumps(bypass_result, indent=2))
            return 1
        if before_access_rules != after_access_rules:
            print("FAIL: access-port rejection unexpectedly changed OVS flows.")
            return 1

        with tempfile.TemporaryDirectory(prefix="netops-live-audit-") as tmp:
            trail = AuditTrail(
                log_path=str(Path(tmp) / "audit.json"),
                key_path=str(Path(tmp) / "audit_key.pem"),
                auto_load=False,
            )
            trail.record_decision(
                decision=decision,
                intent=intent,
                verifier_result=verifier_result,
                execution_result=execution,
            )
            trail.record_decision(
                decision="REJECTED",
                intent=access_intent,
                verifier_result=gate_result,
                execution_result=bypass_result,
            )
            audit_valid, audit_message = trail.verify_chain(trail.chain)
            print(f"Audit check: {audit_message}")
            if not audit_valid:
                print("FAIL: audit chain did not verify.")
                return 1

        print("PASS: trunk blocked at both ends, live pingall stayed at 0% loss, and access-port block was rejected without flow changes.")
        return 0
    finally:
        print("Stopping the temporary Mininet topology...")
        net.stop()


if __name__ == "__main__":
    sys.exit(main())
