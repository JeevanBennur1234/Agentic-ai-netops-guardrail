#!/usr/bin/env python3
"""Measure one real OVS executor transaction on the isolated Mininet testbed."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.controller.human_verifier import HumanApprovalStore
from netops_guardrail.executor.remediation_executor import RemediationExecutor
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.testbed.redundant_topo import RedundantTopo
from netops_guardrail.testbed.validate_trunk_remediation import (
    ACCESS_PORTS,
    EXPECTED_LINKS,
    TRUNK_PORTS,
    dump_flows,
    observed_trunk_links,
    priority_65500_rules,
    read_telemetry,
    state_map,
)
from netops_guardrail.verifier.safety_verifier import build_topology

ROOT = NETOPS_HOME
TELEMETRY_PATH = ROOT / "telemetry/data/latest.json"

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    date = datetime.now().astimezone().isoformat(timespec="seconds")
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown"
    command = os.environ.get("NETOPS_EXPERIMENT_COMMAND", " ".join(sys.argv))
    report = {
        "metadata": {
            "date": date,
            "commit_hash": commit,
            "model_name": "none-live-OVS-Mininet-with-synthetic-test-approval",
            "command": command,
            "testbed": "LIVE Mininet + Open vSwitch + Ryu",
            "measurement_scope": "executor.execute wall-clock duration including live OVS mutation, verification, and live connectivity check; excludes topology startup and synthetic approval preparation",
        },
        "result": "INCONCLUSIVE",
        "reason": None,
        "baseline_ping_loss_percent": None,
        "gate_result": None,
        "execution_result": None,
        "latency_ms": None,
        "postconditions": {},
        "test_approval_method": "synthetic approval record prepared before latency timer; no human interaction latency included",
    }
    bridges = run(["ovs-vsctl", "list-br"])
    if bridges.returncode != 0:
        report["reason"] = f"could not inspect OVS bridges: {bridges.stderr.strip()}"
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2
    if any(name in {"s1", "s2"} for name in bridges.stdout.split()):
        report["reason"] = "refusing to run because pre-existing s1/s2 bridges were found"
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2

    setLogLevel("warning")
    net = Mininet(
        topo=RedundantTopo(), controller=None, switch=OVSKernelSwitch,
        autoSetMacs=True, autoStaticArp=False, build=True, waitConnected=True,
    )
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    approval_tmp = None
    try:
        net.start()
        deadline = time.monotonic() + 35
        telemetry, states, links = {}, {}, set()
        while time.monotonic() < deadline:
            telemetry = read_telemetry()
            states = state_map(telemetry)
            links = observed_trunk_links(telemetry)
            blocked = any(states.get(port) == "BLOCK" for port in TRUNK_PORTS)
            access_ok = all(states.get(port) == "FORWARD" for port in ACCESS_PORTS)
            if blocked and access_ok and EXPECTED_LINKS.issubset(links):
                break
            time.sleep(1)
        report["initial_stp_states"] = {f"s{sw}-p{port}": state for (sw, port), state in states.items()}
        report["discovered_trunk_links"] = sorted([list(link) for link in links])
        if not EXPECTED_LINKS.issubset(links) or not any(states.get(port) == "BLOCK" for port in TRUNK_PORTS) or not all(states.get(port) == "FORWARD" for port in ACCESS_PORTS):
            report["reason"] = "baseline STP/LLDP preconditions were not satisfied before the latency transaction"
            return 2
        baseline_loss = net.pingAll(timeout=2)
        report["baseline_ping_loss_percent"] = baseline_loss
        if baseline_loss != 0:
            report["reason"] = f"baseline pingall loss was {baseline_loss:.1f}%; no mutation attempted"
            return 2

        telemetry = read_telemetry()
        graph = build_topology(telemetry)
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "P2 latency measurement: block the STP-blocked redundant trunk while preserving host reachability",
        }
        gate = apply_intent_to_graph(graph, intent)
        report["gate_result"] = gate
        if gate.get("safe") is not True:
            report["reason"] = "safety gate rejected the standby-trunk intent; no mutation attempted"
            return 2

        required_hosts = ["s1-p1", "s2-p3"]
        post_graph = graph.copy()
        target_node = "s1-p3"
        if target_node not in post_graph:
            report["reason"] = "standby trunk node missing from the live telemetry graph"
            return 2
        post_graph.remove_node(target_node)
        def topology_provider(phase="pre"):
            return (post_graph if phase == "post" else graph, required_hosts)

        approval_tmp = tempfile.TemporaryDirectory(prefix="netops-p2-latency-approval-")
        approval_store = HumanApprovalStore(path=str(Path(approval_tmp.name) / "approvals.json"))
        proposal = approval_store.create_proposal(intent, gate, str(TELEMETRY_PATH), requested_by="p2-live-ovs-latency-test")
        approval_store.decide(
            proposal["proposal_id"], "approve", approver_id="p2-test-operator",
            reason="Synthetic test approval for isolated live OVS latency measurement",
            proposal_fingerprint_value=proposal["proposal_fingerprint"],
        )
        executor = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            topology_provider=topology_provider,
            connectivity_checker=lambda: net.pingAll(timeout=2) == 0,
            approval_store=approval_store,
        )
        started = time.perf_counter()
        execution = executor.execute(intent, "APPROVED", gate, approval_id=proposal["proposal_id"])
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        report["latency_ms"] = elapsed_ms
        report["execution_result"] = execution
        s1_rules = priority_65500_rules(dump_flows("s1"))
        s2_rules = priority_65500_rules(dump_flows("s2"))
        flow_s1 = any("in_port=3" in line and "actions=drop" in line for line in s1_rules)
        flow_s2 = any("in_port=2" in line and "actions=drop" in line for line in s2_rules)
        post_loss = net.pingAll(timeout=2)
        report["postconditions"] = {
            "executor_success": execution.get("success") is True,
            "change_verified": execution.get("change_verified") is True,
            "safety_verified": execution.get("safety_verified") is True,
            "connectivity_verified": execution.get("connectivity_verified") is True,
            "drop_rule_s1_p3_present": flow_s1,
            "drop_rule_s2_p2_present": flow_s2,
            "post_transaction_ping_loss_percent": post_loss,
        }
        all_pass = (
            report["postconditions"]["executor_success"]
            and report["postconditions"]["change_verified"]
            and report["postconditions"]["safety_verified"]
            and report["postconditions"]["connectivity_verified"]
            and flow_s1 and flow_s2 and post_loss == 0
        )
        report["result"] = "PASS" if all_pass else "FAIL"
        if not all_pass:
            report["reason"] = "executor transaction or one or more live OVS postconditions failed"
        return 0 if all_pass else 1
    except Exception as exc:
        report["result"] = "INCONCLUSIVE"
        report["reason"] = f"{type(exc).__name__}: {exc}"
        return 2
    finally:
        try:
            net.stop()
        finally:
            if approval_tmp is not None:
                approval_tmp.cleanup()
            output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            csv_path = output_path.with_suffix(".csv")
            import csv
            fields = ["date", "commit_hash", "model_name", "command", "result", "latency_ms", "baseline_ping_loss_percent", "reason", "test_approval_method", "postconditions_json"]
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                w.writerow({
                    "date": date, "commit_hash": commit, "model_name": report["metadata"]["model_name"],
                    "command": command, "result": report["result"], "latency_ms": report["latency_ms"],
                    "baseline_ping_loss_percent": report["baseline_ping_loss_percent"], "reason": report["reason"],
                    "test_approval_method": report["test_approval_method"],
                    "postconditions_json": json.dumps(report["postconditions"], sort_keys=True),
                })

if __name__ == "__main__":
    raise SystemExit(main())
