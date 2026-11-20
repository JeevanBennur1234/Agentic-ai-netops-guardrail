#!/usr/bin/env python3
"""Live Phase 2 fault trials for the isolated Mininet/OVS lab."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from netops_guardrail.faults.flow_rule_drift import FlowRuleDriftFault
from netops_guardrail.faults.link_flapping import LinkFlappingFault
from netops_guardrail.faults.mac_flooding import MacFloodingFault
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.testbed.redundant_topo import RedundantTopo

ROOT = Path(NETOPS_HOME)
TELEMETRY = ROOT / "telemetry/data/latest.json"
RESULTS = ROOT / "experiments/results"
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
RAW = RESULTS / f"{RUN_ID}_phase2_live_faults.json"
TXT = RESULTS / f"{RUN_ID}_phase2_live_faults.txt"
COMMANDS = []

def now():
    return datetime.now(timezone.utc).isoformat()

def run_cmd(command, **kwargs):
    command = list(command)
    if len(command) >= 2 and command[0] == "sudo" and command[1] == "-n":
        command = command[2:]
    p = subprocess.run(command, **kwargs)
    COMMANDS.append({"at": now(), "command": command, "returncode": p.returncode,
                    "stdout": p.stdout, "stderr": p.stderr})
    return p

def telemetry():
    try:
        return json.loads(TELEMETRY.read_text())
    except (OSError, json.JSONDecodeError):
        return {}

def wait_for(fn, timeout=18, label="condition"):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = fn()
        if last:
            return last
        time.sleep(.4)
    raise RuntimeError(f"Timed out waiting for {label}: {last!r}")

def ping(net):
    loss = float(net.pingAll(timeout=2))
    return {"loss_percent": loss, "passed": loss == 0.0}

def dump_flows(bridge):
    p = run_cmd(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge],
                capture_output=True, text=True, check=False, timeout=5)
    if p.returncode:
        raise RuntimeError(f"dump-flows {bridge} failed: {p.stderr}")
    return p.stdout

def flow_present():
    return f"cookie=0x{FlowRuleDriftFault.marker_cookie:x}" in dump_flows("s1")

def flow_test(net):
    f = FlowRuleDriftFault()
    baseline = ping(net)
    if not baseline["passed"]:
        raise RuntimeError(f"flow baseline failed: {baseline}")
    injected = f.injector({"run_command": run_cmd})
    if not injected.get("success"):
        raise RuntimeError(f"flow injection failed: {injected}")
    detected = wait_for(lambda: (d if (d := f.detector(telemetry())).get("detected") else None),
                        20, "flow marker detection")
    restored = f.restore({"run_command": run_cmd})
    if not restored.get("success"):
        raise RuntimeError(f"flow restore failed: {restored}")
    wait_for(lambda: not flow_present(), 15, "scoped marker removal")
    policy_ok = not flow_present()
    connectivity = ping(net)
    truth = f.ground_truth_check({"flow_policy_checker": lambda: policy_ok})
    if not truth.get("passed") or not connectivity["passed"]:
        raise RuntimeError(f"flow recovery failed: {truth}, {connectivity}")
    return {"baseline": baseline, "injection": injected, "detection": detected,
            "restoration": restored, "independent_policy_check": policy_ok,
            "ground_truth": truth, "connectivity": connectivity, "passed": True}

def flap_events():
    return [e for e in telemetry().get("port_status_events", [])
            if str(e.get("switch_id")) == "1" and str(e.get("port_id")) == "3"
            and str(e.get("state", "")).upper() in {"UP", "DOWN", "MISSING"}]

def flap_link_events():
    return [e for e in telemetry().get("link_events", [])
            if (str(e.get("src_switch")) == "1" and str(e.get("src_port")) == "3")
            or (str(e.get("dst_switch")) == "1" and str(e.get("dst_port")) == "3")]

def interface_up(name):
    p = run_cmd(["ip", "-j", "link", "show", "dev", name],
                capture_output=True, text=True, check=False, timeout=3)
    if p.returncode:
        return False
    info = json.loads(p.stdout)[0]
    return "UP" in info.get("flags", []) and info.get("operstate") == "UP"

def flap_test(net):
    f, trials, iface = LinkFlappingFault(), [], "s1-eth3"
    for number in range(1, 6):
        baseline = ping(net)
        if not baseline["passed"]:
            raise RuntimeError(f"flap trial {number} baseline failed: {baseline}")
        before_ports = len(flap_events())
        before_links = len(flap_link_events())
        injected = f.injector({"run_command": run_cmd, "interface": iface,
                               "cycles": 2, "interval_seconds": .2})
        if not injected.get("success"):
            raise RuntimeError(f"flap trial {number} injection failed: {injected}")
        def new_event_evidence():
            new_count = (len(flap_events()) - before_ports) + (len(flap_link_events()) - before_links)
            detection = f.detector(telemetry())
            return {"detection": detection, "new_event_count": new_count} if (
                new_count >= 4 and detection.get("detected") is True) else None
        detected_evidence = wait_for(new_event_evidence, 15, f"flap trial {number} event detection")
        detected = detected_evidence["detection"]
        restored = f.restore({"run_command": run_cmd, "interface": iface})
        if not restored.get("success"):
            raise RuntimeError(f"flap trial {number} restore failed: {restored}")
        def topology_converged():
            data = telemetry()
            states = {
                (sw, port): state
                for sw, item in data.get("switches", {}).items()
                for port, state in item.get("stp_port_states", {}).items()
            }
            access_forward = states.get(("1", "1")) == "FORWARD" and states.get(("2", "3")) == "FORWARD"
            trunk_blocked = any(states.get(port) == "BLOCK" for port in
                                (("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")))
            return access_forward and trunk_blocked
        wait_for(topology_converged, 35, f"STP reconvergence after flap trial {number}")
        restored_at = now()
        time.sleep(1)
        def stable():
            if not interface_up(iface):
                return False
            recent = [e for e in flap_events()
                      if e.get("timestamp_utc", "") >= restored_at]
            return all(str(e.get("state", "")).upper() == "UP" for e in recent)
        truth = f.ground_truth_check({"link_stability_checker": stable})
        connectivity = wait_for(
            lambda: (p if (p := ping(net))["passed"] else None),
            20, f"host connectivity after flap trial {number}")
        port_events = flap_events()[before_ports:]
        link_events = flap_link_events()[before_links:]
        item = {"trial": number, "baseline": baseline, "injection": injected,
                "detection": detected, "restoration": restored,
                "new_port_status_events": port_events, "new_link_events": link_events,
                "new_detector_event_count": detected_evidence["new_event_count"],
                "link_stability": truth,
                "connectivity": connectivity,
                "passed": truth.get("passed") is True and connectivity["passed"]}
        trials.append(item)
        if not item["passed"]:
            raise RuntimeError(f"flap trial {number} recovery failed: {item}")
    return {"requested_trials": 5, "completed_trials": len(trials),
            "interface": iface, "cycles_per_trial": 2, "trials": trials,
            "passed": len(trials) == 5 and all(t["passed"] for t in trials)}

def mac_test(net):
    f = MacFloodingFault()
    baseline = ping(net)
    if not baseline["passed"]:
        raise RuntimeError(f"MAC baseline failed: {baseline}")
    helper = Path(tempfile.gettempdir()) / "netops_phase2_mac_flood.py"
    helper.write_text(
        "import socket,sys,time\n"
        "n=int(sys.argv[1]); delay=float(sys.argv[2]); iface=sys.argv[3]\n"
        "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind((iface,0))\n"
        "for i in range(n):\n"
        " src=bytes([2,170,187,204,221,i&255]); frame=b'\\xff'*6+src+b'\\x88\\xb5'+b'NETOPS'+bytes([i&255]); s.send(frame); time.sleep(delay)\n"
        "print('frames_sent='+str(n))\n", encoding="utf-8")
    h1 = net.get("h1")
    def generator(count, interval_seconds):
        output = h1.cmd(f"python3 {helper} {int(count)} {float(interval_seconds)} h1-eth0")
        return {"success": f"frames_sent={int(count)}" in output, "output": output}
    injected = f.injector({"mac_flood_generator": generator})
    if not injected.get("success"):
        raise RuntimeError(f"MAC injection failed: {injected}")
    detected = wait_for(lambda: (d if (d := f.detector(telemetry())).get("detected") else None),
                        20, "MAC flood detector")
    def reset_table():
        down = run_cmd(["ip", "link", "set", "dev", "s1-eth1", "down"],
                       capture_output=True, text=True, check=False, timeout=3)
        time.sleep(.3)
        up = run_cmd(["ip", "link", "set", "dev", "s1-eth1", "up"],
                     capture_output=True, text=True, check=False, timeout=3)
        return {"success": down.returncode == 0 and up.returncode == 0,
                "method": "access-port DOWN/UP invokes controller learning-state flush",
                "down_rc": down.returncode, "up_rc": up.returncode}
    restored = f.restore({"mac_table_reset": reset_table})
    if not restored.get("success"):
        raise RuntimeError(f"MAC reset failed: {restored}")
    wait_for(lambda: interface_up("s1-eth1"), 10, "h1 access link UP")
    def stp_after_reset():
        data = telemetry()
        states = {
            (sw, port): state
            for sw, item in data.get("switches", {}).items()
            for port, state in item.get("stp_port_states", {}).items()
        }
        access_forward = states.get(("1", "1")) == "FORWARD" and states.get(("2", "3")) == "FORWARD"
        trunk_blocked = any(states.get(port) == "BLOCK" for port in
                            (("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")))
        return access_forward and trunk_blocked
    wait_for(stp_after_reset, 35, "STP reconvergence after MAC-table reset")
    connectivity = wait_for(
        lambda: (p if (p := ping(net))["passed"] else None),
        20, "host connectivity after MAC-table reset")
    for _ in range(2):
        connectivity = ping(net)
        if not connectivity["passed"]:
            raise RuntimeError(f"endpoint relearning ping failed: {connectivity}")
        time.sleep(1)
    def table_check():
        data = telemetry()
        counts = {sw: int(data.get("switches", {}).get(sw, {}).get("learned_mac_count", 0))
                  for sw in ("1", "2")}
        learned_flows = {}
        for bridge in ("s1", "s2"):
            learned_flows[bridge] = sum("priority=1" in line
                                        for line in dump_flows(bridge).splitlines())
        ok = all(v <= 2 for v in counts.values()) and all(v <= 2 for v in learned_flows.values())
        return {"passed": ok, "learned_mac_count_by_switch": counts,
                "priority_1_flow_count_by_switch": learned_flows,
                "expected_max_endpoints_per_switch": 2}
    table = wait_for(lambda: (v if (v := table_check()).get("passed") else None),
                     15, "MAC table recovery")
    truth = f.ground_truth_check({
        "mac_table_checker": lambda: table["passed"],
        "connectivity_checker": lambda: ping(net)["passed"]})
    time.sleep(31)
    post_window = f.detector(telemetry())
    if not truth.get("passed") or post_window.get("detected") is not False:
        raise RuntimeError(f"MAC recovery failed: {truth}, {table}, {post_window}")
    return {"baseline": baseline, "injection": injected, "detection": detected,
            "restoration": restored, "independent_mac_table_check": table,
            "ground_truth": truth, "connectivity": connectivity,
            "post_30_second_window_detection": post_window, "passed": True}

def main():
    if os.geteuid() != 0:
        print("ERROR: run this script elevated inside Ubuntu-22.04.")
        return 2
    try:
        with socket.create_connection(("127.0.0.1", 6653), timeout=2):
            pass
    except OSError as exc:
        print(f"ERROR: Ryu controller unavailable: {exc}")
        return 2
    for bridge in ("s1", "s2"):
        if subprocess.run(["ovs-vsctl", "br-exists", bridge],
                          capture_output=True, check=False).returncode == 0:
            print(f"ERROR: existing bridge {bridge}; refusing to take ownership.")
            return 2
    RESULTS.mkdir(parents=True, exist_ok=True)
    result = {"run_id": RUN_ID, "started_at_utc": now(),
              "evidence_type": "LIVE_MININET_OVS",
              "repository": str(ROOT), "branch": subprocess.run(
                  ["git", "-C", str(ROOT), "branch", "--show-current"],
                  capture_output=True, text=True).stdout.strip(),
              "experiments": {}, "command_log": COMMANDS, "passed": False}
    setLogLevel("warning")
    net = Mininet(topo=RedundantTopo(), controller=None, switch=OVSKernelSwitch,
                  autoSetMacs=True, autoStaticArp=False, build=True, waitConnected=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    code = 1
    try:
        print("Starting isolated redundant Mininet topology...")
        net.start()
        def topology_ready():
            data = telemetry()
            switches = data.get("switches", {})
            if not all(s in switches for s in ("1", "2")):
                return None
            states = {
                (sw, port): state
                for sw, item in switches.items()
                for port, state in item.get("stp_port_states", {}).items()
            }
            access_forward = states.get(("1", "1")) == "FORWARD" and states.get(("2", "3")) == "FORWARD"
            trunk_blocked = any(states.get(port) == "BLOCK" for port in
                                (("1", "2"), ("1", "3"), ("2", "1"), ("2", "2")))
            return data if access_forward and trunk_blocked else None
        wait_for(topology_ready, 40, "STP access forwarding and redundant trunk blocking")
        baseline = ping(net)
        if not baseline["passed"]:
            baseline = wait_for(
                lambda: (p if (p := ping(net))["passed"] else None),
                15, "healthy initial host connectivity")
        result["initial_baseline"] = baseline
        print("PASS baseline: 0% packet loss")
        only = os.environ.get("PHASE2_ONLY", "").strip().lower()
        if only not in {"", "mac"}:
            raise RuntimeError(f"Unsupported PHASE2_ONLY value: {only}")
        if only != "mac":
            print("Flow-rule drift...")
            result["experiments"]["flow_rule_drift"] = flow_test(net)
            print("PASS flow-rule drift")
            print("Five link-flapping trials...")
            result["experiments"]["link_flapping"] = flap_test(net)
            print("PASS link-flapping 5/5")
        print("Controlled MAC-learning flood...")
        result["experiments"]["mac_flooding"] = mac_test(net)
        print("PASS MAC-learning flood and recovery")
        result["passed"] = all(v.get("passed") is True for v in result["experiments"].values())
        code = 0 if result["passed"] else 1
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        print("EXPERIMENT FAILURE:", result["error"])
    finally:
        print("Stopping only the topology created by this run...")
        try:
            net.stop()
        except Exception as exc:
            result["cleanup_error"] = f"{type(exc).__name__}: {exc}"
        result["finished_at_utc"] = now()
        result["final_telemetry"] = telemetry()
        result["command_log"] = COMMANDS
        RAW.write_text(json.dumps(result, indent=2), encoding="utf-8")
        TXT.write_text(
            f"run_id: {RUN_ID}\nevidence_type: LIVE_MININET_OVS\n"
            f"passed: {result.get('passed')}\nraw_json: {RAW}\n\n"
            + json.dumps({"initial_baseline": result.get("initial_baseline"),
                          "experiments": result.get("experiments"),
                          "error": result.get("error"),
                          "cleanup_error": result.get("cleanup_error")}, indent=2),
            encoding="utf-8")
        print(f"RAW_JSON={RAW}")
        print(f"SUMMARY_TXT={TXT}")
        print(f"OVERALL_PASSED={result.get('passed')}")
    return code

if __name__ == "__main__":
    sys.exit(main())
