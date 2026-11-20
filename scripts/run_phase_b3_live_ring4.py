#!/usr/bin/env python3
"""Phase B3 Live Ring4 Verification Script.

Executes all Phase B3 requirements on the live Mininet + Ryu ring4 lab:
7(a) disable_port on ACTIVE trunk (s1-p3) with continuous h1->h4 ping running.
     Reports loss window and recovery time.
7(b) restore_port for a link absent from telemetry links (union-merged from topology_spec.json).
7(c) rate_limit_port on s1-p1 while h1 sends broadcasts for 15 s.
     Reports rx/tx counter deltas on the STP-blocked link (s4-eth4, must stay flat)
     and h1->h4 ping RTT.
7(d) Confirm approvals used the real HumanApprovalStore with require_human_approval=True.
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.append("/usr/lib/python3/dist-packages")

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from netops_guardrail.controller.human_verifier import (
    HumanApprovalStore,
    topology_fingerprint_from_path,
)
from netops_guardrail.executor.remediation_executor import RemediationExecutor
from netops_guardrail.verifier.safety_verifier import (
    _union_merge_links,
    load_topology_spec,
)
from testbed.ring4_topo import Ring4Topo

TELEMETRY_PATH = PROJECT_ROOT / "telemetry" / "data" / "latest.json"
LEDGER_PATH = PROJECT_ROOT / "audit" / "phase_b3_live_cookie_ledger.json"
APPROVALS_PATH = PROJECT_ROOT / "audit" / "live_approvals_b3.json"
TOPOLOGY_SPEC_PATH = PROJECT_ROOT / "telemetry" / "topology_spec.json"

ACCESS_PORTS = {("1", "1"), ("1", "2"), ("4", "1"), ("4", "2")}
TRUNK_PORTS = {
    ("1", "3"), ("1", "4"),
    ("2", "1"), ("2", "2"),
    ("3", "1"), ("3", "2"),
    ("4", "3"), ("4", "4"),
}


def approve(store, proposal):
    return store.decide(
        proposal["proposal_id"],
        "approve",
        approver_id="live-network-admin",
        reason="Reviewed live proposal (Phase B3)",
        proposal_fingerprint_value=proposal["proposal_fingerprint"],
    )


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


def wait_for_new_telemetry(previous_updated_at: str | None, timeout: float = 15.0) -> bool:
    """Wait until the controller replaces the prior snapshot with a fresh one."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = read_telemetry().get("updated_at_utc")
        if current and current != previous_updated_at:
            try:
                updated = datetime.fromisoformat(str(current).replace("Z", "+00:00"))
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - updated).total_seconds() <= 10:
                    return True
            except ValueError:
                pass
        time.sleep(0.25)
    return False


def wait_for_stp_convergence(timeout: float = 30.0) -> tuple[bool, float, str]:
    t_start = time.monotonic()
    deadline = t_start + timeout
    while time.monotonic() < deadline:
        telem = read_telemetry()
        switches = telem.get("switches", {})
        if len(switches) >= 4:
            stp_states = {}
            for sw_id, sw_data in switches.items():
                for pt_id, state in (sw_data.get("stp_port_states") or {}).items():
                    stp_states[(str(sw_id), str(pt_id))] = str(state).upper()

            blocked_trunks = [pt for pt in TRUNK_PORTS if stp_states.get(pt) == "BLOCK"]
            access_forward = all(stp_states.get(pt) == "FORWARD" for pt in ACCESS_PORTS)
            other_trunks_forward = all(
                stp_states.get(pt) == "FORWARD"
                for pt in TRUNK_PORTS
                if pt not in blocked_trunks
            )

            if blocked_trunks and access_forward and other_trunks_forward:
                conv_time = round(time.monotonic() - t_start, 2)
                blocked_port = f"s{blocked_trunks[0][0]}-p{blocked_trunks[0][1]}"
                return True, conv_time, blocked_port
        time.sleep(0.3)
    return False, round(time.monotonic() - t_start, 2), ""


def wait_for_ports_forward(switches_ports: dict[str, list[str]], timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        telem = read_telemetry()
        all_ok = True
        for sw_id, ports in switches_ports.items():
            stp_states = telem.get("switches", {}).get(str(sw_id), {}).get("stp_port_states", {})
            for p in ports:
                if stp_states.get(str(p)) != "FORWARD":
                    all_ok = False
                    break
            if not all_ok:
                break
        if all_ok:
            return True
        time.sleep(0.5)
    return False


def wait_for_stable_telemetry(quiet_seconds: float = 3.0, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    last_fp = None
    quiet_start = time.monotonic()
    while time.monotonic() < deadline:
        try:
            fp = topology_fingerprint_from_path(str(TELEMETRY_PATH))
            if fp == last_fp:
                if time.monotonic() - quiet_start >= quiet_seconds:
                    return True
            else:
                last_fp = fp
                quiet_start = time.monotonic()
        except Exception:
            pass
        time.sleep(0.5)
    return False


def wait_for_full_baseline_telemetry(timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        telem = read_telemetry()
        links = telem.get("links", [])
        switches = telem.get("switches", {})
        has_s1_p3 = any(
            (str(l.get("src_switch")) == "1" and str(l.get("src_port")) == "3")
            or (str(l.get("dst_switch")) == "1" and str(l.get("dst_port")) == "3")
            for l in links
        )
        has_s4_p3 = any(
            (str(l.get("src_switch")) == "4" and str(l.get("src_port")) == "3")
            or (str(l.get("dst_switch")) == "4" and str(l.get("dst_port")) == "3")
            for l in links
        )
        s1_stp = switches.get("1", {}).get("stp_port_states", {}).get("3")
        s4_stp = switches.get("4", {}).get("stp_port_states", {}).get("4")
        if has_s1_p3 and has_s4_p3 and s1_stp == "FORWARD" and s4_stp == "BLOCK":
            return True
        time.sleep(0.5)
    return False


def get_interface_counters(iface: str) -> dict[str, int]:
    base = Path(f"/sys/class/net/{iface}/statistics")
    if not base.exists():
        return {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}
    try:
        return {
            "rx_packets": int((base / "rx_packets").read_text().strip()),
            "tx_packets": int((base / "tx_packets").read_text().strip()),
            "rx_bytes": int((base / "rx_bytes").read_text().strip()),
            "tx_bytes": int((base / "tx_bytes").read_text().strip()),
        }
    except Exception:
        return {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}


def get_of_port_counters(bridge: str, port: int) -> dict[str, int]:
    rc, out, _ = RemediationExecutor._default_cmd_runner([
        "ovs-ofctl", "-O", "OpenFlow13", "dump-ports", bridge, str(port)
    ])
    rx_pkts, tx_pkts = 0, 0
    if rc == 0 and out:
        m_rx = re.search(r"rx pkts=(\d+)", out)
        m_tx = re.search(r"tx pkts=(\d+)", out)
        if m_rx:
            rx_pkts = int(m_rx.group(1))
        if m_tx:
            tx_pkts = int(m_tx.group(1))
    return {"rx_packets": rx_pkts, "tx_packets": tx_pkts}



def get_meter_stats(bridge: str, meter_id: int) -> dict[str, int]:
    """Read OpenFlow meter band drop counters; fail instead of inferring drops."""
    rc, output, error = RemediationExecutor._default_cmd_runner([
        "ovs-ofctl", "-O", "OpenFlow13", "meter-stats", bridge, f"meter={meter_id}"
    ])
    if rc != 0:
        raise RuntimeError(f"Unable to read meter statistics: {error or output}")
    packets = [int(value) for value in re.findall(r"packet_count\s*[:=]\s*(\d+)", output or "")]
    byte_counts = [int(value) for value in re.findall(r"byte_count\s*[:=]\s*(\d+)", output or "")]
    if not packets or not byte_counts:
        raise RuntimeError(f"Meter statistics do not contain band counters: {output!r}")
    return {"drop_packets": sum(packets), "drop_bytes": sum(byte_counts), "raw": output}


def assert_clean_baseline(net, label: str, results: dict) -> dict:
    """Require pingall=0, expected STP, every physical port up and no guardrail flow."""
    loss = float(net.pingAll(timeout=2))
    if loss != 0.0:
        raise AssertionError(f"{label}: baseline pingall loss is {loss}%")
    converged, convergence_seconds, blocked_port = wait_for_stp_convergence(timeout=30.0)
    if not converged or blocked_port != "s4-p4":
        raise AssertionError(f"{label}: expected s4-p4 blocked at stable baseline, got {blocked_port!r}")

    ports_snapshot, flows_snapshot = {}, {}
    for switch_id in ("1", "2", "3", "4"):
        bridge = f"s{switch_id}"
        rc, desc, err = RemediationExecutor._default_cmd_runner([
            "ovs-ofctl", "-O", "OpenFlow13", "dump-ports-desc", bridge
        ])
        if rc != 0:
            raise AssertionError(f"{label}: unable to inspect {bridge} ports: {err or desc}")
        down_ports = []
        current_port = None
        for line in (desc or "").splitlines():
            if line.lstrip().startswith("LOCAL("):
                current_port = None
                continue
            port_match = re.search(r"^\s*(\d+)\(", line)
            if port_match:
                current_port = port_match.group(1)
            if "config:" in line and "PORT_DOWN" in line and current_port:
                down_ports.append(current_port)
        if down_ports:
            raise AssertionError(f"{label}: admin-down ports on {bridge}: {down_ports}; dump={desc!r}")
        ports_snapshot[bridge] = {"administratively_down": down_ports, "raw": desc}

        rc, flows, err = RemediationExecutor._default_cmd_runner([
            "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge
        ])
        if rc != 0:
            raise AssertionError(f"{label}: unable to inspect {bridge} flows: {err or flows}")
        suspicious = [
            line.strip() for line in (flows or "").splitlines()
            if re.search(r"\bpriority=(?:65000|65500)\b", line)
        ]
        if suspicious:
            raise AssertionError(f"{label}: existing meter/guardrail flows on {bridge}: {suspicious}")
        flows_snapshot[bridge] = {"guardrail_or_meter_flows": suspicious}

    snapshot = {
        "label": label,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "pingall_loss_percent": loss,
        "stp_convergence_seconds": convergence_seconds,
        "blocked_port": blocked_port,
        "ports": ports_snapshot,
        "flows": flows_snapshot,
        "telemetry": read_telemetry(),
    }
    results.setdefault("baseline_snapshots", []).append(snapshot)
    return snapshot


def run_live_experiment():
    started = datetime.now(timezone.utc)
    try:
        commit = subprocess.check_output(
            ["git", "-c", "safe.directory=/home/bennurjeevan/netops_guardrail", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True
        ).strip()
    except Exception:
        commit = "unavailable"
    results_dir = PROJECT_ROOT / "experiments" / "results" / "phase_b3"
    result = {
        "phase": "B3",
        "started_at_utc": started.isoformat(),
        "command": " ".join(sys.argv),
        "commit": commit,
        "model": None,
        "provenance": "live_mininet_ovs",
        "baseline_snapshots": [],
        "scenarios": {},
    }

    def persist_results():
        results_dir.mkdir(parents=True, exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        destination = results_dir / f"{stamp}_phase_b3_live_ring4.json"
        temporary = destination.with_suffix(".json.tmp")
        result["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        temporary.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(destination)
        result["result_file"] = str(destination)

    print("=" * 75)
    print("  PHASE B3 LIVE RING4 DEMONSTRATION & VERIFICATION")
    print("=" * 75)

    # Fail closed instead of deleting bridges or clearing shared runtime state.
    existing_bridges = set(subprocess.check_output(["ovs-vsctl", "list-br"], text=True).split())
    conflicting_bridges = sorted(existing_bridges.intersection({"s1", "s2", "s3", "s4"}))
    if conflicting_bridges:
        raise RuntimeError(
            f"Refusing to start: OVS bridges already exist: {conflicting_bridges}. "
            "Stop only the lab instance you own, then retry."
        )
    if wait_for_port(port=6653, timeout=0.5):
        raise RuntimeError("Refusing to start: TCP port 6653 is already occupied.")

    # Keep every run's approval and cookie ledger for auditability.
    global LEDGER_PATH, APPROVALS_PATH
    run_stamp = started.strftime("%Y%m%dT%H%M%SZ")
    LEDGER_PATH = PROJECT_ROOT / "audit" / f"phase_b3_live_cookie_ledger_{run_stamp}.json"
    APPROVALS_PATH = PROJECT_ROOT / "audit" / f"live_approvals_b3_{run_stamp}.json"
    previous_telemetry_updated_at = read_telemetry().get("updated_at_utc")

    # 1. Start Ryu
    print("\n[1] Starting Ryu Controller with telemetry_controller (OF 1.3, port 6653)...")
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
        if not wait_for_port(port=6653, timeout=12.0):
            print("ERROR: Ryu controller did not open port 6653.")
            return

        print("Ryu controller active and listening on port 6653.")
        # 2. Start Mininet Ring4
        print("\n[2] Initializing Mininet Ring4 Topology (s1..s4, h1..h4)...")
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
        net.start()
        if not wait_for_new_telemetry(previous_telemetry_updated_at, timeout=15.0):
            raise RuntimeError("Controller did not publish a fresh telemetry snapshot after switch connection; refusing stale baseline.")

        print("Waiting for STP convergence across s1..s4...")
        converged, conv_time, blocked_port = wait_for_stp_convergence(timeout=30.0)
        if not converged:
            print("ERROR: STP convergence failed.")
            net.stop()
            return

        print(f"STP Converged in {conv_time}s. Blocked port: {blocked_port}")
        print("Testing baseline pingall...")
        loss = net.pingAll(timeout=2)
        print(f"Baseline pingall loss: {loss:.1f}%")
        if loss != 0.0:
            raise RuntimeError(f"Initial ring4 baseline is dirty: pingall loss={loss:.1f}%")
        assert_clean_baseline(net, "before_7a_active_trunk", result)
        persist_results()

        # Setup approval store and executor
        approval_store = HumanApprovalStore(path=str(APPROVALS_PATH))

        def live_connectivity_checker():
            h1 = net.get("h1")
            res = h1.cmd("ping -c 1 -W 1 10.0.0.4")
            return "1 packets transmitted, 1 received" in res or "1 received" in res

        executor = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=live_connectivity_checker,
            convergence_window_seconds=25.0,
            ledger_path=str(LEDGER_PATH),
        )

        h1 = net.get("h1")
        h4 = net.get("h4")

        # -------------------------------------------------------------
        # 7(a) disable_port on ACTIVE trunk with continuous h1->h4 ping
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("[7a] disable_port on ACTIVE trunk (s1-p3) with continuous h1->h4 ping...")
        print("-" * 70)

        # Confirm s1-p3 is an active trunk and s4-p4 is the blocked one
        telem = read_telemetry()
        s1_stp = telem.get("switches", {}).get("1", {}).get("stp_port_states", {})
        s4_stp = telem.get("switches", {}).get("4", {}).get("stp_port_states", {})
        print(f"  Pre-disable STP: s1-p3 = {s1_stp.get('3')}, s4-p4 = {s4_stp.get('4')}")
        assert s1_stp.get("3") == "FORWARD", "s1-p3 must be an active trunk"
        assert s4_stp.get("4") == "BLOCK", "s4-p4 must be the STP-blocked link"

        # Start background continuous ping h1 -> h4 with timestamps (interval 0.2s = 5 pings/sec)
        ping_log = PROJECT_ROOT / "ping_loss_window.log"
        if ping_log.exists():
            ping_log.unlink()

        ping_cmd = f"ping -i 0.2 -W 1 10.0.0.4 | while read pong; do echo \"$(date +%s.%N) $pong\"; done > {ping_log} 2>&1 &"
        h1.cmd(ping_cmd)
        time.sleep(1.0)  # let continuous ping establish baseline replies

        # Create proposal and approve using HumanApprovalStore
        intent_disable = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Administrative isolation of active trunk s1-p3",
        }
        verifier_result = {"safe": True}
        prop_disable = approval_store.create_proposal(
            intent=intent_disable,
            verifier_result=verifier_result,
            telemetry_path=str(TELEMETRY_PATH),
            requested_by="netops-agent",
        )
        approve(approval_store, prop_disable)
        print(f"  Approval proposal created and approved: {prop_disable['proposal_id']}")

        t_disable_start = time.monotonic()
        res_disable = executor.execute(
            intent=intent_disable,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=prop_disable["proposal_id"],
        )
        t_disable_done = time.monotonic()

        print(f"  Execution result: success={res_disable['success']}")
        print(f"  Reported convergence time: {res_disable.get('convergence_time_seconds')}s")
        assert res_disable["success"] is True
        assert res_disable["change_verified"] is True
        assert res_disable["safety_verified"] is True

        # Stop continuous ping and analyze loss window
        time.sleep(2.0)
        h1.cmd("killall -9 ping")

        # Parse ping log to compute exact packet loss window and recovery time
        ping_lines = ping_log.read_text().splitlines() if ping_log.exists() else []
        seq_replies = []
        for line in ping_lines:
            m = re.search(r"(\d+\.\d+)\s+.*icmp_seq=(\d+)\s+ttl=\d+\s+time=([0-9\.]+)\s+ms", line)
            if m:
                ts = float(m.group(1))
                seq = int(m.group(2))
                rtt = float(m.group(3))
                seq_replies.append((ts, seq, rtt))

        loss_window_seconds = None
        recovery_time_seconds = res_disable.get("convergence_time_seconds", round(t_disable_done - t_disable_start, 2))
        lost_packets = 0
        reply_intervals = [
            seq_replies[i + 1][0] - seq_replies[i][0]
            for i in range(len(seq_replies) - 1)
            if seq_replies[i + 1][1] == seq_replies[i][1] + 1
        ]
        baseline_interval_seconds = statistics.median(reply_intervals) if reply_intervals else 0.2

        if len(seq_replies) >= 2:
            max_seq_gap = 0
            gap_start_ts = None
            gap_end_ts = None
            for i in range(len(seq_replies) - 1):
                gap = seq_replies[i + 1][1] - seq_replies[i][1]
                if gap > max_seq_gap:
                    max_seq_gap = gap
                    gap_start_ts = seq_replies[i][0]
                    gap_end_ts = seq_replies[i + 1][0]
            if max_seq_gap > 1:
                lost_packets = max_seq_gap - 1
                loss_window_seconds = round(gap_end_ts - gap_start_ts, 2)
            else:
                loss_window_seconds = 0.0

        print("  Continuous ping analysis:")
        print(f"    Total replies recorded:    {len(seq_replies)}")
        print(f"    Packets lost during failover: {lost_packets}")
        estimated_loss_seconds = round(lost_packets * baseline_interval_seconds, 3)
        residual_seconds = round((loss_window_seconds or 0) - estimated_loss_seconds, 3)
        print(f"    Measured reply-to-reply gap: {loss_window_seconds}s")
        print(f"    Sequence-count estimated loss: {estimated_loss_seconds}s")
        print(f"    Baseline median reply interval: {round(baseline_interval_seconds, 4)}s")
        print(f"    Unexplained gap residual: {residual_seconds}s")
        print(f"    Executor-reported STP convergence: {recovery_time_seconds}s")

        result["scenarios"]["7a_active_trunk_disable"] = {
            "active_port": "s1-p3",
            "standby_port": "s4-p4",
            "execution": res_disable,
            "ping_reply_count": len(seq_replies),
            "lost_sequence_count": lost_packets,
            "measured_reply_gap_seconds": loss_window_seconds,
            "baseline_median_reply_interval_seconds": baseline_interval_seconds,
            "interval_estimated_loss_seconds": estimated_loss_seconds,
            "unexplained_gap_residual_seconds": residual_seconds,
            "executor_stp_convergence_seconds": recovery_time_seconds,
        }
        persist_results()

        # Verify STP state post-failover: s4-p4 unblocked and forwarding
        wait_for_ports_forward({"4": ["4"]}, timeout=10.0)
        telem_after = read_telemetry()
        s4_p4_after = telem_after.get("switches", {}).get("4", {}).get("stp_port_states", {}).get("4")
        print(f"    s4-p4 state post-failover: {s4_p4_after} (unblocked to preserve reachability)")
        assert s4_p4_after == "FORWARD", "s4-p4 must have transitioned to FORWARD"

        # Re-enable s1-p3 to return to baseline ring topology before 7(b)
        print("  Restoring s1-p3 to return to baseline ring topology...")
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s1", "3", "up"], check=True)
        print("  Waiting for Ryu to discover full baseline topology (links & STP)...")
        if not wait_for_full_baseline_telemetry(timeout=25.0):
            raise RuntimeError("Full topology telemetry did not recover after 7a")
        time.sleep(1.0)
        baseline_telem = read_telemetry()
        print(f"  Baseline links discovered: {len(baseline_telem.get('links', []))} links active.")
        assert_clean_baseline(net, "after_7a_before_7b", result)
        persist_results()

        # -------------------------------------------------------------
        # 7(b) restore_port for a link absent from telemetry links
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("[7b] restore_port for a link absent from telemetry links...")
        print("-" * 70)

        # Baseline: s4-p3 is active (forwarding), s4-p4 is blocked.
        # Part 1: Demonstrate Requirement 1(b): restoring absent redundant link (s4-p4)
        # that would create a loop is REJECTED by the verifier.
        print("  Testing 1(b): Restoring absent standby link (s4-p4) when redundant creates loop -> should be REJECTED...")
        telem_1b = read_telemetry()
        # Omit s4-p4 link from telemetry links
        telem_1b["links"] = [
            l for l in telem_1b.get("links", [])
            if not (
                (str(l.get("src_switch")) == "4" and str(l.get("src_port")) == "4")
                or (str(l.get("dst_switch")) == "4" and str(l.get("dst_port")) == "4")
            )
        ]
        TELEMETRY_PATH.write_text(json.dumps(telem_1b, indent=2))

        intent_restore_redundant = {
            "action": "restore_port",
            "target_switch": "4",
            "from_port": "4",
            "reason": "Attempting to restore standby link s4-p4 while s4-p3 is active",
        }
        prop_rejected = approval_store.create_proposal(
            intent=intent_restore_redundant,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
            requested_by="netops-agent",
        )
        approve(approval_store, prop_rejected)
        res_rejected = executor.execute(
            intent=intent_restore_redundant,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=prop_rejected["proposal_id"],
        )
        print(f"  Pre-execution rejection as expected: success={res_rejected['success']}")
        print(f"  Error details: {res_rejected.get('error')}")
        assert res_rejected["success"] is False
        assert "FAIL: Loop(s) present" in res_rejected["error"]
        print("  VERIFIED Requirement 1(b): Restoring absent redundant link creating loop was safely REJECTED.")

        # Part 2: Demonstrate Requirement 1(a): link absent + network partitioned -> restore APPROVED and executed live.
        print("  Testing 1(a): Both s4 uplinks are disabled to create a genuine edge partition...")
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s4", "3", "down"], check=True)
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s4", "4", "down"], check=True)
        time.sleep(1.0)
        telem_1a = json.loads(json.dumps(baseline_telem))
        port_status = telem_1a.setdefault("switches", {}).setdefault("4", {}).setdefault("port_status", {})
        for down_port in ("3", "4"):
            port_status[down_port] = {
                "state": "DOWN", "admin_down": True, "link_down": True
            }
        telem_1a["links"] = [
            link for link in telem_1a.get("links", [])
            if not (
                (str(link.get("src_switch")) == "4" and str(link.get("src_port")) in ("3", "4"))
                or (str(link.get("dst_switch")) == "4" and str(link.get("dst_port")) in ("3", "4"))
            )
        ]
        TELEMETRY_PATH.write_text(json.dumps(telem_1a, indent=2))

        partition_reachable = live_connectivity_checker()
        if partition_reachable:
            raise AssertionError("Both-uplink edge partition failed: h1 still reaches h4")
        print("  Genuine edge partition confirmed: both s4 uplinks down; h1 cannot reach h4.")
        result["scenarios"]["7b_edge_partition"] = {
            "disabled_uplinks": ["s4-p3", "s4-p4"],
            "removed_telemetry_links": ["s4-p3", "s4-p4"],
            "h1_to_h4_reachable_before_restore": partition_reachable,
            "telemetry_snapshot": telem_1a,
        }
        persist_results()

        # Verify load_topology_spec and _union_merge_links finds s4-p3
        spec_links = load_topology_spec(TOPOLOGY_SPEC_PATH, num_switches=4)
        merged = _union_merge_links(telem_1a["links"], spec_links)
        has_s4_p3 = any(
            (str(l.get("src_switch")) == "4" and str(l.get("src_port")) == "3")
            or (str(l.get("dst_switch")) == "4" and str(l.get("dst_port")) == "3")
            for l in merged
        )
        print(f"  Union-merge with topology_spec.json restores link presence: {has_s4_p3}")
        assert has_s4_p3 is True

        # Now propose and execute restore_port on s4-p3 (Requirement 1a: absent + partitioned -> approved)
        intent_restore = {
            "action": "restore_port",
            "target_switch": "4",
            "from_port": "3",
            "reason": "Restore trunk link s4-p3 absent from telemetry links to recover partition",
        }
        prop_restore = approval_store.create_proposal(
            intent=intent_restore,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
            requested_by="netops-agent",
        )
        approve(approval_store, prop_restore)
        print(f"  Approval proposal created and approved: {prop_restore['proposal_id']}")

        res_restore = executor.execute(
            intent=intent_restore,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=prop_restore["proposal_id"],
        )
        print(f"  Execution result: success={res_restore['success']}")
        print(f"  Reported convergence time: {res_restore.get('convergence_time_seconds')}s")
        print(f"  Details: {res_restore.get('details')}")
        assert res_restore["success"] is True
        assert res_restore["change_verified"] is True
        assert res_restore["safety_verified"] is True
        assert res_restore["connectivity_verified"] is True
        print("  VERIFIED Requirement 1(a): Restoring absent link on partitioned network APPROVED and verified live.")
        result["scenarios"]["7b_restore_port"] = {
            "intent": intent_restore,
            "execution": res_restore,
            "human_approval_id": prop_restore["proposal_id"],
        }
        persist_results()

        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s4", "4", "up"], check=True)
        print("  Waiting for STP to re-stabilize to baseline ring...")
        time.sleep(2.0)
        converged, conv_time, blocked_port = wait_for_stp_convergence(timeout=30.0)
        print(f"  STP re-converged in {conv_time}s. Blocked port: {blocked_port}")
        if not converged or blocked_port != "s4-p4":
            raise RuntimeError(f"Ring4 baseline did not recover after 7b: blocked_port={blocked_port}")
        assert_clean_baseline(net, "after_7b_before_7c", result)
        persist_results()

        # -------------------------------------------------------------
        # 7(c) rate_limit_port on s1-p1 with 15s broadcast flood
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("[7c] rate_limit_port on s1-p1 while h1 sends broadcasts for 15 s...")
        print("-" * 70)

        # Find the STP-blocked link
        telem_c = read_telemetry()
        s4_p4_state = telem_c.get("switches", {}).get("4", {}).get("stp_port_states", {}).get("4")
        print(f"  Current STP state on s4-p4 (facing s3-p2): {s4_p4_state}")

        # Propose and approve rate_limit_port on s1-p1 (access port to h1)
        intent_rl = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 2000,
            "reason": "Broadcast rate limiting on access port s1-p1",
        }
        prop_rl = approval_store.create_proposal(
            intent=intent_rl,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
            requested_by="netops-agent",
        )
        approve(approval_store, prop_rl)

        res_rl = executor.execute(
            intent=intent_rl,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=prop_rl["proposal_id"],
        )
        print(f"  rate_limit_port execution result: success={res_rl['success']}")
        assert res_rl["success"] is True
        assert res_rl["change_verified"] is True

        # Read blocked-port and meter counters before flooding.
        initial_counters = get_interface_counters("s4-eth4")
        initial_of = get_of_port_counters("s4", 4)
        initial_meter = get_meter_stats("s1", 1)
        print(f"  Initial counters on STP-blocked link: kernel={initial_counters}, openflow={initial_of}")
        print(f"  Initial meter drop counters: {initial_meter}")

        # Start h1 (rate-limited ingress) and h2 (independent host) pings.
        ping_rtt_log = PROJECT_ROOT / "ping_rtt_under_bcast.log"
        if ping_rtt_log.exists():
            ping_rtt_log.unlink()
        h1.cmd(f"ping -i 0.5 -W 1 -c 32 10.0.0.4 > {ping_rtt_log} 2>&1 &")
        h2_ping_log = Path("/tmp/phase_b3_h2_to_h4_ping.log")
        if h2_ping_log.exists():
            h2_ping_log.unlink()
        h2 = net.get("h2")
        h2.cmd(f"ping -i 0.5 -W 1 -c 32 10.0.0.4 > {h2_ping_log} 2>&1 &")

        # Generate broadcast traffic from h1 for 15 seconds
        print("  Generating broadcast flood from h1 for 15 seconds...")
        t_bcast_start = time.monotonic()
        # Send broadcast UDP packets using socat/python
        bcast_proc = h1.popen([
            sys.executable, "-c",
            "import socket, time\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)\n"
            "payload = b'X' * 1400\n"
            "deadline = time.monotonic() + 15.0\n"
            "while time.monotonic() < deadline:\n"
            "    s.sendto(payload, ('10.0.0.255', 9999))\n"
            "    time.sleep(0.001)\n"
        ])
        bcast_proc.wait(timeout=20.0)
        t_bcast_elapsed = round(time.monotonic() - t_bcast_start, 2)
        print(f"  Broadcast generation complete ({t_bcast_elapsed}s elapsed).")

        # Read final interface counters on STP-blocked link s4-eth4
        time.sleep(1.0)
        final_counters = get_interface_counters("s4-eth4")
        final_of = get_of_port_counters("s4", 4)
        final_meter = get_meter_stats("s1", 1)
        meter_drop_packets = final_meter["drop_packets"] - initial_meter["drop_packets"]
        meter_drop_bytes = final_meter["drop_bytes"] - initial_meter["drop_bytes"]
        delta_rx = final_counters["rx_packets"] - initial_counters["rx_packets"]
        delta_tx = final_counters["tx_packets"] - initial_counters["tx_packets"]
        delta_of_rx = final_of["rx_packets"] - initial_of["rx_packets"]
        delta_of_tx = final_of["tx_packets"] - initial_of["tx_packets"]
        print(f"  Final counters on STP-blocked link: kernel={final_counters}, openflow={final_of}")
        print(f"  Counter deltas on STP-blocked link: kernel(rx={delta_rx}, tx={delta_tx}), openflow(rx={delta_of_rx}, tx={delta_of_tx})")
        # Over 15s, exactly 0 data or broadcast packets are forwarded out of the STP-blocked port.
        # At most 1-2 standard 70-byte STP BPDU control frames may be emitted by the STP daemon.
        assert delta_tx <= 2, f"STP-blocked link transmitted data packets: tx_delta={delta_tx}"
        assert delta_of_tx <= 2, f"STP-blocked link transmitted openflow data packets: tx_delta={delta_of_tx}"
        print(
            "  VERIFIED: no broadcast/data packets transmitted out of the STP-blocked port; "
            f"tx_delta={delta_tx} kernel / {delta_of_tx} OpenFlow. RX may rise because "
            "frames can arrive at a blocked port and then be discarded."
        )
        print(f"  Meter drop deltas: packets={meter_drop_packets}, bytes={meter_drop_bytes}")
        if meter_drop_packets <= 0 or meter_drop_bytes <= 0:
            raise AssertionError("Flood did not exercise the meter: meter drop counters did not increase")

        h1.cmd("wait")
        h2.cmd("wait")
        rtt_summary = ""
        if ping_rtt_log.exists():
            for line in ping_rtt_log.read_text().splitlines():
                if "rtt min/avg/max/mdev" in line:
                    rtt_summary = line.strip()
                    break
        print(f"  h1->h4 Ping RTT during broadcast flood: {rtt_summary or 'No RTT summary returned'}")
        h2_ping_text = h2_ping_log.read_text(errors="replace") if h2_ping_log.exists() else ""
        h2_stats = re.search(
            r"(\d+) packets transmitted, (\d+) (?:packets )?received, (\d+)% packet loss",
            h2_ping_text,
        )
        if not h2_stats:
            raise AssertionError(f"Could not parse independent h2 ping result: {h2_ping_text}")
        h2_sent, h2_received, h2_loss = map(int, h2_stats.groups())
        print(f"  h2->h4 independent ping: sent={h2_sent}, received={h2_received}, loss={h2_loss}%")
        if h2_loss != 0:
            raise AssertionError(f"Independent h2->h4 traffic was affected: packet loss={h2_loss}%")

        result["scenarios"]["7c_rate_limit_port"] = {
            "intent": intent_rl,
            "execution": res_rl,
            "broadcast": {
                "duration_seconds": t_bcast_elapsed,
                "payload_bytes": 1400,
                "requested_interval_seconds": 0.001,
                "configured_meter_rate_kbps": 2000,
            },
            "meter_before": initial_meter,
            "meter_after": final_meter,
            "meter_drop_packets": meter_drop_packets,
            "meter_drop_bytes": meter_drop_bytes,
            "blocked_port_counter_delta": {
                "kernel_rx": delta_rx, "kernel_tx": delta_tx,
                "openflow_rx": delta_of_rx, "openflow_tx": delta_of_tx,
            },
            "h1_to_h4_rtt_summary": rtt_summary,
            "h2_to_h4_ping": {
                "transmitted": h2_sent, "received": h2_received,
                "packet_loss_percent": h2_loss,
            },
        }

        # -------------------------------------------------------------
        # 7(d) Confirm HumanApprovalStore used with require_human_approval
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("[7d] Confirming HumanApprovalStore audit & single-use lifecycle...")
        print("-" * 70)
        all_proposals = approval_store.list_proposals(include_decided=True)
        consumed = [p for p in all_proposals if p.get("status") == "consumed"]
        print(f"  Total proposals in store: {len(all_proposals)}")
        print(f"  Total consumed proposals: {len(consumed)}")
        for p in consumed:
            print(f"    - Proposal {p['proposal_id'][:12]}... | Action: {p['intent']['action']:<15} | Approver: {p.get('decision', {}).get('approver_id')} | ConsumedAt: {p.get('consumed_at')}")
            assert p["status"] == "consumed", "Approved proposal must be marked consumed"
            assert p.get("decision", {}).get("approver_id") == "live-network-admin"

        assert len(consumed) >= 3, "At least 3 actions must have used real HumanApprovalStore"
        print("  VERIFIED: All actions used real HumanApprovalStore with require_human_approval=True.")
        result["approval_lifecycle"] = {
            "approval_store": str(APPROVALS_PATH),
            "require_human_approval": True,
            "consumed_proposals": [
                {
                    "proposal_id": item["proposal_id"],
                    "action": item["intent"]["action"],
                    "approver_id": item.get("decision", {}).get("approver_id"),
                    "consumed_at": item.get("consumed_at"),
                }
                for item in consumed
            ],
        }
        result["status"] = "passed"
        persist_results()

        print("\n" + "=" * 75)
        print("  PHASE B3 LIVE RING4 VERIFICATION COMPLETE: ALL 4 ITEMS PASSED")
        print("=" * 75)

    except Exception as exc:
        result["status"] = "failed"
        result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        persist_results()
        raise
    finally:
        persist_results()
        print("\nTearing down Mininet and Ryu...")
        try:
            net.stop()
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(ryu_proc.pid), signal.SIGTERM)
            ryu_proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(ryu_proc.pid), signal.SIGKILL)
            except Exception:
                pass
        # Do not run global `mn -c`: it can tear down unrelated Mininet labs.
        # Mininet.net.stop() above owns teardown for this process only.

        # Once Mininet has removed the ring4 bridges, its guardrail cookies no
        # longer refer to installed OVS rules. Retire them under the real ledger
        # lock so later non-root tests/services do not see stale active entries.
        try:
            remaining_bridges = set(subprocess.check_output(
                ["ovs-vsctl", "list-br"], text=True
            ).split())
            lab_bridges = remaining_bridges.intersection({"s1", "s2", "s3", "s4"})
            if lab_bridges:
                raise RuntimeError(f"Mininet bridges remain after cleanup: {sorted(lab_bridges)}")
            from netops_guardrail.verifier.safety_verifier import (
                load_guardrail_cookies,
                remove_guardrail_cookie,
            )
            cookies = load_guardrail_cookies(LEDGER_PATH)
            for cookie in sorted(cookies):
                remove_guardrail_cookie(cookie, ledger_path=LEDGER_PATH)
            result["cleanup"] = {
                "lab_bridges_remaining": [],
                "retired_guardrail_cookies": len(cookies),
            }
        except Exception as cleanup_error:
            result["cleanup"] = {
                "error": f"Could not verify lab teardown or retire cookie ledger: {cleanup_error}"
            }

        # Persist final cleanup metadata before ownership normalization. A write
        # after chown would recreate a root-owned result JSON.
        persist_results()

        # The lab must run as root, but runtime records belong to the account
        # that owns the checkout so normal app/test processes can read them.
        if os.geteuid() == 0:
            repo_stat = os.stat(PROJECT_ROOT)
            runtime_roots = (
                PROJECT_ROOT / "audit",
                results_dir,
                TELEMETRY_PATH.parent,
            )
            for runtime_root in runtime_roots:
                if runtime_root.exists():
                    for runtime_path in runtime_root.rglob("*"):
                        os.chown(runtime_path, repo_stat.st_uid, repo_stat.st_gid)
                    os.chown(runtime_root, repo_stat.st_uid, repo_stat.st_gid)
            for runtime_file in (
                PROJECT_ROOT / "ping_loss_window.log",
                PROJECT_ROOT / "ping_rtt_under_bcast.log",
            ):
                if runtime_file.exists():
                    os.chown(runtime_file, repo_stat.st_uid, repo_stat.st_gid)
            for pattern in ("*.pem", "*.json", "*.lock"):
                for runtime_file in (PROJECT_ROOT / "audit").glob(pattern):
                    os.chmod(runtime_file, 0o600)
        print("Cleanup complete.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Must run as root (sudo).")
        sys.exit(1)
    run_live_experiment()
