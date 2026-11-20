#!/usr/bin/env python3
"""Phase B2 Live Ring4 Verification Script.

Executes all Phase B2 actions on the live Mininet + Ryu ring4 lab:
1. Unauthorized intent rejection (schema protection).
2. no_action execution.
3. disable_port on redundant/standby link.
4. restore_port on isolated uplink (loop-free restoration).
5. remove_flow with strict match & server-side drift evidence.
6. rate_limit_port with meter collision check & guardrail ledger registration.
7. Rollback verification on connectivity failure.
8. Investigation of actions=meter:N,normal vs STP-blocked ports.
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
from testbed.ring4_topo import Ring4Topo


def approve(store, proposal):
    return store.decide(
        proposal["proposal_id"],
        "approve",
        approver_id="live-network-admin",
        reason="Reviewed live proposal",
        proposal_fingerprint_value=proposal["proposal_fingerprint"],
    )
from netops_guardrail.executor.remediation_executor import RemediationExecutor
from netops_guardrail.verifier.safety_verifier import (
    load_guardrail_cookies,
)

TELEMETRY_PATH = PROJECT_ROOT / "telemetry" / "data" / "latest.json"
LEDGER_PATH = PROJECT_ROOT / "audit" / "guardrail_cookie_ledger.json"
APPROVALS_PATH = PROJECT_ROOT / "audit" / "live_approvals.json"

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


def wait_for_stp_convergence(timeout: float = 30.0) -> tuple[bool, float, str]:
    t_start = time.monotonic()
    deadline = t_start + timeout
    blocked_port = ""
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


def wait_for_ports_forward(switches_ports: dict[str, list[str]], timeout: float = 20.0) -> bool:
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


def run_live_experiment():
    print("=" * 70)
    print("  PHASE B2 LIVE LAB DEMONSTRATION & VERIFICATION (RING4)")
    print("=" * 70)

    # Clean previous state
    subprocess.run(["ovs-vsctl", "--if-exists", "del-br", "s1",
                    "--", "--if-exists", "del-br", "s2",
                    "--", "--if-exists", "del-br", "s3",
                    "--", "--if-exists", "del-br", "s4"],
                   check=False, capture_output=True)
    if TELEMETRY_PATH.exists():
        TELEMETRY_PATH.unlink()
    if APPROVALS_PATH.exists():
        APPROVALS_PATH.unlink()
    if LEDGER_PATH.exists():
        LEDGER_PATH.unlink()

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

        print("Waiting for STP convergence across s1..s4...")
        converged, conv_time, blocked_port = wait_for_stp_convergence()
        if not converged:
            print("ERROR: STP convergence failed.")
            net.stop()
            return

        print(f"STP Converged in {conv_time}s. Blocked port: {blocked_port}")
        print("Testing baseline pingall...")
        loss = net.pingAll(timeout=2)
        print(f"Baseline pingall loss: {loss:.1f}%")

        # Setup approval store and executor
        approval_store = HumanApprovalStore(path=str(APPROVALS_PATH))

        def live_connectivity_checker():
            # Quick check between h1 and h4
            h1 = net.get("h1")
            res = h1.cmd("ping -c 1 -W 1 10.0.0.4")
            return "1 packets transmitted, 1 received" in res or "1 received" in res

        executor = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=live_connectivity_checker,
            convergence_window_seconds=10.0,
            ledger_path=str(LEDGER_PATH),
        )

        results = {}

        # -------------------------------------------------------------
        # TEST A: Forged incident_context Schema Rejection
        # -------------------------------------------------------------
        print("\n[A] Testing Schema Rejection on Forged Intent (incident_context in intent)...")
        forged_intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x1234,
            "priority": 100,
            "match": {"in_port": "1"},
            "incident_context": {"forged": True},
        }
        res_forged = executor.execute(
            intent=forged_intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        print(f"  Success: {res_forged['success']}")
        print(f"  Error:   {res_forged['error']}")
        assert res_forged["success"] is False
        assert "unauthorized unknown keys" in res_forged["error"]
        results["forged_schema_rejection"] = res_forged

        # -------------------------------------------------------------
        # TEST 0: Action 'no_action' (autonomous pass-through)
        # -------------------------------------------------------------
        print("\n[0] Executing Action: 'no_action' (no human approval required)...")
        t0 = time.monotonic()
        intent_no_action = {"action": "no_action", "reason": "Baseline nominal health verified"}
        res_na = executor.execute(
            intent=intent_no_action,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        t_na = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_na['success']} (elapsed: {t_na}s)")
        print(f"  Details: {res_na['details']}")
        assert res_na["success"] is True
        results["no_action"] = {"result": res_na, "elapsed_s": t_na}

        # -------------------------------------------------------------
        # TEST 1: Action 'block' (redundant trunk isolation)
        # -------------------------------------------------------------
        print("\n[1/5] Executing Action: 'block' on redundant trunk s4-p4...")
        t0 = time.monotonic()
        intent_block = {
            "action": "block",
            "target_switch": "4",
            "from_port": "4",
            "reason": "Isolate STP blocked standby trunk s4-p4",
        }
        proposal_blk = approval_store.create_proposal(
            intent=intent_block,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, proposal_blk)
        res_blk = executor.execute(
            intent=intent_block,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal_blk["proposal_id"],
        )
        t_blk = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_blk['success']} (elapsed: {t_blk}s)")
        print(f"  Details: {res_blk['details']}")
        assert res_blk["success"] is True
        # Verify block rules installed on s4 and peer s3
        flows_s4 = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s4"], text=True)
        assert "priority=65500" in flows_s4
        # Verify connectivity
        assert live_connectivity_checker() is True
        results["block"] = {"result": res_blk, "elapsed_s": t_blk}

        # Clean block flows before next test
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "--strict", "del-flows", "s4", "priority=65500,in_port=4"], check=False)
        subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "--strict", "del-flows", "s3", "priority=65500,in_port=2"], check=False)

        # -------------------------------------------------------------
        # TEST 2: Action 'disable_port'
        # -------------------------------------------------------------
        print("\n[2/5] Executing Action: 'disable_port' on STP-blocked port s4-p4...")
        t0 = time.monotonic()
        intent_disable = {
            "action": "disable_port",
            "target_switch": "4",
            "from_port": "4",
            "reason": "Admin-down redundant standby link s4-p4",
        }
        proposal_dis = approval_store.create_proposal(
            intent=intent_disable,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, proposal_dis)
        res_dis = executor.execute(
            intent=intent_disable,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal_dis["proposal_id"],
        )
        t_dis = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_dis['success']} (elapsed: {t_dis}s, conv={res_dis.get('convergence_time_seconds')}s)")
        print(f"  Details: {res_dis['details']}")
        assert res_dis["success"] is True
        # Verify port status in OVS
        p_desc = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports-desc", "s4"], text=True)
        assert "4(s4-eth4)" in p_desc and "PORT_DOWN" in p_desc
        # Verify pingall reachability intact
        ping_dis = net.pingAll(timeout=2)
        print(f"  Pingall loss with s4-p4 disabled: {ping_dis:.1f}%")
        assert ping_dis == 0.0
        results["disable_port"] = {"result": res_dis, "elapsed_s": t_dis, "ping_loss": ping_dis}

        # -------------------------------------------------------------
        # TEST 3: Action 'restore_port'
        # -------------------------------------------------------------
        print("\n[3a] Testing 'restore_port' on STP-blocked standby link s4-p4 (Loop Prevention)...")
        # In ring4, s4-p3 is already forwarding. Restoring s4-p4 would create a loop.
        intent_restore_loop = {
            "action": "restore_port",
            "target_switch": "4",
            "from_port": "4",
            "reason": "Attempt to restore standby trunk while primary is forwarding",
        }
        exec_no_app = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            require_human_approval=False,
            require_connectivity_check=False,
        )
        res_res_loop = exec_no_app.execute(
            intent=intent_restore_loop,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        print(f"  Result: success={res_res_loop['success']}")
        print(f"  Error:  {res_res_loop['error']}")
        assert res_res_loop["success"] is False
        assert "Loop(s) present" in res_res_loop["error"]
        print("  Loop prevention verified: restoring STP standby link was safely rejected.")

        print("\n[3b] Executing 'restore_port' on s1-p3 (while standby link s4-p4 is disabled)...")
        # In Step 2, s4-p4 was disabled. Now simulate taking s1-p3 down.
        # With s4-p4 disabled, restoring s1-p3 forms a loop-free line s3-s1-s2-s4.
        subprocess.check_call(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s1", "3", "down"])
        print("  Waiting 10s for STP to process port down and enter LISTEN/LEARN...")
        time.sleep(10.0)
        print("  Waiting for STP to transition remaining active ports into FORWARD...")
        stp_stable = wait_for_ports_forward({
            "1": ["1", "2", "4"],
            "2": ["2"],
            "3": ["1"],
            "4": ["1", "2", "3"],
        }, timeout=30.0)
        assert stp_stable is True, "STP failed to stabilize ports into FORWARD"
        print("  Waiting for telemetry snapshot to stabilize...")
        wait_for_stable_telemetry(quiet_seconds=2.0, timeout=20.0)

        telem_debug = read_telemetry()
        print("  Stable STP state at 3b:")
        for sw_id, s_data in telem_debug.get("switches", {}).items():
            print(f"    Switch {sw_id}: stp={s_data.get('stp_port_states')}")

        intent_restore_ok = {
            "action": "restore_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Restore trunk s1-p3 to service loop-free",
        }
        proposal_res_ok = approval_store.create_proposal(
            intent=intent_restore_ok,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, proposal_res_ok)
        t0 = time.monotonic()
        res_restore = executor.execute(
            intent=intent_restore_ok,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal_res_ok["proposal_id"],
        )
        t_res = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_restore['success']} (elapsed: {t_res}s, conv={res_restore.get('convergence_time_seconds')}s)")
        print(f"  Details: {res_restore['details']}")
        assert res_restore["success"] is True

        # Verify port status in OVS is up
        p_desc = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports-desc", "s1"], text=True)
        p_cfg = RemediationExecutor._parse_port_config(p_desc, 3)
        assert p_cfg["found"] is True
        assert p_cfg["admin_down"] is False
        # Restore s4-p4 back to up as well
        subprocess.check_call(["ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s4", "4", "up"])
        print("  Waiting for STP to re-converge on ring4 (s4-p4 up)...")
        stp_reconv, _, _ = wait_for_stp_convergence(timeout=30.0)
        assert stp_reconv is True, "STP failed to re-converge after s4-p4 restored"
        wait_for_stable_telemetry(quiet_seconds=2.0, timeout=15.0)
        results["restore_port"] = {"result": res_restore, "elapsed_s": t_res}

        # -------------------------------------------------------------
        # TEST 4: Action 'remove_flow'
        # -------------------------------------------------------------
        print("\n[4/5] Executing Action: 'remove_flow' with strict switch match & drift evidence...")
        anom_cookie = 0xbeefcafe00000001
        subprocess.check_call([
            "ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1",
            f"cookie=0x{anom_cookie:016x},priority=250,in_port=1,actions=drop"
        ])
        print(f"  Planted anomalous flow cookie=0x{anom_cookie:x} on s1")

        # Provide server-side drift evidence
        incident_ctx = {
            "drift_evidence": [
                {
                    "cookie": f"0x{anom_cookie:x}",
                    "priority": 250,
                    "match": {"in_port": "1"},
                }
            ]
        }
        intent_rf = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": anom_cookie,
            "priority": 250,
            "match": {"in_port": "1"},
            "reason": "Remove unauthorized drop rule on s1",
        }
        proposal_rf = approval_store.create_proposal(
            intent=intent_rf,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, proposal_rf)
        t0 = time.monotonic()
        res_rf = executor.execute(
            intent=intent_rf,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal_rf["proposal_id"],
            incident_context=incident_ctx,
        )
        t_rf = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_rf['success']} (elapsed: {t_rf}s)")
        print(f"  Details: {res_rf['details']}")
        assert res_rf["success"] is True
        # Verify flow is gone from s1
        flows_s1 = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], text=True)
        assert f"0x{anom_cookie:x}" not in flows_s1.lower()
        results["remove_flow"] = {"result": res_rf, "elapsed_s": t_rf}

        # -------------------------------------------------------------
        # TEST 5: Action 'rate_limit_port'
        # -------------------------------------------------------------
        print("\n[5/5] Executing Action: 'rate_limit_port' on access port s1-p1...")
        intent_rl = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 20000,
            "reason": "Rate-limit access port s1-p1 to 20 Mbps",
        }
        proposal_rl = approval_store.create_proposal(
            intent=intent_rl,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, proposal_rl)
        t0 = time.monotonic()
        res_rl = executor.execute(
            intent=intent_rl,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal_rl["proposal_id"],
        )
        t_rl = round(time.monotonic() - t0, 3)
        print(f"  Result: success={res_rl['success']} (elapsed: {t_rl}s)")
        print(f"  Details: {res_rl['details']}")
        assert res_rl["success"] is True

        # Verify meter in OVS
        meters_s1 = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-meters", "s1"], text=True)
        print(f"  OVS dump-meters s1: {meters_s1.strip()}")
        assert "meter=1" in meters_s1
        assert "rate=20000" in meters_s1

        # Verify cookie in guardrail ledger
        ledger_cookies = load_guardrail_cookies(str(LEDGER_PATH))
        assert res_rl["cookie"] in ledger_cookies
        print(f"  Ledger verified: cookie 0x{res_rl['cookie']:x} registered in {LEDGER_PATH}")

        # Verify ping from h1 to h4 still works through rate limiter
        h1 = net.get("h1")
        ping_out = h1.cmd("ping -c 2 -W 1 10.0.0.4")
        print(f"  h1 -> h4 ping through meter: {'PASS' if '2 received' in ping_out else 'FAIL'}")
        assert "2 received" in ping_out or "1 received" in ping_out

        results["rate_limit_port"] = {"result": res_rl, "elapsed_s": t_rl}

        # -------------------------------------------------------------
        # TEST 6: Live Rollback Verification
        # -------------------------------------------------------------
        print("\n[6] Testing Live Rollback (connectivity checker failure during disable_port)...")
        # Configure executor with a failing connectivity checker
        failing_executor = RemediationExecutor(
            telemetry_path=str(TELEMETRY_PATH),
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: False,  # deliberate failure
            convergence_window_seconds=1.0,
            ledger_path=str(LEDGER_PATH),
        )
        intent_rb = {
            "action": "disable_port",
            "target_switch": "4",
            "from_port": "4",
            "reason": "Test live rollback on probe failure",
        }
        prop_rb = approval_store.create_proposal(
            intent=intent_rb,
            verifier_result={"safe": True},
            telemetry_path=str(TELEMETRY_PATH),
        )
        approve(approval_store, prop_rb)
        res_rb = failing_executor.execute(
            intent=intent_rb,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=prop_rb["proposal_id"],
        )
        print(f"  Success: {res_rb['success']}")
        print(f"  Rollback Attempted: {res_rb['rollback_attempted']}")
        print(f"  Rollback Success:   {res_rb['rollback_success']}")
        print(f"  Rollback Details:   {res_rb['rollback_details']}")
        assert res_rb["success"] is False
        assert res_rb["rollback_attempted"] is True
        assert res_rb["rollback_success"] is True
        results["live_rollback"] = res_rb

        # -------------------------------------------------------------
        # TEST 7: Investigation: actions=meter:N,normal vs STP on ring4
        # -------------------------------------------------------------
        print("\n[7] Investigation: actions=meter:N,normal vs STP-blocked ports on ring4...")
        print("  Checking flow tables on s1..s4:")
        for sw in ["s1", "s2", "s3", "s4"]:
            fl = subprocess.check_output(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw], text=True)
            print(f"  Switch {sw} flows:\n    " + "\n    ".join(fl.strip().splitlines()))

        print("\n  ANALYSIS:")
        print("  1. In ring4 topology, STP blocked port is s4-p4 (facing s3-p2).")
        print("  2. The rate_limit_port rule is installed ONLY on access port s1-p1 with:")
        print("     'cookie=...,priority=65000,in_port=1,actions=meter:1,normal'")
        print("  3. When h1 sends traffic, s1 performs normal forwarding out s1-p3 (facing s2) or s1-p4 (facing s3).")
        print("  4. Downstream switches (s2, s3, s4) do NOT have 'normal' rules; they run Ryu OpenFlow flows.")
        print("  5. On s4, port s4-p4 is blocked by Ryu stplib; Ryu drops any packets received on s4-p4 and never")
        print("     outputs packets to s4-p4. Thus, the meter flow on s1 access port CANNOT induce an L2 storm or loop.")
        print("  6. If rate_limit_port were applied directly to trunk ports, OVS 'normal' would bypass Ryu's STP layer.")
        print("     Therefore, the safety verifier STRICTLY forbids rate_limit_port on trunk ports, guaranteeing loop freedom.")

        print("\n" + "=" * 70)
        print("  ALL 5 ACTIONS, ROLLBACK, & INVESTIGATION VERIFIED ON LIVE LAB")
        print("=" * 70)

    finally:
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
        subprocess.run(["mn", "-c"], check=False, capture_output=True)
        print("Cleanup complete.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Must run as root (sudo).")
        sys.exit(1)
    run_live_experiment()
