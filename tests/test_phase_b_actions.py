import json
import re
import time
from datetime import datetime, timezone

import pytest

from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.controller.decision_gate import apply_intent_to_graph, decide
from netops_guardrail.controller.human_verifier import ApprovalError, HumanApprovalStore
from netops_guardrail.executor.remediation_executor import RemediationExecutor
from netops_guardrail.verifier.safety_verifier import (
    build_topology,
    simulate_remove_flow,
    simulate_restore_port,
)


def approve(store, proposal):
    return store.decide(
        proposal["proposal_id"],
        "approve",
        approver_id="test-network-admin",
        reason="Reviewed test proposal",
        proposal_fingerprint_value=proposal["proposal_fingerprint"],
    )


@pytest.fixture
def phase_b_redundant_telemetry(tmp_path):
    counters = {
        "rx_packets": 100,
        "tx_packets": 100,
        "rx_bytes": 1000,
        "tx_bytes": 1000,
    }
    telemetry_data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {
            "1": {
                "ports": {
                    "1": dict(counters),  # access to h1
                    "2": dict(counters),  # trunk to s2-p1 (active)
                    "3": dict(counters),  # trunk to s2-p2 (redundant)
                },
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
                "flows": []
            },
            "2": {
                "ports": {
                    "1": dict(counters),  # trunk to s1-p2 (active)
                    "2": dict(counters),  # trunk to s1-p3 (STP blocked)
                    "3": dict(counters),  # access to h2
                },
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                "flows": []
            },
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "2", "src_port": "1", "dst_switch": "1", "dst_port": "2"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
            {"src_switch": "2", "src_port": "2", "dst_switch": "1", "dst_port": "3"},
        ],
    }
    path = tmp_path / "latest.json"
    path.write_text(json.dumps(telemetry_data), encoding="utf-8")
    return str(path)


@pytest.fixture
def phase_b_restore_telemetry(tmp_path):
    counters = {
        "rx_packets": 100,
        "tx_packets": 100,
        "rx_bytes": 1000,
        "tx_bytes": 1000,
    }
    telemetry_data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {
            "1": {
                "ports": {
                    "1": dict(counters),  # access to h1
                    "2": dict(counters),  # trunk s1-p2 (STP blocked)
                    "3": dict(counters),  # trunk s1-p3 (being restored)
                },
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                "flows": []
            },
            "2": {
                "ports": {
                    "1": dict(counters),  # trunk s2-p1 (STP blocked)
                    "2": dict(counters),  # trunk s2-p2 (FORWARD)
                    "3": dict(counters),  # access to h2
                },
                "stp_port_states": {"1": "BLOCK", "2": "FORWARD", "3": "FORWARD"},
                "flows": []
            },
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "2", "src_port": "1", "dst_switch": "1", "dst_port": "2"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
            {"src_switch": "2", "src_port": "2", "dst_switch": "1", "dst_port": "3"},
        ],
    }
    path = tmp_path / "restore_latest.json"
    path.write_text(json.dumps(telemetry_data), encoding="utf-8")
    return str(path)


@pytest.fixture
def mock_ovs_runner():
    """Smart mock OVS runner supporting flows, meters, mod-port, dump-ports-desc."""
    installed_flows = []
    port_states = {
        "s1": {"1": "0", "2": "0", "3": "0"},
        "s2": {"1": "0", "2": "0", "3": "0"},
    }
    installed_meters = {}
    history = []

    def runner(args):
        history.append(list(args))
        subcmd = None
        for a in args:
            if a in {"dump-ports-desc", "mod-port", "add-meter", "del-meter", "dump-meters", "add-flow", "del-flows", "dump-flows"}:
                subcmd = a
                break
        idx = args.index(subcmd) if subcmd else -1
        bridge = args[idx + 1] if idx >= 0 and idx + 1 < len(args) else "s1"

        if subcmd == "dump-ports-desc":
            br = bridge
            lines = ["OFPST_PORT_DESC reply (OF1.3) (xid=0x2):"]
            for p, state in port_states.get(br, {}).items():
                lines.append(f" {p}({br}-eth{p}): addr:00:00:00:00:00:0{p}")
                lines.append(f"     config:     {state}")
                lines.append("     state:      LIVE")
            return 0, "\n".join(lines), ""

        if subcmd == "mod-port":
            port = args[idx + 2]
            action = args[idx + 3]
            if bridge not in port_states:
                port_states[bridge] = {}
            if action == "down":
                port_states[bridge][port] = "PORT_DOWN"
            elif action == "up":
                port_states[bridge][port] = "0"
            return 0, "", ""

        if subcmd == "add-meter":
            meter_spec = args[idx + 2]
            m_match = re.search(r"\bmeter=(\d+)\b", meter_spec)
            m_id = m_match.group(1) if m_match else meter_spec
            installed_meters[m_id] = meter_spec
            return 0, "", ""

        if subcmd == "del-meter":
            meter_spec = args[idx + 2]
            m_match = re.search(r"\bmeter=(\d+)\b", meter_spec)
            m_id = m_match.group(1) if m_match else meter_spec
            installed_meters.pop(m_id, None)
            return 0, "", ""

        if subcmd == "dump-meters":
            lines = ["OFPST_METER_CONFIG reply (OF1.3):"]
            for m_id, spec in installed_meters.items():
                lines.append(f" {spec}")
            return 0, "\n".join(lines), ""

        if subcmd == "add-flow":
            flow_spec = args[idx + 2]
            installed_flows.append(flow_spec)
            return 0, "", ""

        if subcmd == "del-flows":
            filter_arg = args[idx + 2]
            cookie_match = re.search(r"cookie=0x([0-9a-f]+)/", filter_arg, re.IGNORECASE)
            if cookie_match:
                target_cookie = int(cookie_match.group(1), 16)
                kept = []
                for line in installed_flows:
                    found = re.search(r"\bcookie=0x([0-9a-f]+)\b", line, re.IGNORECASE)
                    if not found or int(found.group(1), 16) != target_cookie:
                        kept.append(line)
                installed_flows[:] = kept
            else:
                installed_flows.clear()
            return 0, "", ""

        if subcmd == "dump-flows":
            return 0, "NXST_FLOW reply (xid=0x4):\n" + "\n".join(installed_flows), ""

        return 0, "", ""

    runner.installed_flows = installed_flows
    runner.port_states = port_states
    runner.installed_meters = installed_meters
    runner.history = history
    return runner


# =========================================================================
# ACTION 1: disable_port
# =========================================================================

class TestDisablePortAction:

    def test_disable_port_accepted_and_executed(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        intent = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "3",  # redundant trunk
            "reason": "Administrative isolation of redundant trunk",
        }
        verifier_result = {"safe": True}

        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=proposal["proposal_id"],
        )

        assert res["success"] is True
        assert res["action"] == "disable_port"
        assert res["change_verified"] is True
        assert res["safety_verified"] is True
        assert res["connectivity_verified"] is True
        assert res["rollback_attempted"] is False
        assert mock_ovs_runner.port_states["s1"]["3"] == "PORT_DOWN"

        # Verify proposal was consumed
        consumed_prop = approval_store.get_proposal(proposal["proposal_id"])
        assert consumed_prop["status"] == "consumed"

    def test_disable_port_rejected_on_access_port(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "1",  # access port to h1
            "reason": "Try to isolate access port",
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "is an access endpoint" in res["error"]
        assert "isolates that host" in res["error"]

    def test_disable_port_rollback_after_failed_post_check(self, phase_b_redundant_telemetry, tmp_path):
        """If port remains UP after mod-port down, rollback (mod-port up) must be executed."""
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        runner_history = []

        def failing_runner(args):
            runner_history.append(list(args))
            cmd = args[4]
            if cmd == "dump-ports-desc":
                # Return port 3 without PORT_DOWN flag
                return 0, "OFPST_PORT_DESC reply (OF1.3):\n 3(s1-eth3): addr:00\n     config: 0\n     state: LIVE", ""
            return 0, "", ""

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=failing_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=False,
        )
        intent = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Administrative isolation",
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal["proposal_id"],
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        # Verify inverse command (mod-port s1 3 up) was called in history
        inverse_calls = [c for c in runner_history if "mod-port" in c and "up" in c]
        assert len(inverse_calls) >= 1

    def test_disable_port_missing_or_reused_approval(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=False,
        )
        intent = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Test approval rails",
        }
        # Missing approval
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=None,
        )
        assert res["success"] is False
        assert "valid human approval is required" in res["error"]

    def test_disable_port_delayed_convergence_passes(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        """Test with a checker that fails for 9s then passes (convergence window)."""
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        start_time = time.monotonic()

        def delayed_checker():
            return (time.monotonic() - start_time) >= 9.0

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=delayed_checker,
            convergence_window_seconds=25.0,
        )
        intent = {
            "action": "disable_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Test delayed convergence",
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal["proposal_id"],
        )
        assert res["success"] is True
        assert res["convergence_time_seconds"] >= 9.0


# =========================================================================
# ACTION 2: restore_port
# =========================================================================

class TestRestorePortAction:

    def test_restore_port_accepted_and_executed(self, phase_b_restore_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_restore_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        # Initially mark port 3 as down
        mock_ovs_runner.port_states["s1"]["3"] = "PORT_DOWN"

        intent = {
            "action": "restore_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Restore disabled port to service",
        }
        verifier_result = {"safe": True}
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_restore_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=proposal["proposal_id"],
        )
        assert res["success"] is True
        assert res["action"] == "restore_port"
        assert res["change_verified"] is True
        assert res["safety_verified"] is True
        assert mock_ovs_runner.port_states["s1"]["3"] == "0"

    def test_restore_port_rejected_if_creates_loop(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        # In redundant telemetry, primary trunk s1-p2 <-> s2-p1 is already forwarding.
        # Restoring s1-p3 would add a second forwarding path, causing a loop.
        intent = {
            "action": "restore_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Restore port that would form loop",
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "FAIL: Loop(s) present" in res["error"]

    def test_restore_port_rejected_not_in_inventory(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "restore_port",
            "target_switch": "1",
            "from_port": "99",  # not in topology inventory
            "reason": "Restore phantom port",
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "not in the known link/port inventory" in res["error"]

    def test_restore_port_rollback_on_connectivity_failure(self, phase_b_restore_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_restore_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: False,  # live ping fails!
            convergence_window_seconds=1.0,
        )
        intent = {
            "action": "restore_port",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Restore port but probe fails",
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_restore_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal["proposal_id"],
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        # Inverse mod-port down should have restored it to down
        assert mock_ovs_runner.port_states["s1"]["3"] == "PORT_DOWN"

    def test_restore_port_s4_both_uplinks_down_approved(self):
        """Simulation test: both uplinks of s4 down in ring4 -> restore of one is approved."""
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)
        graph = build_topology(telem)

        # Disconnect both uplinks of s4: s4-p3 <-> s2-p2 and s4-p4 <-> s3-p2
        for u, v in [("s4-p3", "s2-p2"), ("s4-p4", "s3-p2")]:
            if graph.has_edge(u, v):
                graph.remove_edge(u, v)

        from netops_guardrail.verifier.safety_verifier import check_connectivity
        conn, _ = check_connectivity(graph)
        assert conn is False

        # Restoring one uplink (s4-p3) reconnects s4 loop-free
        sim = simulate_restore_port(graph, switch="4", port="3")
        assert sim["safe"] is True

    def test_restore_port_stp_blocked_standby_link_rejected_loop(self):
        """Simulation test: restoring STP-blocked standby link that would create a loop -> rejected."""
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)
        graph = build_topology(telem)

        # In ring4 fixture, s4-p4 is STP-blocked while s4-p3 is forwarding.
        # Restoring s4-p4 adds a redundant forwarding path forming a loop
        sim = simulate_restore_port(graph, switch="4", port="4")
        assert sim["safe"] is False
        assert any("Loop(s) present" in c for c in sim["checks"])


# =========================================================================
# ACTION 3: remove_flow
# =========================================================================

class TestRemoveFlowAction:

    def test_remove_flow_accepted_and_executed(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        # Pre-seed an anomalous flow in the switch
        target_cookie = 0xabcdef1234567890
        target_flow = f"cookie=0x{target_cookie:016x},priority=100,in_port=2,actions=drop"
        mock_ovs_runner.installed_flows.append(target_flow)

        incident_context = {
            "drift_evidence": [
                {"cookie": f"0x{target_cookie:x}", "priority": 100, "match": {"in_port": "2"}}
            ]
        }
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": target_cookie,
            "priority": 100,
            "match": {"in_port": "2"},
            "reason": "Delete unauthorized marker flow",
        }
        verifier_result = {"safe": True}

        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=proposal["proposal_id"],
            incident_context=incident_context,
        )

        assert res["success"] is True
        assert res["action"] == "remove_flow"
        assert res["change_verified"] is True
        assert len(mock_ovs_runner.installed_flows) == 0

    def test_remove_flow_rejected_on_baseline_and_guardrail_flows(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        ledger_path = tmp_path / "guardrail_cookie_ledger.json"
        from netops_guardrail.verifier.safety_verifier import record_guardrail_cookie
        record_guardrail_cookie(123, action="block", bridge="s1", ledger_path=ledger_path)

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
            ledger_path=ledger_path,
        )
        # Table-miss baseline (priority 0)
        res0 = executor.execute(
            intent={"action": "remove_flow", "target_switch": "1", "cookie": 0, "priority": 0, "match": {}},
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res0["success"] is False
        assert "cannot delete table-miss baseline flow" in res0["error"]

        # MAC learning baseline (priority 1, cookie 0)
        res1 = executor.execute(
            intent={"action": "remove_flow", "target_switch": "1", "cookie": 0, "priority": 1, "match": {}},
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res1["success"] is False
        assert "cannot delete baseline MAC learning flow" in res1["error"]

        # Guardrail drop rule (cookie in ledger / priority 65500)
        res_guard = executor.execute(
            intent={"action": "remove_flow", "target_switch": "1", "cookie": 123, "priority": 65500, "match": {}},
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res_guard["success"] is False
        assert (
            "cannot delete active guardrail remediation drop rule" in res_guard["error"]
            or "present in guardrail ledger" in res_guard["error"]
            or "guardrail" in res_guard["error"].lower()
        )

    def test_remove_flow_rejected_if_not_in_drift_evidence(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        # Cookie does not appear in drift evidence
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x9999,
            "priority": 200,
            "match": {"in_port": "2"},
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            incident_context={"drift_evidence": [{"cookie": "0x1111", "priority": 200, "match": {"in_port": "2"}}]},
        )
        assert res["success"] is False
        assert "target flow does not appear in the incident's drift evidence" in res["error"]

    def test_intent_carrying_incident_context_rejected(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x1111,
            "priority": 100,
            "match": {"in_port": "2"},
            "incident_context": {"drift_evidence": []},
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "unauthorized unknown keys" in res["error"]
        assert "incident_context" in res["error"]

    def test_remove_flow_string_match_rejected(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x1111,
            "priority": 100,
            "match": "in_port=2",
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "strings not allowed" in res["error"]

    def test_remove_flow_invalid_match_fields_rejected(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x1111,
            "priority": 100,
            "match": {"unsupported_foo": "bar"},
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "unauthorized fields" in res["error"]

    def test_remove_flow_dumped_match_differs_from_evidence_refused(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        target_cookie = 0x5555
        target_flow = f"cookie=0x{target_cookie:016x},priority=150,in_port=2,actions=drop"
        mock_ovs_runner.installed_flows.append(target_flow)

        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": target_cookie,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        # Evidence says in_port=3
        incident_context = {
            "drift_evidence": [
                {"cookie": f"0x{target_cookie:x}", "priority": 150, "match": {"in_port": "3"}}
            ]
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            incident_context=incident_context,
        )
        assert res["success"] is False
        assert "differs from evidence" in res["error"]
        # Ensure switch was never mutated
        assert len(mock_ovs_runner.installed_flows) == 1

    def test_remove_flow_failed_deletion_never_adds_new_flow(self, phase_b_redundant_telemetry):
        target_cookie = 0x7777
        target_flow = f"cookie=0x{target_cookie:016x},priority=150,in_port=2,actions=drop"
        commands_run = []

        def failing_del_runner(args):
            commands_run.append(list(args))
            subcmd = None
            for a in args:
                if a in {"dump-flows", "del-flows", "add-flow"}:
                    subcmd = a
                    break
            if subcmd == "dump-flows":
                return 0, f"NXST_FLOW reply (xid=0x4):\n{target_flow}", ""
            if subcmd == "del-flows":
                return 1, "", "OVS deliberate failure on del-flows"
            return 0, "", ""

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=failing_del_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": target_cookie,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            incident_context={"drift_evidence": [{"cookie": f"0x{target_cookie:x}", "priority": 150, "match": {"in_port": "2"}}]},
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is False
        # Verify add-flow was never executed
        add_flow_calls = [c for c in commands_run if "add-flow" in c]
        assert len(add_flow_calls) == 0

    def test_remove_flow_refuses_guardrail_ledger_cookie(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        ledger_path = tmp_path / "guardrail_cookie_ledger.json"
        from netops_guardrail.verifier.safety_verifier import record_guardrail_cookie
        ledger_cookie = 0x987654321
        record_guardrail_cookie(ledger_cookie, action="block", bridge="s1", ledger_path=ledger_path)

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
            ledger_path=ledger_path,
        )
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": ledger_cookie,
            "priority": 100,
            "match": {"in_port": "1"},
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "present in guardrail ledger" in res["error"]


# =========================================================================
# ACTION 4: rate_limit_port
# =========================================================================

class TestRateLimitPortAction:

    def test_rate_limit_accepted_and_executed(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",  # access port to h1
            "rate_kbps": 5000,
            "reason": "Throttle flood on access port",
        }
        verifier_result = {"safe": True}
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=proposal["proposal_id"],
        )

        assert res["success"] is True
        assert res["action"] == "rate_limit_port"
        assert res["change_verified"] is True
        assert any("meter=1,kbps" in m for m in mock_ovs_runner.installed_meters.values())
        assert any("actions=meter:1,normal" in f for f in mock_ovs_runner.installed_flows)

    def test_rate_limit_port_meter_collision_refused(self, phase_b_redundant_telemetry, mock_ovs_runner):
        # Pre-install meter 1 in the switch
        mock_ovs_runner.installed_meters["1"] = "meter=1,kbps,band=type=drop,rate=1000"

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 5000,
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "meter ID 1 is already in use" in res["error"]

    def test_rate_limit_port_rollback_cleans_up_only_created_resources(self, phase_b_redundant_telemetry):
        history = []
        def failing_flow_runner(args):
            history.append(list(args))
            subcmd = None
            for a in args:
                if a in {"dump-meters", "add-meter", "add-flow", "del-meter", "dump-flows"}:
                    subcmd = a
                    break
            if subcmd == "dump-meters":
                return 0, "OFPST_METER_CONFIG reply (OF1.3):", ""
            if subcmd == "add-meter":
                return 0, "", ""
            if subcmd == "add-flow":
                return 1, "", "OVS flow addition failed"
            if subcmd == "del-meter":
                return 0, "", ""
            return 0, "", ""

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=failing_flow_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 4000,
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is True
        del_meter_calls = [c for c in history if "del-meter" in c]
        assert len(del_meter_calls) == 1
        # del-flows was NOT needed since flow failed to add
        del_flow_calls = [c for c in history if "del-flows" in c]
        assert len(del_flow_calls) == 0

    def test_rate_limit_rejected_on_trunk_port(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "2",  # trunk port to s2
            "rate_kbps": 5000,
            "reason": "Try to meter trunk",
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "is an inter-switch trunk" in res["error"]
        assert "rate limiting is permitted on access ports only" in res["error"]

    def test_rate_limit_rejected_out_of_bounds_rates(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        # Rate too low (< 100)
        res_low = executor.execute(
            intent={"action": "rate_limit_port", "target_switch": "1", "from_port": "1", "rate_kbps": 50},
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res_low["success"] is False
        assert "outside allowed range" in res_low["error"]

        # Rate too high (> 1,000,000)
        res_high = executor.execute(
            intent={"action": "rate_limit_port", "target_switch": "1", "from_port": "1", "rate_kbps": 5000000},
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res_high["success"] is False
        assert "outside allowed range" in res_high["error"]

    def test_rate_limit_rollback_after_failed_post_check(self, phase_b_redundant_telemetry, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        runner_history = []

        def failing_runner(args):
            runner_history.append(list(args))
            cmd = args[4]
            if cmd == "dump-flows":
                # Do not return the meter flow so verification fails
                return 0, "NXST_FLOW reply (OF1.3):", ""
            return 0, "", ""

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=failing_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=False,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 10000,
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal["proposal_id"],
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        # Verify rollback commands (del-flows and del-meter) were called
        del_flow_calls = [c for c in runner_history if "del-flows" in c]
        del_meter_calls = [c for c in runner_history if "del-meter" in c]
        assert len(del_flow_calls) >= 1
        assert len(del_meter_calls) >= 1


# =========================================================================
# UNSUPPORTED ACTION & REGRESSION TESTS
# =========================================================================

class TestUnsupportedAndRegressions:

    def test_unsupported_action_rejected(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        for bad_action in ["reboot_switch", "drop_table", "flapping_port"]:
            res = executor.execute(
                intent={"action": bad_action},
                decision="APPROVED",
                verifier_result={"safe": True},
            )
            assert res["success"] is False
            assert f"unsupported action '{bad_action}'" in res["error"]

    def test_regression_existing_block_behavior(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Isolate redundant trunk",
        }
        verifier_result = {"safe": True}
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result=verifier_result,
            approval_id=proposal["proposal_id"],
        )

        assert res["success"] is True
        assert res["action"] == "block"
        assert res["target_ports"] == [(1, 3), (2, 2)]
        assert len(mock_ovs_runner.installed_flows) == 2

    def test_regression_existing_no_action_behavior(self, phase_b_redundant_telemetry, mock_ovs_runner):
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        intent = {"action": "no_action", "reason": "nominal"}
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
        )

        assert res["success"] is True
        assert res["action"] == "no_action"
        assert res["change_verified"] is True
        assert res["safety_verified"] is True


class TestDecisionGatePhaseBIntegration:

    def test_decision_gate_creates_proposal_for_new_action(self, phase_b_redundant_telemetry, tmp_path, monkeypatch):
        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        audit_trail = AuditTrail(
            log_path=str(tmp_path / "audit_log.json"),
            key_path=str(tmp_path / "audit_key.pem"),
        )
        monkeypatch.setattr(
            "netops_guardrail.controller.decision_gate.propose_remediation",
            lambda telem, incident_context=None: {
                "action": "rate_limit_port",
                "target_switch": "1",
                "from_port": "1",
                "rate_kbps": 2000,
                "reason": "Agent mitigates flood",
            }
        )

        res = decide(
            telemetry_path=phase_b_redundant_telemetry,
            approval_store=approval_store,
            audit_logger=audit_trail,
            execute_approved=True,
            connectivity_checker=lambda: True,
        )

        assert res["decision"] == "PENDING_HUMAN_APPROVAL"
        assert res["verification"]["safe"] is True
        assert res["intent"]["action"] == "rate_limit_port"
        proposals = [p for p in approval_store.list_proposals() if p["status"] == "pending"]
        assert len(proposals) == 1
        assert proposals[0]["intent"]["action"] == "rate_limit_port"

    def test_decision_gate_executes_approved_proposal(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        with open(phase_b_redundant_telemetry, "r", encoding="utf-8") as f:
            telem_dict = json.load(f)
        graph = build_topology(telem_dict)

        approval_store = HumanApprovalStore(path=tmp_path / "approvals.json")
        audit_trail = AuditTrail(
            log_path=str(tmp_path / "audit_log.json"),
            key_path=str(tmp_path / "audit_key.pem"),
        )
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=True,
            connectivity_checker=lambda: True,
        )
        intent = {
            "action": "rate_limit_port",
            "target_switch": "1",
            "from_port": "1",
            "rate_kbps": 3000,
            "reason": "Approved rate limit",
        }
        verifier_result = apply_intent_to_graph(graph, intent)
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result=verifier_result,
            telemetry_path=phase_b_redundant_telemetry,
        )
        approve(approval_store, proposal)

        res = decide(
            telemetry_path=phase_b_redundant_telemetry,
            approval_store=approval_store,
            approval_id=proposal["proposal_id"],
            audit_logger=audit_trail,
            executor=executor,
            execute_approved=True,
            connectivity_checker=lambda: True,
        )

        assert res["decision"] == "APPROVED"
        assert res["verification"]["safe"] is True
        assert res["execution"]["success"] is True
        # Proposal is now consumed
        assert approval_store.get_proposal(proposal["proposal_id"])["status"] == "consumed"
        # Audit trail has entry with execution result
        assert len(audit_trail.chain) >= 1
        valid, msg = audit_trail.verify_chain(audit_trail.chain)
        assert valid is True

        assert res["execution"]["safety_verified"] is True
        assert res["execution"]["change_verified"] is True


# =========================================================================
# PHASE B3 TESTS: CLOSE REVIEW FINDINGS
# =========================================================================

class TestPhaseB3RestorePortSpecUnionMerge:
    """Requirement 1: restore_port link absent from telemetry, union-merged with spec file."""

    def test_restore_port_link_absent_and_partitioned_approved(self, tmp_path):
        """(a) Link absent from telemetry links + network partitioned -> restore approved."""
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)

        # Omit both s4 uplinks from telemetry links so s4 is partitioned
        telem["links"] = [
            l for l in telem["links"]
            if not (
                (str(l.get("src_switch")) == "4" and str(l.get("src_port")) in ("3", "4"))
                or (str(l.get("dst_switch")) == "4" and str(l.get("dst_port")) in ("3", "4"))
            )
        ]
        graph = build_topology(telem)

        from netops_guardrail.verifier.safety_verifier import check_connectivity
        conn, _ = check_connectivity(graph)
        assert conn is False, "Topology must be partitioned before restore"

        # Restoring s4-p3 re-adds the edge from topology_spec.json via union-merge
        sim = simulate_restore_port(graph, switch="4", port="3")
        assert sim["safe"] is True, f"Restore should be approved: {sim.get('reason')}"
        assert any("PASS: Topology is connected" in c for c in sim["checks"])

    def test_restore_port_link_absent_and_redundant_loop_rejected(self, tmp_path):
        """(b) Link absent from telemetry links + restoring redundant link creating loop -> rejected."""
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)

        # Remove only s4-p4 link from telemetry links; s4-p3 remains active/forwarding
        telem["links"] = [
            l for l in telem["links"]
            if not (
                (str(l.get("src_switch")) == "4" and str(l.get("src_port")) == "4")
                or (str(l.get("dst_switch")) == "4" and str(l.get("dst_port")) == "4")
            )
        ]
        graph = build_topology(telem)

        # Restoring s4-p4 would re-add the redundant link creating a cycle/loop
        sim = simulate_restore_port(graph, switch="4", port="4", require_loop_free=True)
        assert sim["safe"] is False
        assert any("Loop(s) present" in c for c in sim["checks"])

    def test_restore_port_link_present_port_down_same_behavior(self, tmp_path):
        """(c) Link present in telemetry links but port down -> same behavior."""
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)

        # Keep link in telem["links"], but set s4-p3 port state to DOWN
        telem["switches"]["4"]["port_status"]["3"] = {"state": "DOWN", "link_down": True}
        graph = build_topology(telem)

        # Restoring port 3 sets it UP and forwarding
        sim = simulate_restore_port(graph, switch="4", port="3")
        assert sim["safe"] is True


class TestPhaseB3RemoveFlowEvidenceAndNormalization:
    """Requirement 2: remove_flow non-empty bidirectional match, priority equality, OVS dump mapping."""

    def test_remove_flow_empty_match_rejected(self, phase_b_redundant_telemetry):
        from netops_guardrail.verifier.safety_verifier import load_telemetry
        telem = load_telemetry(phase_b_redundant_telemetry)
        graph = build_topology(telem)

        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x4444,
            "priority": 150,
            "match": {},
        }
        incident_context = {
            "drift_evidence": [{"cookie": "0x4444", "priority": 150, "match": {}}]
        }
        sim = simulate_remove_flow(graph, intent, incident_context=incident_context)
        assert sim["safe"] is False
        assert "non-empty match is required" in sim["reason"]

    def test_remove_flow_bidirectional_match_mismatch_rejected(self, phase_b_redundant_telemetry):
        from netops_guardrail.verifier.safety_verifier import load_telemetry
        telem = load_telemetry(phase_b_redundant_telemetry)
        graph = build_topology(telem)

        # Extra key in intent -> rejected
        intent_extra = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x4444,
            "priority": 150,
            "match": {"in_port": "2", "eth_type": "0x0800"},
        }
        incident_context = {
            "drift_evidence": [{"cookie": "0x4444", "priority": 150, "match": {"in_port": "2"}}]
        }
        sim = simulate_remove_flow(graph, intent_extra, incident_context=incident_context)
        assert sim["safe"] is False

        # Extra key in evidence -> rejected
        intent_missing = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x4444,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        incident_context_extra = {
            "drift_evidence": [
                {"cookie": "0x4444", "priority": 150, "match": {"in_port": "2", "eth_type": "0x0800"}}
            ]
        }
        sim2 = simulate_remove_flow(graph, intent_missing, incident_context=incident_context_extra)
        assert sim2["safe"] is False

    def test_remove_flow_priority_equality_required(self, phase_b_redundant_telemetry):
        from netops_guardrail.verifier.safety_verifier import load_telemetry
        telem = load_telemetry(phase_b_redundant_telemetry)
        graph = build_topology(telem)

        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x4444,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        # Evidence has priority 160
        incident_context = {
            "drift_evidence": [{"cookie": "0x4444", "priority": 160, "match": {"in_port": "2"}}]
        }
        sim = simulate_remove_flow(graph, intent, incident_context=incident_context)
        assert sim["safe"] is False
        assert "differs from evidence" in sim["reason"]

    def test_remove_flow_ovs_mapping_dl_type_0x88b5(self, phase_b_redundant_telemetry, mock_ovs_runner):
        """Map OVS dl_type to schema eth_type for 0x88b5."""
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
        )
        target_cookie = 0x88b5
        target_flow = f"cookie=0x{target_cookie:016x},priority=200,dl_type=0x88b5,actions=drop"
        mock_ovs_runner.installed_flows.append(target_flow)

        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": target_cookie,
            "priority": 200,
            "match": {"eth_type": "0x88b5"},
        }
        incident_context = {
            "drift_evidence": [
                {"cookie": f"0x{target_cookie:x}", "priority": 200, "match": {"eth_type": "0x88b5"}}
            ]
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            incident_context=incident_context,
        )
        assert res["success"] is True, f"Failed execution: {res.get('error')}"
        assert res["change_verified"] is True
        assert len(mock_ovs_runner.installed_flows) == 0

    def test_remove_flow_ovs_shorthand_ip_and_icmp(self, phase_b_redundant_telemetry, mock_ovs_runner):
        """Map OVS shorthand ip and icmp correctly."""
        from netops_guardrail.verifier.safety_verifier import (
            matches_strictly_equal,
        )

        # 'ip' maps to eth_type 0x0800
        ovs_ip = "ip,nw_dst=10.0.0.4"
        schema_ip = {"eth_type": "0x0800", "nw_dst": "10.0.0.4"}
        assert matches_strictly_equal(ovs_ip, schema_ip) is True

        # 'icmp' maps to eth_type 0x0800 and ip_proto 1
        ovs_icmp = "icmp,nw_src=10.0.0.1"
        schema_icmp = {"eth_type": "0x0800", "ip_proto": "1", "nw_src": "10.0.0.1"}
        assert matches_strictly_equal(ovs_icmp, schema_icmp) is True


class TestPhaseB3GuardrailLedgerReliability:
    """Requirement 3: Ledger unreadable/corrupt fail-closed, real file locking."""

    def test_ledger_corrupt_fails_closed(self, tmp_path, phase_b_redundant_telemetry, mock_ovs_runner):
        from netops_guardrail.verifier.safety_verifier import (
            CorruptLedgerError,
            load_guardrail_cookies,
            load_telemetry,
        )

        corrupt_ledger = tmp_path / "corrupt_ledger.json"
        corrupt_ledger.write_text("{invalid json format: corrupt", encoding="utf-8")

        with pytest.raises(CorruptLedgerError):
            load_guardrail_cookies(corrupt_ledger)

        telem = load_telemetry(phase_b_redundant_telemetry)
        graph = build_topology(telem)
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x1234,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        incident_context = {
            "drift_evidence": [{"cookie": "0x1234", "priority": 150, "match": {"in_port": "2"}}]
        }
        sim = simulate_remove_flow(graph, intent, incident_context=incident_context, ledger_path=corrupt_ledger)
        assert sim["safe"] is False
        assert "unreadable or corrupt" in sim["reason"]

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            require_human_approval=False,
            require_connectivity_check=False,
            ledger_path=corrupt_ledger,
        )
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            incident_context=incident_context,
        )
        assert res["success"] is False
        assert "unreadable or corrupt" in res["error"]

    def test_record_guardrail_cookie_refuses_corrupt_ledger_without_overwrite(self, tmp_path):
        from netops_guardrail.verifier.safety_verifier import (
            CorruptLedgerError,
            record_guardrail_cookie,
        )
        corrupt = tmp_path / "corrupt_write_ledger.json"
        original = b"{not valid json"
        corrupt.write_bytes(original)
        with pytest.raises(CorruptLedgerError, match="unreadable or corrupt"):
            record_guardrail_cookie(0xA001, action="block", bridge="s1", ledger_path=corrupt)
        assert corrupt.read_bytes() == original

    def test_remove_guardrail_cookie_refuses_corrupt_ledger(self, tmp_path):
        from netops_guardrail.verifier.safety_verifier import (
            CorruptLedgerError,
            remove_guardrail_cookie,
        )
        corrupt = tmp_path / "corrupt_remove_ledger.json"
        corrupt.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(CorruptLedgerError, match="unreadable or corrupt"):
            remove_guardrail_cookie(0xA002, ledger_path=corrupt)

    def test_block_does_not_mutate_ovs_when_ledger_cannot_be_written(
        self, tmp_path, phase_b_redundant_telemetry, mock_ovs_runner
    ):
        corrupt = tmp_path / "corrupt_block_ledger.json"
        corrupt.write_text("{not valid json", encoding="utf-8")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry, cmd_runner=mock_ovs_runner,
            require_human_approval=False, require_connectivity_check=False, ledger_path=corrupt,
        )
        result = executor.execute(
            {"action": "block", "target_switch": "1", "from_port": "3"},
            "APPROVED", {"safe": True},
        )
        assert result["success"] is False
        assert "ledger could not be persisted" in result["error"]
        assert not any("add-flow" in command for command in mock_ovs_runner.history)

    def test_rate_limit_does_not_mutate_ovs_when_ledger_cannot_be_written(
        self, tmp_path, phase_b_redundant_telemetry, mock_ovs_runner
    ):
        corrupt = tmp_path / "corrupt_rate_limit_ledger.json"
        corrupt.write_text("{not valid json", encoding="utf-8")
        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry, cmd_runner=mock_ovs_runner,
            require_human_approval=False, require_connectivity_check=False, ledger_path=corrupt,
        )
        intent = {"action": "rate_limit_port", "target_switch": "1", "from_port": "1", "rate_kbps": 1000}
        result = executor.execute(intent, "APPROVED", {"safe": True})
        assert result["success"] is False
        assert "ledger could not be persisted" in result["error"]
        assert not any("add-meter" in command or "add-flow" in command for command in mock_ovs_runner.history)

    def test_ledger_real_file_locking_read_modify_write(self, tmp_path):
        import threading

        from netops_guardrail.verifier.safety_verifier import (
            load_guardrail_cookies,
            record_guardrail_cookie,
            remove_guardrail_cookie,
        )

        ledger_file = tmp_path / "test_locked_ledger.json"
        num_threads = 10
        errors = []

        def worker(thread_idx):
            try:
                cookie = 0x1000 + thread_idx
                record_guardrail_cookie(cookie, action="block", bridge="s1", ledger_path=ledger_file)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Threading errors occurred during locked write: {errors}"
        cookies = load_guardrail_cookies(ledger_file)
        assert len(cookies) == num_threads
        for i in range(num_threads):
            assert (0x1000 + i) in cookies

        # Test rollback marking under lock
        remove_guardrail_cookie(0x1000, ledger_path=ledger_file)
        updated_cookies = load_guardrail_cookies(ledger_file)
        assert 0x1000 not in updated_cookies
        assert len(updated_cookies) == num_threads - 1


class TestPhaseB3EvidenceBinding:
    """Requirement 4: Evidence hash binding and execute endpoint incident context loading."""

    def test_tampered_evidence_after_approval_refused(self, phase_b_redundant_telemetry, tmp_path):
        approval_store = HumanApprovalStore(tmp_path / "approvals.json")
        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": 0x9999,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        original_context = {
            "drift_evidence": [{"cookie": "0x9999", "priority": 150, "match": {"in_port": "2"}}]
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_redundant_telemetry,
            incident_context=original_context,
        )
        assert proposal.get("evidence_hash") is not None
        approve(approval_store, proposal)

        # Caller tampers with evidence after approval
        tampered_context = {
            "drift_evidence": [{"cookie": "0x9999", "priority": 150, "match": {"in_port": "3"}}]
        }
        with pytest.raises(ApprovalError, match="tampered with after approval"):
            approval_store.validate_approved(
                proposal["proposal_id"],
                intent,
                {"safe": True},
                phase_b_redundant_telemetry,
                incident_context=tampered_context,
            )

        with pytest.raises(ApprovalError, match="tampered with after approval"):
            approval_store.consume_approval(
                proposal["proposal_id"],
                intent,
                {"safe": True},
                phase_b_redundant_telemetry,
                incident_context=tampered_context,
            )

    def test_execute_loads_incident_context_from_stored_proposal(self, phase_b_redundant_telemetry, mock_ovs_runner, tmp_path):
        approval_store = HumanApprovalStore(tmp_path / "approvals.json")
        target_cookie = 0x7777
        target_flow = f"cookie=0x{target_cookie:016x},priority=150,in_port=2,actions=drop"
        mock_ovs_runner.installed_flows.append(target_flow)

        intent = {
            "action": "remove_flow",
            "target_switch": "1",
            "cookie": target_cookie,
            "priority": 150,
            "match": {"in_port": "2"},
        }
        incident_context = {
            "drift_evidence": [{"cookie": f"0x{target_cookie:x}", "priority": 150, "match": {"in_port": "2"}}]
        }
        proposal = approval_store.create_proposal(
            intent=intent,
            verifier_result={"safe": True},
            telemetry_path=phase_b_redundant_telemetry,
            incident_context=incident_context,
        )
        approve(approval_store, proposal)

        executor = RemediationExecutor(
            telemetry_path=phase_b_redundant_telemetry,
            cmd_runner=mock_ovs_runner,
            approval_store=approval_store,
            require_human_approval=True,
            require_connectivity_check=False,
        )
        # Execute endpoint passes approval_id with incident_context=None; executor loads it from proposal
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True},
            approval_id=proposal["proposal_id"],
            incident_context=None,
        )
        assert res["success"] is True
        assert res["change_verified"] is True
        assert len(mock_ovs_runner.installed_flows) == 0


class TestPhaseB3AllowedActionsSingleSource:
    """Requirement 5: Assert single source of truth for allowed actions across all modules."""

    def test_allowed_actions_single_source_identity(self):
        from netops_guardrail.controller import decision_gate, human_verifier
        from netops_guardrail.executor import remediation_executor
        from netops_guardrail.verifier import safety_verifier

        assert safety_verifier.ALLOWED_ACTIONS == remediation_executor.SUPPORTED_ACTIONS
        assert (
            safety_verifier.MUTATION_ACTIONS
            == human_verifier.ALLOWLISTED_APPROVAL_ACTIONS
            == decision_gate.EXECUTABLE_REMEDIATION_ACTIONS
            == remediation_executor.MUTATION_ACTIONS
            == remediation_executor.EXECUTABLE_ACTIONS
        )
        assert "disable_port" in safety_verifier.ALLOWED_ACTIONS
        assert "restore_port" in safety_verifier.ALLOWED_ACTIONS
        assert "remove_flow" in safety_verifier.ALLOWED_ACTIONS
        assert "rate_limit_port" in safety_verifier.ALLOWED_ACTIONS
        assert "block" in safety_verifier.ALLOWED_ACTIONS
        assert "no_action" in safety_verifier.ALLOWED_ACTIONS
        assert "no_action" not in safety_verifier.MUTATION_ACTIONS


class TestPhaseB3GetAccessEndpoints:
    """Requirement 6: get_access_endpoints documentation and down trunk exclusion tests."""

    def test_single_switch_star_all_ports_are_access(self):
        import networkx as nx

        from netops_guardrail.verifier.safety_verifier import get_access_endpoints

        graph = nx.Graph()
        graph.add_node("s1", type="switch")
        for p in ["1", "2", "3"]:
            p_node = f"s1-p{p}"
            graph.add_node(p_node, type="port", switch_id="1", port_id=p)
            graph.add_edge("s1", p_node, kind="attachment")

        access = get_access_endpoints(graph)
        assert access == ["s1-p1", "s1-p2", "s1-p3"]

    def test_ring4_baseline_access_endpoints(self):
        from netops_guardrail.verifier.safety_verifier import get_access_endpoints
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)
        graph = build_topology(telem)

        access = get_access_endpoints(graph)
        # s1-p1, s1-p2 (h1, h2) and s4-p1, s4-p2 (h3, h4) are host access endpoints
        assert access == ["s1-p1", "s1-p2", "s4-p1", "s4-p2"]

    def test_ring4_down_trunk_excluded_from_access_endpoints(self):
        """Down or absent trunk ports must NOT be classified as host access endpoints."""
        from netops_guardrail.verifier.safety_verifier import get_access_endpoints
        fixture_path = "tests/fixtures/ring4_live_telemetry_fixture.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            telem = json.load(f)

        # Omit trunk link s1-p3 <-> s2-p1 from telemetry links (simulating link down)
        telem["links"] = [
            l for l in telem["links"]
            if not (
                (str(l.get("src_switch")) == "1" and str(l.get("src_port")) == "3")
                or (str(l.get("dst_switch")) == "1" and str(l.get("dst_port")) == "3")
            )
        ]
        graph = build_topology(telem)

        access = get_access_endpoints(graph)
        # Even with the trunk link absent from live links, s1-p3 and s2-p1 are excluded
        assert "s1-p3" not in access
        assert "s2-p1" not in access
        assert access == ["s1-p1", "s1-p2", "s4-p1", "s4-p2"]
