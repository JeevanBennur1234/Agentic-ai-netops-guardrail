import json
import re
import pytest
from unittest.mock import MagicMock

from remediation_executor import RemediationExecutor
from safety_verifier import build_topology
from audit_trail import AuditTrail, GENESIS_HASH


@pytest.fixture
def mock_telemetry_file(tmp_path):
    telemetry_data = {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0},
                    "1": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100},
                    "2": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100},
                    "3": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100}
                },
                "flows": []
            }
        }
    }
    p = tmp_path / "latest.json"
    p.write_text(json.dumps(telemetry_data))
    return str(p)


@pytest.fixture
def mock_redundant_telemetry_file(tmp_path):
    counters = {
        "rx_packets": 10,
        "tx_packets": 10,
        "rx_bytes": 100,
        "tx_bytes": 100,
    }
    telemetry_data = {
        "switches": {
            "1": {"ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)}, "flows": []},
            "2": {"ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)}, "flows": []},
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "2", "src_port": "1", "dst_switch": "1", "dst_port": "2"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
            {"src_switch": "2", "src_port": "2", "dst_switch": "1", "dst_port": "3"},
        ],
    }
    p = tmp_path / "redundant_latest.json"
    p.write_text(json.dumps(telemetry_data))
    return str(p)


def redundant_topology_provider(telemetry_path):
    with open(telemetry_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)
    pre_graph = build_topology(telemetry)
    post_graph = pre_graph.copy()
    post_graph.remove_node("s1-p2")

    def provider(phase="pre"):
        return (post_graph if phase == "post" else pre_graph, None)

    return provider


@pytest.fixture
def mock_cmd_runner():
    """Mock command runner that simulates successful OVS add-flow and dump-flows."""
    installed_flows = []

    def runner(args):
        # args is an array, like the production executor's subprocess call.
        if "add-flow" in args:
            installed_flows.append(args[-1])
            return 0, "", ""
        if "del-flows" in args:
            filter_arg = args[-1] if args else ""
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
        if "dump-flows" in args:
            return 0, "NXST_FLOW reply (xid=0x4):\n" + "\n".join(installed_flows), ""
        return 0, "", ""

    runner.installed_flows = installed_flows
    return runner


class TestRemediationExecutor:

    def test_approved_intent_executes(self, mock_telemetry_file, mock_cmd_runner):
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=mock_cmd_runner
        )
        intent = {
            "action": "no_action",
            "reason": "nominal state"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is True
        assert res["change_verified"] is True
        assert res["safety_verified"] is True

    def test_approved_block_intent_executes(
        self, mock_redundant_telemetry_file, mock_cmd_runner
    ):
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "isolate redundant trunk port"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is True
        assert res["change_verified"] is True
        assert res["target_ports"] == [(1, 2), (2, 1)]
        assert len(mock_cmd_runner.installed_flows) == 2

    def test_rejected_intent_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "1",
            "reason": "unsafe block"
        }
        res = executor.execute(
            intent=intent,
            decision="REJECTED",
            verifier_result={"safe": False}
        )
        assert res["success"] is False
        assert "not APPROVED" in res["error"]
        spy_runner.assert_not_called()

    def test_local_port_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "4294967294",
            "reason": "malicious local port"
        }
        # Even if artificially passed decision='APPROVED'
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "4294967294" in res["error"]
        spy_runner.assert_not_called()

    def test_nonexistent_switch_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "block",
            "target_switch": "99",
            "from_port": "1",
            "reason": "bad switch"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "does not exist in topology" in res["error"]
        spy_runner.assert_not_called()

    def test_nonexistent_port_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "99",
            "reason": "bad port"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "does not exist in topology" in res["error"]
        spy_runner.assert_not_called()

    def test_unsupported_action_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "drop_table",
            "reason": "unsupported action"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "unsupported action" in res["error"]
        spy_runner.assert_not_called()

    def test_malformed_intent_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        # Non-dict intent
        res = executor.execute(
            intent="invalid string",
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "malformed" in res["error"]
        spy_runner.assert_not_called()

    def test_executor_cannot_bypass_decision_gate(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=spy_runner
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "1",
            "reason": "attempted bypass"
        }

        # Bypasses with non-approved states:
        for invalid_decision in [None, "PENDING", "UNKNOWN", ""]:
            res = executor.execute(
                intent=intent,
                decision=invalid_decision,
                verifier_result={"safe": True}
            )
            assert res["success"] is False
            assert "not APPROVED" in res["error"]

        # Bypasses with unsafe verifier_result:
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": False}
        )
        assert res["success"] is False
        assert "not marked safe" in res["error"]
        spy_runner.assert_not_called()

    def test_successful_execution_is_recorded(self, tmp_path, mock_telemetry_file, mock_cmd_runner):
        log_file = str(tmp_path / "exec_audit.json")
        key_file = str(tmp_path / "exec_key.pem")
        trail = AuditTrail(log_path=log_file, key_path=key_file)

        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=mock_cmd_runner
        )
        intent = {"action": "no_action", "reason": "nominal"}
        verifier_res = {"safe": True}
        decision = "APPROVED"

        exec_res = executor.execute(intent, decision, verifier_res)
        assert exec_res["success"] is True

        # Record in cryptographic audit trail
        rec = trail.record_decision(
            decision=decision,
            intent=intent,
            verifier_result=verifier_res,
            execution_result=exec_res
        )

        assert "execution_result" in rec
        assert rec["execution_result"]["success"] is True

        # Verify chain integrity
        valid, msg = trail.verify_chain(trail.chain)
        assert valid is True
        assert "Chain integrity verified" in msg

    def test_failed_execution_is_recorded(self, tmp_path, mock_redundant_telemetry_file):
        log_file = str(tmp_path / "fail_audit.json")
        key_file = str(tmp_path / "fail_key.pem")
        trail = AuditTrail(log_path=log_file, key_path=key_file)

        # Inspection succeeds, but adding the rule fails. The executor must
        # still attempt cookie-scoped cleanup and report the rollback outcome.
        def failing_runner(args):
            if "dump-flows" in args:
                return 0, "", ""
            if "add-flow" in args:
                return 1, "", "OVS connection error"
            if "del-flows" in args:
                return 0, "", ""
            return 0, "", ""

        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=failing_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        intent = {"action": "block", "target_switch": "1", "from_port": "2", "reason": "test"}
        verifier_res = {"safe": True}
        decision = "APPROVED"

        exec_res = executor.execute(intent, decision, verifier_res)
        assert exec_res["success"] is False

        rec = trail.record_decision(
            decision=decision,
            intent=intent,
            verifier_result=verifier_res,
            execution_result=exec_res
        )

        assert rec["execution_result"]["success"] is False
        assert rec["execution_result"]["rollback_attempted"] is True
        assert rec["execution_result"]["rollback_success"] is True
        valid, msg = trail.verify_chain(trail.chain)
        assert valid is True

    def test_post_execution_verification_detects_unsuccessful_change(self, mock_redundant_telemetry_file):
        """
        Simulate a case where ovs-ofctl returned exit code 0,
        but the rule was silently dropped and is NOT in the dump-flows output.
        The executor must detect this and report failure!
        """
        def phantom_success_runner(args):
            if "add-flow" in args:
                # Returns 0 as if it succeeded
                return 0, "", ""
            elif "dump-flows" in args:
                # But flow table does NOT contain the rule!
                return 0, "NXST_FLOW reply (xid=0x4):\n (empty flow table)", ""
            return 0, "", ""

        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=phantom_success_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "phantom test"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )

        # Must report failure despite exit code 0!
        assert res["success"] is False
        assert res["change_verified"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        assert "not found in active OVS flow table" in res["details"]

    def test_executor_rejects_access_port_even_if_verifier_claims_safe(
        self, mock_telemetry_file, mock_cmd_runner
    ):
        with open(mock_telemetry_file, "r", encoding="utf-8") as f:
            graph = build_topology(json.load(f))
        # Deliberately include the target access port in the required-host list:
        # the executor must reject it independently of how the caller labels hosts.
        provider = lambda phase="pre": (graph, ["s1-p1", "s1-p2", "s1-p3"])
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=provider,
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "unsafe access-port block",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "access endpoint" in res["error"]
        assert mock_cmd_runner.installed_flows == []

    def test_post_safety_failure_rolls_back_verified_flow(
        self, mock_redundant_telemetry_file, mock_cmd_runner, monkeypatch
    ):
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        monkeypatch.setattr(
            executor, "_verify_topology_safety",
            lambda: (False, "simulated post-change reachability failure"),
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "safe trunk isolation test",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert res["change_verified"] is True
        assert res["safety_verified"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        assert mock_cmd_runner.installed_flows == []
        assert "simulated post-change reachability failure" in res["error"]

    def test_live_connectivity_success_reports_two_ended_block(
        self, mock_redundant_telemetry_file, mock_cmd_runner
    ):
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
            connectivity_checker=lambda: True,
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "redundant trunk test",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is True
        assert res["connectivity_verified"] is True
        assert res["target_ports"] == [(1, 2), (2, 1)]
        assert len(mock_cmd_runner.installed_flows) == 2

    def test_live_connectivity_failure_rolls_back_both_trunk_ends(
        self, mock_redundant_telemetry_file, mock_cmd_runner
    ):
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
            connectivity_checker=lambda: False,
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "forced connectivity failure",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert res["connectivity_verified"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is True
        assert mock_cmd_runner.installed_flows == []
        assert "connectivity check failed" in res["error"].lower()

    def test_rollback_failure_is_reported_honestly(
        self, mock_redundant_telemetry_file, mock_cmd_runner, monkeypatch
    ):
        def failing_delete_runner(args):
            if "del-flows" in args:
                return 1, "", "simulated delete failure"
            return mock_cmd_runner(args)

        failing_delete_runner.installed_flows = mock_cmd_runner.installed_flows
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=failing_delete_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        monkeypatch.setattr(
            executor, "_verify_topology_safety",
            lambda: (False, "simulated post-change reachability failure"),
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "rollback failure test",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert res["rollback_attempted"] is True
        assert res["rollback_success"] is False
        assert "Rollback FAILED" in res["error"]
        assert any(
            "in_port=2" in line and "actions=drop" in line
            for line in failing_delete_runner.installed_flows
        )

    def test_refuses_to_overwrite_matching_priority_flow(
        self, mock_redundant_telemetry_file
    ):
        calls = []

        def runner(args):
            calls.append(args)
            if "dump-flows" in args:
                return 0, (
                    "cookie=0x55, duration=1s, table=0, n_packets=0, "
                    "n_bytes=0, priority=65500,in_port=2 actions=drop\n"
                ), ""
            return 0, "", ""

        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "collision test",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "Refusing to overwrite" in res["error"]
        assert not any("add-flow" in args for args in calls)

    def test_missing_topology_fails_closed(self, tmp_path):
        spy_runner = MagicMock()
        missing = str(tmp_path / "missing-telemetry.json")
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False, telemetry_path=missing, cmd_runner=spy_runner)
        res = executor.execute(
            intent={"action": "no_action", "reason": "missing topology"},
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "fail-closed" in res["error"]
        spy_runner.assert_not_called()

    def test_reroute_is_rejected_until_forwarding_aware_verifier_exists(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(require_human_approval=False, require_connectivity_check=False, telemetry_path=mock_telemetry_file, cmd_runner=spy_runner)
        res = executor.execute(
            intent={"action": "reroute", "target_switch": "1", "from_port": "2", "to_port": "3", "reason": "test"},
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is False
        assert "forwarding-aware" in res["error"]
        spy_runner.assert_not_called()


    def test_live_block_fails_closed_without_required_connectivity_checker(
        self, mock_redundant_telemetry_file, mock_cmd_runner
    ):
        executor = RemediationExecutor(
            require_human_approval=False,
            require_connectivity_check=True,
            telemetry_path=mock_redundant_telemetry_file,
            cmd_runner=mock_cmd_runner,
            topology_provider=redundant_topology_provider(mock_redundant_telemetry_file),
        )
        res = executor.execute(
            intent={
                "action": "block",
                "target_switch": "1",
                "from_port": "2",
                "reason": "missing live connectivity checker",
            },
            decision="APPROVED",
            verifier_result={"safe": True},
        )
        assert res["success"] is False
        assert "connectivity checker is required" in res["error"]
        assert res["rollback_attempted"] is False
        assert mock_cmd_runner.installed_flows == []
