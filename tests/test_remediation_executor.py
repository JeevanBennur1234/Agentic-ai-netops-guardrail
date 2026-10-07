import json
import pytest
from unittest.mock import MagicMock

from remediation_executor import RemediationExecutor
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
def mock_cmd_runner():
    """Mock command runner that simulates successful OVS add-flow and dump-flows."""
    installed_flows = []

    def runner(args):
        # args is a list of strings
        if "add-flow" in args:
            rule = args[-1]
            installed_flows.append(rule)
            return 0, "", ""
        elif "dump-flows" in args:
            # Return dump containing installed flows
            output = "NXST_FLOW reply (xid=0x4):\n" + "\n".join(installed_flows)
            return 0, output, ""
        return 0, "", ""

    return runner


class TestRemediationExecutor:

    def test_approved_intent_executes(self, mock_telemetry_file, mock_cmd_runner):
        executor = RemediationExecutor(
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

    def test_approved_block_intent_executes(self, mock_telemetry_file, mock_cmd_runner):
        executor = RemediationExecutor(
            telemetry_path=mock_telemetry_file,
            cmd_runner=mock_cmd_runner
        )
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "isolate faulty port"
        }
        res = executor.execute(
            intent=intent,
            decision="APPROVED",
            verifier_result={"safe": True}
        )
        assert res["success"] is True
        assert res["change_verified"] is True

    def test_rejected_intent_never_executes(self, mock_telemetry_file):
        spy_runner = MagicMock()
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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
        executor = RemediationExecutor(
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

        executor = RemediationExecutor(
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

    def test_failed_execution_is_recorded(self, tmp_path, mock_telemetry_file):
        log_file = str(tmp_path / "fail_audit.json")
        key_file = str(tmp_path / "fail_key.pem")
        trail = AuditTrail(log_path=log_file, key_path=key_file)

        # Fail runner
        def failing_runner(args):
            return 1, "", "OVS connection error"

        executor = RemediationExecutor(
            telemetry_path=mock_telemetry_file,
            cmd_runner=failing_runner
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
        valid, msg = trail.verify_chain(trail.chain)
        assert valid is True

    def test_post_execution_verification_detects_unsuccessful_change(self, mock_telemetry_file):
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

        executor = RemediationExecutor(
            telemetry_path=mock_telemetry_file,
            cmd_runner=phantom_success_runner
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
        assert "not found in active OVS flow table" in res["details"]
