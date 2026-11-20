"""Fail-closed regression test suite for Phase 1 backend pipeline orchestration.

Locks in the fail-closed requirements:
1. Stale telemetry -> no AI call.
2. Monitor heartbeat stale -> no inject.
3. Baseline connectivity fails -> no inject.
4. Invalid/empty LLM output -> no_action.
5. Safety fails or errors -> never reaches approval.
6. No connectivity checker -> execution refused.
7. Post-check fails -> rollback recorded.
8. Approval missing/expired/reused -> executor refuses.
9. Agent module imports no executor/subprocess/os.system.
10. Scope of execution: only block is executable; non-block faults terminate at recommendation_only.
"""

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from netops_guardrail.agent import remediation_agent as agent
from netops_guardrail.controller.decision_gate import decide
from netops_guardrail.controller.human_verifier import ApprovalError, HumanApprovalStore
from netops_guardrail.controller.monitor import IncidentMonitor, detect_incidents
from netops_guardrail.controller.pipeline_run import (
    PipelineRun,
    PipelineRunManager,
    check_injection_preconditions,
)
from netops_guardrail.observability.server import create_metrics_app
from netops_guardrail.verifier.safety_verifier import build_topology


# Helper to build fresh nominal telemetry snapshot
def _nominal_telemetry():
    now = datetime.now(timezone.utc)
    return {
        "updated_at_utc": now.isoformat(),
        "switches": {
            "1": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
            },
            "2": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "BLOCK"},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
            },
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "link_events": [],
    }


# 1. Stale telemetry -> no AI call
def test_stale_telemetry_prevents_ai_call(tmp_path):
    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    telemetry = _nominal_telemetry()
    telemetry["updated_at_utc"] = stale_time

    incidents = detect_incidents(telemetry, stale_after_seconds=30)
    assert len(incidents) == 1
    assert incidents[0]["type"] == "telemetry_stale"
    assert incidents[0]["remediation_allowed"] is False
    assert incidents[0]["execution_allowed"] is False

    # Verify IncidentMonitor does not dispatch AI call
    ai_called = []

    def fake_pipeline(**kwargs):
        ai_called.append(kwargs)
        return {"decision": "REJECTED"}

    monitor = IncidentMonitor(tmp_path, decision_pipeline=fake_pipeline, debounce_reads=1)
    emitted = monitor.process_snapshot(telemetry)
    assert len(emitted) == 1
    assert emitted[0]["type"] == "telemetry_stale"
    assert ai_called == []  # AI was never called


# 2. Monitor heartbeat stale -> no inject
def test_stale_monitor_heartbeat_refuses_injection(tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    # Monitor status is stale (>15 seconds)
    monitor_path = tmp_path / "monitor_status.json"
    old_heartbeat = (datetime.now(timezone.utc) - timedelta(seconds=25)).isoformat()
    monitor_path.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": old_heartbeat,
                "interval_seconds": 5,
            }
        ),
        encoding="utf-8",
    )

    manager = PipelineRunManager(tmp_path / "runs")
    allowed, error, code = check_injection_preconditions(
        telemetry_path=telemetry_path,
        monitor_status_path=monitor_path,
        connectivity_checker=lambda: True,
        manager=manager,
    )
    assert allowed is False
    assert "Incident monitor heartbeat is stale" in error
    assert code == 503


# 3. Baseline connectivity fails -> no inject
def test_failed_baseline_connectivity_refuses_injection(tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    # Fresh monitor status
    monitor_path = tmp_path / "monitor_status.json"
    monitor_path.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "interval_seconds": 5,
            }
        ),
        encoding="utf-8",
    )

    manager = PipelineRunManager(tmp_path / "runs")
    # Connectivity checker reports false (hosts cannot ping)
    allowed, error, code = check_injection_preconditions(
        telemetry_path=telemetry_path,
        monitor_status_path=monitor_path,
        connectivity_checker=lambda: False,
        manager=manager,
    )
    assert allowed is False
    assert "Baseline host-to-host connectivity check failed" in error
    assert code == 503


# 4. Invalid/empty LLM output -> no_action
def test_invalid_or_empty_llm_output_fails_closed_to_no_action(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    # Simulate empty response from Ollama
    class EmptyResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"response": ""}).encode("utf-8")

    monkeypatch.setattr(agent.urllib.request, "urlopen", lambda *a, **k: EmptyResponse())

    result = agent.propose_remediation(
        str(telemetry_path),
        incident_context={
            "fault_type": "standby_forwarding_anomaly",
            "source": "live_telemetry",
            "evidence_id": "ev-1",
            "evidence": {},
        },
    )
    assert result["action"] == "no_action"
    assert (
        "could not be parsed" in result["reason"]
        or "invalid" in result["_agent_metadata"]["status"]
    )

    # Simulate malformed schema
    class MalformedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"response": json.dumps({"action": "unknown_action_xyz"})}).encode(
                "utf-8"
            )

    monkeypatch.setattr(agent.urllib.request, "urlopen", lambda *a, **k: MalformedResponse())

    result_malformed = agent.propose_remediation(
        str(telemetry_path),
        incident_context={
            "fault_type": "standby_forwarding_anomaly",
            "source": "live_telemetry",
            "evidence_id": "ev-2",
            "evidence": {},
        },
    )
    assert result_malformed["action"] == "no_action"


# 5. Safety fails or errors -> never reaches approval
def test_safety_failure_never_reaches_approval(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    approval_store = HumanApprovalStore(path=str(tmp_path / "approvals.json"))

    # Intent to block the only active access port (isolating host)
    unsafe_intent = {
        "action": "block",
        "target_switch": "1",
        "from_port": "1",
        "reason": "adversarial block of host access port",
    }
    monkeypatch.setattr(agent, "propose_remediation", lambda *a, **k: unsafe_intent)

    result = decide(
        telemetry_path=str(telemetry_path),
        approval_store=approval_store,
        execute_approved=False,
    )
    assert result["decision"] == "REJECTED"
    assert result["verification"]["safe"] is False

    # Must NOT have created any pending or approved proposal in the approval store
    assert len(approval_store.list_proposals()) == 0


# 6. No connectivity checker -> execution refused
def test_no_connectivity_checker_refuses_execution(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    monkeypatch.delenv("NETOPS_CONNECTIVITY_CHECKER", raising=False)
    monkeypatch.setenv("NETOPS_APPROVER_TOKEN", "test-token")
    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", json.dumps({"test-admin": "test-token"}))

    app = create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(tmp_path / "audit.json"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    client = app.test_client()

    approval_store = app.config["NETOPS_APPROVAL_STORE"]
    prop = approval_store.create_proposal(
        intent={"action": "block", "target_switch": "1", "from_port": "3"},
        verifier_result={"safe": True, "checks": ["test"]},
        telemetry_path=str(telemetry_path),
        requested_by="operator",
    )
    approval_store.decide(
        proposal_id=prop["proposal_id"],
        decision="approved",
        approver_id="test-admin",
        reason="approved for test",
        proposal_fingerprint_value=prop["proposal_fingerprint"],
    )

    # Record the approved decision in audit trail so audit check passes
    audit = app.config["NETOPS_AUDIT"]
    audit.record_decision(
        decision="APPROVED",
        intent=prop["intent"],
        verifier_result=prop["verifier_result"],
        execution_result={
            "human_approval": {
                "proposal_id": prop["proposal_id"],
                "status": "approved",
                "approver_id": "test-admin",
                "reason": "approved for test",
                "proposal_fingerprint": prop["proposal_fingerprint"],
            }
        },
    )

    res = client.post(
        f"/api/approvals/{prop['proposal_id']}/execute",
        headers={"Authorization": "Bearer test-token"},
    )
    assert res.status_code == 503
    assert "configure NETOPS_CONNECTIVITY_CHECKER" in res.get_json()["error"]


# 7. Post-check fails -> rollback recorded
def test_post_check_fails_records_rollback(monkeypatch, tmp_path):
    import re

    from netops_guardrail.executor.remediation_executor import RemediationExecutor

    telem = _nominal_telemetry()
    telem_path = tmp_path / "telemetry.json"
    telem_path.write_text(json.dumps(telem), encoding="utf-8")

    installed_flows = []

    def mock_runner(args):
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

    executor = RemediationExecutor(
        require_human_approval=False,
        require_connectivity_check=False,
        telemetry_path=str(telem_path),
        cmd_runner=mock_runner,
        topology_provider=lambda: build_topology(telem),
    )
    monkeypatch.setattr(
        executor,
        "_verify_topology_safety",
        lambda: (False, "simulated post-change reachability failure"),
    )
    res = executor.execute(
        intent={
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "test block",
        },
        decision="APPROVED",
        verifier_result={"safe": True},
    )

    assert res["success"] is False
    assert res["rollback_attempted"] is True
    assert res["rollback_success"] is True
    assert "simulated post-change reachability failure" in res["error"]


# 8. Approval missing/expired/reused -> executor refuses
def test_approval_missing_expired_reused_refuses_execution(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_nominal_telemetry()), encoding="utf-8")

    monkeypatch.setenv(
        "NETOPS_CONNECTIVITY_CHECKER",
        "netops_guardrail.testbed.live_connectivity:check_host_connectivity",
    )
    monkeypatch.setenv("NETOPS_APPROVER_TOKEN", "test-token")
    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", json.dumps({"test-admin": "test-token"}))

    app = create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(tmp_path / "audit.json"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    client = app.test_client()

    headers = {"Authorization": "Bearer test-token"}

    # 8a. Missing proposal
    res_missing = client.post("/api/approvals/non-existent-id/execute", headers=headers)
    assert res_missing.status_code == 404

    # 8b. Unapproved proposal
    approval_store = app.config["NETOPS_APPROVAL_STORE"]
    prop = approval_store.create_proposal(
        intent={"action": "block", "target_switch": "1", "from_port": "3"},
        verifier_result={"safe": True},
        telemetry_path=str(telemetry_path),
        requested_by="operator",
    )
    res_unapproved = client.post(f"/api/approvals/{prop['proposal_id']}/execute", headers=headers)
    assert res_unapproved.status_code == 409
    assert "Only an approved" in res_unapproved.get_json()["error"]

    # 8c. Expired proposal
    approval_store.decide(
        proposal_id=prop["proposal_id"],
        decision="approved",
        approver_id="test-admin",
        reason="testing expiration",
        proposal_fingerprint_value=prop["proposal_fingerprint"],
    )
    # Force expire
    proposals_data = approval_store.list_proposals(include_decided=True)
    for p in proposals_data:
        if p["proposal_id"] == prop["proposal_id"]:
            p["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    approval_store._write(proposals_data)

    # Expired proposal is rejected by approval store
    with pytest.raises(ApprovalError, match="expired"):
        approval_store.validate_approved(
            prop["proposal_id"],
            prop["intent"],
            prop["verifier_result"],
            str(telemetry_path),
        )

    with pytest.raises(ApprovalError, match="expired"):
        approval_store.consume_approval(
            prop["proposal_id"],
            prop["intent"],
            prop["verifier_result"],
            str(telemetry_path),
        )

    # 8d. Reused (already consumed) proposal cannot be consumed twice
    fresh_prop = approval_store.create_proposal(
        intent={"action": "block", "target_switch": "1", "from_port": "3"},
        verifier_result={"safe": True},
        telemetry_path=str(telemetry_path),
        requested_by="operator",
    )
    approval_store.decide(
        proposal_id=fresh_prop["proposal_id"],
        decision="approved",
        approver_id="test-admin",
        reason="first use",
        proposal_fingerprint_value=fresh_prop["proposal_fingerprint"],
    )
    consumed = approval_store.consume_approval(
        fresh_prop["proposal_id"],
        fresh_prop["intent"],
        fresh_prop["verifier_result"],
        str(telemetry_path),
    )
    assert consumed["status"] == "consumed"

    # Second consumption attempt (reuse) must raise ApprovalError
    with pytest.raises(ApprovalError, match="consumed"):
        approval_store.consume_approval(
            fresh_prop["proposal_id"],
            fresh_prop["intent"],
            fresh_prop["verifier_result"],
            str(telemetry_path),
        )


# 9. Agent module imports no executor/subprocess/os.system
def test_agent_module_has_no_execution_imports():
    agent_path = Path(agent.__file__)
    source_text = agent_path.read_text(encoding="utf-8")

    assert "subprocess" not in source_text
    assert "os.system" not in source_text
    assert "RemediationExecutor" not in source_text
    assert "remediation_executor" not in source_text

    tree = ast.parse(source_text, filename=str(agent_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in {"subprocess", "os.system", "remediation_executor"}
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in {"subprocess", "os.system", "netops_guardrail.executor"}


# 10. Scope of execution: only block is executable; non-block faults terminate at recommendation_only
def test_scope_of_execution_non_block_faults_terminate_at_recommendation_only(
    monkeypatch, tmp_path
):
    # PipelineRun executable flag enforces that non-block faults are recommendation-only
    assert PipelineRun("r1", "flow_drift").executable is False
    assert PipelineRun("r2", "link_flapping").executable is False
    assert PipelineRun("r3", "mac_flooding").executable is False
    assert PipelineRun("r4", "trunk_down").executable is False
    assert PipelineRun("r5", "redundant_trunk_restored").executable is True

    # HumanApprovalStore strictly rejects creating proposals for non-block intents
    store = HumanApprovalStore(tmp_path / "approvals.json")
    with pytest.raises(ApprovalError, match="Only a validated block proposal"):
        store.create_proposal(
            intent={"action": "no_action", "reason": "policy recommendation"},
            verifier_result={"safe": True},
            telemetry_path=str(tmp_path / "telemetry.json"),
        )

    # API execution route rejects non-block actions with 409
    monkeypatch.setenv("NETOPS_APPROVER_TOKEN", "test-token")
    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", json.dumps({"test-admin": "test-token"}))

    app = create_metrics_app(
        telemetry_path=str(tmp_path / "telemetry.json"),
        audit_log_path=str(tmp_path / "audit.json"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    client = app.test_client()

    # Manually inject an approved non-block proposal into store to test executor rejection
    fake_proposal = {
        "proposal_id": "test-non-block-prop",
        "status": "approved",
        "intent": {"action": "no_action", "reason": "test recommendation"},
        "verifier_result": {"safe": True},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "execution_allowed": True,
        "requested_by": "test",
        "proposal_fingerprint": "fake-fp",
    }
    app.config["NETOPS_APPROVAL_STORE"]._write([fake_proposal])

    res = client.post(
        "/api/approvals/test-non-block-prop/execute",
        headers={"Authorization": "Bearer test-token"},
    )
    assert res.status_code == 409
    assert "only 'block' is executable" in res.get_json()["error"]
