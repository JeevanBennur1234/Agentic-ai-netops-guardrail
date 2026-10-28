import json
from datetime import datetime, timezone

import pytest

from human_verifier import ApprovalError, HumanApprovalStore
from remediation_executor import RemediationExecutor


def telemetry_fixture():
    counters = {"rx_packets": 1, "tx_packets": 1, "rx_bytes": 64, "tx_bytes": 64}
    return {
        "switches": {
            "1": {
                "ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)},
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
            },
            "2": {
                "ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)},
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
            },
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
    }


def write_telemetry(path, data=None):
    data = data or telemetry_fixture()
    data["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def make_pending(store, telemetry_path):
    return store.create_proposal(
        intent={
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Approved test proposal for a known standby trunk",
        },
        verifier_result={"safe": True, "checks": ["PASS: test fixture"]},
        telemetry_path=telemetry_path,
    )


def approve(store, proposal):
    return store.decide(
        proposal["proposal_id"],
        "approve",
        approver_id="test-network-admin",
        reason="Reviewed test proposal",
        proposal_fingerprint_value=proposal["proposal_fingerprint"],
    )


def test_human_approval_is_bound_and_single_use(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    assert proposal["status"] == "pending"

    approved = approve(store, proposal)
    assert approved["status"] == "approved"
    checked = store.validate_approved(
        proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], telemetry_path
    )
    assert checked["decision"]["approver_id"] == "test-network-admin"

    consumed = store.consume_approval(
        proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], telemetry_path
    )
    assert consumed["status"] == "consumed"
    with pytest.raises(ApprovalError, match="not usable"):
        store.consume_approval(
            proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], telemetry_path
        )


def test_human_approval_rejects_tampered_intent(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    approve(store, proposal)

    tampered = dict(proposal["intent"])
    tampered["from_port"] = "2"
    with pytest.raises(ApprovalError, match="changed after approval"):
        store.validate_approved(
            proposal["proposal_id"], tampered, proposal["verifier_result"], telemetry_path
        )


def test_human_approval_rejects_topology_change(tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    write_telemetry(telemetry_path)
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, str(telemetry_path))
    approve(store, proposal)

    changed = telemetry_fixture()
    changed["switches"]["2"]["stp_port_states"]["2"] = "FORWARD"
    write_telemetry(telemetry_path, changed)
    with pytest.raises(ApprovalError, match="topology changed"):
        store.validate_approved(
            proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], str(telemetry_path)
        )


def test_human_approval_requires_fingerprint_and_reasoned_decision(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    with pytest.raises(ApprovalError, match="fingerprint"):
        store.decide(
            proposal["proposal_id"], "approve", "admin", "Looks fine",
            proposal_fingerprint_value="not-the-fingerprint",
        )
    with pytest.raises(ApprovalError, match="Decision must be"):
        store.decide(
            proposal["proposal_id"], "anything", "admin", "reason",
            proposal_fingerprint_value=proposal["proposal_fingerprint"],
        )


def test_unsafe_proposal_cannot_enter_human_queue(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    with pytest.raises(ApprovalError, match="Unsafe"):
        store.create_proposal(
            {"action": "block", "target_switch": "1", "from_port": "3"},
            {"safe": False},
            telemetry_path,
        )


def test_request_changes_closes_proposal_and_cannot_be_executed(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)

    updated = store.decide(
        proposal["proposal_id"],
        "request_changes",
        approver_id="test-network-admin",
        reason="Please provide a clearer impact and rollback plan.",
        proposal_fingerprint_value=proposal["proposal_fingerprint"],
    )
    assert updated["status"] == "changes_requested"
    with pytest.raises(ApprovalError, match="not usable"):
        store.consume_approval(
            proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], telemetry_path
        )


def test_executor_rejects_direct_approved_string_without_human_approval(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    commands = []

    def runner(args):
        commands.append(args)
        return 0, "", ""

    executor = RemediationExecutor(
        telemetry_path=telemetry_path,
        cmd_runner=runner,
        require_human_approval=True,
        require_connectivity_check=False,
    )
    result = executor.execute(
        intent={"action": "block", "target_switch": "1", "from_port": "3", "reason": "bypass attempt"},
        decision="APPROVED",
        verifier_result={"safe": True},
    )
    assert result["success"] is False
    assert "human approval is required" in result["error"]
    assert commands == []

def test_controller_records_openflow_port_down_event(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from telemetry_controller import TelemetryController

    app = TelemetryController.__new__(TelemetryController)
    app.telemetry = {"switches": {}}
    app.logger = Mock()
    app._write_telemetry = Mock()
    ofproto = SimpleNamespace(
        OFPPR_ADD=0, OFPPR_DELETE=1, OFPPR_MODIFY=2,
        OFPPC_PORT_DOWN=1, OFPPS_LINK_DOWN=1,
    )
    desc = SimpleNamespace(port_no=2, config=0, state=1)
    datapath = SimpleNamespace(id=2, ofproto=ofproto)
    msg = SimpleNamespace(datapath=datapath, desc=desc, reason=2)

    app.port_status_handler(SimpleNamespace(msg=msg))

    recorded = app.telemetry["switches"]["2"]["port_status"]["2"]
    assert recorded["state"] == "DOWN"
    assert recorded["link_down"] is True
    assert recorded["reason"] == "MODIFY"
    app._write_telemetry.assert_called_once()


def test_duplicate_pending_proposals_reuse_existing_id(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    first = make_pending(store, telemetry_path)
    second = make_pending(store, telemetry_path)
    assert first["proposal_id"] == second["proposal_id"]
    assert len(store.list_proposals(include_decided=True)) == 1


def test_decision_gate_creates_pending_human_approval_instead_of_executing(
    tmp_path, monkeypatch
):
    import decision_gate
    from audit_trail import AuditTrail

    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    approval_store = HumanApprovalStore(tmp_path / "approvals.json")
    audit = AuditTrail(
        log_path=str(tmp_path / "audit.json"),
        key_path=str(tmp_path / "audit.pem"),
        auto_load=False,
    )
    monkeypatch.setattr(decision_gate, "audit_trail", audit)
    monkeypatch.setattr(
        decision_gate,
        "propose_remediation",
        lambda _path: {
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "standby trunk review test",
        },
    )

    class ForbiddenExecutor:
        def execute(self, **kwargs):
            raise AssertionError("executor must never run while human approval is pending")

    result = decision_gate.decide(
        telemetry_path=telemetry_path,
        execute_approved=True,
        executor=ForbiddenExecutor(),
        approval_store=approval_store,
    )

    assert result["decision"] == "PENDING_HUMAN_APPROVAL"
    assert result["execution"] is None
    approval = approval_store.get_proposal(result["human_approval"]["proposal_id"])
    assert approval["status"] == "pending"
    assert len(audit.chain) == 1
    assert audit.chain[0]["decision"] == "PENDING_HUMAN_APPROVAL"


def test_approved_gate_revalidates_exact_proposal_before_execution(tmp_path, monkeypatch):
    import decision_gate
    from audit_trail import AuditTrail

    telemetry_file = tmp_path / "telemetry.json"
    telemetry_path = write_telemetry(telemetry_file)
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    approve(store, proposal)

    audit = AuditTrail(
        log_path=str(tmp_path / "audit.json"),
        key_path=str(tmp_path / "audit.pem"),
        auto_load=False,
    )
    monkeypatch.setattr(decision_gate, "audit_trail", audit)

    class ForbiddenExecutor:
        def execute(self, **kwargs):
            raise AssertionError("stale/changed proposal should be rejected before executor call")

    changed = telemetry_fixture()
    changed["switches"]["2"]["stp_port_states"]["2"] = "FORWARD"
    write_telemetry(telemetry_file, changed)

    result = decision_gate.decide(
        telemetry_path=telemetry_path,
        execute_approved=True,
        executor=ForbiddenExecutor(),
        approval_id=proposal["proposal_id"],
        approval_store=store,
    )
    assert result["decision"] == "REJECTED"
    assert result["execution"] is None
    assert "topology changed" in result["verification"]["reason"].lower()


def test_expired_approval_is_rejected(tmp_path, monkeypatch):
    import human_verifier
    from datetime import timedelta

    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    approve(store, proposal)
    original_now = human_verifier._utc_now()
    monkeypatch.setattr(human_verifier, "_utc_now", lambda: original_now + timedelta(hours=1))
    with pytest.raises(ApprovalError, match="expired"):
        store.validate_approved(
            proposal["proposal_id"], proposal["intent"], proposal["verifier_result"], telemetry_path
        )


def test_approval_refuses_stale_or_untimestamped_telemetry(tmp_path, monkeypatch):
    import human_verifier
    from datetime import timedelta

    stale_file = tmp_path / "stale.json"
    stale = telemetry_fixture()
    stale["updated_at_utc"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    stale_file.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(ApprovalError, match="stale"):
        HumanApprovalStore(tmp_path / "stale-approvals.json").create_proposal(
            {"action": "block"}, {"safe": True}, str(stale_file)
        )

    missing_file = tmp_path / "missing-timestamp.json"
    missing_file.write_text(json.dumps(telemetry_fixture()), encoding="utf-8")
    with pytest.raises(ApprovalError, match="timestamp missing"):
        HumanApprovalStore(tmp_path / "missing-approvals.json").create_proposal(
            {"action": "block"}, {"safe": True}, str(missing_file)
        )


def test_executor_requires_live_connectivity_checker_by_default_after_human_approval(tmp_path):
    telemetry_path = write_telemetry(tmp_path / "telemetry.json")
    store = HumanApprovalStore(tmp_path / "approvals.json")
    proposal = make_pending(store, telemetry_path)
    approve(store, proposal)
    commands = []

    def runner(args):
        commands.append(args)
        return 0, "", ""

    executor = RemediationExecutor(
        telemetry_path=telemetry_path,
        cmd_runner=runner,
        approval_store=store,
    )
    result = executor.execute(
        intent=proposal["intent"],
        decision="APPROVED",
        verifier_result=proposal["verifier_result"],
        approval_id=proposal["proposal_id"],
    )
    assert result["success"] is False
    assert "connectivity checker is required" in result["error"]
    assert commands == []
    assert store.get_proposal(proposal["proposal_id"])["status"] == "approved"
