import json

from netops_guardrail.experiments.evaluate_guardrail_cases import stp_redundant
from netops_guardrail.testbed.create_demo_approval import append_pipeline_trace, select_standby_s1_port
from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.verifier.safety_verifier import build_topology


def test_demo_approval_selects_only_the_stp_blocked_redundant_trunk():
    telemetry = stp_redundant()
    assert select_standby_s1_port(telemetry) == "3"


def test_demo_approval_candidate_passes_existing_safety_verifier():
    telemetry = stp_redundant()
    port = select_standby_s1_port(telemetry)
    intent = {
        "action": "block",
        "target_switch": "1",
        "from_port": port,
        "reason": "test-only review proposal",
    }
    result = apply_intent_to_graph(build_topology(telemetry), intent)
    assert result.get("safe") is True


def test_demo_approval_is_written_to_dashboard_trace(tmp_path):
    trace_path = tmp_path / "pipeline_trace.jsonl"
    intent = {"action": "block", "target_switch": "1", "from_port": "3", "reason": "demo"}
    verification = {"safe": True, "checks": ["PASS: Topology is connected"]}
    proposal = {
        "proposal_id": "demo-proposal",
        "status": "pending",
        "proposal_fingerprint": "demo-fingerprint",
        "expires_at": "2030-01-01T00:05:00+00:00",
    }
    audit_record = {"decision": "PENDING_HUMAN_APPROVAL", "current_hash": "abc"}

    append_pipeline_trace(intent, verification, proposal, audit_record, trace_path=trace_path)
    entry = json.loads(trace_path.read_text(encoding="utf-8").strip())

    assert entry["decision"] == "PENDING_HUMAN_APPROVAL"
    assert entry["verification"]["safe"] is True
    assert entry["human_approval"]["proposal_id"] == "demo-proposal"
    assert entry["execution"] is None
