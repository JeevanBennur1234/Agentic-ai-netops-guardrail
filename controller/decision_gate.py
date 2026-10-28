from datetime import datetime, timezone
import json
import sys
import os

sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "verifier")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "agent")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "audit")
)
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "executor")
)
sys.path.append(os.path.dirname(__file__))

from human_verifier import HumanApprovalStore, ApprovalError
from safety_verifier import (
    build_topology,
    run_safety_checks,
    test_port_removal
)
from remediation_agent import propose_remediation
from audit_trail import AuditTrail
from remediation_executor import RemediationExecutor

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_LOCAL_TELEMETRY = os.path.join(_PROJECT_ROOT, "telemetry", "data", "latest.json")
_HOME_TELEMETRY = os.path.expanduser("~/netops_guardrail/telemetry/data/latest.json")
DEFAULT_TELEMETRY_PATH = (
    _LOCAL_TELEMETRY if os.path.exists(_LOCAL_TELEMETRY) else _HOME_TELEMETRY
)
_TRACE_DIR = os.path.join(_PROJECT_ROOT, "observability", "data")
_TRACE_FILE = os.path.join(_TRACE_DIR, "pipeline_trace.jsonl")


audit_trail = AuditTrail()


def build_graph_from_json(telemetry_path):
    """Load telemetry JSON and build the topology graph."""
    with open(telemetry_path, "r") as file:
        telemetry = json.load(file)
    return build_topology(telemetry)


def apply_intent_to_graph(graph, intent):
    """
    Apply a proposed intent against a simulated copy of the topology graph.
    Returns a verifier result dict with at least a 'safe' boolean.
    """
    sim_graph = graph.copy()
    action = intent.get("action")

    if action in ("reroute", "block"):
        target_switch = intent.get("target_switch")
        from_port = intent.get("from_port")

        if not target_switch or not from_port:
            return {
                "safe": False,
                "reason": "Missing target_switch or from_port for remediation action"
            }

        port_node = f"s{target_switch}-p{from_port}"

        # Proposed physical port must exist before simulation
        if port_node not in graph:
            return {
                "safe": False,
                "reason": f"Port {port_node} does not exist"
            }

        if action == "reroute":
            return {
                "safe": False,
                "reason": "Reroute is disabled: topology-only reachability checks cannot prove OpenFlow forwarding safety"
            }

        return test_port_removal(sim_graph, port_node)

    elif action == "no_action":
        return run_safety_checks(sim_graph)

    else:
        return {
            "safe": False,
            "reason": f"Unhandled action type: {action}"
        }


def decide(
    telemetry_path=None,
    execute_approved=True,
    executor=None,
    connectivity_checker=None,
    approval_id=None,
    approval_store=None,
    audit_logger=None,
    incident_context=None,
):
    if telemetry_path is None:
        telemetry_path = DEFAULT_TELEMETRY_PATH

    graph = build_graph_from_json(telemetry_path)
    approval_store = approval_store or HumanApprovalStore()
    audit_sink = audit_logger or audit_trail
    pending_proposal = None

    if approval_id:
        # Execute only the exact proposal reviewed by the human, never a fresh
        # LLM-generated action substituted after approval.
        pending_proposal = approval_store.get_proposal(approval_id)
        if pending_proposal is None:
            intent = {"action": "block", "reason": "Unknown human approval proposal"}
            result = {"safe": False, "reason": "Unknown human approval proposal; refusing execution"}
        elif pending_proposal.get("status") != "approved":
            intent = pending_proposal.get("intent", {})
            result = {
                "safe": False,
                "reason": f"Human approval is not approved (status={pending_proposal.get('status')}); refusing execution",
            }
        elif approval_store._is_expired(pending_proposal):
            intent = pending_proposal.get("intent", {})
            result = {"safe": False, "reason": "Human approval expired; a fresh review is required"}
        else:
            intent = pending_proposal.get("intent", {})
            result = apply_intent_to_graph(graph, intent)
            try:
                approval_store.validate_approved(
                    approval_id, intent, result, telemetry_path
                )
            except ApprovalError as exc:
                result = {"safe": False, "reason": f"Human approval no longer matches current state: {exc}"}
    else:
        try:
            if incident_context:
                intent = propose_remediation(
                    telemetry_path,
                    incident_context=incident_context,
                )
            else:
                intent = propose_remediation(telemetry_path)
        except Exception as exc:
            intent = {
                "action": "no_action",
                "reason": f"Remediation agent error: {exc}. Defaulted safely to no_action."
            }
        result = apply_intent_to_graph(graph, intent)

    print("1. AGENT PROPOSED:")
    print(json.dumps(intent, indent=2))

    print("\n2. VERIFIER RESULT:")
    print(json.dumps(result, indent=2))

    human_approval = None
    if not result.get("safe"):
        decision = "REJECTED"
    elif intent.get("action") == "block" and not approval_id:
        try:
            human_approval = approval_store.create_proposal(
                intent=intent,
                verifier_result=result,
                telemetry_path=telemetry_path,
            )
            decision = "PENDING_HUMAN_APPROVAL"
        except ApprovalError as exc:
            result = {"safe": False, "reason": f"Human approval proposal failed closed: {exc}"}
            decision = "REJECTED"
    else:
        decision = "APPROVED"
    print(f"\n3. DECISION: {decision}")

    execution_res = None
    if decision == "APPROVED" and execute_approved:
        if executor is None:
            # Autonomous blocking stays fail-closed unless the caller supplies
            # a real post-change host-to-host connectivity probe.
            executor = RemediationExecutor(
                telemetry_path=telemetry_path,
                audit_trail=audit_sink,
                connectivity_checker=connectivity_checker,
                require_connectivity_check=True,
                approval_store=approval_store,
                require_human_approval=True,
            )
        # Do not let a caller-supplied executor weaken the gate's approval
        # or connectivity requirements.
        if not isinstance(executor, RemediationExecutor):
            execution_res = {
                "success": False,
                "action": intent.get("action"),
                "error": "Refusing execution: supplied executor does not implement the guarded RemediationExecutor contract",
                "change_verified": False,
                "safety_verified": False,
                "rollback_attempted": False,
                "rollback_success": None,
                "rollback_details": "No network mutation was attempted",
            }
        else:
            executor.approval_store = approval_store
            executor.audit_trail = audit_sink
            executor.require_human_approval = True
            executor.require_connectivity_check = True
            if connectivity_checker is not None:
                executor.connectivity_checker = connectivity_checker
            execution_res = executor.execute(
                intent=intent,
                decision=decision,
                verifier_result=result,
                approval_id=approval_id,
            )
        print("\n4. EXECUTION RESULT:")
        print(json.dumps(execution_res, indent=2))

    # Every gate decision produces a signed audit record. Pending decisions
    # include the proposal id/fingerprint so the review UI can be correlated
    # with the cryptographic audit trail.
    audit_execution_result = execution_res
    if execution_res is None and human_approval:
        audit_execution_result = {
            "human_approval": {
                "proposal_id": human_approval["proposal_id"],
                "status": human_approval["status"],
                "proposal_fingerprint": human_approval["proposal_fingerprint"],
                "expires_at": human_approval["expires_at"],
            }
        }
    record = audit_sink.record_decision(
        decision=decision,
        intent=intent,
        verifier_result=result,
        execution_result=audit_execution_result
    )

    print(
        f"\n5. AUDIT RECORD LOGGED: "
        f"index={record['index']} hash={record['current_hash'][:16]}..."
    )

    res = {
        "intent": intent,
        "verification": result,
        "incident_context": incident_context,
        "decision": decision,
        "execution": execution_res,
        "human_approval": ({
            "proposal_id": human_approval.get("proposal_id"),
            "status": human_approval.get("status"),
            "proposal_fingerprint": human_approval.get("proposal_fingerprint"),
            "expires_at": human_approval.get("expires_at"),
        } if human_approval else None),
        "audit_record": record
    }

    try:
        os.makedirs(_TRACE_DIR, exist_ok=True)
        trace_entry = dict(res)
        trace_entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(_TRACE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(trace_entry) + "\n")
    except Exception as e:
        print(f"Warning: Failed to write to pipeline trace log ({e})")

    return res


if __name__ == "__main__":
    decide()
