"""Human proposals and remediation decision routes for NetOps Guardrail."""
import json
import os
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request

import netops_guardrail.observability.server as server_module
from netops_guardrail.controller.human_verifier import ApprovalError
from netops_guardrail.observability.blueprints.auth import authenticated_approver
from netops_guardrail.verifier.safety_verifier import build_topology

proposals_bp = Blueprint("proposals", __name__)


@proposals_bp.route("/approvals", methods=["GET"])
def human_approval_page():
    return render_template("approvals.html")


@proposals_bp.route("/api/simulate", methods=["GET"])
def api_simulate():
    collector = current_app.config["NETOPS_COLLECTOR"]
    audit = current_app.config["NETOPS_AUDIT"]
    scenario = request.args.get("scenario", "normal")
    telem = {}
    if os.path.exists(collector.telemetry_path):
        with open(collector.telemetry_path, "r", encoding="utf-8") as f:
            telem = json.load(f)

    graph = build_topology(telem) if telem else None

    if scenario == "normal":
        intent = {
            "action": "no_action",
            "reason": "Nominal traffic across all ports, zero congestion"
        }
    elif scenario == "unsafe_block":
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "1",
            "reason": "Adversarial or erroneous intent to isolate access port"
        }
    elif scenario == "injection":
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "1; rm -rf /",
            "reason": "Shell command injection payload attempt"
        }
    else:
        intent = {"action": "no_action", "reason": "Default check"}

    if graph is not None:
        verif_res = server_module.apply_intent_to_graph(graph, intent)
    else:
        verif_res = {"safe": False, "reason": "No active topology"}

    decision = "APPROVED" if verif_res.get("safe") else "REJECTED"

    record = audit.record_decision(
        decision=decision,
        intent=intent,
        verifier_result=verif_res,
        execution_result={"success": True if decision == "APPROVED" else False}
    )

    return jsonify({
        "scenario": scenario,
        "intent": intent,
        "verification": verif_res,
        "decision": decision,
        "audit_record": record
    }), 200


@proposals_bp.route("/api/approvals", methods=["GET"])
def api_human_approvals():
    approver, error = authenticated_approver()
    if error:
        return error
    approval_store = current_app.config["NETOPS_APPROVAL_STORE"]
    all_proposals = approval_store.list_proposals(include_decided=True)
    active_proposals = [
        p for p in all_proposals
        if p.get("status") in {"pending", "approved"}
        and not approval_store._is_expired(p)
    ]
    terminal_statuses = {"rejected", "changes_requested", "consumed"}
    recent_decisions = [
        p for p in all_proposals if p.get("status") in terminal_statuses
    ]
    recent_decisions.sort(
        key=lambda p: (
            (p.get("decision") or {}).get("decided_at")
            or p.get("consumed_at")
            or p.get("created_at")
            or ""
        ),
        reverse=True,
    )
    proposals = active_proposals + recent_decisions[:10]
    return jsonify({"proposals": proposals, "authenticated_approver": approver}), 200


@proposals_bp.route("/api/approvals/<proposal_id>/decision", methods=["POST"])
def api_human_approval_decision(proposal_id):
    approver, error = authenticated_approver()
    if error:
        return error
    approval_store = current_app.config["NETOPS_APPROVAL_STORE"]
    audit = current_app.config["NETOPS_AUDIT"]
    trace_file = current_app.config["NETOPS_TRACE_FILE"]

    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason", "")).strip()
    if not reason:
        return jsonify({"error": "A decision reason is required"}), 400
    current = approval_store.get_proposal(proposal_id)
    if current is None:
        return jsonify({"error": "Proposal not found"}), 404
    try:
        updated = approval_store.decide(
            proposal_id=proposal_id,
            decision=payload.get("decision", ""),
            approver_id=approver,
            reason=reason,
            proposal_fingerprint_value=payload.get("proposal_fingerprint"),
        )
    except ApprovalError as exc:
        return jsonify({"error": str(exc)}), 409
    audit_decision = {"approved": "APPROVED", "rejected": "REJECTED", "changes_requested": "CHANGES_REQUESTED"}[updated["status"]]
    audit_record = audit.record_decision(
        decision=audit_decision,
        intent=current["intent"],
        verifier_result=current["verifier_result"],
        execution_result={"human_approval": {
            "proposal_id": proposal_id,
            "status": updated["status"],
            "approver_id": approver,
            "reason": reason,
            "proposal_fingerprint": updated["proposal_fingerprint"],
        }},
    )

    decision_details = updated.get("decision") or {}
    trace_event = {
        "event_type": "human_approval_decision",
        "decision": audit_decision,
        "intent": current.get("intent") or {},
        "verification": current.get("verifier_result") or {},
        "execution": None,
        "human_approval": {
            "proposal_id": proposal_id,
            "status": updated["status"],
            "proposal_fingerprint": updated.get("proposal_fingerprint"),
            "expires_at": updated.get("expires_at"),
            "decision": decision_details,
        },
        "decision_reason": reason,
        "audit_record": audit_record,
        "timestamp": decision_details.get("decided_at") or datetime.now(timezone.utc).isoformat(),
    }
    try:
        os.makedirs(os.path.dirname(trace_file) or ".", exist_ok=True)
        with open(trace_file, "a", encoding="utf-8") as trace_handle:
            trace_handle.write(json.dumps(trace_event) + "\n")
    except OSError:
        current_app.logger.exception("Failed to append human approval decision to pipeline trace")

    return jsonify({
        "proposal": updated,
        "audit_status": "recorded",
        "trace_status": "recorded",
    }), 200


@proposals_bp.route("/api/approvals/<proposal_id>/execute", methods=["POST"])
def api_execute_human_approved(proposal_id):
    approver, error = authenticated_approver()
    if error:
        return error
    approval_store = current_app.config["NETOPS_APPROVAL_STORE"]
    audit = current_app.config["NETOPS_AUDIT"]
    collector = current_app.config["NETOPS_COLLECTOR"]

    proposal = approval_store.get_proposal(proposal_id)
    if proposal is None:
        return jsonify({"error": "Proposal not found"}), 404
    if proposal.get("status") != "approved":
        return jsonify({"error": "Only an approved, unconsumed proposal can execute"}), 409
    chain_ok, chain_message = audit.verify_chain(audit.chain)
    if not chain_ok:
        return jsonify({"error": f"Audit chain verification failed; execution blocked: {chain_message}"}), 503
    approval_audited = any(
        record.get("decision") == "APPROVED"
        and record.get("intent") == proposal.get("intent")
        and isinstance(record.get("execution_result"), dict)
        and isinstance(record["execution_result"].get("human_approval"), dict)
        and record["execution_result"]["human_approval"].get("proposal_id") == proposal_id
        and record["execution_result"]["human_approval"].get("status") == "approved"
        for record in audit.chain
    )
    if not approval_audited:
        return jsonify({
            "error": "Matching signed approval record is missing; execution remains blocked."
        }), 503
    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    if ":" not in checker_spec:
        return jsonify({
            "error": "Execution disabled: configure NETOPS_CONNECTIVITY_CHECKER=module:function for a real host-to-host connectivity check."
        }), 503
    module_name, function_name = checker_spec.split(":", 1)
    try:
        checker = getattr(server_module.importlib.import_module(module_name), function_name)
        if not callable(checker):
            raise ValueError("checker is not callable")
    except Exception as exc:
        return jsonify({"error": f"Connectivity checker could not be loaded: {exc}"}), 503

    result = server_module.decide(
        telemetry_path=collector.telemetry_path,
        execute_approved=True,
        connectivity_checker=checker,
        approval_id=proposal_id,
        approval_store=approval_store,
        audit_logger=audit,
    )
    execution = result.get("execution") or {}
    status_code = 200 if execution.get("success") else 409
    return jsonify({"authenticated_approver": approver, "result": result}), status_code
