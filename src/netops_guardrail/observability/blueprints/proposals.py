"""Human proposals and remediation decision routes for NetOps Guardrail."""
import importlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, render_template, request

from netops_guardrail.controller.human_verifier import ApprovalError
from netops_guardrail.controller.pipeline_run import PipelineRunManager
from netops_guardrail.observability.blueprints.auth import authenticated_approver

proposals_bp = Blueprint("proposals", __name__)


def _get_pipeline_manager() -> PipelineRunManager:
    runs_dir = current_app.config.get("NETOPS_PIPELINE_RUNS_DIR")
    if runs_dir:
        return PipelineRunManager(runs_dir)
    collector = current_app.config.get("NETOPS_COLLECTOR")
    if collector and hasattr(collector, "telemetry_path"):
        base_dir = Path(collector.telemetry_path).resolve().parents[2]
        return PipelineRunManager(base_dir / "observability" / "data" / "pipeline_runs")
    return PipelineRunManager()


@proposals_bp.route("/approvals", methods=["GET"])
def human_approval_page():
    return render_template("approvals.html")


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

    # Update pipeline run if active and linked
    pipeline_mgr = _get_pipeline_manager()
    run = pipeline_mgr.get_current_run()
    if run and (run.proposal_id == proposal_id or not run.proposal_id):
        run.proposal_id = proposal_id
        if updated["status"] == "approved":
            intent = current.get("intent") or {}
            # Scope of execution: only block is executable
            if intent.get("action") != "block" or not run.executable:
                run.complete_stage("awaiting_approval")
                run.complete_stage("approved")
                run.skip_stage(
                    "executed",
                    reason="Scope of execution: only 'block' is executable; recommendation only.",
                )
                run.skip_stage(
                    "connectivity_verified",
                    reason="Recommendation only; no network mutation executed.",
                )
                run.status = "RECOMMENDATION_ONLY"
                pipeline_mgr.finalize_run(run, outcome="recommendation_only")
            else:
                run.complete_stage("awaiting_approval")
                run.complete_stage("approved")
                run.status = "APPROVED"
                pipeline_mgr.save_run(run)
        else:
            run.fail_stage(
                "awaiting_approval",
                error=f"Human decision: {updated['status']}",
                outcome="failed",
            )
            pipeline_mgr.finalize_run(run, outcome="failed")

    return jsonify({
        "proposal": updated,
        "audit_status": "recorded",
        "trace_status": "recorded",
    }), 200


@proposals_bp.route("/api/approvals/<proposal_id>/execute", methods=["POST"])
@proposals_bp.route("/api/proposals/<proposal_id>/execute", methods=["POST"])
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
    if proposal.get("execution_allowed", True) is False or proposal.get("requested_by") == "presentation-demo":
        return jsonify({"error": "This proposal is review-only; network execution is disabled."}), 409

    # Scope of execution: only 'block' is executable
    intent = proposal.get("intent") or {}
    if intent.get("action") != "block":
        return jsonify({
            "error": (
                f"Scope of execution: only 'block' is executable. "
                f"Action '{intent.get('action')}' is recommendation-only; executor cannot be called."
            )
        }), 409

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
        checker = getattr(importlib.import_module(module_name), function_name)
        if not callable(checker):
            raise ValueError("checker is not callable")
    except Exception as exc:
        return jsonify({"error": f"Connectivity checker could not be loaded: {exc}"}), 503

    pipeline_mgr = _get_pipeline_manager()
    run = pipeline_mgr.get_current_run()
    if run and (run.proposal_id == proposal_id or not run.proposal_id):
        run.proposal_id = proposal_id
        run.start_stage("executed")
        pipeline_mgr.save_run(run)

    result = current_app.config["NETOPS_DECIDE"](
        telemetry_path=collector.telemetry_path,
        execute_approved=True,
        connectivity_checker=checker,
        approval_id=proposal_id,
        approval_store=approval_store,
        audit_logger=audit,
    )
    execution = result.get("execution") or {}
    exec_success = bool(execution.get("success"))

    if run and (run.proposal_id == proposal_id or not run.proposal_id):
        if exec_success:
            run.complete_stage("executed", evidence=execution)
            # Post-execution connectivity check
            try:
                post_ok = checker()
            except Exception:
                post_ok = False
            if post_ok:
                run.complete_stage("connectivity_verified", evidence={"post_ping_passed": True})
                run.status = "CONNECTIVITY_VERIFIED"
                pipeline_mgr.finalize_run(run, outcome="connectivity_verified")
            else:
                run.fail_stage(
                    "connectivity_verified",
                    error="Post-execution ping check failed",
                    evidence={"post_ping_passed": False},
                    outcome="rolled_back",
                )
                pipeline_mgr.finalize_run(run, outcome="rolled_back")
        else:
            run.fail_stage(
                "executed",
                error=execution.get("error", "execution failed"),
                evidence=execution,
                outcome="rolled_back",
            )
            pipeline_mgr.finalize_run(run, outcome="rolled_back")

    status_code = 200 if exec_success else 409
    return jsonify({"authenticated_approver": approver, "result": result}), status_code
