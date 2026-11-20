"""Pipeline orchestration endpoints: GET /api/pipeline/current and POST /api/pipeline/inject."""

import hmac
import importlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from netops_guardrail.controller.pipeline_run import (
    PipelineRunManager,
    check_injection_preconditions,
    execute_guarded_injection,
    execute_guarded_restore,
    get_live_faults_detail,
    get_preflight_status,
)
from netops_guardrail.faults.registry import get_fault
from netops_guardrail.observability.blueprints.auth import authenticated_approver

pipeline_bp = Blueprint("pipeline", __name__)


def _get_manager() -> PipelineRunManager:
    runs_dir = current_app.config.get("NETOPS_PIPELINE_RUNS_DIR")
    if runs_dir:
        return PipelineRunManager(runs_dir)
    collector = current_app.config.get("NETOPS_COLLECTOR")
    if collector and hasattr(collector, "telemetry_path"):
        telemetry_file = Path(collector.telemetry_path).resolve()
        # Preserve the canonical NETOPS_HOME layout for production telemetry,
        # but keep test/custom telemetry paths isolated beside their data.
        if (telemetry_file.name == "latest.json" and telemetry_file.parent.name == "data"
                and telemetry_file.parent.parent.name == "telemetry"):
            base_dir = telemetry_file.parents[2]
        else:
            base_dir = telemetry_file.parent
        return PipelineRunManager(base_dir / "observability" / "data" / "pipeline_runs")
    return PipelineRunManager()


def _get_connectivity_checker():
    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    if ":" not in checker_spec:
        return None
    module_name, function_name = checker_spec.split(":", 1)
    try:
        checker = getattr(importlib.import_module(module_name), function_name)
        return checker if callable(checker) else None
    except Exception:
        return None


def _advance_pipeline_after_injection(fault_id, manager, collector):
    """Advance the persisted run using fresh telemetry, deterministic detection, AI and safety evidence."""
    run = manager.get_current_run()
    if run is None or run.fault_id != fault_id:
        return None, {"error": "Pipeline run record is missing after injection."}, 503

    def fail(stage, message, evidence=None, code=503):
        run.fail_stage(stage, message, evidence=evidence or {})
        manager.finalize_run(run, outcome="failed")
        return run, {"error": message}, code

    fault = get_fault(fault_id)
    deadline = time.time() + (14.0 if fault_id in {"trunk_down", "link_flapping"} else 6.0)
    telemetry = None
    detection = None
    parsed = None
    age = 0.0

    while True:
        try:
            with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
                telemetry = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            if time.time() >= deadline:
                return fail("telemetry_observed", f"Post-injection telemetry unavailable: {exc}")
            time.sleep(0.5)
            continue

        if not isinstance(telemetry, dict):
            if time.time() >= deadline:
                return fail("telemetry_observed", "Post-injection telemetry is not a JSON object.")
            time.sleep(0.5)
            continue

        updated = telemetry.get("updated_at_utc")
        try:
            parsed_cand = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
            if parsed_cand.tzinfo is None:
                parsed_cand = parsed_cand.replace(tzinfo=timezone.utc)
            age_cand = (datetime.now(timezone.utc) - parsed_cand).total_seconds()
        except (TypeError, ValueError):
            parsed_cand = None
            age_cand = 999.0

        if parsed_cand is not None and -5 <= age_cand <= 30:
            parsed = parsed_cand
            age = age_cand
            try:
                det = fault.detector(telemetry)
                if isinstance(det, dict) and det.get("detected") is True:
                    # In live STP networks, allow alternate trunk convergence before evaluating graph safety
                    if fault_id == "trunk_down":
                        s1_stp = (telemetry.get("switches", {}).get("1", {}).get("stp_port_states", {}) or {})
                        s2_stp = (telemetry.get("switches", {}).get("2", {}).get("stp_port_states", {}) or {})
                        if not s1_stp or (s1_stp.get("3") == "FORWARD" and s2_stp.get("2") == "FORWARD"):
                            detection = det
                            break
                    elif fault_id == "link_flapping":
                        s1_stp = (telemetry.get("switches", {}).get("1", {}).get("stp_port_states", {}) or {})
                        if not s1_stp or s1_stp.get("2") == "FORWARD":
                            detection = det
                            break
                    else:
                        detection = det
                        break
                elif detection is None or isinstance(det, dict):
                    detection = det
            except Exception as exc:
                detection = exc

        if time.time() >= deadline:
            break
        time.sleep(0.5)

    if parsed is None or age > 30 or age < -5:
        return fail(
            "telemetry_observed",
            "Post-injection telemetry is stale or from the future; AI analysis is blocked.",
            {"age_seconds": round(age, 2), "updated_at_utc": telemetry.get("updated_at_utc") if isinstance(telemetry, dict) else None},
        )

    run.complete_stage(
        "telemetry_observed",
        evidence={
            "updated_at_utc": parsed.isoformat(),
            "age_seconds": round(age, 2),
            "source": "live_telemetry",
        },
    )

    if not isinstance(detection, dict) or detection.get("detected") is not True:
        return fail(
            "detected",
            "The injected condition was not independently confirmed by live telemetry; AI analysis is blocked.",
            {"detection": detection if isinstance(detection, dict) else {"result": str(detection)}},
            code=409,
        )
    run.complete_stage("detected", evidence=detection)

    decision_pipeline = current_app.config.get("NETOPS_DECIDE")
    if not callable(decision_pipeline):
        return fail("ai_analysis", "AI decision pipeline is not configured.")
    incident_type = "flow_rule_drift" if fault_id == "flow_drift" else fault_id
    evidence_id = detection.get("evidence_id")
    incident_context = {
        "fault_type": incident_type,
        "source": "lab_injected_live",
        "evidence_id": evidence_id,
        "evidence": detection,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    try:
        pipeline_result = decision_pipeline(
            telemetry_path=collector.telemetry_path,
            execute_approved=False,
            audit_logger=current_app.config.get("NETOPS_AUDIT"),
            incident_context=incident_context,
        )
    except Exception as exc:
        return fail(
            "ai_analysis", f"AI decision pipeline failed closed: {type(exc).__name__}: {exc}"
        )
    if not isinstance(pipeline_result, dict):
        return fail("ai_analysis", "AI decision pipeline returned an invalid result.")
    intent = pipeline_result.get("intent") or {}
    metadata = intent.get("_agent_metadata") or {}
    run.complete_stage(
        "ai_analysis",
        evidence={
            "intent": intent,
            "model": metadata.get("model"),
            "model_invoked": metadata.get("model_invoked"),
            "agent_status": metadata.get("status", "unknown"),
            "raw_output": metadata.get("raw_output"),
            "parsed_decision": metadata.get("parsed_decision"),
            "prompt_sha256": metadata.get("prompt_sha256"),
            "decision": pipeline_result.get("decision"),
        },
    )

    verification = pipeline_result.get("verification") or {}
    if verification.get("safe") is not True:
        return fail(
            "safety_verified",
            "Independent safety verification did not pass; no approval or execution is permitted.",
            {"verification": verification},
            code=409,
        )
    run.complete_stage("safety_verified", evidence=verification)

    action = intent.get("action")
    human_approval = pipeline_result.get("human_approval")
    if run.executable:
        if action == "no_action":
            # Safe model outcome: no fabricated approval proposal is created.
            run.executable = False
            run.start_stage(
                "awaiting_approval",
                evidence={
                    "acknowledgement_required": True,
                    "recommendation_only": True,
                    "executor_called": False,
                    "reason": intent.get("reason"),
                    "proposal_created": False,
                    "safe_no_action": True,
                },
            )
            run.status = "RECOMMENDATION_ONLY_PENDING_ACK"
        elif action != "block" or not isinstance(human_approval, dict):
            metadata = intent.get("_agent_metadata") or {}
            detail = (
                "AI returned action=" + repr(action) +
                "; model_status=" + str(metadata.get("status", "unknown")) +
                "; model_invoked=" + str(metadata.get("model_invoked", "unknown")) +
                ". No verified human-reviewable block proposal was created."
            )
            return fail(
                "awaiting_approval",
                detail,
                {
                    "action": action,
                    "reason": intent.get("reason"),
                    "agent_metadata": {
                        "model": metadata.get("model"),
                        "status": metadata.get("status"),
                        "model_invoked": metadata.get("model_invoked"),
                    },
                    "verification": verification,
                    "human_approval": human_approval,
                },
                code=409,
            )
        else:
            run.proposal_id = human_approval.get("proposal_id")
            run.start_stage(
                "awaiting_approval",
                evidence={
                    "proposal_id": run.proposal_id,
                    "expires_at": human_approval.get("expires_at"),
                    "execution_started": False,
                },
            )
            run.status = "AWAITING_APPROVAL"
    else:
        if action != "no_action":
            return fail(
                "awaiting_approval",
                "This fault is recommendation-only; any executable AI action is rejected.",
                {"action": action},
                code=409,
            )
        run.start_stage(
            "awaiting_approval",
            evidence={
                "acknowledgement_required": True,
                "recommendation_only": True,
                "executor_called": False,
                "reason": intent.get("reason"),
            },
        )
        run.status = "RECOMMENDATION_ONLY_PENDING_ACK"

    manager.save_run(run)
    return run, {"pipeline": pipeline_result}, 200


@pipeline_bp.route("/api/pipeline/current", methods=["GET"])
def api_pipeline_current():
    """Retrieve the current active pipeline run, or last known run state."""
    manager = _get_manager()
    run = manager.get_current_run()
    if run is None:
        return jsonify({"active": False, "run": None}), 200
    is_active = manager.is_run_active()
    return jsonify(
        {
            "active": is_active,
            "run": run.to_dict(),
        }
    ), 200


@pipeline_bp.route("/api/pipeline/preflight", methods=["GET"])
def api_pipeline_preflight():
    """Inspect all injection preconditions and return status, ages, and readiness."""
    manager = _get_manager()
    collector = current_app.config.get("NETOPS_COLLECTOR")
    telemetry_path = collector.telemetry_path if collector else ""
    monitor_path = current_app.config.get(
        "NETOPS_MONITOR_STATUS_PATH",
        os.path.join(
            os.path.dirname(current_app.config.get("NETOPS_INCIDENT_PATH", "")),
            "monitor_status.json",
        ),
    )
    checker = _get_connectivity_checker()
    precondition_checker = current_app.config.get("NETOPS_CONNECTIVITY_CHECKER_OVERRIDE", checker)

    status = get_preflight_status(
        telemetry_path=telemetry_path,
        monitor_status_path=monitor_path,
        connectivity_checker=precondition_checker,
        manager=manager,
    )
    return jsonify(status), 200


@pipeline_bp.route("/api/pipeline/faults", methods=["GET"])
def api_pipeline_faults():
    """Return live-injectable fault metadata and telemetry-derived target policies."""
    generator = current_app.config.get("NETOPS_MAC_FLOOD_GENERATOR")
    mac_table_reset = current_app.config.get("NETOPS_MAC_TABLE_RESET")
    return jsonify(
        {
            "faults": get_live_faults_detail(
                mac_flood_generator=generator, mac_table_reset=mac_table_reset
            ),
        }
    ), 200


@pipeline_bp.route("/api/pipeline/restore", methods=["POST"])
def api_pipeline_restore():
    """Guarded manual lab restore action requiring operator token."""
    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify({"error": "Lab restore is disabled. Configure NETOPS_CHAOS_API_TOKEN."}), 503

    supplied_token = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        supplied_token = auth_header[7:].strip()
    if not supplied_token:
        payload = request.get_json(silent=True) or {}
        supplied_token = str(payload.get("operator_token") or payload.get("token") or "").strip()

    if not supplied_token or not hmac.compare_digest(supplied_token, configured_token):
        return jsonify({"error": "Unauthorized"}), 401

    manager = _get_manager()
    collector = current_app.config.get("NETOPS_COLLECTOR")
    if collector is None or not getattr(collector, "telemetry_path", None):
        return jsonify({"success": False, "error": "Controller telemetry source is unavailable; lab restore refused."}), 503
    context = {"telemetry_path": collector.telemetry_path}
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        if isinstance(payload.get("context"), dict):
            context = {key: value for key, value in payload["context"].items()
                       if key not in {"telemetry", "telemetry_path", "target", "run_command"}}
    context["telemetry_path"] = collector.telemetry_path
    if "NETOPS_RUN_COMMAND_OVERRIDE" in current_app.config:
        context["run_command"] = current_app.config["NETOPS_RUN_COMMAND_OVERRIDE"]
    if "NETOPS_APPROVAL_STORE" in current_app.config:
        context["approval_store"] = current_app.config["NETOPS_APPROVAL_STORE"]

    try:
        with manager.exclusive_run_lock():
            res, code = execute_guarded_restore(context=context, manager=manager)
    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 409
    return jsonify(res), code


@pipeline_bp.route("/api/pipeline/inject", methods=["POST"])
def api_pipeline_inject():
    """Inject a live fault scenario with fail-closed guards and create a pipeline run."""
    # 1. Bearer token auth
    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify(
            {"error": "Fault injection is disabled. Configure NETOPS_CHAOS_API_TOKEN."}
        ), 503

    supplied_token = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        supplied_token = auth_header[7:].strip()
    if not supplied_token:
        payload = request.get_json(silent=True) or {}
        supplied_token = str(payload.get("operator_token") or payload.get("token") or "").strip()

    if not supplied_token or not hmac.compare_digest(supplied_token, configured_token):
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    fault_id = payload.get("fault_id")
    if not fault_id or not isinstance(fault_id, str):
        return jsonify({"error": "Missing or invalid 'fault_id' in JSON body."}), 400

    manager = _get_manager()
    collector = current_app.config.get("NETOPS_COLLECTOR")
    telemetry_path = collector.telemetry_path if collector else ""
    monitor_path = current_app.config.get(
        "NETOPS_MONITOR_STATUS_PATH",
        os.path.join(
            os.path.dirname(current_app.config.get("NETOPS_INCIDENT_PATH", "")),
            "monitor_status.json",
        ),
    )

    try:
        with manager.exclusive_run_lock():
            # 2. Check all fail-closed preconditions
            checker = _get_connectivity_checker()
            precondition_checker = current_app.config.get(
                "NETOPS_CONNECTIVITY_CHECKER_OVERRIDE", checker
            )

            allowed, error_msg, status_code = check_injection_preconditions(
                telemetry_path=telemetry_path,
                monitor_status_path=monitor_path,
                connectivity_checker=precondition_checker,
                manager=manager,
            )
            if not allowed:
                return jsonify({"error": error_msg, "fault_id": fault_id}), status_code

            # 3. Execute guarded injection
            context = {"telemetry_path": telemetry_path}
            if "NETOPS_RUN_COMMAND_OVERRIDE" in current_app.config:
                context["run_command"] = current_app.config["NETOPS_RUN_COMMAND_OVERRIDE"]
            if "NETOPS_MAC_FLOOD_GENERATOR" in current_app.config:
                context["mac_flood_generator"] = current_app.config["NETOPS_MAC_FLOOD_GENERATOR"]
            if "NETOPS_MAC_TABLE_RESET" in current_app.config:
                context["mac_table_reset"] = current_app.config["NETOPS_MAC_TABLE_RESET"]

            result, code = execute_guarded_injection(
                fault_id=fault_id,
                context=context,
                manager=manager,
            )
            if code != 201:
                return jsonify(result), code

            run, orchestration, orchestration_code = _advance_pipeline_after_injection(
                fault_id=fault_id,
                manager=manager,
                collector=collector,
            )
            response = dict(result)
            response["run"] = run.to_dict() if run else None
            response.update(orchestration)
            return jsonify(response), orchestration_code
    except RuntimeError as exc:
        return jsonify({"error": str(exc), "fault_id": fault_id}), 409


@pipeline_bp.route("/api/pipeline/acknowledge", methods=["POST"])
def api_pipeline_acknowledge_recommendation():
    """Record explicit human acknowledgement of a non-executable recommendation."""
    approver, error = authenticated_approver()
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason", "")).strip()
    if not reason:
        return jsonify({"error": "A human acknowledgement reason is required."}), 400

    manager = _get_manager()
    run = manager.get_current_run()
    if run is None or run.status != "RECOMMENDATION_ONLY_PENDING_ACK":
        return jsonify({"error": "There is no recommendation awaiting human acknowledgement."}), 409
    if run.executable:
        return jsonify(
            {"error": "Executable runs must use the separate proposal approval workflow."}
        ), 409

    run.complete_stage(
        "awaiting_approval",
        evidence={
            "acknowledged": True,
            "acknowledged_by": approver,
            "acknowledgement_reason": reason,
            "acknowledged_at_utc": datetime.now(timezone.utc).isoformat(),
        },
    )
    run.skip_stage(
        "approved", reason="Recommendation-only run; no executable approval was granted."
    )
    run.skip_stage("executed", reason="Recommendation-only run; executor was not called.")
    run.skip_stage("connectivity_verified", reason="No network mutation was executed.")
    manager.finalize_run(run, outcome="recommendation_only")
    return jsonify(
        {
            "success": True,
            "run": run.to_dict(),
            "executor_called": False,
        }
    ), 200
