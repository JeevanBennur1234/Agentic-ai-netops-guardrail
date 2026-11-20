"""Topology and fault injection routes for NetOps Guardrail."""

import hmac
import importlib
import json
import os
import subprocess

from flask import Blueprint, current_app, jsonify, request

from netops_guardrail.controller.trunk_roles import derive_discovered_hosts, derive_trunk_roles
from netops_guardrail.faults.registry import get_fault
from netops_guardrail.verifier.safety_verifier import build_topology

topology_bp = Blueprint("topology", __name__)


@topology_bp.route("/api/topology", methods=["GET"])
def api_topology():
    collector = current_app.config["NETOPS_COLLECTOR"]
    telem_path = collector.telemetry_path
    if not os.path.exists(telem_path):
        return jsonify({"nodes": [], "edges": []}), 200
    try:
        with open(telem_path, "r", encoding="utf-8") as f:
            telem = json.load(f)
        if not isinstance(telem, dict):
            return jsonify({"nodes": [], "edges": []}), 200
        graph = build_topology(telem)
        nodes = [{"id": str(n), "type": graph.nodes[n].get("type", "unknown")} for n in graph.nodes]
        edges = [{"source": str(u), "target": str(v)} for u, v in graph.edges]
        trunk_roles = telem.get("trunk_roles") or derive_trunk_roles(telem)
        hosts = telem.get("hosts") or derive_discovered_hosts(telem)
        return jsonify({"nodes": nodes, "edges": edges, "trunk_roles": trunk_roles, "hosts": hosts}), 200
    except Exception:
        return jsonify({"nodes": [], "edges": []}), 200


@topology_bp.route("/api/chaos/inject-loop", methods=["POST"])
def api_chaos_inject_loop():
    """Restore the redundant trunk as a controlled fault, then run the AI gate."""
    collector = current_app.config["NETOPS_COLLECTOR"]
    audit = current_app.config["NETOPS_AUDIT"]
    fault = get_fault("redundant_trunk_restored")

    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify(
            {
                "error": "Fault injection is disabled. Configure NETOPS_CHAOS_API_TOKEN when starting the local server."
            }
        ), 503
    supplied_token = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
        return jsonify({"error": "Unauthorized"}), 401
    if request.args.get("confirm", "").strip().lower() != "true":
        return jsonify(
            {"error": "Confirmation required. Call with ?confirm=true to continue."}
        ), 400

    for bridge in ("s1", "s2"):
        check = subprocess.run(
            ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if check.returncode != 0:
            return jsonify(
                {
                    "error": f"Controlled fault injection requires live Mininet bridge {bridge}; no command was run."
                }
            ), 409

    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    module_name, separator, function_name = checker_spec.partition(":")
    if not separator or not module_name or not function_name:
        return jsonify(
            {
                "error": "Fault injection disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function first."
            }
        ), 503
    try:
        checker_module = importlib.import_module(module_name)
        connectivity_checker = getattr(checker_module, function_name)
        if not callable(connectivity_checker):
            raise TypeError("configured connectivity checker is not callable")
        baseline = fault.ground_truth_check({"connectivity_checker": connectivity_checker})
        if baseline.get("error"):
            return jsonify(
                {"error": f"Baseline connectivity checker failed closed: {baseline['error']}"}
            ), 503
        if baseline.get("passed") is not True:
            return jsonify(
                {
                    "error": "Baseline host-to-host connectivity did not pass; refusing to inject a fault."
                }
            ), 409
    except Exception as exc:
        return jsonify(
            {"error": f"Baseline connectivity checker failed closed: {type(exc).__name__}: {exc}"}
        ), 503

    injection = fault.injector({"run_command": subprocess.run})
    if not injection.get("success"):
        command = injection.get("failed_command") or ["", "", "unknown"]
        return jsonify(
            {
                "error": f"Fault reset command failed ({command[2]}): {injection.get('error', '')}",
                "network_mutation_attempted": injection.get("network_mutation_attempted", True),
                "execution_started": False,
            }
        ), 503

    try:
        post_reset = fault.ground_truth_check({"connectivity_checker": connectivity_checker})
        if post_reset.get("error"):
            return jsonify(
                {
                    "error": f"Post-reset connectivity checker failed closed: {post_reset['error']}",
                    "network_mutation_attempted": True,
                    "execution_started": False,
                }
            ), 503
        if post_reset.get("passed") is not True:
            return jsonify(
                {
                    "error": "Host-to-host connectivity did not pass after restoring the redundant trunk; no AI proposal was created.",
                    "network_mutation_attempted": True,
                    "execution_started": False,
                }
            ), 503
    except Exception as exc:
        return jsonify(
            {
                "error": f"Post-reset connectivity checker failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 503

    try:
        with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
            telemetry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify(
            {
                "error": f"Cannot read Ryu telemetry after fault reset: {exc}",
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 503

    detection = fault.detector(telemetry)
    states = detection["stp_states"]
    prerequisites = detection["prerequisites"]
    if not (
        prerequisites["primary_trunk_discovered"] and prerequisites["standby_trunk_discovered"]
    ):
        return jsonify(
            {
                "error": "Ryu telemetry does not confirm both redundant trunks; keep Mininet/Ryu running and retry.",
                "observed_links": detection["observed_links"],
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 409
    if not detection["detected"]:
        return jsonify(
            {
                "error": "Safety precondition failed: host access and primary trunk must be FORWARD, and a standby endpoint must be STP BLOCK.",
                "stp_states": states,
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 409

    incident_context = {
        "fault_type": "redundant_trunk_restored",
        "summary": "Controlled fault injection restored redundant trunk B and cleared prior guardrail drop rules on that trunk. Use current Ryu topology and STP telemetry as evidence.",
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
        "expected_action": "block",
        "expected_target_switch": "1",
        "expected_from_port": "3",
        "reason": "Re-isolate the restored standby trunk while preserving the primary trunk and host reachability.",
    }
    try:
        pipeline = current_app.config["NETOPS_DECIDE"](
            telemetry_path=collector.telemetry_path,
            execute_approved=False,
            audit_logger=audit,
            incident_context=incident_context,
        )
    except Exception as exc:
        return jsonify(
            {
                "error": f"AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 503

    if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
        return jsonify(
            {
                "error": "AI/verifier did not produce a safe human-reviewable block proposal. No remediation was executed.",
                "fault": incident_context,
                "pipeline": pipeline,
                "network_mutation_attempted": True,
                "execution_started": False,
            }
        ), 409

    return jsonify(
        {
            "status": "fault_injected_proposal_created",
            "fault": incident_context,
            "pipeline": pipeline,
            "proposal_id": pipeline["human_approval"]["proposal_id"],
            "expires_at": pipeline["human_approval"]["expires_at"],
            "network_mutation_attempted": True,
            "execution_started": False,
            "next_step": "Open /approvals, inspect the AI-generated intent and verifier checks, and approve/reject with a reason.",
        }
    ), 200


@topology_bp.route("/api/chaos/standby-forwarding", methods=["POST"])
def api_issue2_standby_forwarding():
    """Create an Issue 2 proposal only from verified live telemetry."""
    collector = current_app.config["NETOPS_COLLECTOR"]
    audit = current_app.config["NETOPS_AUDIT"]
    fault = get_fault("standby_forwarding_anomaly")

    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify({"error": "Issue 2 is disabled: configure NETOPS_CHAOS_API_TOKEN."}), 503
    supplied_token = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
        return jsonify({"error": "Unauthorized"}), 401
    if request.args.get("confirm", "").strip().lower() != "true":
        return jsonify({"error": "Confirmation required. Call with ?confirm=true."}), 400

    for bridge in ("s1", "s2"):
        check = subprocess.run(
            ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if check.returncode != 0:
            return jsonify(
                {
                    "error": f"Issue 2 requires live Mininet bridge {bridge}; no proposal was created.",
                    "network_mutation_attempted": False,
                }
            ), 409

    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    module_name, separator, function_name = checker_spec.partition(":")
    if not separator or not module_name or not function_name:
        return jsonify(
            {
                "error": "Issue 2 disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function.",
                "network_mutation_attempted": False,
            }
        ), 503
    try:
        checker_module = importlib.import_module(module_name)
        connectivity_checker = getattr(checker_module, function_name)
        if not callable(connectivity_checker):
            raise TypeError("configured connectivity checker is not callable")
        baseline = fault.ground_truth_check({"connectivity_checker": connectivity_checker})
        if baseline.get("error") or baseline.get("passed") is not True:
            return jsonify(
                {
                    "error": "Live baseline host connectivity did not pass; no proposal was created.",
                    "network_mutation_attempted": False,
                }
            ), 409
    except Exception as exc:
        return jsonify(
            {
                "error": f"Live connectivity check failed closed: {type(exc).__name__}: {exc}",
                "network_mutation_attempted": False,
            }
        ), 503

    for bridge, port in (("s1", "3"), ("s2", "2")):
        result = subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        if result.returncode != 0:
            return jsonify(
                {
                    "error": f"Could not inspect existing flows on {bridge}; refusing duplicate proposal.",
                    "network_mutation_attempted": False,
                }
            ), 503
        for line in (result.stdout or "").splitlines():
            if "priority=65500" in line and f"in_port={port}" in line and "actions=drop" in line:
                return jsonify(
                    {
                        "error": f"Standby trunk already has a guardrail drop rule on {bridge} port {port}; reconcile the existing action before a new proposal.",
                        "network_mutation_attempted": False,
                    }
                ), 409

    try:
        telemetry = json.loads(open(collector.telemetry_path, "r", encoding="utf-8").read())
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify(
            {
                "error": f"Could not read live Ryu telemetry: {exc}",
                "network_mutation_attempted": False,
            }
        ), 503

    observation = fault.detector(telemetry)
    if not observation.get("ready_for_investigation") or not observation.get("detected"):
        return jsonify(
            {
                "status": "no_live_anomaly",
                "message": "Live Ryu telemetry does not confirm the standby-forwarding anomaly. No AI proposal was created.",
                "observation": observation,
                "network_mutation_attempted": False,
                "execution_started": False,
            }
        ), 200

    incident_context = {
        "fault_type": "standby_forwarding_anomaly",
        "summary": "Live telemetry reports both standby endpoints forwarding.",
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
        "reason": "Evaluate standby forwarding while preserving primary-path host reachability.",
        "source": "live_telemetry",
        "observation": observation,
        "execution_allowed": True,
    }
    try:
        pipeline = current_app.config["NETOPS_DECIDE"](
            telemetry_path=collector.telemetry_path,
            execute_approved=False,
            audit_logger=audit,
            incident_context=incident_context,
        )
    except Exception as exc:
        return jsonify(
            {
                "error": f"Issue 2 AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
                "incident_context": incident_context,
                "network_mutation_attempted": False,
                "execution_started": False,
            }
        ), 503

    if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
        return jsonify(
            {
                "error": "AI/verifier did not create a safe human-reviewable proposal. No remediation was executed.",
                "incident_context": incident_context,
                "observation": observation,
                "pipeline": pipeline,
                "network_mutation_attempted": False,
                "execution_started": False,
            }
        ), 409

    return jsonify(
        {
            "status": "issue2_proposal_created",
            "issue": "unexpected_standby_forwarding",
            "detection_mode": "live_telemetry",
            "observation": observation,
            "incident_context": incident_context,
            "pipeline": pipeline,
            "proposal_id": pipeline["human_approval"]["proposal_id"],
            "expires_at": pipeline["human_approval"]["expires_at"],
            "network_mutation_attempted": False,
            "execution_started": False,
            "next_step": "Review the proposal on /approvals. Approval is separate from execution; reject if you disagree.",
        }
    ), 200
