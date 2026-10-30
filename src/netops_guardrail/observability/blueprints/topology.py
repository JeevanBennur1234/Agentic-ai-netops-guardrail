"""Topology and fault injection routes for NetOps Guardrail."""
import hmac
import importlib
import json
import os
import subprocess
from flask import Blueprint, current_app, jsonify, request

import netops_guardrail.observability.server as server_module
from netops_guardrail.controller.standby_anomaly import inspect_standby_forwarding
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
        nodes = [
            {"id": str(n), "type": graph.nodes[n].get("type", "unknown")}
            for n in graph.nodes
        ]
        edges = [
            {"source": str(u), "target": str(v)}
            for u, v in graph.edges
        ]
        return jsonify({"nodes": nodes, "edges": edges}), 200
    except Exception:
        return jsonify({"nodes": [], "edges": []}), 200


@topology_bp.route("/api/chaos/inject-loop", methods=["POST"])
def api_chaos_inject_loop():
    """Restore the redundant trunk as a controlled fault, then run the AI gate."""
    collector = current_app.config["NETOPS_COLLECTOR"]
    audit = current_app.config["NETOPS_AUDIT"]

    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify({
            "error": "Fault injection is disabled. Configure NETOPS_CHAOS_API_TOKEN when starting the local server."
        }), 503
    supplied_token = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
        return jsonify({"error": "Unauthorized"}), 401
    if request.args.get("confirm", "").strip().lower() != "true":
        return jsonify({"error": "Confirmation required. Call with ?confirm=true to continue."}), 400

    for bridge in ("s1", "s2"):
        check = server_module.subprocess.run(
            ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
            shell=False, capture_output=True, text=True, check=False, timeout=3,
        )
        if check.returncode != 0:
            return jsonify({
                "error": f"Controlled fault injection requires live Mininet bridge {bridge}; no command was run."
            }), 409

    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    module_name, separator, function_name = checker_spec.partition(":")
    if not separator or not module_name or not function_name:
        return jsonify({
            "error": "Fault injection disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function first."
        }), 503
    try:
        checker_module = server_module.importlib.import_module(module_name)
        connectivity_checker = getattr(checker_module, function_name)
        if not callable(connectivity_checker):
            raise TypeError("configured connectivity checker is not callable")
        if connectivity_checker() is not True:
            return jsonify({
                "error": "Baseline host-to-host connectivity did not pass; refusing to inject a fault."
            }), 409
    except Exception as exc:
        return jsonify({
            "error": f"Baseline connectivity checker failed closed: {type(exc).__name__}: {exc}"
        }), 503

    commands = [
        ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "in_port=3"],
        ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s2", "in_port=2"],
        ["sudo", "-n", "ip", "link", "set", "s1-eth3", "up"],
        ["sudo", "-n", "ip", "link", "set", "s2-eth2", "up"],
    ]
    for command in commands:
        try:
            result = server_module.subprocess.run(
                command, shell=False, capture_output=True, text=True,
                check=False, timeout=4,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return jsonify({
                "error": f"Fault reset command failed ({command[2]}): {exc}",
                "network_mutation_attempted": True, "execution_started": False,
            }), 503
        if result.returncode != 0:
            return jsonify({
                "error": f"Fault reset command failed ({command[2]}): {(result.stderr or result.stdout).strip()}",
                "network_mutation_attempted": True, "execution_started": False,
            }), 503

    try:
        if connectivity_checker() is not True:
            return jsonify({
                "error": "Host-to-host connectivity did not pass after restoring the redundant trunk; no AI proposal was created.",
                "network_mutation_attempted": True,
                "execution_started": False,
            }), 503
    except Exception as exc:
        return jsonify({
            "error": f"Post-reset connectivity checker failed closed: {type(exc).__name__}: {exc}",
            "network_mutation_attempted": True,
            "execution_started": False,
        }), 503

    try:
        with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
            telemetry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({
            "error": f"Cannot read Ryu telemetry after fault reset: {exc}",
            "network_mutation_attempted": True, "execution_started": False,
        }), 503

    switches = telemetry.get("switches", {})
    states = {
        str(sw): {str(port): str(state).upper()
                  for port, state in (data.get("stp_port_states") or {}).items()}
        for sw, data in switches.items() if isinstance(data, dict)
    }
    links = set()
    for link in telemetry.get("links", []):
        if isinstance(link, dict):
            a = f"s{str(link.get('src_switch', '')).strip()}-p{str(link.get('src_port', '')).strip()}"
            b = f"s{str(link.get('dst_switch', '')).strip()}-p{str(link.get('dst_port', '')).strip()}"
            links.add(tuple(sorted((a, b))))
    trunk_a = tuple(sorted(("s1-p2", "s2-p1")))
    trunk_b = tuple(sorted(("s1-p3", "s2-p2")))
    if trunk_a not in links or trunk_b not in links:
        return jsonify({
            "error": "Ryu telemetry does not confirm both redundant trunks; keep Mininet/Ryu running and retry.",
            "observed_links": sorted(links), "network_mutation_attempted": True,
            "execution_started": False,
        }), 409
    if not (
        states.get("1", {}).get("1") == "FORWARD"
        and states.get("2", {}).get("3") == "FORWARD"
        and states.get("1", {}).get("2") == "FORWARD"
        and states.get("2", {}).get("1") == "FORWARD"
        and "BLOCK" in {states.get("1", {}).get("3", "UNKNOWN"),
                        states.get("2", {}).get("2", "UNKNOWN")}
    ):
        return jsonify({
            "error": "Safety precondition failed: host access and primary trunk must be FORWARD, and a standby endpoint must be STP BLOCK.",
            "stp_states": states, "network_mutation_attempted": True,
            "execution_started": False,
        }), 409

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
        pipeline = server_module.decide(
            telemetry_path=collector.telemetry_path,
            execute_approved=False,
            audit_logger=audit,
            incident_context=incident_context,
        )
    except Exception as exc:
        return jsonify({
            "error": f"AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
            "network_mutation_attempted": True, "execution_started": False,
        }), 503

    if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
        return jsonify({
            "error": "AI/verifier did not produce a safe human-reviewable block proposal. No remediation was executed.",
            "fault": incident_context, "pipeline": pipeline,
            "network_mutation_attempted": True, "execution_started": False,
        }), 409

    return jsonify({
        "status": "fault_injected_proposal_created",
        "fault": incident_context,
        "pipeline": pipeline,
        "proposal_id": pipeline["human_approval"]["proposal_id"],
        "expires_at": pipeline["human_approval"]["expires_at"],
        "network_mutation_attempted": True,
        "execution_started": False,
        "next_step": "Open /approvals, inspect the AI-generated intent and verifier checks, and approve/reject with a reason.",
    }), 200


@topology_bp.route("/api/chaos/standby-forwarding", methods=["POST"])
def api_issue2_standby_forwarding():
    """Run Issue 2 detection or an explicitly labeled, non-disruptive demo signal."""
    collector = current_app.config["NETOPS_COLLECTOR"]
    audit = current_app.config["NETOPS_AUDIT"]

    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify({"error": "Issue 2 is disabled: configure NETOPS_CHAOS_API_TOKEN."}), 503
    supplied_token = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
        return jsonify({"error": "Unauthorized"}), 401
    if request.args.get("confirm", "").strip().lower() != "true":
        return jsonify({"error": "Confirmation required. Call with ?confirm=true."}), 400

    payload = request.get_json(silent=True) or {}
    allow_simulation = payload.get("allow_controlled_simulation") is True

    for bridge in ("s1", "s2"):
        check = server_module.subprocess.run(
            ["sudo", "-n", "ovs-vsctl", "br-exists", bridge],
            shell=False, capture_output=True, text=True, check=False, timeout=3,
        )
        if check.returncode != 0:
            return jsonify({
                "error": f"Issue 2 requires live Mininet bridge {bridge}; no proposal was created.",
                "network_mutation_attempted": False,
            }), 409

    checker_spec = os.environ.get("NETOPS_CONNECTIVITY_CHECKER", "")
    module_name, separator, function_name = checker_spec.partition(":")
    if not separator or not module_name or not function_name:
        return jsonify({
            "error": "Issue 2 disabled: configure a real NETOPS_CONNECTIVITY_CHECKER=module:function.",
            "network_mutation_attempted": False,
        }), 503
    try:
        checker_module = server_module.importlib.import_module(module_name)
        connectivity_checker = getattr(checker_module, function_name)
        if not callable(connectivity_checker) or connectivity_checker() is not True:
            return jsonify({
                "error": "Live baseline host connectivity did not pass; no proposal was created.",
                "network_mutation_attempted": False,
            }), 409
    except Exception as exc:
        return jsonify({
            "error": f"Live connectivity check failed closed: {type(exc).__name__}: {exc}",
            "network_mutation_attempted": False,
        }), 503

    for bridge, port in (("s1", "3"), ("s2", "2")):
        result = server_module.subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge],
            shell=False, capture_output=True, text=True, check=False, timeout=3,
        )
        if result.returncode != 0:
            return jsonify({
                "error": f"Could not inspect existing flows on {bridge}; refusing duplicate proposal.",
                "network_mutation_attempted": False,
            }), 503
        for line in (result.stdout or "").splitlines():
            if "priority=65500" in line and f"in_port={port}" in line and "actions=drop" in line:
                return jsonify({
                    "error": f"Standby trunk already has a guardrail drop rule on {bridge} port {port}; reconcile the existing action before a new proposal.",
                    "network_mutation_attempted": False,
                }), 409

    try:
        with open(collector.telemetry_path, "r", encoding="utf-8") as handle:
            telemetry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({
            "error": f"Could not read live Ryu telemetry: {exc}",
            "network_mutation_attempted": False,
        }), 503

    observation = inspect_standby_forwarding(telemetry)
    if not observation["ready_for_investigation"]:
        return jsonify({
            "error": "Live telemetry is stale or the primary/host path preconditions are not healthy; no Issue 2 proposal was created.",
            "observation": observation,
            "network_mutation_attempted": False,
        }), 409

    live_anomaly = observation["detected"]
    if not live_anomaly and not allow_simulation:
        return jsonify({
            "status": "no_live_anomaly",
            "message": "Live Ryu telemetry does not currently show both standby endpoints FORWARD. No AI proposal was created. Use the explicitly labeled controlled demo option only when you need to demonstrate the review workflow.",
            "observation": observation,
            "network_mutation_attempted": False,
            "execution_started": False,
        }), 200

    incident_context = {
        "fault_type": "standby_forwarding_anomaly",
        "summary": (
            "Live telemetry reports both standby endpoints forwarding."
            if live_anomaly else
            "Controlled simulation of an unexpected standby-forwarding alert; the simulation signal is not a claim that live STP state is anomalous."
        ),
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
        "expected_action": "block",
        "expected_target_switch": "1",
        "expected_from_port": "3",
        "simulation_mode": not live_anomaly,
        "signal_source": "live_telemetry" if live_anomaly else "controlled_demo_signal",
        "observation": observation,
        "reason": (
            "Contain unexpected standby forwarding while preserving the primary trunk and host reachability."
            if live_anomaly else
            "Demonstrate the Issue 2 review flow safely; propose standby isolation for human review without changing switch/STP state during incident injection."
        ),
    }
    try:
        pipeline = server_module.decide(
            telemetry_path=collector.telemetry_path,
            execute_approved=False,
            audit_logger=audit,
            incident_context=incident_context,
        )
    except Exception as exc:
        return jsonify({
            "error": f"Issue 2 AI decision pipeline failed closed: {type(exc).__name__}: {exc}",
            "incident_context": incident_context,
            "network_mutation_attempted": False,
            "execution_started": False,
        }), 503

    if pipeline.get("decision") != "PENDING_HUMAN_APPROVAL" or not pipeline.get("human_approval"):
        return jsonify({
            "error": "AI/verifier did not create a safe human-reviewable proposal. No remediation was executed.",
            "incident_context": incident_context,
            "observation": observation,
            "pipeline": pipeline,
            "network_mutation_attempted": False,
            "execution_started": False,
        }), 409

    return jsonify({
        "status": "issue2_proposal_created",
        "issue": "unexpected_standby_forwarding",
        "detection_mode": "live_telemetry" if live_anomaly else "controlled_simulation",
        "observation": observation,
        "incident_context": incident_context,
        "pipeline": pipeline,
        "proposal_id": pipeline["human_approval"]["proposal_id"],
        "expires_at": pipeline["human_approval"]["expires_at"],
        "network_mutation_attempted": False,
        "execution_started": False,
        "next_step": "Review the proposal on /approvals. Approval is separate from execution; reject if you disagree.",
    }), 200
