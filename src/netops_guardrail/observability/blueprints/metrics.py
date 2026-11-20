"""Metrics and dashboard routes for NetOps Guardrail observability."""
import json
import os
from datetime import datetime, timezone

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
)
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest

from netops_guardrail.controller.trunk_roles import derive_trunk_roles

metrics_bp = Blueprint("metrics", __name__)


def _derive_discovered_hosts(telemetry):
    """Infer endpoint observations only from MAC learning on non-trunk physical ports."""
    switches = telemetry.get("switches") or {}
    trunk_ports = set()
    # Keep known inter-switch endpoints classified as trunks even after a
    # DELETE event removes them from the active "links" snapshot. Otherwise,
    # MACs learned on former trunk ports can be misreported as directly attached
    # hosts while the testbed is being torn down.
    for link in (telemetry.get("links") or []) + (telemetry.get("link_events") or []):
        if not isinstance(link, dict):
            continue
        event = str(link.get("event", "ADD")).upper()
        if event not in {"ADD", "DELETE"}:
            continue
        src_switch = str(link.get("src_switch", "")).strip()
        src_port = str(link.get("src_port", "")).strip()
        dst_switch = str(link.get("dst_switch", "")).strip()
        dst_port = str(link.get("dst_port", "")).strip()
        if src_switch and src_port:
            trunk_ports.add((src_switch, src_port))
        if dst_switch and dst_port:
            trunk_ports.add((dst_switch, dst_port))

    latest = {}
    for event in telemetry.get("mac_learning_events") or []:
        if not isinstance(event, dict):
            continue
        switch_id = str(event.get("switch_id", ""))
        port_id = str(event.get("port_id", ""))
        mac = str(event.get("source_mac", "")).lower()
        if not switch_id or not port_id or not mac or (switch_id, port_id) in trunk_ports:
            continue
        switch = switches.get(switch_id) or {}
        if port_id not in (switch.get("ports") or {}):
            continue
        try:
            if int(port_id) >= 4294967040:
                continue
        except ValueError:
            continue
        key = (switch_id, port_id, mac)
        timestamp = str(event.get("timestamp_utc", ""))
        if key not in latest or timestamp > latest[key]:
            latest[key] = timestamp

    return [
        {
            "id": "host-" + mac.replace(":", ""),
            "label": "Host " + mac[-5:],
            "mac": mac,
            "switch_id": switch_id,
            "port_id": port_id,
            "last_seen_utc": timestamp,
        }
        for (switch_id, port_id, mac), timestamp in sorted(latest.items())
    ]


@metrics_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "netops-guardrail-observability",
        "read_only": True
    }), 200


@metrics_bp.route("/metrics", methods=["GET"])
def metrics():
    collector = current_app.config["NETOPS_COLLECTOR"]
    registry = CollectorRegistry()
    registry.register(collector)
    data = generate_latest(registry)
    return Response(data, mimetype=CONTENT_TYPE_LATEST)


@metrics_bp.route("/metrics/json", methods=["GET"])
def metrics_json():
    collector = current_app.config["NETOPS_COLLECTOR"]
    return jsonify(collector.get_summary_dict()), 200


@metrics_bp.route("/dashboard", methods=["GET"])
def dashboard():
    base_dir = current_app.config.get("BASE_DIR", "")
    dash_path = os.path.join(base_dir, "dashboard", "index.html")
    if os.path.exists(dash_path):
        return send_file(dash_path)
    return render_template("dashboard.html")


@metrics_bp.route("/api/status", methods=["GET"])
def api_status():
    collector = current_app.config["NETOPS_COLLECTOR"]
    telem = {}
    if os.path.exists(collector.telemetry_path):
        try:
            with open(collector.telemetry_path, "r", encoding="utf-8") as f:
                telem = json.load(f)
        except Exception:
            pass

    records = []
    if os.path.exists(collector.audit_log_path):
        try:
            with open(collector.audit_log_path, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            pass

    if isinstance(telem, dict):
        telem["hosts"] = telem.get("hosts") or _derive_discovered_hosts(telem)
        telem["trunk_roles"] = telem.get("trunk_roles") or derive_trunk_roles(telem)

    incident_path = current_app.config.get(
        "NETOPS_INCIDENT_PATH",
        os.path.join(current_app.config.get("BASE_DIR", ""), "observability", "data", "incidents", "incidents.json"),
    )
    incidents = []
    if os.path.exists(incident_path):
        try:
            with open(incident_path, "r", encoding="utf-8") as f:
                incidents = json.load(f)
        except (OSError, json.JSONDecodeError):
            incidents = []

    monitor_path = current_app.config.get(
        "NETOPS_MONITOR_STATUS_PATH",
        os.path.join(os.path.dirname(incident_path), "monitor_status.json"),
    )
    monitor = {"status": "stopped", "ai_enabled": False, "last_heartbeat_utc": None}
    if os.path.exists(monitor_path):
        try:
            with open(monitor_path, "r", encoding="utf-8") as f:
                candidate = json.load(f)
            if not isinstance(candidate, dict):
                raise ValueError("Monitor heartbeat must be a JSON object")
            heartbeat = datetime.fromisoformat(
                str(candidate.get("last_heartbeat_utc", "")).replace("Z", "+00:00")
            )
            if heartbeat.tzinfo is None:
                heartbeat = heartbeat.replace(tzinfo=timezone.utc)
            interval = max(0.1, float(candidate.get("interval_seconds", 5)))
            age = max(0.0, (datetime.now(timezone.utc) - heartbeat).total_seconds())
            if age <= max(30.0, interval * 6) and candidate.get("status") in {"running", "degraded"}:
                monitor = {
                    **candidate,
                    "status": candidate["status"],
                    "heartbeat_age_seconds": round(age, 1),
                }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            monitor = {"status": "unknown", "ai_enabled": False, "last_heartbeat_utc": None}

    return jsonify({
        "metrics": collector.get_summary_dict(),
        "telemetry": telem,
        "audit_records": records,
        "incidents": incidents if isinstance(incidents, list) else [],
        "monitor": monitor,
    }), 200


@metrics_bp.route("/", methods=["GET"])
def index():
    accept_header = request.headers.get("Accept", "")
    if "text/html" in accept_header:
        base_dir = current_app.config.get("BASE_DIR", "")
        dash_path = os.path.join(base_dir, "dashboard", "index.html")
        if os.path.exists(dash_path):
            return send_file(dash_path)
        return render_template("dashboard.html")
    return jsonify({
        "name": "Agentic AI-NetOps Guardrail Observability Service",
        "endpoints": [
            "/health",
            "/metrics",
            "/metrics/json",
            "/dashboard",
            "/api/status",
            "/api/pipeline/current",
            "/api/pipeline/inject",
            "/api/pipeline/preflight",
            "/api/pipeline/restore",
            "/api/pipeline/faults",
            "/api/topology",
            "/api/pipeline/trace",
            "/api/audit/chain",
            "/approvals",
            "/api/approvals",
            "/api/approvals/<proposal_id>/decision",
            "/api/approvals/<proposal_id>/execute",
            "/api/chaos/inject-loop",
            "/api/chaos/standby-forwarding",
            "/api/faults"
        ]
    }), 200
