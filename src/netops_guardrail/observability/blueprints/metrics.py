"""Metrics and dashboard routes for NetOps Guardrail observability."""
import json
import os

from flask import Blueprint, Response, current_app, jsonify, render_template, request, send_file
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest

metrics_bp = Blueprint("metrics", __name__)


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

    return jsonify({
        "metrics": collector.get_summary_dict(),
        "telemetry": telem,
        "audit_records": records
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
            "/api/simulate",
            "/api/topology",
            "/api/pipeline/trace",
            "/api/audit/chain",
            "/approvals",
            "/api/approvals",
            "/api/approvals/<proposal_id>/decision",
            "/api/approvals/<proposal_id>/execute",
            "/api/chaos/inject-loop",
            "/api/chaos/standby-forwarding"
        ]
    }), 200
