"""Audit chain and pipeline trace routes for NetOps Guardrail."""
import json
import os

from flask import Blueprint, current_app, jsonify, request

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/api/pipeline/trace", methods=["GET"])
def api_pipeline_trace():
    trace_file = current_app.config["NETOPS_TRACE_FILE"]
    try:
        limit = int(request.args.get("limit", 20))
        if limit < 1:
            limit = 20
    except (ValueError, TypeError):
        limit = 20

    if not os.path.exists(trace_file):
        return jsonify([]), 200

    try:
        with open(trace_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        records = []
        for line in lines[-limit:]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return jsonify(records), 200
    except Exception:
        return jsonify([]), 200


@audit_bp.route("/api/audit/chain", methods=["GET"])
def api_audit_chain():
    collector = current_app.config["NETOPS_COLLECTOR"]
    try:
        limit = int(request.args.get("limit", 20))
        if limit < 1:
            limit = 20
    except (ValueError, TypeError):
        limit = 20

    log_path = collector.audit_log_path
    if not os.path.exists(log_path):
        return jsonify([]), 200

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            records = json.load(f)
        if not isinstance(records, list):
            return jsonify([]), 200

        chain_summary = []
        for r in records[-limit:]:
            intent = r.get("intent") or {}
            action = (
                intent.get("action", "unknown")
                if isinstance(intent, dict)
                else str(intent)
            )
            curr_hash = str(r.get("current_hash", ""))
            chain_summary.append({
                "index": r.get("index"),
                "decision": r.get("decision"),
                "action": action,
                "current_hash": curr_hash[:16] if len(curr_hash) >= 16 else curr_hash,
                "timestamp": r.get("timestamp")
            })
        return jsonify(chain_summary), 200
    except Exception:
        return jsonify([]), 200
