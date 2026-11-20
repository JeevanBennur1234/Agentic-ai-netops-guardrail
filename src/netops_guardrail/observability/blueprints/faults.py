"""Authenticated fault registry endpoint."""

import hmac
import os

from flask import Blueprint, jsonify, request

from netops_guardrail.faults.registry import list_faults

faults_bp = Blueprint("faults", __name__)


@faults_bp.route("/api/faults", methods=["GET"])
def api_faults():
    """List registered faults; use the same bearer token as chaos endpoints."""
    configured_token = os.environ.get("NETOPS_CHAOS_API_TOKEN", "")
    if not configured_token:
        return jsonify({
            "error": "Fault registry is disabled. Configure NETOPS_CHAOS_API_TOKEN."
        }), 503

    supplied_token = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied_token, f"Bearer {configured_token}"):
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"faults": list_faults()}), 200
