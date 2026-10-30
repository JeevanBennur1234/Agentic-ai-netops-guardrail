"""Authentication blueprint and helpers for NetOps Guardrail observability."""
import hmac
import json
import os

from flask import Blueprint, jsonify, request

auth_bp = Blueprint("auth", __name__)


def authenticated_approver():
    """Authenticate a human operator using an explicit token-to-identity map."""
    raw_tokens = os.environ.get("NETOPS_APPROVER_TOKENS", "")
    try:
        token_map = json.loads(raw_tokens) if raw_tokens else {}
    except json.JSONDecodeError:
        token_map = {}
    if not isinstance(token_map, dict) or not token_map:
        return None, (jsonify({
            "error": "Human approval API is disabled. Configure NETOPS_APPROVER_TOKENS as a JSON object mapping approver IDs to strong tokens."
        }), 503)
    header = request.headers.get("Authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return None, (jsonify({"error": "Bearer authentication required"}), 401)
    for approver_id, configured_token in token_map.items():
        if isinstance(configured_token, str) and hmac.compare_digest(supplied, configured_token):
            return str(approver_id), None
    return None, (jsonify({"error": "Unauthorized"}), 401)
