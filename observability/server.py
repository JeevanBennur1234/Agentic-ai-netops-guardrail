import os
import sys
from flask import Flask, Response, jsonify

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller", "executor", "observability"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from metrics import NetOpsMetricsCollector


def create_metrics_app(telemetry_path=None, audit_log_path=None):
    """
    Factory function for the Flask Observability & Metrics server.
    Ensures testability with isolated telemetry and audit log files.
    """
    app = Flask(__name__)
    collector = NetOpsMetricsCollector(
        telemetry_path=telemetry_path,
        audit_log_path=audit_log_path
    )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "service": "netops-guardrail-observability",
            "read_only": True
        }), 200

    @app.route("/metrics", methods=["GET"])
    def metrics():
        registry = CollectorRegistry()
        registry.register(collector)
        data = generate_latest(registry)
        return Response(data, mimetype=CONTENT_TYPE_LATEST)

    @app.route("/metrics/json", methods=["GET"])
    def metrics_json():
        return jsonify(collector.get_summary_dict()), 200

    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "name": "Agentic AI-NetOps Guardrail Observability Service",
            "endpoints": [
                "/health",
                "/metrics",
                "/metrics/json"
            ]
        }), 200

    return app


if __name__ == "__main__":
    port = int(os.environ.get("METRICS_PORT", 8000))
    host = os.environ.get("METRICS_HOST", "0.0.0.0")
    print(f"Starting NetOps Observability Metrics Server on http://{host}:{port}/metrics")
    app = create_metrics_app()
    app.run(host=host, port=port)
