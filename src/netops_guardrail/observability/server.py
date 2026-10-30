"""Observability service and dashboard application for Agentic AI-NetOps Guardrail."""

import importlib
import os
import subprocess

from flask import Flask

from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.controller.decision_gate import apply_intent_to_graph, decide
from netops_guardrail.controller.human_verifier import ApprovalError, HumanApprovalStore
from netops_guardrail.controller.standby_anomaly import inspect_standby_forwarding
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.observability.blueprints import (
    audit_bp,
    auth_bp,
    metrics_bp,
    proposals_bp,
    topology_bp,
)
from netops_guardrail.observability.metrics import NetOpsMetricsCollector
from netops_guardrail.verifier.safety_verifier import (
    build_topology,
    run_safety_checks,
    test_port_removal,
)

base_dir = str(NETOPS_HOME)

# Load DASHBOARD_HTML template content for backwards-compatible reference
_template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
if os.path.exists(_template_path):
    with open(_template_path, "r", encoding="utf-8") as _f:
        DASHBOARD_HTML = _f.read()
else:
    DASHBOARD_HTML = ""


def create_metrics_app(
    telemetry_path=None,
    audit_log_path=None,
    trace_log_path=None,
    approval_path=None,
) -> Flask:
    template_folder = os.path.join(os.path.dirname(__file__), "templates")
    static_folder = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder,
        static_url_path="/static",
    )

    collector = NetOpsMetricsCollector(
        telemetry_path=telemetry_path,
        audit_log_path=audit_log_path,
    )
    audit = AuditTrail(log_path=audit_log_path, auto_load=True)
    trace_file = trace_log_path or os.path.join(
        base_dir, "observability", "data", "pipeline_trace.jsonl"
    )
    approval_store = HumanApprovalStore(path=approval_path)

    app.config["NETOPS_COLLECTOR"] = collector
    app.config["NETOPS_AUDIT"] = audit
    app.config["NETOPS_TRACE_FILE"] = trace_file
    app.config["NETOPS_APPROVAL_STORE"] = approval_store
    app.config["BASE_DIR"] = base_dir

    app.register_blueprint(auth_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(proposals_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(audit_bp)

    return app


def main():
    port = int(os.environ.get("METRICS_PORT", 8000))
    host = os.environ.get("METRICS_HOST", "127.0.0.1")
    print(f"Starting NetOps Observability Metrics Server on http://{host}:{port}/")
    print(f"Interactive Web Dashboard available at: http://localhost:{port}/dashboard")
    print(f"Prometheus Metrics Feed available at:   http://localhost:{port}/metrics")
    app = create_metrics_app()
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()

__all__ = [
    "create_metrics_app",
    "main",
    "subprocess",
    "importlib",
    "apply_intent_to_graph",
    "decide",
    "ApprovalError",
    "HumanApprovalStore",
    "inspect_standby_forwarding",
    "build_topology",
    "run_safety_checks",
    "test_port_removal",
    "AuditTrail",
    "NetOpsMetricsCollector",
    "base_dir",
    "DASHBOARD_HTML",
]
