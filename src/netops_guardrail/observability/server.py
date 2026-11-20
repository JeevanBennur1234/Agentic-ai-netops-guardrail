"""Observability service and dashboard application for Agentic AI-NetOps Guardrail."""

import importlib
import os
import subprocess
from pathlib import Path

from flask import Flask

from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.controller.decision_gate import apply_intent_to_graph, decide
from netops_guardrail.controller.human_verifier import ApprovalError, HumanApprovalStore
from netops_guardrail.controller.standby_anomaly import inspect_standby_forwarding
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.observability.blueprints import (
    audit_bp,
    auth_bp,
    faults_bp,
    metrics_bp,
    pipeline_bp,
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
    app_base_dir = Path(base_dir)
    if telemetry_path:
        telemetry_file = Path(telemetry_path).resolve()
        if (telemetry_file.name == "latest.json" and telemetry_file.parent.name == "data"
                and telemetry_file.parent.parent.name == "telemetry"):
            app_base_dir = telemetry_file.parents[2]
        else:
            app_base_dir = telemetry_file.parent
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
        str(app_base_dir), "observability", "data", "pipeline_trace.jsonl"
    )
    approval_store = HumanApprovalStore(path=approval_path)

    app.config["NETOPS_COLLECTOR"] = collector
    app.config["NETOPS_AUDIT"] = audit
    app.config["NETOPS_TRACE_FILE"] = trace_file
    app.config["NETOPS_APPROVAL_STORE"] = approval_store
    incident_dir = app_base_dir / "observability" / "data" / "incidents"
    app.config["NETOPS_INCIDENT_PATH"] = str(incident_dir / "incidents.json")
    app.config["NETOPS_MONITOR_STATUS_PATH"] = str(incident_dir / "monitor_status.json")
    app.config["NETOPS_DECIDE"] = decide
    app.config["NETOPS_APPLY_INTENT_TO_GRAPH"] = apply_intent_to_graph
    app.config["BASE_DIR"] = str(app_base_dir)
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(app_base_dir / "observability" / "data" / "pipeline_runs")

    app.register_blueprint(auth_bp)
    app.register_blueprint(faults_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(proposals_bp)
    app.register_blueprint(topology_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(pipeline_bp)

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
