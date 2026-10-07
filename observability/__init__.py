"""
Observability package for Agentic AI-NetOps Guardrail.
Provides Prometheus metrics exposition, endpoint server, and Grafana dashboard assets.
"""

from .metrics import NetOpsMetricsCollector
from .server import create_metrics_app

__all__ = ["NetOpsMetricsCollector", "create_metrics_app"]
