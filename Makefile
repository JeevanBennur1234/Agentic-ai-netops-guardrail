.PHONY: help install test lint run-dashboard demo

# Default target
help:
	@echo "Agentic AI-NetOps Guardrail - Developer Commands"
	@echo ""
	@echo "Targets:"
	@echo "  install        Install package in editable mode with development dependencies"
	@echo "  test           Run test suite with pytest"
	@echo "  lint           Run Ruff linter on codebase"
	@echo "  run-dashboard  Start observability metrics server and web dashboard"
	@echo "  demo           Generate demo approval proposals and trace records"
	@echo ""
	@echo "Environment Variables:"
	@echo "  METRICS_HOST           Host interface to bind the dashboard server (default: 0.0.0.0)"
	@echo "  METRICS_PORT           Port to bind the dashboard server (default: 8000)"
	@echo "  NETOPS_APPROVER_TOKENS Comma-separated list of bearer tokens for human approvers"
	@echo "  NETOPS_CHAOS_API_TOKEN Bearer token required for fault-injection chaos endpoints"

install:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check .

run-dashboard:
	netops-server

demo:
	python3 -m netops_guardrail.testbed.create_demo_approval
