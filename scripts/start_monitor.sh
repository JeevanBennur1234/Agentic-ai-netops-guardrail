#!/usr/bin/env bash
# Standalone launcher for the background deterministic Incident Monitor.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
export NETOPS_HOME="$ROOT"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PY="$PYTHON_BIN"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PY="$VIRTUAL_ENV/bin/python"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "Starting standalone Incident Monitor..."
echo "Telemetry path: $ROOT/telemetry/data/latest.json"
echo "Incident dir:   $ROOT/observability/data/incidents"
exec "$PY" -m netops_guardrail.controller.monitor \
  --telemetry "$ROOT/telemetry/data/latest.json" \
  --incident-dir "$ROOT/observability/data/incidents"
