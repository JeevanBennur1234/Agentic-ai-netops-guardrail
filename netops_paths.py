"""Shared repository path configuration for Agentic AI-NetOps Guardrail."""
from pathlib import Path
import os

# NETOPS_HOME may point at a relocated checkout. Default to this module's repo root.
NETOPS_HOME = Path(
    os.environ.get("NETOPS_HOME", Path(__file__).resolve().parent)
).expanduser().resolve()
