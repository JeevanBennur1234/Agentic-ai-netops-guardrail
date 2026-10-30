"""Shared repository path configuration for Agentic AI-NetOps Guardrail."""
import os
from pathlib import Path


def get_netops_home() -> Path:
    """Return the repository root directory for data, logs, and telemetry."""
    env_home = os.environ.get("NETOPS_HOME")
    if env_home:
        return Path(env_home).expanduser().resolve()

    # Search upwards from this file for repository root indicators
    current = Path(__file__).resolve().parent
    for candidate in [current, *current.parents]:
        if (candidate / "pyproject.toml").is_file() and (candidate / "telemetry").is_dir():
            return candidate
        if (candidate / "telemetry").is_dir() and (candidate / "dashboard").is_dir():
            return candidate

    # Standard fallback for src/netops_guardrail layout (parents: src, repo_root)
    if len(current.parents) >= 2 and current.parents[0].name == "src":
        return current.parents[1]

    return current.parent


NETOPS_HOME = get_netops_home()
