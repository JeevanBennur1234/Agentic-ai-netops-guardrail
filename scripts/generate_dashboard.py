#!/usr/bin/env python3
"""Generate dashboard/index.html from the canonical source of truth."""

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "src" / "netops_guardrail" / "observability" / "templates" / "dashboard.html"
DEST = REPO_ROOT / "dashboard" / "index.html"


def generate_dashboard():
    if not SOURCE.exists():
        raise FileNotFoundError(f"Source template not found: {SOURCE}")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE, DEST)
    print(f"Generated {DEST} from source of truth {SOURCE}")


if __name__ == "__main__":
    generate_dashboard()
