#!/usr/bin/env python3
"""Summarize the five successful 90-second 2026-11-13 live failover trials."""
import csv
import json
import statistics
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments" / "results"
TRIAL_IDS = ("02", "03", "06", "07", "08")
FILES = [
    RESULTS / f"2026-11-13_live_active_failover_trial_{trial}.json"
    for trial in TRIAL_IDS
]
COMMAND = "python experiments/summarize_failover_results.py"


def git_value(*args):
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


rows = []
for trial, path in zip(TRIAL_IDS, FILES):
    if not path.is_file():
        raise SystemExit(f"Missing required evidence file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    rows.append({
        "trial": trial,
        "result_file": path.name,
        "result": data.get("result"),
        "baseline_ping_loss_percent": data.get("baseline_ping_loss_percent"),
        "baseline_ping_attempts": data.get("baseline_ping_attempts"),
        "baseline_consecutive_successes": data.get("baseline_consecutive_successes"),
        "observation_window_seconds": data.get("metadata", {}).get("observation_window_seconds"),
        "observation_window_ping_samples": data.get("observation_window_ping_samples"),
        "failover_recovered": data.get("failover_recovered"),
        "recovery_time_seconds": data.get("failover_recovery_time_seconds"),
        "post_failure_ping_loss_percent": data.get("post_failure_ping_loss_percent"),
        "post_recovery_nonzero_loss_samples": data.get("post_recovery_nonzero_loss_samples"),
        "alternate_s1_p3_state": data.get("post_failure_stp_states", {}).get("s1-p3"),
        "alternate_s2_p2_state": data.get("post_failure_stp_states", {}).get("s2-p2"),
        "injection_method": next(
            (event.get("injection_method") for event in data.get("events", [])
             if event.get("event") == "link_down"),
            None,
        ),
    })

recoveries = [
    row["recovery_time_seconds"]
    for row in rows
    if isinstance(row["recovery_time_seconds"], (int, float))
]
all_pass = all(
    row["result"] == "PASS"
    and row["baseline_ping_loss_percent"] == 0.0
    and row["failover_recovered"] is True
    and row["observation_window_seconds"] == 90.0
    and row["observation_window_ping_samples"] is not None
    and row["post_recovery_nonzero_loss_samples"] == 0
    for row in rows
)

summary = {
    "metadata": {
        "date": datetime.now().astimezone().isoformat(timespec="seconds"),
        "head_commit": git_value("rev-parse", "HEAD") or "unknown",
        "working_tree_dirty": bool(git_value("status", "--porcelain")),
        "command": COMMAND,
        "testbed": "Mininet + Open vSwitch + Ryu",
        "fault_injection": "OpenFlow 1.3 mod-port down (administrative port failure)",
        "observation_window_seconds": 90,
        "source_files": [path.name for path in FILES],
    },
    "summary": {
        "trials": len(rows),
        "successful_trials": sum(row["result"] == "PASS" for row in rows),
        "all_five_meet_pass_criteria": all_pass,
        "baseline_clean_trials": sum(row["baseline_ping_loss_percent"] == 0.0 for row in rows),
        "alternate_path_forwarding_trials": sum(
            row["alternate_s1_p3_state"] == "FORWARD"
            and row["alternate_s2_p2_state"] == "FORWARD"
            for row in rows
        ),
        "post_recovery_loss_free_trials": sum(
            row["post_recovery_nonzero_loss_samples"] == 0 for row in rows
        ),
        "recovery_min_seconds": min(recoveries) if recoveries else None,
        "recovery_median_seconds": statistics.median(recoveries) if recoveries else None,
        "recovery_max_seconds": max(recoveries) if recoveries else None,
        "recovery_times_seconds": recoveries,
        "total_observation_ping_samples": sum(
            row["observation_window_ping_samples"] or 0 for row in rows
        ),
        "limitations": [
            "Emulated Mininet/OVS/Ryu testbed, not physical production hardware.",
            "Fault injection used OpenFlow administrative port-down, not cable unplug.",
            "This experiment validates STP path failover, not autonomous AI remediation.",
            "Five trials are a small sample and do not establish a production SLA.",
        ],
    },
    "trials": rows,
}

json_path = RESULTS / "2026-11-13_live_active_failover_summary.json"
csv_path = RESULTS / "2026-11-13_live_active_failover_summary.csv"
json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print(json.dumps({
    "json": str(json_path),
    "csv": str(csv_path),
    "summary": summary["summary"],
}, indent=2))
