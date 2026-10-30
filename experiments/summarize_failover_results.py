#!/usr/bin/env python3
"""Summarize the five pre-registered 90-second live failover trials."""
import csv
import json
import statistics
import subprocess
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments" / "results"
FILES = [RESULTS / f"2026-10-30_4e6bc80_failover_trial_{i:02d}.json" for i in range(1, 6)]
COMMAND = "cd /home/bennurjeevan/netops_guardrail && .venv/bin/python experiments/summarize_failover_results.py"
def percentile(values, p):
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    rank = (len(xs) - 1) * p
    lo = int(rank)
    hi = min(lo + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (rank - lo), 3)

commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown"
rows = []
for path in FILES:
    d = json.loads(path.read_text(encoding="utf-8"))
    events = d.get("events", [])
    pick = lambda names: next((e for e in events if e.get("event") in names), None)
    link = pick({"link_down"})
    failure = pick({"first_ping_failure"})
    success = pick({"first_ping_success_after_failure", "first_ping_success_after_link_down"})
    of_events = [e for e in events if e.get("event") == "of_port_down_event_observed"]
    stp_events = [e for e in events if e.get("event") == "stp_port_state_change"]
    rows.append({
        "trial": int(path.stem.rsplit("_", 1)[-1]),
        "result_file": path.name,
        "result": d.get("result"),
        "baseline_ping_loss_percent": d.get("baseline_ping_loss_percent"),
        "link_down_timestamp_utc": link.get("timestamp_utc") if link else None,
        "first_ping_failure_timestamp_utc": failure.get("timestamp_utc") if failure else None,
        "first_ping_failure_seconds_after_link_down": failure.get("since_link_down_seconds") if failure else None,
        "first_ping_success_timestamp_utc": success.get("timestamp_utc") if success else None,
        "first_ping_success_seconds_after_link_down": success.get("since_link_down_seconds") if success else None,
        "of_port_down_events": of_events,
        "stp_state_changes": stp_events,
        "stp_state_change_count": len(stp_events),
        "alternate_s2_p2_state_after_failure": d.get("post_failure_stp_states", {}).get("s2-p2"),
        "post_failure_ping_loss_percent": d.get("post_failure_ping_loss_percent"),
        "failover_recovered": d.get("failover_recovered"),
        "recovery_time_seconds": d.get("failover_recovery_time_seconds"),
        "rollback_recovered": d.get("rollback_recovered"),
        "rollback_recovery_time_seconds": d.get("rollback_recovery_time_seconds"),
        "failure_reason": d.get("failover_failure_reason") or d.get("failure_reason"),
    })
valid_recoveries = [r["recovery_time_seconds"] for r in rows if isinstance(r["recovery_time_seconds"], (int, float))]
summary = {
    "metadata": {
        "date": datetime.now().astimezone().isoformat(timespec="seconds"),
        "commit_hash": commit,
        "model_name": "none (live OVS/Mininet failover summary)",
        "command": COMMAND,
        "source_files": [p.name for p in FILES],
        "observation_window_seconds": 90,
        "testbed": "LIVE Mininet + OVS + Ryu",
    },
    "summary": {
        "trials": len(rows),
        "valid_baseline_trials": sum(r["baseline_ping_loss_percent"] == 0 for r in rows),
        "failover_passes": sum(r["result"] == "PASS" for r in rows),
        "failover_not_recovered": sum(r["result"] == "FAILOVER_FAILED_ROLLBACK_PASS" for r in rows),
        "inconclusive_trials": sum(r["result"] == "INCONCLUSIVE" for r in rows),
        "validated_recovery_min_seconds": min(valid_recoveries) if valid_recoveries else None,
        "validated_recovery_median_seconds": statistics.median(valid_recoveries) if valid_recoveries else None,
        "validated_recovery_max_seconds": max(valid_recoveries) if valid_recoveries else None,
        "rollback_recovered_trials": sum(r["rollback_recovered"] is True for r in rows),
        "of_port_down_event_trials": sum(bool(r["of_port_down_events"]) for r in rows),
        "of_port_down_event_count": sum(len(r["of_port_down_events"]) for r in rows),
        "alternate_path_forwarding_trials": sum(r["alternate_s2_p2_state_after_failure"] == "FORWARD" for r in rows),
        "first_ping_failure_seconds": [r["first_ping_failure_seconds_after_link_down"] for r in rows],
        "first_ping_failure_min_seconds": min(r["first_ping_failure_seconds_after_link_down"] for r in rows if r["first_ping_failure_seconds_after_link_down"] is not None),
        "first_ping_failure_median_seconds": statistics.median(r["first_ping_failure_seconds_after_link_down"] for r in rows if r["first_ping_failure_seconds_after_link_down"] is not None),
        "first_ping_failure_max_seconds": max(r["first_ping_failure_seconds_after_link_down"] for r in rows if r["first_ping_failure_seconds_after_link_down"] is not None),
        "first_ping_success_seconds": [r["first_ping_success_seconds_after_link_down"] for r in rows],
        "first_ping_success_min_seconds": min(r["first_ping_success_seconds_after_link_down"] for r in rows if r["first_ping_success_seconds_after_link_down"] is not None),
        "first_ping_success_median_seconds": statistics.median(r["first_ping_success_seconds_after_link_down"] for r in rows if r["first_ping_success_seconds_after_link_down"] is not None),
        "first_ping_success_max_seconds": max(r["first_ping_success_seconds_after_link_down"] for r in rows if r["first_ping_success_seconds_after_link_down"] is not None),
    },
    "trials": rows,
}
json_path = RESULTS / "2026-10-30_4e6bc80_failover_summary.json"
csv_path = RESULTS / "2026-10-30_4e6bc80_failover_summary.csv"
json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
fields = ["date", "commit_hash", "model_name", "command"] + [k for k in rows[0] if k not in {"of_port_down_events", "stp_state_changes"}] + ["of_port_down_events_json", "stp_state_changes_json"]
with csv_path.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for row in rows:
        flat = {"date": summary["metadata"]["date"], "commit_hash": commit, "model_name": summary["metadata"]["model_name"], "command": COMMAND, **row}
        flat["of_port_down_events_json"] = json.dumps(row["of_port_down_events"], sort_keys=True)
        flat["stp_state_changes_json"] = json.dumps(row["stp_state_changes"], sort_keys=True)
        flat.pop("of_port_down_events", None)
        flat.pop("stp_state_changes", None)
        w.writerow(flat)
print(json.dumps({"json": str(json_path), "csv": str(csv_path), "summary": summary["summary"]}, indent=2))
