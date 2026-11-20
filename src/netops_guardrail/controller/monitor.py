"""Read-only deterministic incident monitor with guarded AI proposal dispatch.

The monitor observes controller telemetry and may ask the existing decision gate
for a human-reviewable proposal. It never executes network commands or calls an
executor. Human approval and the existing guarded execution path remain mandatory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from netops_guardrail.faults.flow_rule_drift import FlowRuleDriftFault
from netops_guardrail.faults.link_flapping import LinkFlappingFault
from netops_guardrail.faults.mac_flooding import MacFloodingFault
from netops_guardrail.faults.redundant_trunk import RedundantTrunkRestoredFault
from netops_guardrail.faults.standby_forwarding import StandbyForwardingFault
from netops_guardrail.faults.trunk_down import TrunkDownFault
from netops_guardrail.netops_paths import NETOPS_HOME

LOGGER = logging.getLogger(__name__)
DEFAULT_TELEMETRY = NETOPS_HOME / "telemetry" / "data" / "latest.json"
INCIDENT_DIR = NETOPS_HOME / "observability" / "data" / "incidents"
ACTIVE_STATES = {
    "DETECTED",
    "AI_PENDING",
    "PENDING_HUMAN_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "AI_REVIEWED",
    "AI_FAILED_CLOSED",
    "AI_RATE_LIMITED",
}
KNOWN_SOURCES = {"live_telemetry", "lab_injected_live", "test_fixture"}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _stable_evidence(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _stable_evidence(item)
            for key, item in value.items()
            if key
            not in {
                "age_seconds",
                "updated_at_utc",
                "snapshot_updated_at_utc",
                "observed_at_utc",
                "timestamp_utc",
                "timestamp",
            }
        }
    if isinstance(value, list):
        return [_stable_evidence(item) for item in value]
    return value


def _evidence_id(kind: str, evidence: Mapping[str, Any]) -> str:
    return _stable_hash({"kind": kind, "evidence": _stable_evidence(evidence)})


def _source_from_snapshot(snapshot: Mapping[str, Any]) -> str:
    """Only controller-produced provenance is accepted; never read request fields."""
    if "provenance" not in snapshot:
        return "live_telemetry"
    provenance = snapshot.get("provenance")
    if isinstance(provenance, Mapping):
        source = provenance.get("source")
        if source in KNOWN_SOURCES:
            return str(source)
    return "unknown"


def detect_incidents(
    snapshot: Mapping[str, Any], now: datetime | None = None, stale_after_seconds: int = 30
) -> list[dict[str, Any]]:
    """Produce evidence-backed deterministic detections from one telemetry snapshot."""
    now = now or datetime.now(timezone.utc)
    updated = _parse_time(snapshot.get("updated_at_utc"))
    age = (now - updated).total_seconds() if updated else None
    if age is None or age > stale_after_seconds or age < -5:
        evidence = {"updated_at_utc": snapshot.get("updated_at_utc"), "age_seconds": age}
        return [
            {
                "type": "telemetry_stale",
                "source": _source_from_snapshot(snapshot),
                "evidence": evidence,
                "evidence_id": _evidence_id("telemetry_stale", evidence),
                "observed_at_utc": now.isoformat(),
                "execution_allowed": False,
                "remediation_allowed": False,
            }
        ]

    source = _source_from_snapshot(snapshot)
    switches = snapshot.get("switches") or {}
    active_links = snapshot.get("links") or []

    # A controller can keep refreshing its snapshot while every datapath has
    # disconnected. Treat an entirely missing testbed as offline, not as six
    # independent link faults that might be sent to the AI agent.
    physical_port_status = []
    for switch_id, switch in switches.items():
        if not isinstance(switch, Mapping):
            continue
        for port_id in switch.get("ports") or {}:
            try:
                if int(port_id) >= 4294967040:
                    continue
            except (TypeError, ValueError):
                if str(port_id).lower() == "local":
                    continue
            status = (switch.get("port_status") or {}).get(str(port_id))
            status_data = dict(status) if isinstance(status, Mapping) else {}
            physical_port_status.append(
                {
                    "switch_id": str(switch_id),
                    "port_id": str(port_id),
                    "state": str(status_data.get("state", "UNKNOWN")).upper(),
                    "status": status_data,
                }
            )

    all_ports_missing = (
        bool(physical_port_status)
        and all(item["state"] == "MISSING" for item in physical_port_status)
        and not active_links
    )
    if all_ports_missing:
        evidence = {
            "missing_ports": physical_port_status,
            "active_link_count": 0,
            "snapshot_updated_at_utc": snapshot.get("updated_at_utc"),
        }
        return [
            {
                "type": "topology_offline",
                "source": source,
                "evidence": evidence,
                "evidence_id": _evidence_id("topology_offline", evidence),
                "observed_at_utc": now.isoformat(),
                "execution_allowed": False,
                "remediation_allowed": False,
            }
        ]

    results: list[dict[str, Any]] = []
    detectors = (
        ("standby_forwarding_anomaly", StandbyForwardingFault().detector),
        ("flow_rule_drift", FlowRuleDriftFault().detector),
        ("link_flapping", LinkFlappingFault().detector),
        ("mac_flooding", MacFloodingFault().detector),
        ("trunk_down", TrunkDownFault().detector),
        ("redundant_trunk_restored", RedundantTrunkRestoredFault().detector),
    )
    for name, detector in detectors:
        result = detector(snapshot)
        if result.get("detected") is True:
            evidence = {
                "detector": name,
                "result": result,
                "snapshot_updated_at_utc": snapshot.get("updated_at_utc"),
            }
            results.append(
                {
                    "type": name,
                    "source": source,
                    "evidence": evidence,
                    "evidence_id": _evidence_id(name, evidence),
                    "observed_at_utc": now.isoformat(),
                    "execution_allowed": source in {"live_telemetry", "lab_injected_live"},
                    "remediation_allowed": source in {"live_telemetry", "lab_injected_live"},
                }
            )

    failed_ports = []
    for switch_id, switch in switches.items():
        if not isinstance(switch, Mapping):
            continue
        for port_id, status in (switch.get("port_status") or {}).items():
            if isinstance(status, Mapping) and str(status.get("state", "")).upper() in {
                "DOWN",
                "MISSING",
                "LINK_DOWN",
                "ADMIN_DOWN",
            }:
                failed_ports.append(
                    {"switch_id": str(switch_id), "port_id": str(port_id), "status": dict(status)}
                )

    def link_key(link):
        left = (str(link.get("src_switch", "")), str(link.get("src_port", "")))
        right = (str(link.get("dst_switch", "")), str(link.get("dst_port", "")))
        if not all(left) or not all(right):
            return None
        return tuple(sorted((left, right)))

    active_link_keys = {
        key
        for link in active_links
        if isinstance(link, Mapping)
        if (key := link_key(link)) is not None
    }
    latest_link_events = {}
    for event in snapshot.get("link_events") or []:
        if not isinstance(event, Mapping):
            continue
        event_time = _parse_time(event.get("timestamp_utc"))
        if event_time is None:
            continue
        event_age = (now - event_time).total_seconds()
        if event_age < -5 or event_age > 30:
            continue
        key = link_key(event)
        if key is None or key in active_link_keys:
            continue
        event_name = str(event.get("event", event.get("action", ""))).upper()
        if event_name not in {"ADD", "DELETE"}:
            continue
        previous = latest_link_events.get(key)
        if previous is None or event_time > previous[0]:
            latest_link_events[key] = (event_time, dict(event))

    deleted_links = [
        event
        for event_time, event in latest_link_events.values()
        if str(event.get("event", event.get("action", ""))).upper() == "DELETE"
    ]
    if failed_ports or deleted_links:
        evidence = {
            "failed_ports": failed_ports,
            "deleted_links": deleted_links,
            "snapshot_updated_at_utc": snapshot.get("updated_at_utc"),
        }
        results.append(
            {
                "type": "link_failure",
                "source": source,
                "evidence": evidence,
                "evidence_id": _evidence_id("link_failure", evidence),
                "observed_at_utc": now.isoformat(),
                "execution_allowed": source in {"live_telemetry", "lab_injected_live"},
                "remediation_allowed": source in {"live_telemetry", "lab_injected_live"},
            }
        )
    return results


class IncidentMonitor:
    """Debounce, persist, deduplicate and optionally dispatch through decision_gate."""

    def __init__(
        self,
        incident_dir: Path = INCIDENT_DIR,
        debounce_reads: int = 2,
        cooldown_seconds: int = 60,
        max_ai_calls_per_hour: int = 12,
        decision_pipeline: Callable[..., dict] | None = None,
    ):
        self.incident_dir = Path(incident_dir)
        self.incident_dir.mkdir(parents=True, exist_ok=True)
        self.debounce_reads = max(1, int(debounce_reads))
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self.max_ai_calls_per_hour = max(0, int(max_ai_calls_per_hour))
        self.decision_pipeline = decision_pipeline
        self._counts: dict[str, int] = {}
        self._last_emitted: dict[str, float] = {}
        self._last_scan_utc: str | None = None
        self._last_detection_count = 0
        self._last_scan_summary = "Monitor has not completed its first telemetry scan."
        self._last_telemetry_timestamp: str | None = None

    @property
    def records_path(self) -> Path:
        return self.incident_dir / "incidents.json"

    @property
    def dispatch_path(self) -> Path:
        return self.incident_dir / "ai_dispatches.json"

    def _read_json(self, path: Path, fallback: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8")) if path.exists() else fallback
        except (OSError, json.JSONDecodeError):
            LOGGER.exception("Could not read monitor state file %s", path)
            return fallback

    def _write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(path)

    def _load_records(self) -> list[dict[str, Any]]:
        value = self._read_json(self.records_path, [])
        return value if isinstance(value, list) else []

    def _load_dispatches(self) -> list[dict[str, Any]]:
        value = self._read_json(self.dispatch_path, [])
        return value if isinstance(value, list) else []

    def _persist_records(self, records: list[dict[str, Any]]) -> None:
        self._write_json(self.records_path, records)

    def _write_heartbeat(self, interval_seconds: float, error: str | None = None) -> None:
        """Publish monitor liveness separately from persisted incident history."""
        self._write_json(
            self.incident_dir / "monitor_status.json",
            {
                "status": "degraded" if error else "running",
                "pid": os.getpid(),
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "interval_seconds": max(0.1, float(interval_seconds)),
                "ai_enabled": self.decision_pipeline is not None,
                "last_error": error,
                "last_scan_utc": self._last_scan_utc,
                "last_detection_count": self._last_detection_count,
                "last_scan_summary": self._last_scan_summary,
                "telemetry_timestamp_utc": self._last_telemetry_timestamp,
            },
        )

    def _dispatch(self, record: dict[str, Any], telemetry_path: Path | None) -> None:
        if not self.decision_pipeline or not record.get("ai_call_allowed"):
            return
        if not record.get("remediation_allowed") or record.get("source") not in {
            "live_telemetry",
            "lab_injected_live",
        }:
            return
        incident_id = record["incident_id"]
        records = self._load_records()
        current = next((r for r in records if r.get("incident_id") == incident_id), None)
        if current is None or current.get("state") in ACTIVE_STATES - {"DETECTED"}:
            return

        dispatches = self._load_dispatches()
        now = time.time()
        dispatches = [d for d in dispatches if now - float(d.get("timestamp", 0)) < 3600]
        if len(dispatches) >= self.max_ai_calls_per_hour:
            current["ai_call_allowed"] = False
            current["state"] = "AI_RATE_LIMITED"
            self._persist_records(records)
            return
        # Persist reservation before calling the model to avoid duplicate calls on restart.
        dispatches.append({"incident_id": incident_id, "timestamp": now})
        self._write_json(self.dispatch_path, dispatches)
        current["state"] = "AI_PENDING"
        self._persist_records(records)

        context = {
            "fault_type": record["type"],
            "incident_id": incident_id,
            "source": record["source"],
            "evidence_id": record["evidence_id"],
            "evidence": record["evidence"],
            "observed_at_utc": record["observed_at_utc"],
        }
        try:
            result = self.decision_pipeline(
                telemetry_path=str(telemetry_path) if telemetry_path else None,
                execute_approved=False,
                incident_context=context,
            )
            intent = result.get("intent") or {}
            agent_metadata = intent.get("_agent_metadata") or {}
            model_invoked = agent_metadata.get("model_invoked")
            if model_invoked is True:
                ai_stage = (
                    "COMPLETED"
                    if agent_metadata.get("status") == "completed"
                    else f"FAILED_CLOSED — {agent_metadata.get('status', 'unknown')}"
                )
            elif model_invoked is False:
                ai_stage = f"SKIPPED — {agent_metadata.get('status', 'policy rule')}"
            else:
                ai_stage = "UNKNOWN — MODEL INVOCATION NOT REPORTED"

            current["ai_decision"] = intent
            current["ai_invoked"] = model_invoked
            current["ai_model"] = agent_metadata.get("model")
            current["ai_status"] = agent_metadata.get("status", "unknown")
            current["safety_verdict"] = result.get("verification")
            current["decision"] = result.get("decision")
            current["human_approval"] = result.get("human_approval")
            current["stages"] = {
                "deterministic": "DETECTED",
                "ai": ai_stage,
                "safety": "PASSED"
                if (result.get("verification") or {}).get("safe")
                else "REJECTED",
                "human": (result.get("human_approval") or {}).get("status", "NOT_REQUIRED"),
                "executor": "NOT_STARTED",
            }
            current["audit_record"] = (
                {
                    "index": result["audit_record"].get("index"),
                    "current_hash": result["audit_record"].get("current_hash"),
                }
                if isinstance(result.get("audit_record"), Mapping)
                else None
            )
            current["state"] = (
                "PENDING_HUMAN_APPROVAL"
                if result.get("decision") == "PENDING_HUMAN_APPROVAL"
                else "AI_REVIEWED"
            )
        except Exception as exc:  # fail closed; no alternate execution path
            LOGGER.exception("Decision pipeline failed for incident %s", incident_id)
            current["state"] = "AI_FAILED_CLOSED"
            current["ai_error"] = f"{type(exc).__name__}: {exc}"
        self._persist_records(records)

    def process_snapshot(
        self,
        snapshot: Mapping[str, Any],
        now: datetime | None = None,
        telemetry_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        now = now or datetime.now(timezone.utc)
        detections = detect_incidents(snapshot, now=now)
        self._last_scan_utc = now.isoformat()
        self._last_detection_count = len(detections)
        self._last_telemetry_timestamp = str(snapshot.get("updated_at_utc") or "") or None
        detected_types = sorted({str(item.get("type", "unknown")) for item in detections})
        self._last_scan_summary = (
            "No invariant violations detected in the latest scan."
            if not detections else "Detected: " + ", ".join(detected_types)
        )
        current = {f"{item['type']}:{item['evidence_id']}": item for item in detections}
        for key in list(self._counts):
            if key not in current:
                self._counts[key] = 0

        records = self._load_records()
        emitted: list[dict[str, Any]] = []
        active_keys = set(current)
        # Resolve incidents when their deterministic condition is no longer present.
        for prior in records:
            if prior.get("state") in ACTIVE_STATES and prior.get("dedupe_key") not in active_keys:
                prior["state"] = "RESOLVED"
                prior["resolved_at_utc"] = now.isoformat()
                prior.setdefault("stages", {})["deterministic"] = "RESOLVED"
        self._persist_records(records)
        for key, incident in current.items():
            self._counts[key] = self._counts.get(key, 0) + 1
            if self._counts[key] < self.debounce_reads:
                continue
            if time.time() - self._last_emitted.get(key, 0.0) < self.cooldown_seconds:
                continue
            # Enforce cooldown across process restarts using persisted incident timestamps.
            previous_records = [r for r in records if r.get("dedupe_key") == key]
            previous_times = [
                parsed
                for parsed in (_parse_time(r.get("observed_at_utc")) for r in previous_records)
                if parsed is not None
            ]
            if (
                previous_times
                and (now - max(previous_times)).total_seconds() < self.cooldown_seconds
            ):
                continue
            existing = next(
                (
                    r
                    for r in records
                    if r.get("dedupe_key") == key and r.get("state") in ACTIVE_STATES
                ),
                None,
            )
            if existing:
                continue

            record = {
                "incident_id": "inc-" + incident["evidence_id"],
                "dedupe_key": key,
                "type": incident["type"],
                "source": incident["source"],
                "evidence_id": incident["evidence_id"],
                "evidence": incident["evidence"],
                "observed_at_utc": incident["observed_at_utc"],
                "state": "DETECTED",
                "execution_allowed": incident["execution_allowed"],
                "remediation_allowed": incident["remediation_allowed"],
                "ai_call_allowed": bool(incident["remediation_allowed"]),
                "stages": {
                    "deterministic": "DETECTED",
                    "ai": "NOT_STARTED",
                    "safety": "NOT_STARTED",
                    "human": "NOT_STARTED",
                    "executor": "NOT_STARTED",
                },
            }
            records.append(record)
            emitted.append(record)
            self._last_emitted[key] = time.time()
            self._persist_records(records)
            self._dispatch(record, telemetry_path)
            records = self._load_records()
        return emitted

    def run(
        self,
        telemetry_path: Path = DEFAULT_TELEMETRY,
        interval_seconds: float = 5,
        max_iterations: int | None = None,
    ) -> None:
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            last_error = None
            try:
                snapshot = json.loads(Path(telemetry_path).read_text(encoding="utf-8"))
                if isinstance(snapshot, dict):
                    self.process_snapshot(snapshot, telemetry_path=Path(telemetry_path))
                else:
                    raise ValueError("Telemetry snapshot must be a JSON object")
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                LOGGER.exception("Unable to process telemetry snapshot %s", telemetry_path)
            self._write_heartbeat(interval_seconds, last_error)
            iteration += 1
            if max_iterations is None or iteration < max_iterations:
                time.sleep(max(0.1, interval_seconds))


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only deterministic NetOps incident monitor")
    parser.add_argument("--telemetry", type=Path, default=DEFAULT_TELEMETRY)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--debounce", type=int, default=2)
    parser.add_argument("--cooldown", type=int, default=60)
    parser.add_argument("--max-ai-calls-per-hour", type=int, default=12)
    parser.add_argument("--incident-dir", type=Path, default=INCIDENT_DIR)
    parser.add_argument(
        "--no-ai", action="store_true", help="Record incidents without invoking Ollama"
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    decision_pipeline = None
    if not args.no_ai:
        # Lazy import keeps observation/replay tests independent from execution modules.
        from netops_guardrail.controller.decision_gate import decide

        decision_pipeline = decide
    monitor = IncidentMonitor(
        incident_dir=args.incident_dir,
        debounce_reads=args.debounce,
        cooldown_seconds=args.cooldown,
        max_ai_calls_per_hour=args.max_ai_calls_per_hour,
        decision_pipeline=decision_pipeline,
    )
    monitor.run(args.telemetry, args.interval, max_iterations=1 if args.once else None)


if __name__ == "__main__":
    main()
