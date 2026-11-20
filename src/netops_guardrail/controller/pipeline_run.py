"""Pipeline Run Record module for end-to-end continuous NetOps orchestration.

Manages the lifecycle, evidence, provenance, and fail-closed transitions of an
orchestrated remediation run:
  fault_injected -> telemetry_observed -> detected -> ai_analysis ->
  safety_verified -> awaiting_approval -> approved -> executed ->
  connectivity_verified (or rolled_back / recommendation_only / failed).

All provenance source labels (LAB, DETERMINISTIC, AI, SAFETY, HUMAN, EXECUTOR)
are assigned by internal producer code, never accepted from user request parameters.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from netops_guardrail.faults.registry import (
    LIVE_INJECTABLE_FAULTS,
    PASSIVE_ONLY_FAULTS,
    get_fault,
)
from netops_guardrail.netops_paths import NETOPS_HOME

LOGGER = logging.getLogger(__name__)

STAGE_NAMES = (
    "fault_injected",
    "telemetry_observed",
    "detected",
    "ai_analysis",
    "safety_verified",
    "awaiting_approval",
    "approved",
    "executed",
    "connectivity_verified",
)

STAGE_SOURCES = {
    "fault_injected": "LAB",
    "telemetry_observed": "DETERMINISTIC",
    "detected": "DETERMINISTIC",
    "ai_analysis": "AI",
    "safety_verified": "SAFETY",
    "awaiting_approval": "HUMAN",
    "approved": "HUMAN",
    "executed": "EXECUTOR",
    "connectivity_verified": "LAB",
}

DEFAULT_RUNS_DIR = NETOPS_HOME / "observability" / "data" / "pipeline_runs"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class StageRecord:
    """Serializable record of a single pipeline stage with immutable provenance."""

    def __init__(
        self,
        name: str,
        source: str,
        status: str = "PENDING",
        started_at_utc: str | None = None,
        completed_at_utc: str | None = None,
        evidence: dict[str, Any] | None = None,
        error: str | None = None,
    ):
        self.name = name
        self.source = source  # Always assigned by producer, never from client requests
        self.status = status
        self.started_at_utc = started_at_utc
        self.completed_at_utc = completed_at_utc
        self.evidence = evidence or {}
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "status": self.status,
            "started_at_utc": self.started_at_utc,
            "completed_at_utc": self.completed_at_utc,
            "evidence": self.evidence,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StageRecord":
        return cls(
            name=data["name"],
            source=data.get("source", STAGE_SOURCES.get(data["name"], "UNKNOWN")),
            status=data.get("status", "PENDING"),
            started_at_utc=data.get("started_at_utc"),
            completed_at_utc=data.get("completed_at_utc"),
            evidence=data.get("evidence") or {},
            error=data.get("error"),
        )


class PipelineRun:
    """One end-to-end remediation pipeline run record."""

    def __init__(
        self,
        run_id: str,
        fault_id: str,
        status: str = "ACTIVE",
        outcome: str | None = None,
        created_at_utc: str | None = None,
        updated_at_utc: str | None = None,
        executable: bool | None = None,
        proposal_id: str | None = None,
        stages: list[StageRecord] | None = None,
        error: str | None = None,
    ):
        self.run_id = run_id
        self.fault_id = fault_id
        self.status = status
        self.outcome = outcome
        self.created_at_utc = created_at_utc or _now_utc()
        self.updated_at_utc = updated_at_utc or self.created_at_utc
        # Scope of execution: only block (e.g. redundant_trunk_restored) is executable
        self.executable = (
            (fault_id == "redundant_trunk_restored") if executable is None else bool(executable)
        )
        self.proposal_id = proposal_id
        self.error = error
        if stages is not None:
            self.stages = {s.name: s for s in stages}
        else:
            self.stages = {
                name: StageRecord(name=name, source=STAGE_SOURCES[name]) for name in STAGE_NAMES
            }

    def get_stage(self, name: str) -> StageRecord:
        if name not in self.stages:
            self.stages[name] = StageRecord(name=name, source=STAGE_SOURCES.get(name, "UNKNOWN"))
        return self.stages[name]

    def start_stage(self, name: str, evidence: dict[str, Any] | None = None) -> StageRecord:
        stage = self.get_stage(name)
        stage.status = "IN_PROGRESS"
        stage.started_at_utc = _now_utc()
        if evidence:
            stage.evidence.update(evidence)
        self.updated_at_utc = _now_utc()
        return stage

    def complete_stage(
        self,
        name: str,
        evidence: dict[str, Any] | None = None,
    ) -> StageRecord:
        stage = self.get_stage(name)
        stage.status = "COMPLETED"
        if not stage.started_at_utc:
            stage.started_at_utc = _now_utc()
        stage.completed_at_utc = _now_utc()
        if evidence:
            stage.evidence.update(evidence)
        self.updated_at_utc = _now_utc()
        return stage

    def fail_stage(
        self,
        name: str,
        error: str,
        evidence: dict[str, Any] | None = None,
        outcome: str = "failed",
    ) -> StageRecord:
        stage = self.get_stage(name)
        stage.status = "FAILED"
        if not stage.started_at_utc:
            stage.started_at_utc = _now_utc()
        stage.completed_at_utc = _now_utc()
        stage.error = str(error)
        if evidence:
            stage.evidence.update(evidence)
        self.status = "FAILED"
        self.outcome = outcome
        self.error = str(error)
        self.updated_at_utc = _now_utc()
        return stage

    def skip_stage(self, name: str, reason: str = "") -> StageRecord:
        stage = self.get_stage(name)
        stage.status = "SKIPPED"
        stage.completed_at_utc = _now_utc()
        if reason:
            stage.evidence["skip_reason"] = reason
        self.updated_at_utc = _now_utc()
        return stage

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "fault_id": self.fault_id,
            "status": self.status,
            "outcome": self.outcome,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "executable": self.executable,
            "proposal_id": self.proposal_id,
            "error": self.error,
            "stages": [self.stages[name].to_dict() for name in STAGE_NAMES if name in self.stages],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PipelineRun":
        stages = [StageRecord.from_dict(s) for s in data.get("stages", [])]
        return cls(
            run_id=data["run_id"],
            fault_id=data["fault_id"],
            status=data.get("status", "ACTIVE"),
            outcome=data.get("outcome"),
            created_at_utc=data.get("created_at_utc"),
            updated_at_utc=data.get("updated_at_utc"),
            executable=data.get("executable", False),
            proposal_id=data.get("proposal_id"),
            stages=stages,
            error=data.get("error"),
        )


class PipelineRunManager:
    """Thread-safe disk store for managing one active pipeline run at a time."""

    def __init__(self, runs_dir: Path | str = DEFAULT_RUNS_DIR):
        self.runs_dir = Path(runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.current_run_path = self.runs_dir / "current_run.json"
        self.history_path = self.runs_dir / "pipeline_runs.json"
        self.lock_path = self.runs_dir / ".injection.lock"

    @contextmanager
    def exclusive_run_lock(self):
        """Acquire a process-shared, non-blocking lock around injection/restore transactions."""
        with open(self.lock_path, "a+", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    "Another pipeline injection or restore transaction is in progress."
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def get_current_run(self) -> PipelineRun | None:
        if not self.current_run_path.exists():
            return None
        try:
            with open(self.current_run_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return PipelineRun.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return None

    def is_run_active(self) -> bool:
        current = self.get_current_run()
        if current is None:
            return False
        terminal_statuses = {
            "COMPLETED",
            "CONNECTIVITY_VERIFIED",
            "RECOMMENDATION_ONLY",
            "ROLLED_BACK",
            "FAILED",
        }
        terminal_outcomes = {"failed", "recommendation_only", "rolled_back", "connectivity_verified"}
        if current.outcome and str(current.outcome).lower() in terminal_outcomes:
            return False
        return current.status not in terminal_statuses

    def save_run(self, run: PipelineRun) -> None:
        run.updated_at_utc = _now_utc()
        temp_path = self.current_run_path.with_suffix(".tmp")
        payload = run.to_dict()
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            temp_path.replace(self.current_run_path)
        except OSError:
            if temp_path.exists():
                temp_path.unlink()
            raise

    def finalize_run(self, run: PipelineRun, outcome: str) -> None:
        run.outcome = outcome
        run.status = outcome.upper()
        run.updated_at_utc = _now_utc()
        self.save_run(run)
        # Append to historical ledger
        history = []
        if self.history_path.exists():
            try:
                with open(self.history_path, "r", encoding="utf-8") as f:
                    history = json.load(f)
                if not isinstance(history, list):
                    history = []
            except (OSError, json.JSONDecodeError):
                history = []
        history.append(run.to_dict())
        temp_hist = self.history_path.with_suffix(".tmp")
        try:
            with open(temp_hist, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            temp_hist.replace(self.history_path)
        except OSError:
            if temp_hist.exists():
                temp_hist.unlink()


def get_preflight_status(
    telemetry_path: Path | str,
    monitor_status_path: Path | str,
    connectivity_checker: Optional[Callable[[], bool]] = None,
    manager: Optional[PipelineRunManager] = None,
    max_telemetry_age_seconds: float = 30.0,
    max_heartbeat_age_seconds: float = 15.0,
) -> dict[str, Any]:
    """Inspect all injection preconditions and return their status, ages, and readiness."""
    now = datetime.now(timezone.utc)
    token_configured = bool(os.environ.get("NETOPS_CHAOS_API_TOKEN"))

    # 1. Telemetry check
    telemetry_info: dict[str, Any] = {
        "status": "missing",
        "age_seconds": None,
        "max_age_seconds": max_telemetry_age_seconds,
        "updated_at_utc": None,
        "error": None,
    }
    telemetry_file = Path(telemetry_path) if telemetry_path else None
    if not telemetry_file or not telemetry_file.exists():
        telemetry_info["error"] = (
            "Telemetry data is missing. Cannot verify network state before injection."
        )
    else:
        try:
            with open(telemetry_file, "r", encoding="utf-8") as f:
                telem = json.load(f)
            if not isinstance(telem, dict):
                telemetry_info["status"] = "error"
                telemetry_info["error"] = "Telemetry is not a valid JSON object"
            else:
                updated_at = _parse_time(telem.get("updated_at_utc"))
                if updated_at is None:
                    telemetry_info["status"] = "error"
                    telemetry_info["error"] = (
                        "Telemetry has no valid updated_at_utc timestamp. Injection refused."
                    )
                else:
                    age = (now - updated_at).total_seconds()
                    telemetry_info["age_seconds"] = round(age, 1)
                    telemetry_info["updated_at_utc"] = updated_at.isoformat()
                    if age > max_telemetry_age_seconds or age < -5.0:
                        telemetry_info["status"] = "stale"
                        telemetry_info["error"] = (
                            f"Telemetry is stale (age={age:.1f}s > {max_telemetry_age_seconds}s). Injection refused."
                        )
                    else:
                        telemetry_info["status"] = "ok"
        except Exception as exc:
            telemetry_info["status"] = "error"
            telemetry_info["error"] = f"Failed to validate telemetry freshness: {exc}"

    # 2. Monitor Heartbeat check
    monitor_info: dict[str, Any] = {
        "status": "missing",
        "age_seconds": None,
        "max_age_seconds": max_heartbeat_age_seconds,
        "last_heartbeat_utc": None,
        "monitor_status": None,
        "error": None,
    }
    monitor_file = Path(monitor_status_path) if monitor_status_path else None
    if not monitor_file or not monitor_file.exists():
        monitor_info["error"] = (
            "Incident monitor heartbeat is missing. Start monitor before injecting faults."
        )
    else:
        try:
            with open(monitor_file, "r", encoding="utf-8") as f:
                status_data = json.load(f)
            if not isinstance(status_data, dict):
                monitor_info["status"] = "error"
                monitor_info["error"] = "Monitor status is not a JSON object"
            else:
                mon_status = status_data.get("status")
                monitor_info["monitor_status"] = mon_status
                if mon_status not in {"running", "degraded"}:
                    monitor_info["status"] = "stopped"
                    monitor_info["error"] = (
                        f"Incident monitor is not running (status={mon_status}). Injection refused."
                    )
                else:
                    last_hb = _parse_time(status_data.get("last_heartbeat_utc"))
                    if last_hb is None:
                        monitor_info["status"] = "error"
                        monitor_info["error"] = (
                            "Incident monitor has no valid last_heartbeat_utc. Injection refused."
                        )
                    else:
                        hb_age = (now - last_hb).total_seconds()
                        monitor_info["age_seconds"] = round(hb_age, 1)
                        monitor_info["last_heartbeat_utc"] = last_hb.isoformat()
                        if hb_age > max_heartbeat_age_seconds or hb_age < -5.0:
                            monitor_info["status"] = "stale"
                            monitor_info["error"] = (
                                f"Incident monitor heartbeat is stale (age={hb_age:.1f}s > {max_heartbeat_age_seconds}s). Injection refused."
                            )
                        else:
                            monitor_info["status"] = "ok"
        except Exception as exc:
            monitor_info["status"] = "error"
            monitor_info["error"] = f"Failed to validate monitor heartbeat: {exc}"

    # 3. Baseline Connectivity check
    connectivity_info: dict[str, Any] = {
        "status": "unknown",
        "passed": None,
        "checked_at_utc": None,
        "error": None,
    }
    if connectivity_checker is not None:
        try:
            passed = connectivity_checker()
            connectivity_info["passed"] = bool(passed)
            connectivity_info["checked_at_utc"] = _now_utc()
            if passed:
                connectivity_info["status"] = "passed"
            else:
                connectivity_info["status"] = "failed"
                connectivity_info["error"] = (
                    "Baseline host-to-host connectivity check failed (h1<->h2 unreachable). Injection refused."
                )
        except Exception as exc:
            connectivity_info["status"] = "error"
            connectivity_info["passed"] = False
            connectivity_info["error"] = f"Baseline connectivity check errored: {exc}"

    # 4. Active Run check
    run_present = False
    active_run_id = None
    active_run_status = None
    if manager:
        run_present = manager.is_run_active()
        cur_run = manager.get_current_run()
        if cur_run:
            active_run_id = cur_run.run_id
            active_run_status = cur_run.status

    active_run_info = {
        "present": run_present,
        "run_id": active_run_id,
        "status": active_run_status,
    }

    # Readiness determination
    ready = (
        telemetry_info["status"] == "ok"
        and monitor_info["status"] == "ok"
        and connectivity_info["status"] == "passed"
        and not run_present
        and token_configured
    )

    return {
        "ready": ready,
        "telemetry": telemetry_info,
        "monitor_heartbeat": monitor_info,
        "baseline_connectivity": connectivity_info,
        "active_run": active_run_info,
        "token_configured": token_configured,
        "checked_at_utc": _now_utc(),
    }


def check_injection_preconditions(
    telemetry_path: Path | str,
    monitor_status_path: Path | str,
    connectivity_checker: Optional[Callable[[], bool]] = None,
    manager: Optional[PipelineRunManager] = None,
    max_telemetry_age_seconds: float = 30.0,
    max_heartbeat_age_seconds: float = 15.0,
) -> tuple[bool, str, int]:
    """Fail-closed check of all pre-injection prerequisites.

    Refuses injection if:
    1. A pipeline run is already active.
    2. Telemetry is missing, invalid, or stale (> 30s).
    3. Incident monitor heartbeat is missing, invalid, stopped, or stale (> 15s).
    4. Baseline host-to-host connectivity check fails.
    """
    preflight = get_preflight_status(
        telemetry_path=telemetry_path,
        monitor_status_path=monitor_status_path,
        connectivity_checker=connectivity_checker,
        manager=manager,
        max_telemetry_age_seconds=max_telemetry_age_seconds,
        max_heartbeat_age_seconds=max_heartbeat_age_seconds,
    )

    # 1. Concurrency: only one active run allowed
    if preflight["active_run"]["present"]:
        run_id = preflight["active_run"]["run_id"] or "unknown"
        return False, f"A pipeline run is already active (run_id={run_id}). Injection refused.", 409

    # 2. Telemetry freshness check (fail-closed)
    if preflight["telemetry"]["status"] != "ok":
        return False, preflight["telemetry"]["error"] or "Telemetry validation failed.", 503

    # 3. Monitor heartbeat check (fail-closed)
    if preflight["monitor_heartbeat"]["status"] != "ok":
        return (
            False,
            preflight["monitor_heartbeat"]["error"] or "Incident monitor validation failed.",
            503,
        )

    # 4. Baseline connectivity check (fail-closed)
    if preflight["baseline_connectivity"]["status"] == "failed":
        return (
            False,
            preflight["baseline_connectivity"]["error"]
            or "Baseline host-to-host connectivity check failed (h1<->h2 unreachable). Injection refused.",
            503,
        )
    if preflight["baseline_connectivity"]["status"] != "passed":
        return (
            False,
            preflight["baseline_connectivity"]["error"]
            or "Baseline connectivity checker is missing or did not prove h1<->h2 reachability. Injection refused.",
            503,
        )

    return True, "Preconditions satisfied", 200


def execute_guarded_injection(
    fault_id: str,
    context: Mapping[str, Any] | None = None,
    manager: Optional[PipelineRunManager] = None,
) -> tuple[dict[str, Any], int]:
    """Execute a guarded injection and record exact commands, timestamps, and results.

    Always attempts a restore if injection fails mid-way.
    """
    context = context or {}
    # Validate fault in allowlist
    if fault_id in PASSIVE_ONLY_FAULTS:
        return {
            "error": f"Fault '{fault_id}' has no live injector; detection is passive only.",
            "fault_id": fault_id,
        }, 400

    if fault_id not in LIVE_INJECTABLE_FAULTS:
        return {
            "error": f"Fault '{fault_id}' is not in the live fault allowlist.",
            "allowed_faults": sorted(LIVE_INJECTABLE_FAULTS),
        }, 400

    try:
        fault = get_fault(fault_id)
    except KeyError:
        return {"error": f"Unknown fault identifier: {fault_id}"}, 400

    # Generator requirement for mac_flooding
    if fault_id == "mac_flooding" and not callable(context.get("mac_flood_generator")):
        return {
            "error": "mac_flooding requires a live mac_flood_generator callback. Injection refused.",
            "fault_id": fault_id,
        }, 400

    command_events: list[dict[str, Any]] = []
    original_run_command = context.get("run_command", subprocess.run)

    def recording_run_command(command, **kwargs):
        if not isinstance(command, (list, tuple)) or not command:
            raise ValueError("Only non-empty allowlisted argument arrays may be executed.")
        if kwargs.get("shell", False) is not False:
            raise ValueError("Shell execution is prohibited for fault injection and restore.")
        kwargs["shell"] = False
        event = {
            "command": list(command),
            "started_at_utc": _now_utc(),
            "shell": False,
        }
        try:
            result = original_run_command(command, **kwargs)
            event.update(
                {
                    "completed_at_utc": _now_utc(),
                    "returncode": getattr(result, "returncode", None),
                    "stdout": (getattr(result, "stdout", "") or "").strip(),
                    "stderr": (getattr(result, "stderr", "") or "").strip(),
                }
            )
            command_events.append(event)
            return result
        except Exception as exc:
            event.update(
                {
                    "completed_at_utc": _now_utc(),
                    "returncode": -1,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            command_events.append(event)
            raise

    execution_context = dict(context)
    execution_context["run_command"] = recording_run_command
    injection_started_at = _now_utc()
    try:
        inject_res = fault.injector(execution_context)
    except Exception as exc:
        # Unexpected error: always attempt restore
        restore_res = {}
        try:
            restore_res = fault.restore(execution_context)
        except Exception as r_exc:
            restore_res = {"error": str(r_exc), "success": False}
        return {
            "error": f"Injection crashed: {exc}",
            "restore_attempted": True,
            "restore_result": restore_res,
            "command_events": command_events,
        }, 500

    injection_completed_at = _now_utc()

    if not inject_res.get("success"):
        # Injection failed: always attempt restore
        restore_res = {}
        try:
            restore_res = fault.restore(execution_context)
        except Exception as r_exc:
            restore_res = {"error": str(r_exc), "success": False}
        return {
            "error": f"Fault injection failed: {inject_res.get('error', 'unknown error')}",
            "injection_result": inject_res,
            "restore_attempted": True,
            "restore_result": restore_res,
            "command_events": command_events,
        }, 500

    # Injection succeeded: initialize new PipelineRun
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    is_executable = fault_id == "redundant_trunk_restored"
    run = PipelineRun(
        run_id=run_id,
        fault_id=fault_id,
        status="ACTIVE",
        executable=is_executable,
    )
    # Stage 1: fault_injected
    run.complete_stage(
        "fault_injected",
        evidence={
            "fault_id": fault_id,
            "injection_started_at": injection_started_at,
            "injection_completed_at": injection_completed_at,
            "injection_result": inject_res,
            "command_events": command_events,
            "network_mutation_attempted": inject_res.get("network_mutation_attempted", True),
        },
    )

    if manager:
        manager.save_run(run)

    return {
        "success": True,
        "run_id": run_id,
        "fault_id": fault_id,
        "run": run.to_dict(),
    }, 201


RESTORE_COMMANDS = (
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s1", "2", "up"),
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s2", "1", "up"),
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s1", "3", "up"),
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "mod-port", "s2", "2", "up"),
    ("sudo", "-n", "ip", "link", "set", "dev", "s1-eth3", "up"),
    ("sudo", "-n", "ip", "link", "set", "dev", "s2-eth2", "up"),
    (
        "sudo",
        "-n",
        "ovs-ofctl",
        "-O",
        "OpenFlow13",
        "--strict",
        "del-flows",
        "s1",
        "cookie=0x4e45544f5053/-1,priority=65500,in_port=3",
    ),
    (
        "sudo",
        "-n",
        "ovs-ofctl",
        "-O",
        "OpenFlow13",
        "--strict",
        "del-flows",
        "s2",
        "cookie=0x4e45544f5053/-1,priority=65500,in_port=2",
    ),
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "cookie=0x4e45544f5053/-1"),
    ("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s2", "cookie=0x4e45544f5053/-1"),
)


def execute_guarded_restore(
    context: Mapping[str, Any] | None = None,
    manager: Optional[PipelineRunManager] = None,
) -> tuple[dict[str, Any], int]:
    """Execute fixed command sequence with shell=False to restore the lab to baseline.

    Records each use in the run record with commands and timestamps.
    May restore network state even if a pipeline/proposal is stuck awaiting
    approval. It does not clear or decide approval records.
    """
    context = context or {}

    # Manual LAB RESET is a recovery action, not remediation or approval.
    # It is intentionally allowed even if a proposal/run is stuck awaiting
    # approval: it restores network links and removes only tagged lab flows.
    # Approval/proposal records are NOT deleted or bypassed by this action.

    original_run_command = context.get("run_command", subprocess.run)
    command_events: list[dict[str, Any]] = []

    def recording_run_command(command, **kwargs):
        if not isinstance(command, (list, tuple)) or not command:
            raise ValueError("Only non-empty allowlisted argument arrays may be executed.")
        if kwargs.get("shell", False) is not False:
            raise ValueError("Shell execution is prohibited for fault injection and restore.")
        kwargs["shell"] = False
        event = {
            "command": list(command),
            "started_at_utc": _now_utc(),
            "shell": False,
        }
        try:
            result = original_run_command(command, **kwargs)
            event.update(
                {
                    "completed_at_utc": _now_utc(),
                    "returncode": getattr(result, "returncode", None),
                    "stdout": (getattr(result, "stdout", "") or "").strip(),
                    "stderr": (getattr(result, "stderr", "") or "").strip(),
                }
            )
            command_events.append(event)
            return result
        except Exception as exc:
            event.update(
                {
                    "completed_at_utc": _now_utc(),
                    "returncode": -1,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            command_events.append(event)
            raise

    run_command = recording_run_command
    completed = []
    failed = []

    restore_started_at = _now_utc()
    for cmd in RESTORE_COMMANDS:
        cmd_list = list(cmd)
        try:
            res = run_command(
                cmd_list,
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=4,
            )
            rc = getattr(res, "returncode", 0)
            stdout = getattr(res, "stdout", "")
            stderr = getattr(res, "stderr", "")
            record = {
                "command": cmd_list,
                "returncode": rc,
                "stdout": (stdout or "").strip(),
                "stderr": (stderr or "").strip(),
            }
            if rc == 0:
                completed.append(record)
            else:
                failed.append(record)
        except Exception as exc:
            failed.append(
                {
                    "command": cmd_list,
                    "returncode": -1,
                    "error": str(exc),
                }
            )

    restore_completed_at = _now_utc()
    all_ok = len(failed) == 0

    # Record each use in the run record with commands and timestamps
    updated_run = None
    if manager:
        current_run = manager.get_current_run()
        restore_evidence = {
            "restore_executed": True,
            "restore_type": "manual_baseline_restore",
            "restore_started_at": restore_started_at,
            "restore_completed_at": restore_completed_at,
            "commands": [event["command"] for event in command_events],
            "command_events": command_events,
            "completed_commands": completed,
            "failed_commands": failed,
            "completed_count": len(completed),
            "failed_count": len(failed),
        }
        if current_run and manager.is_run_active():
            current_run.complete_stage(
                "connectivity_verified",
                evidence=restore_evidence,
            )
            manager.finalize_run(current_run, outcome="rolled_back")
            updated_run = current_run.to_dict()
        else:
            # Create a run record for the lab reset when idle
            reset_run = PipelineRun(
                run_id=f"run-lab-reset-{uuid.uuid4().hex[:8]}",
                fault_id="lab_reset",
                status="ACTIVE",
                executable=False,
            )
            reset_run.start_stage("fault_injected", evidence={"trigger": "manual_lab_reset"})
            reset_run.complete_stage("fault_injected")
            reset_run.complete_stage("connectivity_verified", evidence=restore_evidence)
            manager.finalize_run(reset_run, outcome="rolled_back")
            updated_run = reset_run.to_dict()

    response_payload = {
        "success": all_ok,
        "restore_started_at": restore_started_at,
        "restore_completed_at": restore_completed_at,
        "completed_commands": completed,
        "failed_commands": failed,
        "command_events": command_events,
        "run": updated_run,
    }
    return response_payload, 200 if all_ok else 500


def get_live_faults_detail(mac_flood_generator: Any = None) -> list[dict[str, Any]]:
    """Return live-injectable faults; MAC flooding requires a configured generator."""
    faults = [
        {
            "id": "trunk_down",
            "name": "trunk_down",
            "display_name": "Issue 6 — Active trunk down",
            "target": "s1 port 2, s2 port 1 (Trunk A - Primary)",
            "description": "Administratively disables active trunk ports via OpenFlow 1.3 mod-port down.",
            "commands": [
                "sudo -n ovs-ofctl -O OpenFlow13 mod-port s1 2 down",
                "sudo -n ovs-ofctl -O OpenFlow13 mod-port s2 1 down",
            ],
            "safe_expectation": "STP transitions the alternate trunk to FORWARD; no host-facing or alternate ports are disabled.",
            "executable": False,
        },
        {
            "id": "redundant_trunk_restored",
            "name": "redundant_trunk_restored",
            "display_name": "Issue 1 — Restored redundant trunk",
            "target": "s1 port 3, s2 port 2 (Trunk B - Standby)",
            "description": "Restores redundant trunk by enabling interfaces and removing drop flows.",
            "commands": [
                "sudo -n ovs-ofctl -O OpenFlow13 --strict del-flows s1 cookie=0x4e45544f5053/-1,priority=65500,in_port=3",
                "sudo -n ovs-ofctl -O OpenFlow13 --strict del-flows s2 cookie=0x4e45544f5053/-1,priority=65500,in_port=2",
                "sudo -n ip link set dev s1-eth3 up",
                "sudo -n ip link set dev s2-eth2 up",
            ],
            "safe_expectation": "Re-isolate only the standby trunk through the existing guarded, human-approved remediation path while preserving the primary trunk and host reachability.",
            "executable": True,
        },
        {
            "id": "flow_drift",
            "name": "flow_drift",
            "display_name": "Issue 3 — Unauthorized OpenFlow rule drift",
            "target": "s1 Flow Table 0",
            "description": "Installs a uniquely tagged, high-priority drop rule for marker EtherType 0x88b5.",
            "commands": [
                "sudo -n ovs-ofctl -O OpenFlow13 add-flow s1 cookie=0x4e45544f5053,table=0,priority=65000,dl_type=0x88b5,actions=drop",
            ],
            "safe_expectation": "Remove only the identified unauthorized marker rule after policy verification.",
            "executable": False,
        },
        {
            "id": "link_flapping",
            "name": "link_flapping",
            "display_name": "Issue 4 — Link flapping",
            "target": "s1 port 2 (Trunk A - Primary)",
            "description": "Rapidly alternates primary trunk carrier state between down and up.",
            "commands": [
                "sudo -n ovs-ofctl -O OpenFlow13 mod-port s1 2 down",
                "sudo -n ovs-ofctl -O OpenFlow13 mod-port s1 2 up",
            ],
            "safe_expectation": "Stabilize trunk or isolate unstable flapping port without disrupting alternative paths.",
            "executable": False,
        },
        {
            "id": "mac_flooding",
            "name": "mac_flooding",
            "display_name": "Issue 5 — MAC table flooding",
            "target": "s1 MAC Address Table",
            "description": "Floods switch MAC table with random source addresses.",
            "commands": [
                "Synthetic frame generation (generator callback)",
            ],
            "safe_expectation": "Limit MAC learning or isolate flooding source port.",
            "executable": False,
        },
    ]
    if not callable(mac_flood_generator):
        faults = [fault for fault in faults if fault["id"] != "mac_flooding"]
    return faults
