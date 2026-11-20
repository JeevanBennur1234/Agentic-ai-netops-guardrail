"""Tests for PipelineRun, PipelineRunManager, and pipeline API endpoints."""

import json
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from netops_guardrail.controller.pipeline_run import (
    PipelineRun,
    PipelineRunManager,
    build_lab_restore_commands,
    check_injection_preconditions,
    execute_guarded_injection,
    get_live_faults_detail,
    get_preflight_status,
)
from netops_guardrail.faults.registry import get_fault
from netops_guardrail.observability.server import create_metrics_app


def test_pipeline_run_initial_stages_and_provenance():
    run = PipelineRun(run_id="test-run-1", fault_id="redundant_trunk_restored", executable=True)
    d = run.to_dict()
    assert d["run_id"] == "test-run-1"
    assert d["fault_id"] == "redundant_trunk_restored"
    assert d["executable"] is True
    assert d["status"] == "ACTIVE"

    # Verify stage sources are fixed and immutable
    stages = {s["name"]: s for s in d["stages"]}
    assert stages["fault_injected"]["source"] == "LAB"
    assert stages["telemetry_observed"]["source"] == "DETERMINISTIC"
    assert stages["detected"]["source"] == "DETERMINISTIC"
    assert stages["ai_analysis"]["source"] == "AI"
    assert stages["safety_verified"]["source"] == "SAFETY"
    assert stages["awaiting_approval"]["source"] == "HUMAN"
    assert stages["approved"]["source"] == "HUMAN"
    assert stages["executed"]["source"] == "EXECUTOR"
    assert stages["connectivity_verified"]["source"] == "LAB"


def test_pipeline_run_manager_persistence(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    assert manager.get_current_run() is None
    assert manager.is_run_active() is False

    run = PipelineRun(run_id="run-100", fault_id="redundant_trunk_restored", executable=True)
    manager.save_run(run)

    loaded = manager.get_current_run()
    assert loaded is not None
    assert loaded.run_id == "run-100"
    assert manager.is_run_active() is True

    # Finalize run
    manager.finalize_run(loaded, outcome="connectivity_verified")
    assert manager.is_run_active() is False

    # Check history
    history = json.loads((tmp_path / "runs" / "pipeline_runs.json").read_text(encoding="utf-8"))
    assert len(history) == 1
    assert history[0]["outcome"] == "connectivity_verified"


def test_failed_outcome_is_terminal_even_if_status_is_stale_approved(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    run = PipelineRun(
        run_id="run-stale-approved",
        fault_id="redundant_trunk_restored",
        status="APPROVED",
        outcome="failed",
        executable=True,
    )
    manager.save_run(run)
    assert manager.is_run_active() is False



def _live_injection_telemetry():
    now = datetime.now(timezone.utc).isoformat()
    return {
        "updated_at_utc": now,
        "provenance": {"source": "live_telemetry"},
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "port_status": {"1": {"state": "UP"}, "2": {"state": "UP"}, "3": {"state": "DOWN"}},
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "BLOCK"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "port_status": {"1": {"state": "UP"}, "2": {"state": "DOWN"}, "3": {"state": "UP"}},
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "link_events": [{"timestamp_utc": now, "event": "DELETE", "src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}],
        "hosts": [{"switch_id": "1", "port_id": "1", "mac": "02:00:00:00:00:01"}],
    }

def test_execute_guarded_injection_records_commands_and_creates_run(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    calls = []

    def mock_run(cmd, **kwargs):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result, code = execute_guarded_injection(
        fault_id="redundant_trunk_restored",
        context={"run_command": mock_run, "telemetry": _live_injection_telemetry()},
        manager=manager,
    )
    assert code == 201
    assert result["success"] is True
    assert "run" in result

    # Check that stage 1 recorded the commands
    stage1 = result["run"]["stages"][0]
    assert stage1["name"] == "fault_injected"
    assert stage1["status"] == "COMPLETED"
    assert stage1["source"] == "LAB"
    assert len(stage1["evidence"]["injection_result"]["completed_commands"]) == 4


def test_passive_fault_has_no_injector_and_is_rejected(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    result, code = execute_guarded_injection(
        fault_id="standby_forwarding",
        manager=manager,
    )
    assert code == 400
    assert "passive only" in result["error"]


def test_mac_flooding_requires_generator_callback(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    result, code = execute_guarded_injection(
        fault_id="mac_flooding",
        context={},
        manager=manager,
    )
    assert code == 400
    assert "mac_flood_generator callback" in result["error"]


def test_mac_flooding_requires_recovery_callback_before_injection(tmp_path):
    manager = PipelineRunManager(tmp_path / "runs")
    context = {
        "telemetry": _live_injection_telemetry(),
        "mac_flood_generator": lambda **kwargs: True,
    }
    result, code = execute_guarded_injection(
        fault_id="mac_flooding", context=context, manager=manager
    )
    assert code == 400
    assert "mac_table_reset recovery callback" in result["error"]


def test_trunk_down_injector_and_restore():
    fault = get_fault("trunk_down")
    calls = []

    def mock_run(cmd, **kwargs):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    from netops_guardrail.faults.targets import resolve_fault_target
    telemetry = _live_injection_telemetry()
    target = resolve_fault_target("trunk_down", telemetry)
    context = {"run_command": mock_run, "target": target}
    res = fault.injector(context)
    assert res["success"] is True
    assert len(calls) == 2
    assert "down" in calls[0]
    assert "down" in calls[1]

    calls.clear()
    restore_res = fault.restore(context)
    assert restore_res["success"] is True
    assert len(calls) == 2
    assert "up" in calls[0]
    assert "up" in calls[1]


def test_pipeline_api_endpoints_auth_and_guards(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                "provenance": {"source": "live_telemetry", "producer": "test-controller"},
                "switches": {
                    "1": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                          "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "BLOCK"},
                          "port_status": {"1": {"state": "UP"}, "2": {"state": "UP"}, "3": {"state": "DOWN"}}},
                    "2": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                          "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                          "port_status": {"1": {"state": "UP"}, "2": {"state": "DOWN"}, "3": {"state": "UP"}}},
                },
                "links": [
                {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
                {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
            ],
                "link_events": [{"timestamp_utc": datetime.now(timezone.utc).isoformat(), "event": "DELETE",
                                  "src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}],
                "hosts": [{"switch_id": "1", "port_id": "1", "mac": "02:00:00:00:00:01"}],
            }
        ),
        encoding="utf-8",
    )

    incident_dir = tmp_path / "incidents"
    incident_dir.mkdir(parents=True, exist_ok=True)
    monitor_path = incident_dir / "monitor_status.json"
    monitor_path.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "interval_seconds": 5,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "chaos-token-123")

    app = create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(tmp_path / "audit.json"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(tmp_path / "runs")
    app.config["NETOPS_MONITOR_STATUS_PATH"] = str(monitor_path)
    app.config["NETOPS_CONNECTIVITY_CHECKER_OVERRIDE"] = lambda: True

    client = app.test_client()

    # GET /api/pipeline/current
    res = client.get("/api/pipeline/current")
    assert res.status_code == 200
    assert res.get_json()["active"] is False

    # POST /api/pipeline/inject without token -> 401
    res_no_auth = client.post("/api/pipeline/inject", json={"fault_id": "flow_drift"})
    assert res_no_auth.status_code == 401

    # POST /api/pipeline/inject with token for passive fault -> 400
    res_passive = client.post(
        "/api/pipeline/inject",
        json={"fault_id": "standby_forwarding"},
        headers={"Authorization": "Bearer chaos-token-123"},
    )
    assert res_passive.status_code == 400
    assert "passive only" in res_passive.get_json()["error"]


def test_pipeline_preflight_endpoint(monkeypatch, tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                "switches": {},
            }
        ),
        encoding="utf-8",
    )

    incident_dir = tmp_path / "incidents"
    incident_dir.mkdir(parents=True, exist_ok=True)
    monitor_path = incident_dir / "monitor_status.json"
    monitor_path.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
                "interval_seconds": 5,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "test-token")

    app = create_metrics_app(telemetry_path=str(telemetry_path))
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(tmp_path / "runs")
    app.config["NETOPS_MONITOR_STATUS_PATH"] = str(monitor_path)
    app.config["NETOPS_CONNECTIVITY_CHECKER_OVERRIDE"] = lambda: True

    client = app.test_client()

    # When all preconditions are satisfied
    res = client.get("/api/pipeline/preflight")
    assert res.status_code == 200
    data = res.get_json()
    assert data["ready"] is True
    assert data["telemetry"]["status"] == "ok"
    assert data["monitor_heartbeat"]["status"] == "ok"
    assert data["baseline_connectivity"]["status"] == "passed"
    assert data["active_run"]["present"] is False
    assert data["token_configured"] is True

    # If telemetry is stale
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": "2020-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    res_stale = client.get("/api/pipeline/preflight")
    data_stale = res_stale.get_json()
    assert data_stale["ready"] is False
    assert data_stale["telemetry"]["status"] == "stale"


def test_pipeline_faults_endpoint(tmp_path):
    app = create_metrics_app(telemetry_path=str(tmp_path / "telemetry.json"))
    client = app.test_client()

    res = client.get("/api/pipeline/faults")
    assert res.status_code == 200
    faults = res.get_json()["faults"]
    assert len(faults) == 4
    ids = {f["id"] for f in faults}
    assert "mac_flooding" not in ids
    assert len(get_live_faults_detail(mac_flood_generator=lambda *_: None)) == 4
    assert len(get_live_faults_detail(
        mac_flood_generator=lambda *_: None, mac_table_reset=lambda: True
    )) == 5
    assert "trunk_down" in ids
    assert "redundant_trunk_restored" in ids
    assert "flow_drift" in ids
    for f in faults:
        assert "target" in f
        assert "description" in f
        assert "commands" in f
        assert isinstance(f["commands"], list)


def test_pipeline_restore_endpoint_guarded(monkeypatch, tmp_path):
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "restore-token-secret")

    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_live_injection_telemetry()), encoding="utf-8")
    app = create_metrics_app(telemetry_path=str(telemetry_path))
    runs_dir = tmp_path / "runs"
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)

    executed_cmds = []

    def mock_run(cmd, **kwargs):
        executed_cmds.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    app.config["NETOPS_RUN_COMMAND_OVERRIDE"] = mock_run
    client = app.test_client()

    # Unauthorized without token
    res_unauth = client.post("/api/pipeline/restore")
    assert res_unauth.status_code == 401

    # Unauthorized with wrong token
    res_bad = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert res_bad.status_code == 401

    # Create an active run first
    manager = PipelineRunManager(runs_dir)
    active_run = PipelineRun(run_id="run-restore-test", fault_id="trunk_down")
    manager.save_run(active_run)
    assert manager.is_run_active() is True

    # Authorized restore via Bearer token
    res_ok = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer restore-token-secret"},
    )
    assert res_ok.status_code == 200
    data = res_ok.get_json()
    assert data["success"] is True
    expected_count = len(build_lab_restore_commands(_live_injection_telemetry()))
    assert len(data["completed_commands"]) == expected_count
    assert len(executed_cmds) == expected_count

    # Verify pipeline run was finalized as rolled_back
    assert manager.is_run_active() is False
    current = manager.get_current_run()
    assert current.status == "ROLLED_BACK"
    assert current.outcome == "rolled_back"


def test_lab_reset_recovers_network_even_when_pipeline_stuck_in_approval(monkeypatch, tmp_path):
    """Emergency baseline restore is independent of pending approval state."""
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "reset-token-secret")

    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_live_injection_telemetry()), encoding="utf-8")
    app = create_metrics_app(telemetry_path=str(telemetry_path))
    runs_dir = tmp_path / "runs"
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)

    manager = PipelineRunManager(runs_dir)
    run_awaiting = PipelineRun(run_id="run-await-test", fault_id="redundant_trunk_restored")
    run_awaiting.start_stage("awaiting_approval")
    manager.save_run(run_awaiting)

    executed_cmds = []
    app.config["NETOPS_RUN_COMMAND_OVERRIDE"] = lambda cmd, **kwargs: executed_cmds.append(list(cmd)) or subprocess.CompletedProcess(cmd, 0, "", "")
    client = app.test_client()

    res_awaiting = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer reset-token-secret"},
    )
    assert res_awaiting.status_code == 200
    assert res_awaiting.get_json()["success"] is True
    expected_count = len(build_lab_restore_commands(_live_injection_telemetry()))
    assert len(res_awaiting.get_json()["completed_commands"]) == expected_count
    assert manager.is_run_active() is False
    assert manager.get_current_run().outcome == "rolled_back"

    # A separate approved/stuck run can also be rolled back by the lab reset.
    run_approved = PipelineRun(run_id="run-approved-test", fault_id="redundant_trunk_restored")
    run_approved.start_stage("approved")
    manager.save_run(run_approved)
    res_approved = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer reset-token-secret"},
    )
    assert res_approved.status_code == 200
    assert res_approved.get_json()["success"] is True
    assert len(executed_cmds) == expected_count * 2


def test_lab_reset_records_commands_and_timestamps_in_run_record(monkeypatch, tmp_path):
    """Each use of lab reset must be recorded in the run record with commands and timestamps."""
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "reset-token-secret")

    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(json.dumps(_live_injection_telemetry()), encoding="utf-8")
    app = create_metrics_app(telemetry_path=str(telemetry_path))
    runs_dir = tmp_path / "runs"
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(runs_dir)

    executed = []

    def mock_run(cmd, **kwargs):
        executed.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    app.config["NETOPS_RUN_COMMAND_OVERRIDE"] = mock_run
    client = app.test_client()

    manager = PipelineRunManager(runs_dir)
    # Reset when idle
    res = client.post(
        "/api/pipeline/restore",
        headers={"Authorization": "Bearer reset-token-secret"},
    )
    assert res.status_code == 200
    current = manager.get_current_run()
    assert current is not None
    assert current.status == "ROLLED_BACK"
    conn_stage = current.get_stage("connectivity_verified")
    assert conn_stage.evidence["restore_executed"] is True
    assert "commands" in conn_stage.evidence
    assert len(conn_stage.evidence["commands"]) == len(build_lab_restore_commands(_live_injection_telemetry()))
    assert "restore_started_at" in conn_stage.evidence
    assert "restore_completed_at" in conn_stage.evidence


def test_missing_connectivity_checker_fails_closed(tmp_path, monkeypatch):
    telemetry = tmp_path / "telemetry.json"
    telemetry.write_text(
        json.dumps(
            {
                "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                "switches": {},
            }
        ),
        encoding="utf-8",
    )
    monitor = tmp_path / "monitor_status.json"
    monitor.write_text(
        json.dumps(
            {
                "status": "running",
                "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "configured")
    preflight = get_preflight_status(
        telemetry_path=telemetry,
        monitor_status_path=monitor,
        connectivity_checker=None,
    )
    assert preflight["baseline_connectivity"]["status"] == "unknown"
    assert preflight["ready"] is False
    allowed, reason, status = check_injection_preconditions(
        telemetry_path=telemetry,
        monitor_status_path=monitor,
        connectivity_checker=None,
    )
    assert allowed is False
    assert status == 503
    assert "connectivity" in reason.lower()


def test_restore_flow_deletes_are_cookie_scoped_only():
    commands = build_lab_restore_commands(_live_injection_telemetry())
    delete_commands = [cmd for cmd in commands if "del-flows" in cmd]
    assert len(delete_commands) == 2
    for command in delete_commands:
        assert any(arg.startswith("cookie=") for arg in command), command
    assert not any("--all" in arg for command in delete_commands for arg in command)


def test_restore_command_events_are_derived_from_live_telemetry(monkeypatch, tmp_path):
    from netops_guardrail.controller.pipeline_run import execute_guarded_restore

    calls = []
    telemetry = _live_injection_telemetry()
    expected_commands = build_lab_restore_commands(telemetry)

    def fake_run(command, **kwargs):
        calls.append(list(command))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    result, status = execute_guarded_restore(
        context={"run_command": fake_run, "telemetry": telemetry},
        manager=PipelineRunManager(tmp_path / "runs"),
    )
    assert status == 200
    assert len(result["command_events"]) == len(expected_commands)
    for event, command in zip(result["command_events"], expected_commands):
        assert event["command"] == list(command)
        assert event["started_at_utc"]
        assert event["completed_at_utc"]
        assert event["returncode"] == 0
    assert calls == [list(command) for command in expected_commands]


def _pipeline_test_app(monkeypatch, tmp_path):
    telemetry = tmp_path / "telemetry.json"
    now = datetime.now(timezone.utc).isoformat()
    telemetry.write_text(
        json.dumps({
            "updated_at_utc": now,
            "provenance": {"source": "live_telemetry", "producer": "test-controller"},
            "switches": {
                "1": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                      "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "BLOCK"},
                      "port_status": {"1": {"state": "UP"}, "2": {"state": "UP"}, "3": {"state": "DOWN"}}},
                "2": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                      "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                      "port_status": {"1": {"state": "UP"}, "2": {"state": "DOWN"}, "3": {"state": "UP"}}},
            },
            "links": [
                {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
                {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
            ],
            "link_events": [{"timestamp_utc": now, "event": "DELETE", "src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}],
            "hosts": [{"switch_id": "1", "port_id": "1", "mac": "02:00:00:00:00:01"}],
        }),
        encoding="utf-8",
    )
    monitor = tmp_path / "monitor_status.json"
    monitor.write_text(
        json.dumps({"status": "running", "last_heartbeat_utc": now}),
        encoding="utf-8",
    )
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "pipeline-token")
    app = create_metrics_app(telemetry_path=str(telemetry))
    app.config["NETOPS_PIPELINE_RUNS_DIR"] = str(tmp_path / "pipeline-runs")
    app.config["NETOPS_MONITOR_STATUS_PATH"] = str(monitor)
    app.config["NETOPS_CONNECTIVITY_CHECKER_OVERRIDE"] = lambda: True
    app.config["NETOPS_RUN_COMMAND_OVERRIDE"] = lambda command, **kwargs: SimpleNamespace(
        returncode=0, stdout="ok", stderr=""
    )
    return app


def test_injection_advances_pipeline_to_human_approval_without_execution(monkeypatch, tmp_path):
    import netops_guardrail.observability.blueprints.pipeline as pipeline_blueprint

    app = _pipeline_test_app(monkeypatch, tmp_path)
    monkeypatch.setattr(
        pipeline_blueprint,
        "get_fault",
        lambda fault_id: SimpleNamespace(
            detector=lambda telemetry: {
                "detected": True,
                "evidence_id": "evidence-live-1",
                "observed": "fixture-detector",
            }
        ),
    )
    app.config["NETOPS_DECIDE"] = lambda **kwargs: {
        "decision": "PENDING_HUMAN_APPROVAL",
        "intent": {
            "action": "block",
            "target_switch": "1",
            "from_port": "3",
            "reason": "Evidence-backed standby isolation proposal.",
            "_agent_metadata": {
                "model": "test-model",
                "model_invoked": True,
                "status": "completed",
            },
        },
        "verification": {"safe": True, "checks": ["PASS: host reachability preserved"]},
        "human_approval": {
            "proposal_id": "proposal-pipeline-1",
            "expires_at": "2030-01-01T00:00:00+00:00",
        },
    }

    response = app.test_client().post(
        "/api/pipeline/inject",
        headers={"Authorization": "Bearer pipeline-token"},
        json={"fault_id": "redundant_trunk_restored"},
    )
    assert response.status_code == 200, response.get_json()
    data = response.get_json()
    assert data["run"]["status"] == "AWAITING_APPROVAL"
    stages = {stage["name"]: stage for stage in data["run"]["stages"]}
    assert stages["fault_injected"]["status"] == "COMPLETED"
    assert stages["telemetry_observed"]["status"] == "COMPLETED"
    assert stages["detected"]["status"] == "COMPLETED"
    assert stages["ai_analysis"]["status"] == "COMPLETED"
    assert stages["safety_verified"]["status"] == "COMPLETED"
    assert stages["awaiting_approval"]["status"] == "IN_PROGRESS"
    assert stages["executed"]["status"] == "PENDING"
    assert data["run"]["proposal_id"] == "proposal-pipeline-1"


def test_executable_fault_safe_no_action_becomes_recommendation_only(monkeypatch, tmp_path):
    import netops_guardrail.observability.blueprints.pipeline as pipeline_blueprint

    app = _pipeline_test_app(monkeypatch, tmp_path)
    monkeypatch.setattr(
        pipeline_blueprint,
        "get_fault",
        lambda fault_id: SimpleNamespace(
            detector=lambda telemetry: {
                "detected": True,
                "evidence_id": "evidence-no-action",
                "observed": "fixture-detector",
            }
        ),
    )
    app.config["NETOPS_DECIDE"] = lambda **kwargs: {
        "decision": "APPROVED",
        "intent": {
            "action": "no_action",
            "reason": "STP blocks the standby trunk and primary connectivity remains healthy.",
            "_agent_metadata": {"model": "test-model", "model_invoked": True, "status": "completed"},
        },
        "verification": {"safe": True, "checks": ["PASS: connectivity preserved"]},
        "human_approval": None,
    }
    response = app.test_client().post(
        "/api/pipeline/inject",
        headers={"Authorization": "Bearer pipeline-token"},
        json={"fault_id": "redundant_trunk_restored"},
    )
    assert response.status_code == 200, response.get_json()
    run = response.get_json()["run"]
    assert run["status"] == "RECOMMENDATION_ONLY_PENDING_ACK"
    assert run["executable"] is False
    assert run["proposal_id"] is None
    stages = {stage["name"]: stage for stage in run["stages"]}
    assert stages["ai_analysis"]["status"] == "COMPLETED"
    assert stages["safety_verified"]["status"] == "COMPLETED"
    assert stages["awaiting_approval"]["status"] == "IN_PROGRESS"
    assert stages["awaiting_approval"]["evidence"]["safe_no_action"] is True
    assert stages["executed"]["status"] == "PENDING"


def test_recommendation_only_requires_human_ack_and_never_executes(monkeypatch, tmp_path):
    import netops_guardrail.observability.blueprints.pipeline as pipeline_blueprint

    app = _pipeline_test_app(monkeypatch, tmp_path)
    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", '{"netops-admin":"approver-token"}')
    monkeypatch.setattr(
        pipeline_blueprint,
        "get_fault",
        lambda fault_id: SimpleNamespace(
            detector=lambda telemetry: {"detected": True, "evidence_id": "evidence-live-2"}
        ),
    )
    app.config["NETOPS_DECIDE"] = lambda **kwargs: {
        "decision": "APPROVED",
        "intent": {
            "action": "no_action",
            "reason": "No safe automated remediation is available.",
            "_agent_metadata": {
                "model": "test-model",
                "model_invoked": True,
                "status": "completed",
            },
        },
        "verification": {"safe": True, "checks": ["PASS: evidence reviewed"]},
        "human_approval": None,
    }

    client = app.test_client()
    response = client.post(
        "/api/pipeline/inject",
        headers={"Authorization": "Bearer pipeline-token"},
        json={"fault_id": "flow_drift"},
    )
    assert response.status_code == 200, response.get_json()
    run = response.get_json()["run"]
    assert run["status"] == "RECOMMENDATION_ONLY_PENDING_ACK"
    assert run["executable"] is False
    stages = {stage["name"]: stage for stage in run["stages"]}
    assert stages["awaiting_approval"]["status"] == "IN_PROGRESS"
    assert stages["executed"]["status"] == "PENDING"

    ack = client.post(
        "/api/pipeline/acknowledge",
        headers={"Authorization": "Bearer approver-token"},
        json={"reason": "Reviewed the recommendation; no network change authorized."},
    )
    assert ack.status_code == 200, ack.get_json()
    acknowledged = ack.get_json()
    assert acknowledged["success"] is True
    assert acknowledged["executor_called"] is False
    assert acknowledged["run"]["status"] == "RECOMMENDATION_ONLY"
    final_stages = {stage["name"]: stage for stage in acknowledged["run"]["stages"]}
    assert final_stages["awaiting_approval"]["evidence"]["acknowledged"] is True
    assert final_stages["executed"]["status"] == "SKIPPED"
    assert final_stages["connectivity_verified"]["status"] == "SKIPPED"


def test_pipeline_run_manager_uses_process_shared_exclusive_lock(tmp_path):
    first = PipelineRunManager(tmp_path / "runs")
    second = PipelineRunManager(tmp_path / "runs")
    with first.exclusive_run_lock():
        with pytest.raises(RuntimeError, match="transaction is in progress"):
            with second.exclusive_run_lock():
                raise AssertionError("second lock acquisition must not succeed")
    with second.exclusive_run_lock():
        assert True


def test_lab_restore_recovers_network_if_approval_store_is_unavailable(tmp_path):
    from netops_guardrail.controller.pipeline_run import execute_guarded_restore

    class BrokenApprovalStore:
        def list_proposals(self, include_decided=True):
            raise OSError("approval store unavailable")

    commands = []

    def fake_run(command, **kwargs):
        commands.append(list(command))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result, status = execute_guarded_restore(
        context={
            "approval_store": BrokenApprovalStore(),
            "run_command": fake_run,
            "telemetry": _live_injection_telemetry(),
        },
        manager=PipelineRunManager(tmp_path / "runs"),
    )
    assert status == 200
    assert result["success"] is True
    expected_count = len(build_lab_restore_commands(_live_injection_telemetry()))
    assert len(result["completed_commands"]) == expected_count
    assert len(commands) == expected_count
