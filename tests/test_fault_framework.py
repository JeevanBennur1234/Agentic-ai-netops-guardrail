"""Contract, registry, and deterministic detector tests for the fault framework."""

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from netops_guardrail.faults.base import Fault
from netops_guardrail.faults.registry import FAULTS, get_fault, list_faults

FIXTURES = Path(__file__).parent / "fixtures" / "faults"


def load_fixture(name):
    with (FIXTURES / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_registry_contains_existing_and_phase2_faults():
    assert set(FAULTS) == {
        "redundant_trunk_restored",
        "standby_forwarding_anomaly",
        "flow_rule_drift",
        "link_flapping",
        "mac_flooding",
        "trunk_down",
    }
    assert get_fault("redundant_trunk_restored").name == "redundant_trunk_restored"
    assert get_fault("standby_forwarding_anomaly").name == "standby_forwarding_anomaly"
    assert get_fault("trunk_down").name == "trunk_down"
    assert get_fault("flow_drift").name == "flow_rule_drift"


def test_registry_metadata_is_serializable_and_complete():
    records = list_faults()
    assert len(records) == 6
    required = {
        "name",
        "display_name",
        "description",
        "safe_expectation",
        "dangerous_temptation",
        "ground_truth",
    }
    assert all(required <= set(record) for record in records)
    json.dumps(records)


def test_unknown_fault_is_rejected():
    try:
        get_fault("not-a-real-fault")
    except KeyError as exc:
        assert "Unknown fault" in str(exc)
    else:
        raise AssertionError("Unknown fault unexpectedly resolved")


def test_fault_contract_is_implemented_by_registered_faults():
    assert all(isinstance(fault, Fault) for fault in FAULTS.values())
    for fault in FAULTS.values():
        assert callable(fault.injector)
        assert callable(fault.restore)
        assert callable(fault.detector)
        assert callable(fault.ground_truth_check)


def test_issue1_detector_recognizes_restored_redundant_trunk():
    telemetry = load_fixture("issue1_redundant_trunk_restored.json")
    result = get_fault("redundant_trunk_restored").detector(telemetry)
    assert result["detected"] is True
    assert result["prerequisites"]["primary_trunk_forwarding"] is True
    assert result["prerequisites"]["host_access_ports_forwarding"] is True
    assert result["prerequisites"]["standby_endpoint_stp_blocked"] is True


def test_issue1_detector_fails_closed_when_primary_path_is_not_forwarding():
    telemetry = load_fixture("issue1_redundant_trunk_restored.json")
    telemetry["switches"]["1"]["stp_port_states"]["2"] = "BLOCK"
    result = get_fault("redundant_trunk_restored").detector(telemetry)
    assert result["detected"] is False
    assert result["prerequisites"]["primary_trunk_forwarding"] is False


def test_issue2_detector_recognizes_both_standby_endpoints_forwarding():
    telemetry = load_fixture("issue2_standby_forwarding_anomaly.json")
    telemetry["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    result = get_fault("standby_forwarding_anomaly").detector(telemetry)
    assert result["ready_for_investigation"] is True
    assert result["detected"] is True
    assert result["standby_both_forward"] is True


def test_issue2_detector_fails_closed_for_missing_standby_link():
    telemetry = load_fixture("issue2_standby_forwarding_anomaly.json")
    telemetry["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    telemetry["links"] = telemetry["links"][:1]
    result = get_fault("standby_forwarding_anomaly").detector(telemetry)
    assert result["ready_for_investigation"] is False
    assert result["detected"] is False


def test_issue2_injector_is_non_mutating_and_restore_is_noop():
    fault = get_fault("standby_forwarding_anomaly")
    injected = fault.injector({"signal_source": "controlled_demo_signal"})
    restored = fault.restore()
    assert injected["network_mutation_attempted"] is False
    assert injected["signal_source"] == "controlled_demo_signal"
    assert restored["network_mutation_attempted"] is False


def test_issue1_injector_runs_only_the_existing_reset_commands():
    fault = get_fault("redundant_trunk_restored")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = fault.injector({"run_command": fake_run, "target": {
        "kind": "restorable_link", "endpoints": [
            {"bridge": "s3", "port_id": "4", "interface": "s3-eth4"},
            {"bridge": "s4", "port_id": "2", "interface": "s4-eth2"},
        ]
    }})
    assert result["success"] is True
    assert result["network_mutation_attempted"] is True
    assert len(calls) == 4
    assert calls[0][-2:] == ["s3", "cookie=0x4e45544f5053/-1,priority=65500,in_port=4"]
    assert calls[2][-2:] == ["s4", "cookie=0x4e45544f5053/-1,priority=65500,in_port=2"]
    assert calls[1][-1] == "up" and calls[3][-1] == "up"
    assert all("--strict" in command for command in (calls[0], calls[2]))


def test_issue1_restore_never_bypasses_guarded_remediation():
    result = get_fault("redundant_trunk_restored").restore()
    assert result["status"] == "requires_guarded_remediation"
    assert result["network_mutation_attempted"] is False


def test_ground_truth_uses_explicit_connectivity_checker():
    fault = get_fault("redundant_trunk_restored")
    assert fault.ground_truth_check({"connectivity_checker": lambda: True})["passed"] is True
    assert fault.ground_truth_check({"connectivity_checker": lambda: False})["passed"] is False
    assert fault.ground_truth_check()["available"] is False


def test_fault_registry_endpoint_uses_chaos_bearer_authentication(tmp_path, monkeypatch):
    from netops_guardrail.observability.server import create_metrics_app

    monkeypatch.delenv("NETOPS_CHAOS_API_TOKEN", raising=False)
    app = create_metrics_app(
        telemetry_path=str(tmp_path / "telemetry.json"),
        audit_log_path=str(tmp_path / "audit.json"),
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    client = app.test_client()
    assert client.get("/api/faults").status_code == 503

    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "fault-registry-test-token")
    assert client.get("/api/faults", headers={"Authorization": "Bearer wrong"}).status_code == 401

    response = client.get(
        "/api/faults",
        headers={"Authorization": "Bearer fault-registry-test-token"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert {fault["name"] for fault in payload["faults"]} == {
        "redundant_trunk_restored",
        "standby_forwarding_anomaly",
        "flow_rule_drift",
        "link_flapping",
        "mac_flooding",
        "trunk_down",
    }
