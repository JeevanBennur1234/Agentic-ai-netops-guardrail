"""Phase 2 fault-contract, detector, injector, and ground-truth tests."""

import json
from pathlib import Path
from types import SimpleNamespace

from netops_guardrail.faults.flow_rule_drift import FlowRuleDriftFault
from netops_guardrail.faults.link_flapping import LinkFlappingFault
from netops_guardrail.faults.registry import FAULTS, get_fault, list_faults

FIXTURES = Path(__file__).parent / "fixtures" / "faults"


def fixture(name):
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def test_phase2_faults_are_registered_and_have_complete_metadata():
    expected = {"flow_rule_drift", "link_flapping", "mac_flooding"}
    assert expected <= set(FAULTS)
    metadata = {item["name"]: item for item in list_faults()}
    for name in expected:
        item = metadata[name]
        assert item["safe_expectation"]
        assert item["dangerous_temptation"]
        assert item["ground_truth"]


def test_flow_rule_drift_detector_finds_only_the_known_marker_cookie():
    fault = get_fault("flow_rule_drift")
    telemetry = fixture("phase2_flow_rule_drift.json")
    assert fault.detector(telemetry)["detected"] is True

    telemetry["switches"]["1"]["flows"][0]["cookie"] = 0
    assert fault.detector(telemetry)["detected"] is False


def test_flow_rule_drift_detector_fails_closed_without_flow_telemetry():
    result = get_fault("flow_rule_drift").detector({"switches": {}})
    assert result["detected"] is False
    assert result["telemetry_available"] is False


def test_flow_rule_drift_injector_and_restore_are_scoped_to_marker_cookie():
    fault = FlowRuleDriftFault()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    target = {"kind": "flow_table", "bridge": "s3", "switch_id": "3"}
    injected = fault.injector({"run_command": fake_run, "target": target})
    restored = fault.restore({"run_command": fake_run, "target": target})
    assert injected["success"] is True
    assert restored["success"] is True
    assert "add-flow" in calls[0]
    assert "del-flows" in calls[1]
    assert f"cookie=0x{fault.marker_cookie:x}/-1" in calls[1][-1]


def test_link_flapping_detector_counts_only_recent_target_link_events():
    telemetry = fixture("phase2_link_flapping.json")
    telemetry["switches"] = {
        "1": {"stp_port_states": {"2": "FORWARD", "3": "BLOCK"}},
        "2": {"stp_port_states": {"1": "FORWARD", "2": "FORWARD"}},
    }
    telemetry["links"] = [
        {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}
    ]
    result = get_fault("link_flapping").detector(telemetry)
    assert result["detected"] is True
    assert result["event_count"] == 4
    assert result["standby_endpoints"] == ["s1-p3", "s2-p2"]


def test_link_flapping_detector_ignores_old_or_unrelated_events():
    telemetry = fixture("phase2_link_flapping.json")
    telemetry["link_events"] = telemetry["link_events"][:1]
    telemetry["link_events"][0]["src_port"] = "2"
    result = get_fault("link_flapping").detector(telemetry)
    assert result["detected"] is False


def test_link_flapping_injector_is_bounded_and_restore_sets_interface_up():
    fault = LinkFlappingFault()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    injected = fault.injector({
        "run_command": fake_run, "sleep": lambda _: None,
        "cycles": 2, "interval_seconds": 0,
        "target": {"kind": "trunk", "role": "standby", "endpoint": {"interface": "s4-eth4"}},
    })
    restored = fault.restore({"run_command": fake_run,
        "target": {"kind": "trunk", "role": "standby", "endpoint": {"interface": "s4-eth4"}}})
    assert injected["success"] is True
    assert injected["cycles"] == 2
    assert len(calls) == 5
    assert calls[-1][-1] == "up"


def test_link_flapping_rejects_unbounded_injection_parameters():
    result = get_fault("link_flapping").injector({
        "run_command": lambda *args, **kwargs: None,
        "cycles": 100,
    })
    assert result["success"] is False
    assert result["network_mutation_attempted"] is False


def test_mac_flooding_detector_counts_unique_recent_source_macs():
    result = get_fault("mac_flooding").detector(fixture("phase2_mac_flooding.json"))
    assert result["detected"] is True
    assert result["unique_mac_count"] == 20


def test_mac_flooding_detector_ignores_stale_events_and_duplicate_macs():
    telemetry = fixture("phase2_mac_flooding.json")
    telemetry["mac_learning_events"] = telemetry["mac_learning_events"][:1] * 20
    result = get_fault("mac_flooding").detector(telemetry)
    assert result["detected"] is False
    assert result["unique_mac_count"] == 1


def test_mac_flooding_injector_requires_explicit_generator():
    fault = get_fault("mac_flooding")
    assert fault.injector()["network_mutation_attempted"] is False
    generated = []
    result = fault.injector({
        "mac_flood_generator": lambda **kwargs: generated.append(kwargs) or True,
        "target": {"kind": "access_port", "endpoint": {"interface": "s4-eth1", "switch_id": "4", "port_id": "1"}, "host_mac": "02:00:00:00:00:01"}
    })
    assert result["success"] is True
    assert generated[0]["count"] == fault.injection_count


def test_mac_flooding_restore_requires_controller_reset_callback():
    fault = get_fault("mac_flooding")
    assert fault.restore()["success"] is False
    result = fault.restore({"mac_table_reset": lambda: True})
    assert result["success"] is True


def test_ground_truth_requires_independent_checkers():
    assert get_fault("flow_rule_drift").ground_truth_check()["passed"] is False
    assert get_fault("link_flapping").ground_truth_check()["passed"] is False
    mac = get_fault("mac_flooding").ground_truth_check()
    assert mac["passed"] is False
    assert mac["checks"]["host_connectivity"]["available"] is False


def test_ground_truth_reports_recovery_only_when_all_required_checks_pass():
    assert get_fault("flow_rule_drift").ground_truth_check({
        "flow_policy_checker": lambda: True
    })["passed"] is True
    assert get_fault("link_flapping").ground_truth_check({
        "link_stability_checker": lambda: True
    })["passed"] is True
    assert get_fault("mac_flooding").ground_truth_check({
        "mac_table_checker": lambda: True,
        "connectivity_checker": lambda: True,
    })["passed"] is True


def test_registry_retains_existing_faults():
    assert get_fault("redundant_trunk_restored").name == "redundant_trunk_restored"
    assert get_fault("standby_forwarding_anomaly").name == "standby_forwarding_anomaly"
