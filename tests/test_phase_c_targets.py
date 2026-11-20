from datetime import datetime, timedelta, timezone

import pytest

from netops_guardrail.faults.targets import TargetResolutionError, resolve_fault_target


def ring4_snapshot():
    now = datetime.now(timezone.utc)
    switches = {}
    for switch_id in ("1", "2", "3", "4"):
        switches[str(switch_id)] = {
            "ports": {str(port): {} for port in range(1, 5)},
            "flows": [{"cookie": 0, "priority": 0}],
            "port_status": {str(port): {"state": "UP"} for port in range(1, 5)},
            "stp_port_states": {str(port): "FORWARD" for port in range(1, 5)},
        }
    switches["4"]["stp_port_states"]["4"] = "BLOCK"
    links = [
        {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "1"},
        {"src_switch": "1", "src_port": "4", "dst_switch": "3", "dst_port": "1"},
        {"src_switch": "2", "src_port": "2", "dst_switch": "4", "dst_port": "3"},
        {"src_switch": "3", "src_port": "2", "dst_switch": "4", "dst_port": "4"},
    ]
    return {
        "updated_at_utc": now.isoformat(),
        "provenance": {"source": "live_telemetry", "producer": "unit-test-controller"},
        "switches": switches,
        "links": links,
        "hosts": [{"switch_id": "1", "port_id": "1", "mac": "02:00:00:00:00:01"}],
        "link_events": [],
    }


def test_targets_are_derived_from_live_ring4_telemetry():
    telemetry = ring4_snapshot()
    primary = resolve_fault_target("trunk_down", telemetry)
    standby = resolve_fault_target("link_flapping", telemetry)
    flow = resolve_fault_target("flow_drift", telemetry)
    mac = resolve_fault_target("mac_flooding", telemetry)

    assert primary["role"] == "primary"
    assert primary["endpoint"]["bridge"] in {"s1", "s2", "s3", "s4"}
    assert standby["role"] == "standby"
    assert standby["endpoint"]["interface"].startswith("s")
    assert flow["kind"] == "flow_table"
    assert flow["bridge"] in {"s1", "s2", "s3", "s4"}
    assert mac["endpoint"]["switch_id"] == "1"
    assert mac["endpoint"]["port_id"] == "1"


def test_redundant_restore_uses_stp_blocked_standby_link_from_live_telemetry():
    telemetry = ring4_snapshot()
    target = resolve_fault_target("redundant_trunk_restored", telemetry)
    assert target["kind"] == "restorable_link"
    assert target["role"] == "standby"
    assert {item["switch_id"] for item in target["endpoints"]} == {"3", "4"}


def test_target_resolution_rejects_fixture_or_stale_telemetry():
    telemetry = ring4_snapshot()
    telemetry["provenance"] = {"source": "test_fixture"}
    with pytest.raises(TargetResolutionError):
        resolve_fault_target("trunk_down", telemetry)

    telemetry = ring4_snapshot()
    telemetry["updated_at_utc"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    with pytest.raises(TargetResolutionError):
        resolve_fault_target("trunk_down", telemetry)


def test_target_resolution_fails_closed_when_target_is_not_in_telemetry():
    telemetry = ring4_snapshot()
    telemetry["hosts"] = []
    with pytest.raises(TargetResolutionError):
        resolve_fault_target("mac_flooding", telemetry)


def test_trunk_down_detector_uses_recent_deleted_link_and_physical_port_state():
    from netops_guardrail.faults.trunk_down import TrunkDownFault
    telemetry = ring4_snapshot()
    now = datetime.now(timezone.utc)
    telemetry["links"] = [
        link for link in telemetry["links"]
        if not (link["src_switch"] == "1" and link["src_port"] == "3")
    ]
    telemetry["switches"]["1"]["port_status"]["3"]["state"] = "DOWN"
    telemetry["link_events"] = [{
        "timestamp_utc": telemetry["updated_at_utc"], "event": "DELETE",
        "src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "1",
    }]
    result = TrunkDownFault().detector(telemetry)
    assert result["detected"] is True
    assert result["failed_links"][0]["endpoints"][0]["switch_id"] == "1"


def test_redundant_trunk_detector_recognizes_ring4_without_fixed_ports():
    from netops_guardrail.faults.redundant_trunk import RedundantTrunkRestoredFault
    result = RedundantTrunkRestoredFault().detector(ring4_snapshot())
    assert result["detected"] is True
    assert result["prerequisites"]["standby_endpoint_stp_blocked"] is True
