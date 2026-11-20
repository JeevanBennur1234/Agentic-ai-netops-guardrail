import json
from datetime import datetime, timedelta, timezone

from netops_guardrail.controller.monitor import IncidentMonitor, detect_incidents


def snapshot():
    return {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {
            "1": {"ports": {}, "flows": [], "port_status": {}, "stp_port_states": {}},
            "2": {"ports": {}, "flows": [], "port_status": {}, "stp_port_states": {}},
        },
        "links": [],
        "link_events": [],
    }


def test_stale_telemetry_is_non_remediable():
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    found = detect_incidents({"updated_at_utc": old, "switches": {}})
    assert found[0]["type"] == "telemetry_stale"
    assert found[0]["execution_allowed"] is False
    assert found[0]["remediation_allowed"] is False


def test_monitor_debounces_and_deduplicates(tmp_path):
    monitor = IncidentMonitor(tmp_path, debounce_reads=2, cooldown_seconds=0)
    data = snapshot()
    data["switches"]["1"]["port_status"]["3"] = {"state": "DOWN"}
    assert monitor.process_snapshot(data) == []
    first = monitor.process_snapshot(data)
    assert len(first) == 1
    assert first[0]["type"] == "link_failure"
    assert monitor.process_snapshot(data) == []
    stored = json.loads((tmp_path / "incidents.json").read_text())
    assert len(stored) == 1


def test_monitor_provenance_is_pipeline_assigned(tmp_path):
    monitor = IncidentMonitor(tmp_path, debounce_reads=1)
    data = snapshot()
    data["switches"]["1"]["port_status"]["3"] = {"state": "DOWN"}
    emitted = monitor.process_snapshot(data)
    assert emitted[0]["source"] == "live_telemetry"
    assert "source" not in data


def test_monitor_has_no_execution_imports():
    from pathlib import Path
    source = Path(__import__("netops_guardrail.controller.monitor", fromlist=["x"]).__file__).read_text()
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "remediation_executor" not in source


def test_all_switch_ports_missing_is_non_remediable_topology_offline():
    now = datetime.now(timezone.utc)
    data = {
        "updated_at_utc": now.isoformat(),
        "links": [],
        "switches": {
            switch_id: {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "DISABLE", "2": "DISABLE", "3": "DISABLE"},
                "port_status": {
                    "1": {"state": "MISSING"},
                    "2": {"state": "MISSING"},
                    "3": {"state": "MISSING"},
                },
            }
            for switch_id in ("1", "2")
        },
    }

    detections = detect_incidents(data, now=now)

    assert [item["type"] for item in detections] == ["topology_offline"]
    assert detections[0]["execution_allowed"] is False
    assert detections[0]["remediation_allowed"] is False


def test_historical_delete_event_does_not_keep_link_failure_active():
    now = datetime.now(timezone.utc)
    data = {
        "updated_at_utc": now.isoformat(),
        "links": [],
        "link_events": [{
            "timestamp_utc": (now - timedelta(minutes=5)).isoformat(),
            "event": "DELETE",
            "src_switch": "1", "src_port": "2",
            "dst_switch": "2", "dst_port": "1",
        }],
        "switches": {
            switch_id: {
                "ports": {"1": {}, "2": {}, "3": {}},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
                "flows": [],
                "stp_port_states": {},
            }
            for switch_id in ("1", "2")
        },
    }

    assert detect_incidents(data, now=now) == []


def test_recent_delete_followed_by_add_is_not_a_current_link_failure():
    now = datetime.now(timezone.utc)
    data = {
        "updated_at_utc": now.isoformat(),
        "links": [],
        "link_events": [
            {
                "timestamp_utc": (now - timedelta(seconds=10)).isoformat(),
                "event": "DELETE",
                "src_switch": "1", "src_port": "2",
                "dst_switch": "2", "dst_port": "1",
            },
            {
                "timestamp_utc": (now - timedelta(seconds=5)).isoformat(),
                "event": "ADD",
                "src_switch": "1", "src_port": "2",
                "dst_switch": "2", "dst_port": "1",
            },
        ],
        "switches": {
            switch_id: {
                "ports": {"1": {}, "2": {}, "3": {}},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
                "flows": [],
                "stp_port_states": {},
            }
            for switch_id in ("1", "2")
        },
    }

    assert detect_incidents(data, now=now) == []


def test_recent_delete_event_is_detected_as_link_failure():
    now = datetime.now(timezone.utc)
    data = {
        "updated_at_utc": now.isoformat(),
        "links": [],
        "link_events": [{
            "timestamp_utc": (now - timedelta(seconds=5)).isoformat(),
            "event": "DELETE",
            "src_switch": "1", "src_port": "2",
            "dst_switch": "2", "dst_port": "1",
        }],
        "switches": {
            switch_id: {
                "ports": {"1": {}, "2": {}, "3": {}},
                "port_status": {
                    "1": {"state": "UP"},
                    "2": {"state": "UP"},
                    "3": {"state": "UP"},
                },
                "flows": [],
                "stp_port_states": {},
            }
            for switch_id in ("1", "2")
        },
    }

    detections = detect_incidents(data, now=now)
    assert [item["type"] for item in detections] == ["link_failure"]


def test_mac_flooding_detector_emits_live_evidence_for_ai_review():
    now = datetime.now(timezone.utc)
    data = {
        "updated_at_utc": now.isoformat(),
        "provenance": {"source": "live_telemetry"},
        "switches": {"1": {"ports": {"1": {}}, "flows": [], "port_status": {}}},
        "links": [],
        "mac_learning_events": [
            {
                "timestamp_utc": (now - timedelta(seconds=index)).isoformat(),
                "switch_id": "1",
                "port_id": "1",
                "source_mac": f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
            }
            for index in range(20)
        ],
    }

    detections = detect_incidents(data, now=now)

    assert [item["type"] for item in detections] == ["mac_flooding"]
    assert detections[0]["evidence"]["result"]["unique_mac_count"] == 20
    assert detections[0]["source"] == "live_telemetry"
    assert detections[0]["remediation_allowed"] is True


def test_mac_flooding_fixture_provenance_never_dispatches(tmp_path):
    now = datetime.now(timezone.utc)
    calls = []
    monitor = IncidentMonitor(
        tmp_path,
        debounce_reads=1,
        cooldown_seconds=0,
        decision_pipeline=lambda **kwargs: calls.append(kwargs) or {},
    )
    data = {
        "updated_at_utc": now.isoformat(),
        "provenance": {"source": "test_fixture"},
        "switches": {"1": {"ports": {"1": {}}, "flows": [], "port_status": {}}},
        "links": [],
        "mac_learning_events": [
            {
                "timestamp_utc": (now - timedelta(seconds=index)).isoformat(),
                "switch_id": "1",
                "port_id": "1",
                "source_mac": f"02:00:00:01:{index // 256:02x}:{index % 256:02x}",
            }
            for index in range(20)
        ],
    }

    emitted = monitor.process_snapshot(data, now=now)

    assert [item["type"] for item in emitted] == ["mac_flooding"]
    assert emitted[0]["remediation_allowed"] is False
    assert calls == []
