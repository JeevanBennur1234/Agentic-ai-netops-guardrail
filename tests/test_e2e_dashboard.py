import json
from datetime import datetime, timezone

from netops_guardrail.observability.server import create_metrics_app


def test_dashboard_and_status_api_expose_live_telemetry_and_incidents(tmp_path):
    telemetry_path = tmp_path / "latest.json"
    telemetry_path.write_text(json.dumps({
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {
            "1": {"ports": {"1": {"rx_packets": 1}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD"}, "port_status": {"1": {"state": "UP"}}},
            "2": {"ports": {"1": {"rx_packets": 2}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD"}, "port_status": {"1": {"state": "UP"}}},
            "3": {"ports": {}, "flows": [], "stp_port_states": {}, "port_status": {}},
        },
        "links": [{"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "2"}],
        "mac_learning_events": [
            {"timestamp_utc": "2026-11-15T10:00:00+00:00", "switch_id": "1",
             "source_mac": "aa:bb:cc:dd:ee:ff", "port_id": "1"},
            {"timestamp_utc": "2026-11-15T10:00:01+00:00", "switch_id": "1",
             "source_mac": "aa:bb:cc:dd:ee:ff", "port_id": "2"},
        ],
    }), encoding="utf-8")
    audit_path = tmp_path / "audit.json"
    incidents_path = tmp_path / "incidents.json"
    incidents_path.write_text(json.dumps([{
        "incident_id": "inc-test", "type": "link_failure", "source": "simulation",
        "evidence_id": "evidence-1", "state": "DETECTED", "execution_allowed": False,
        "ai_call_allowed": False, "stages": {"deterministic": "DETECTED", "ai": "NOT_STARTED"},
    }]), encoding="utf-8")
    app = create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(audit_path),
    )
    app.config["NETOPS_INCIDENT_PATH"] = str(incidents_path)
    client = app.test_client()

    status = client.get("/api/status")
    assert status.status_code == 200
    payload = status.get_json()
    assert len(payload["telemetry"]["switches"]) == 3
    assert len(payload["telemetry"]["hosts"]) == 1
    assert payload["telemetry"]["hosts"][0]["switch_id"] == "1"
    assert payload["telemetry"]["hosts"][0]["port_id"] == "1"
    assert payload["incidents"][0]["source"] == "simulation"
    assert payload["incidents"][0]["execution_allowed"] is False

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert b"Continuous Incident Monitor" in dashboard.data
    assert b"topology-freshness" in dashboard.data


def test_deleted_trunk_ports_are_not_reported_as_discovered_hosts(tmp_path):
    telemetry_path = tmp_path / "latest.json"
    telemetry_path.write_text(json.dumps({
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {
            "1": {"ports": {"1": {}, "2": {}}, "flows": [],
                  "stp_port_states": {}, "port_status": {}},
            "2": {"ports": {"1": {}, "2": {}}, "flows": [],
                  "stp_port_states": {}, "port_status": {}},
        },
        "links": [],
        "link_events": [
            {"event": "ADD", "src_switch": "1", "src_port": "2",
             "dst_switch": "2", "dst_port": "1"},
            {"event": "DELETE", "src_switch": "1", "src_port": "2",
             "dst_switch": "2", "dst_port": "1"},
        ],
        "mac_learning_events": [
            {"timestamp_utc": "2026-11-15T10:00:00+00:00", "switch_id": "1",
             "source_mac": "aa:bb:cc:dd:ee:01", "port_id": "1"},
            {"timestamp_utc": "2026-11-15T10:00:01+00:00", "switch_id": "2",
             "source_mac": "aa:bb:cc:dd:ee:01", "port_id": "1"},
            {"timestamp_utc": "2026-11-15T10:00:02+00:00", "switch_id": "2",
             "source_mac": "aa:bb:cc:dd:ee:02", "port_id": "2"},
        ],
    }), encoding="utf-8")

    app = create_metrics_app(telemetry_path=str(telemetry_path))
    payload = app.test_client().get("/api/status").get_json()

    hosts = payload["telemetry"]["hosts"]
    assert [(host["switch_id"], host["port_id"], host["mac"]) for host in hosts] == [
        ("1", "1", "aa:bb:cc:dd:ee:01"),
        ("2", "2", "aa:bb:cc:dd:ee:02"),
    ]

    topology = app.test_client().get("/api/topology").get_json()
    inter_switch_edges = [
        edge for edge in topology["edges"]
        if edge["source"].startswith("s") and "-p" in edge["source"]
        and edge["target"].startswith("s") and "-p" in edge["target"]
    ]
    assert inter_switch_edges == []
