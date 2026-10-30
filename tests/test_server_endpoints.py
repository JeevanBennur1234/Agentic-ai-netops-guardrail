import json
import os
import pytest
from netops_guardrail.observability.server import create_metrics_app


@pytest.fixture
def app_and_client(tmp_path):
    telemetry_file = tmp_path / "telemetry.json"
    telemetry_data = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "switches": {
            "1": {
                "ports": {
                    "1": {"rx_packets": 10, "tx_packets": 20, "rx_bytes": 100, "tx_bytes": 200},
                    "2": {"rx_packets": 5, "tx_packets": 5, "rx_bytes": 50, "tx_bytes": 50},
                },
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD"},
                "flows": [],
            }
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"}
        ],
    }
    telemetry_file.write_text(json.dumps(telemetry_data), encoding="utf-8")

    audit_file = tmp_path / "audit_log.json"
    audit_data = [
        {
            "index": 0,
            "decision": "APPROVED",
            "intent": {"action": "no_action", "reason": "nominal"},
            "verifier_result": {"safe": True, "checks": ["PASS"]},
            "execution_result": {"success": True},
            "previous_hash": "0" * 64,
            "current_hash": "a" * 64,
            "signature": "sig0",
            "timestamp": "2026-10-28T00:00:00+00:00",
        }
    ]
    audit_file.write_text(json.dumps(audit_data), encoding="utf-8")

    trace_file = tmp_path / "pipeline_trace.jsonl"
    trace_record = {
        "event_type": "decision",
        "timestamp": "2026-10-28T00:00:00+00:00",
        "decision": "APPROVED",
        "intent": {"action": "no_action"},
        "verification": {"safe": True},
    }
    trace_file.write_text(json.dumps(trace_record) + "\n", encoding="utf-8")

    approval_file = tmp_path / "human_approvals.json"
    approval_file.write_text("{}", encoding="utf-8")

    app = create_metrics_app(
        telemetry_path=str(telemetry_file),
        audit_log_path=str(audit_file),
        trace_log_path=str(trace_file),
        approval_path=str(approval_file),
    )
    return app, app.test_client()


def test_endpoint_dashboard(app_and_client):
    _, client = app_and_client
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "text/html" in res.content_type


def test_endpoint_simulate_scenarios(app_and_client):
    _, client = app_and_client
    # Scenario: normal
    res = client.get("/api/simulate?scenario=normal")
    assert res.status_code == 200
    data = res.get_json()
    assert data["scenario"] == "normal"
    assert "intent" in data
    assert "verification" in data
    assert "decision" in data
    assert "audit_record" in data

    # Scenario: unsafe_block
    res = client.get("/api/simulate?scenario=unsafe_block")
    assert res.status_code == 200
    data = res.get_json()
    assert data["scenario"] == "unsafe_block"

    # Scenario: injection
    res = client.get("/api/simulate?scenario=injection")
    assert res.status_code == 200
    data = res.get_json()
    assert data["scenario"] == "injection"


def test_endpoint_topology(app_and_client):
    _, client = app_and_client
    res = client.get("/api/topology")
    assert res.status_code == 200
    data = res.get_json()
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


def test_endpoint_pipeline_trace(app_and_client):
    _, client = app_and_client
    res = client.get("/api/pipeline/trace?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["decision"] == "APPROVED"


def test_endpoint_audit_chain(app_and_client):
    _, client = app_and_client
    res = client.get("/api/audit/chain?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) == 1
    item = data[0]
    assert item["index"] == 0
    assert item["decision"] == "APPROVED"
    assert item["action"] == "no_action"
    assert "current_hash" in item
    assert "timestamp" in item


def test_endpoint_root_json_and_html(app_and_client):
    _, client = app_and_client
    # JSON default
    res = client.get("/")
    assert res.status_code == 200
    assert res.is_json
    data = res.get_json()
    assert "name" in data
    assert "endpoints" in data
    assert len(data["endpoints"]) == 15

    # HTML when browser requests it
    res = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert res.status_code == 200
    assert "text/html" in res.content_type
