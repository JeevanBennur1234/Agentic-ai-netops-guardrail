import json

from netops_guardrail.agent import remediation_agent as agent


def test_nonexistent_evidence_reference_fails_closed(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {"1": {"ports": {"1": {}}, "flows": [],
                           "stp_port_states": {}, "port_status": {"1": {"state": "DOWN"}}}},
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return json.dumps({"response": json.dumps({
                "action": "no_action", "reason": "untrusted ref",
                "confidence": 0.5, "evidence_refs": ["not-a-real-evidence-id"],
            })}).encode()
    monkeypatch.setattr(agent.urllib.request, "urlopen", lambda *a, **k: Response())
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "link_failure", "source": "live_telemetry",
        "evidence_id": "real-evidence-id", "evidence": {"failed_ports": [{"switch_id": "1"}]},
    })
    assert result["action"] == "no_action"
    assert "does not exist" in result["reason"]


def test_flow_drift_cannot_create_port_block_intent(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {"1": {"ports": {"1": {}}, "flows": [],
                           "stp_port_states": {}, "port_status": {}}},
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    called = []
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "flow_rule_drift", "source": "live_telemetry",
        "evidence_id": "flow-evidence", "evidence": {"marker_cookie": "0x4e45544f5053"},
    })
    assert result["action"] == "no_action"
    assert called == []
