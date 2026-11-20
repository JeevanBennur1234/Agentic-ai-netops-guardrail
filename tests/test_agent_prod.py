import json

from netops_guardrail.agent import remediation_agent as agent


def test_link_failure_recovered_is_no_action(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {
            "1": {"ports": {"1": {}}, "flows": [], "stp_port_states": {},
                  "port_status": {"1": {"state": "UP"}}},
        },
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "link_failure", "source": "live_telemetry",
        "evidence_id": "evidence-link-1",
        "evidence": {"failed_ports": [{"switch_id": "1", "port_id": "1"}]},
    })
    assert result["action"] == "no_action"
    assert result["evidence_refs"] == ["evidence-link-1"]
    assert result["_agent_metadata"]["model_invoked"] is False
    assert result["_agent_metadata"]["status"] == "recovered_before_model"


def test_flow_rule_drift_is_explicitly_policy_skipped_without_ollama(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {"1": {"ports": {"1": {}}, "flows": [],
                           "stp_port_states": {}, "port_status": {}}},
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")

    def unexpected_model_call(*args, **kwargs):
        raise AssertionError("Flow drift policy path must not invoke Ollama")

    monkeypatch.setattr(agent.urllib.request, "urlopen", unexpected_model_call)
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "flow_rule_drift", "source": "live_telemetry",
        "evidence_id": "evidence-flow-1",
        "evidence": {"marker_cookie": "0xabc"},
    })

    assert result["action"] == "no_action"
    assert result["_agent_metadata"]["model_invoked"] is False
    assert result["_agent_metadata"]["status"] == "policy_no_action"


def test_topology_offline_is_non_remediable_without_model_call(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {"1": {"ports": {"1": {}}, "flows": [],
                           "stp_port_states": {}, "port_status": {"1": {"state": "MISSING"}}}},
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")

    def unexpected_model_call(*args, **kwargs):
        raise AssertionError("Offline topology must not invoke Ollama")

    monkeypatch.setattr(agent.urllib.request, "urlopen", unexpected_model_call)
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "topology_offline", "source": "live_telemetry",
        "evidence_id": "evidence-offline-1", "evidence": {"active_link_count": 0},
    })

    assert result["action"] == "no_action"
    assert result["_agent_metadata"]["model_invoked"] is False
    assert result["_agent_metadata"]["status"] == "skipped_topology_offline"


def test_incident_agent_uses_pipeline_evidence_id(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-11-15T10:00:00+00:00",
        "links": [],
        "switches": {"1": {"ports": {"1": {}}, "flows": [],
                           "stp_port_states": {}, "port_status": {"1": {"state": "DOWN"}}}},
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    captured = {}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return json.dumps({"response": json.dumps({
                "action": "no_action", "reason": "Insufficient evidence",
                "confidence": 0.7, "evidence_refs": ["trusted-evidence-42"],
            })}).encode()
    def fake_urlopen(req, timeout=0):
        captured["prompt"] = json.loads(req.data.decode())["prompt"]
        return Response()
    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    result = agent.propose_remediation(str(path), incident_context={
        "fault_type": "link_failure", "source": "live_telemetry",
        "evidence_id": "trusted-evidence-42",
        "evidence": {"failed_ports": [{"switch_id": "1", "port_id": "1"}]},
    })
    assert "trusted-evidence-42" in captured["prompt"]
    assert result["evidence_refs"] == ["trusted-evidence-42"]
    assert result["_agent_metadata"]["model_invoked"] is True
    assert result["_agent_metadata"]["status"] == "completed"
    assert result["_agent_metadata"]["model"] == agent.MODEL
    assert len(result["_agent_metadata"]["prompt_sha256"]) == 64
