import json

import netops_guardrail.agent.remediation_agent as agent


def test_sanitize_telemetry_keeps_links_and_stp_evidence():
    telemetry = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "links": [{"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}],
        "switches": {
            "1": {"ports": {"1": {"rx_packets": 1}, "3": {"rx_packets": 2}},
                  "flows": [], "stp_port_states": {"1": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"2": {"rx_packets": 2}, "3": {"rx_packets": 1}},
                  "flows": [], "stp_port_states": {"2": "BLOCK", "3": "FORWARD"}},
        },
    }
    clean = agent.sanitize_telemetry(telemetry)
    assert clean["links"] == telemetry["links"]
    assert clean["switches"]["2"]["stp_port_states"]["2"] == "BLOCK"


def test_incident_context_produces_structured_ai_proposal(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"}},
        },
    }
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return json.dumps({"response": json.dumps({
                "action": "block", "target_switch": "1", "from_port": "3",
                "reason": "AI proposal based on the restored standby trunk and STP evidence.",
            })}).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    context = {
        "fault_type": "redundant_trunk_restored",
        "expected_target_switch": "1",
        "expected_from_port": "3",
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
    }
    result = agent.propose_remediation(str(path), incident_context=context)
    assert result["action"] == "block"
    assert result["target_switch"] == "1"
    assert result["from_port"] == "3"
    assert "CONTROLLED FAULT" in captured["payload"]["prompt"]
    assert "standby_has_stp_block" in captured["payload"]["prompt"]


def test_standby_forwarding_anomaly_simulation_is_labeled_honestly(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}}, "flows": [],
                  "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"}},
        },
    }
    path = tmp_path / "telemetry-issue2.json"
    path.write_text(json.dumps(telemetry), encoding="utf-8")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self):
            return json.dumps({"response": json.dumps({
                "action": "block", "target_switch": "1", "from_port": "3",
                "reason": "AI recommends isolating standby trunk for review.",
            })}).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    context = {
        "fault_type": "standby_forwarding_anomaly",
        "simulation_mode": True,
        "expected_target_switch": "1",
        "expected_from_port": "3",
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
    }
    result = agent.propose_remediation(str(path), incident_context=context)
    assert result["action"] == "block"
    assert result["target_switch"] == "1"
    assert result["from_port"] == "3"
    assert "CONTROLLED DEMO SIGNAL" in result["reason"]
    assert "does not confirm that both endpoints are forwarding" in result["reason"]
    assert "controlled simulation" in captured["payload"]["prompt"].lower()
