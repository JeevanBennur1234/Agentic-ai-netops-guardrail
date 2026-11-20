import json

import netops_guardrail.agent.remediation_agent as agent


def test_sanitize_telemetry_keeps_links_and_stp_evidence():
    telemetry = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "links": [{"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"}],
        "switches": {
            "1": {
                "ports": {"1": {"rx_packets": 1}, "3": {"rx_packets": 2}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "3": "FORWARD"},
            },
            "2": {
                "ports": {"2": {"rx_packets": 2}, "3": {"rx_packets": 1}},
                "flows": [],
                "stp_port_states": {"2": "BLOCK", "3": "FORWARD"},
            },
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
            "1": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
            },
            "2": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
            },
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
            return json.dumps(
                {
                    "response": json.dumps(
                        {
                            "action": "block",
                            "target_switch": "1",
                            "from_port": "3",
                            "reason": "AI proposal based on telemetry.",
                            "confidence": 0.9,
                            "evidence_refs": [captured["evidence_id"]],
                        }
                    )
                }
            ).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        import re

        captured["payload"] = json.loads(req.data.decode("utf-8"))
        match = re.search(r'"evidence_id": "([a-f0-9]+)"', captured["payload"]["prompt"])
        captured["evidence_id"] = match.group(1) if match else ""
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
    assert "expected_target_switch" not in captured["payload"]["prompt"]


def test_standby_forwarding_anomaly_simulation_is_labeled_honestly(monkeypatch, tmp_path):
    telemetry = {
        "updated_at_utc": "2026-10-28T00:00:00+00:00",
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
            },
            "2": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
            },
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
            return json.dumps(
                {
                    "response": json.dumps(
                        {
                            "action": "block",
                            "target_switch": "1",
                            "from_port": "3",
                            "reason": "AI recommends review based on telemetry.",
                            "confidence": 0.9,
                            "evidence_refs": [captured["evidence_id"]],
                        }
                    )
                }
            ).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        import re

        captured["payload"] = json.loads(req.data.decode("utf-8"))
        match = re.search(r'"evidence_id": "([a-f0-9]+)"', captured["payload"]["prompt"])
        captured["evidence_id"] = match.group(1) if match else ""
        return FakeResponse()

    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    context = {
        "fault_type": "standby_forwarding_anomaly",
        "source": "test_fixture",
        "expected_target_switch": "1",
        "expected_from_port": "3",
        "affected_link": {"endpoint_a": "s1-p3", "endpoint_b": "s2-p2"},
    }
    result = agent.propose_remediation(str(path), incident_context=context)
    assert result["action"] == "block"
    assert result["target_switch"] == "1"
    assert result["from_port"] == "3"
    assert result["evidence_refs"] == [captured["evidence_id"]]


def test_incident_prompt_uses_placeholders_and_never_hints_fault_action(monkeypatch, tmp_path):
    import io
    import json

    import netops_guardrail.agent.remediation_agent as agent

    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": "2026-11-17T00:00:00+00:00",
                "switches": {
                    "1": {
                        "ports": {"2": {"rx_packets": 1}, "3": {"rx_packets": 2}},
                        "flows": [],
                        "stp_port_states": {"2": "FORWARD", "3": "BLOCK"},
                        "port_status": {"2": {"state": "UP"}, "3": {"state": "DOWN"}},
                    }
                },
                "links": [],
            }
        ),
        encoding="utf-8",
    )

    captured = {}

    def fake_urlopen(request, timeout):
        payload = json.loads(request.data.decode("utf-8"))
        captured["prompt"] = payload["prompt"]
        response = {
            "response": json.dumps(
                {
                    "action": "no_action",
                    "reason": "The supplied evidence does not justify an executable change.",
                    "evidence_refs": ["evidence-fixture-1"],
                }
            )
        }
        return io.BytesIO(json.dumps(response).encode("utf-8"))

    monkeypatch.setattr(agent.urllib.request, "urlopen", fake_urlopen)
    agent.propose_remediation(
        str(telemetry_path),
        incident_context={
            "fault_type": "trunk_down",
            "source": "lab_injected_live",
            "evidence_id": "evidence-fixture-1",
            "evidence": {"detected": True},
        },
    )

    prompt = captured["prompt"]
    examples = prompt.split("JSON format examples:", 1)[1].split("Valid physical ports:", 1)[0]
    assert '"<switch id from evidence>"' in examples
    assert '"<port id from evidence>"' in examples
    assert '"confidence":' not in examples
    assert '"target_switch": "1"' not in examples
    assert '"from_port": "3"' not in examples
    assert "action for this incident" not in prompt.lower()
    assert "alternate active paths maintain end-to-end host reachability" in prompt
