import json
import os
import pytest

from safety_verifier import build_topology, run_safety_checks, test_port_removal as sim_port_removal
from decision_gate import apply_intent_to_graph
from remediation_agent import (
    get_valid_physical_ports,
    sanitize_telemetry,
    INTENT_SCHEMA
)
from jsonschema import validate, ValidationError


@pytest.fixture
def sample_telemetry():
    return {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {
                        "rx_packets": 0,
                        "tx_packets": 0,
                        "rx_bytes": 0,
                        "tx_bytes": 0
                    },
                    "1": {
                        "rx_packets": 20,
                        "tx_packets": 20,
                        "rx_bytes": 1000,
                        "tx_bytes": 1000
                    },
                    "2": {
                        "rx_packets": 20,
                        "tx_packets": 20,
                        "rx_bytes": 1000,
                        "tx_bytes": 1000
                    },
                    "3": {
                        "rx_packets": 20,
                        "tx_packets": 20,
                        "rx_bytes": 1000,
                        "tx_bytes": 1000
                    }
                },
                "flows": []
            }
        }
    }


def test_dynamic_port_derivation(sample_telemetry):
    valid_ports = get_valid_physical_ports(sample_telemetry)
    assert "1" in valid_ports
    # Must only contain physical ports 1, 2, 3
    assert valid_ports["1"] == ["1", "2", "3"]
    # OpenFlow LOCAL port 4294967294 must NOT be present
    assert "4294967294" not in valid_ports["1"]


def test_telemetry_sanitization(sample_telemetry):
    clean = sanitize_telemetry(sample_telemetry)
    ports = clean["switches"]["1"]["ports"]
    assert "4294967294" not in ports
    assert set(ports.keys()) == {"1", "2", "3"}


def test_topology_excludes_local_port(sample_telemetry):
    graph = build_topology(sample_telemetry)
    assert "s1" in graph
    assert "s1-p1" in graph
    assert "s1-p2" in graph
    assert "s1-p3" in graph
    assert "s1-p4294967294" not in graph


def test_sim_port_removal_nonexistent(sample_telemetry):
    graph = build_topology(sample_telemetry)
    res = sim_port_removal(graph, "s1-p4294967294")
    assert res["safe"] is False
    assert "Port s1-p4294967294 does not exist" in res["reason"]


def test_decision_gate_rejects_local_port(sample_telemetry):
    graph = build_topology(sample_telemetry)
    intent = {
        "action": "block",
        "target_switch": "1",
        "from_port": "4294967294",
        "reason": "Test proposal with local port"
    }
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is False
    assert "Port s1-p4294967294 does not exist" in result["reason"]


def test_decision_gate_rejects_nonexistent_port(sample_telemetry):
    graph = build_topology(sample_telemetry)
    intent = {
        "action": "reroute",
        "target_switch": "1",
        "from_port": "99",
        "reason": "Nonexistent port"
    }
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is False
    assert "Port s1-p99 does not exist" in result["reason"]


def test_decision_gate_rejects_missing_fields(sample_telemetry):
    graph = build_topology(sample_telemetry)
    intent = {
        "action": "block",
        "reason": "Missing target_switch and from_port"
    }
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is False


def test_decision_gate_approves_no_action(sample_telemetry):
    graph = build_topology(sample_telemetry)
    intent = {
        "action": "no_action",
        "reason": "Network healthy and balanced"
    }
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is True
    assert "PASS: All ports mutually reachable" in result["checks"]


def test_json_schema_validation():
    valid_intent = {
        "action": "no_action",
        "reason": "Traffic is normal"
    }
    validate(instance=valid_intent, schema=INTENT_SCHEMA)

    invalid_intent = {
        "action": "invalid_action",
        "reason": "Bad"
    }
    with pytest.raises(ValidationError):
        validate(instance=invalid_intent, schema=INTENT_SCHEMA)
