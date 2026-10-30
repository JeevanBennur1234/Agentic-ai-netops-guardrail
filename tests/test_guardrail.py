import pytest
from jsonschema import ValidationError, validate

from netops_guardrail.agent.remediation_agent import (
    INTENT_SCHEMA,
    get_valid_physical_ports,
    sanitize_telemetry,
)
from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.verifier.safety_verifier import build_topology, run_safety_checks
from netops_guardrail.verifier.safety_verifier import test_port_removal as sim_port_removal


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


def _build_redundant_dual_trunk_graph():
    """Build the known 2-switch, dual-trunk topology (s1-p2<->s2-p1, s1-p3<->s2-p2)."""
    import networkx as nx
    graph = nx.Graph()
    graph.add_node("s1", type="switch")
    graph.add_node("s2", type="switch")
    for p in ["1", "2", "3"]:
        graph.add_node(f"s1-p{p}", type="port")
        graph.add_edge("s1", f"s1-p{p}")
        graph.add_node(f"s2-p{p}", type="port")
        graph.add_edge("s2", f"s2-p{p}")
    graph.add_edge("s1-p2", "s2-p1")
    graph.add_edge("s1-p3", "s2-p2")
    return graph


def test_redundant_topology_loop_detected_as_unsafe():
    # Build the known 2-switch, dual-trunk topology (s1-p2<->s2-p1,
    # s1-p3<->s2-p2) exactly as used in the live redundant-topology demo
    graph = _build_redundant_dual_trunk_graph()
    result = run_safety_checks(graph)
    assert result["safe"] is False
    assert any("Loop" in c and "FAIL" in c for c in result["checks"])


def test_no_action_rejected_when_loop_present():
    # Same topology, through the full decision_gate.py path
    graph = _build_redundant_dual_trunk_graph()
    intent = {"action": "no_action", "reason": "test"}
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is False
    assert any("Loop" in c and "FAIL" in c for c in result["checks"])


def test_decision_gate_fails_closed_on_reroute(sample_telemetry):
    graph = build_topology(sample_telemetry)
    intent = {
        "action": "reroute",
        "target_switch": "1",
        "from_port": "2",
        "to_port": "3",
        "reason": "reroute requires forwarding-aware verification"
    }
    result = apply_intent_to_graph(graph, intent)
    assert result["safe"] is False
    assert "Reroute is disabled" in result["reason"]


def _build_stp_aware_redundant_telemetry():
    counters = {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100}
    return {
        "switches": {
            "1": {
                "ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)},
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"},
                "flows": [],
            },
            "2": {
                "ports": {"1": dict(counters), "2": dict(counters), "3": dict(counters)},
                "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"},
                "flows": [],
            },
        },
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
    }


def test_stp_blocked_redundant_trunk_is_not_counted_as_live_path():
    telemetry = _build_stp_aware_redundant_telemetry()
    graph = build_topology(telemetry)

    # The physical edge remains available for discovering its peer, but it must
    # not be treated as a data-plane path when either endpoint is STP-blocked.
    assert graph.has_edge("s1-p3", "s2-p2")
    assert graph.edges["s1-p3", "s2-p2"]["forwarding"] is False

    active_trunk_block = sim_port_removal(graph, "s1-p2")
    assert active_trunk_block["safe"] is False
    assert any("disconnected" in message.lower() or "unreachable" in message.lower()
               for message in active_trunk_block.get("checks", []))

    already_blocked_trunk_block = sim_port_removal(graph, "s1-p3")
    assert already_blocked_trunk_block["safe"] is True


def test_incomplete_stp_state_fails_closed_for_alternate_path():
    telemetry = _build_stp_aware_redundant_telemetry()
    del telemetry["switches"]["2"]["stp_port_states"]["2"]
    graph = build_topology(telemetry)

    # Since STP telemetry exists but the alternate trunk's peer state is
    # unknown, it cannot be used as proof that the alternate path forwards.
    assert graph.edges["s1-p3", "s2-p2"]["forwarding"] is False
    result = sim_port_removal(graph, "s1-p2")
    assert result["safe"] is False


def test_gate_uses_stp_forwarding_state_for_block_decisions():
    graph = build_topology(_build_stp_aware_redundant_telemetry())
    active = apply_intent_to_graph(graph, {
        "action": "block", "target_switch": "1", "from_port": "2",
        "reason": "active trunk would disconnect hosts while alternate is STP-blocked",
    })
    standby = apply_intent_to_graph(graph, {
        "action": "block", "target_switch": "1", "from_port": "3",
        "reason": "standby trunk is already STP-blocked",
    })
    assert active["safe"] is False
    assert standby["safe"] is True


def test_openflow_port_down_status_removes_link_from_forwarding_graph():
    telemetry = _build_stp_aware_redundant_telemetry()
    telemetry["switches"]["1"]["port_status"] = {
        "2": {"state": "DOWN", "link_down": True, "admin_down": False, "reason": "MODIFY"}
    }
    graph = build_topology(telemetry)

    # Keep the physical edge for peer discovery, but never count a reported
    # down endpoint as a usable forwarding path even if stale STP telemetry says FORWARD.
    assert graph.has_edge("s1-p2", "s2-p1")
    assert graph.edges["s1-p2", "s2-p1"]["forwarding"] is False
    assert graph.edges["s1-p2", "s2-p1"]["src_port_status"] == "DOWN"
