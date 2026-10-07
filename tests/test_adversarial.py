import json
import pytest
import networkx as nx
from jsonschema import validate, ValidationError

from safety_verifier import (
    build_topology,
    run_safety_checks,
    test_port_removal as sim_port_removal,
    check_topology_exists,
    check_connectivity,
    check_loop_freedom,
    check_reachability
)
from decision_gate import apply_intent_to_graph
from remediation_agent import (
    INTENT_SCHEMA,
    get_valid_physical_ports,
    sanitize_telemetry
)


@pytest.fixture
def base_telemetry():
    """Single switch s1 with physical ports 1, 2, 3 and LOCAL port 4294967294."""
    return {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0},
                    "1": {"rx_packets": 100, "tx_packets": 100, "rx_bytes": 1000, "tx_bytes": 1000},
                    "2": {"rx_packets": 100, "tx_packets": 100, "rx_bytes": 1000, "tx_bytes": 1000},
                    "3": {"rx_packets": 100, "tx_packets": 100, "rx_bytes": 1000, "tx_bytes": 1000}
                },
                "flows": []
            }
        }
    }


@pytest.fixture
def base_graph(base_telemetry):
    return build_topology(base_telemetry)


# ==============================================================================
# 1. MALFORMED JSON & SCHEMA VALIDATION TESTS
# ==============================================================================

class TestMalformedIntentsAndSchema:

    def test_missing_action_rejected(self):
        intent = {"reason": "Missing action"}
        with pytest.raises(ValidationError):
            validate(instance=intent, schema=INTENT_SCHEMA)

    def test_missing_reason_rejected(self):
        intent = {"action": "no_action"}
        with pytest.raises(ValidationError):
            validate(instance=intent, schema=INTENT_SCHEMA)

    def test_non_dict_payload_rejected(self):
        with pytest.raises(ValidationError):
            validate(instance=["action", "no_action"], schema=INTENT_SCHEMA)
        with pytest.raises(ValidationError):
            validate(instance="no_action", schema=INTENT_SCHEMA)
        with pytest.raises(ValidationError):
            validate(instance=12345, schema=INTENT_SCHEMA)

    def test_invalid_field_types_rejected(self):
        with pytest.raises(ValidationError):
            validate(instance={"action": 123, "reason": "numeric action"}, schema=INTENT_SCHEMA)
        with pytest.raises(ValidationError):
            validate(instance={"action": "block", "target_switch": 1, "reason": "integer switch"}, schema=INTENT_SCHEMA)
        with pytest.raises(ValidationError):
            validate(instance={"action": "block", "from_port": ["1"], "reason": "list port"}, schema=INTENT_SCHEMA)

    def test_empty_payload_rejected(self):
        with pytest.raises(ValidationError):
            validate(instance={}, schema=INTENT_SCHEMA)


# ==============================================================================
# 2. UNSUPPORTED ACTIONS TESTS
# ==============================================================================

class TestUnsupportedActions:

    @pytest.mark.parametrize("bad_action", [
        "drop_table",
        "reboot",
        "delete",
        "flood",
        "isolate",
        "shutdown",
        "BLOCK",       # Case sensitivity
        "REROUTE",
        "",            # Empty string
        "undefined"
    ])
    def test_unsupported_actions_rejected_by_schema(self, bad_action):
        intent = {"action": bad_action, "reason": "Testing unsupported action"}
        with pytest.raises(ValidationError):
            validate(instance=intent, schema=INTENT_SCHEMA)

    @pytest.mark.parametrize("bad_action", [
        "drop_table",
        "reboot",
        "delete",
        "isolate",
        "unknown"
    ])
    def test_unsupported_actions_rejected_by_decision_gate(self, base_graph, bad_action):
        intent = {"action": bad_action, "reason": "Testing bypass"}
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Unhandled action type" in res["reason"]


# ==============================================================================
# 3. INVALID SWITCHES TESTS
# ==============================================================================

class TestInvalidSwitches:

    @pytest.mark.parametrize("invalid_switch", [
        "99",
        "0",
        "-1",
        "switch_1",
        "sw1",
        "9999"
    ])
    def test_nonexistent_switch_rejected(self, base_graph, invalid_switch):
        intent = {
            "action": "block",
            "target_switch": invalid_switch,
            "from_port": "1",
            "reason": f"Targeting invalid switch {invalid_switch}"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert f"Port s{invalid_switch}-p1 does not exist" in res["reason"]

    def test_missing_switch_field_rejected(self, base_graph):
        intent = {
            "action": "block",
            "from_port": "1",
            "reason": "Missing target_switch"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Missing target_switch or from_port" in res["reason"]

    def test_empty_switch_string_rejected(self, base_graph):
        intent = {
            "action": "block",
            "target_switch": "",
            "from_port": "1",
            "reason": "Empty string switch"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Missing target_switch or from_port" in res["reason"]


# ==============================================================================
# 4. INVALID & OPENFLOW LOCAL PORTS TESTS
# ==============================================================================

class TestInvalidAndLocalPorts:

    def test_openflow_local_port_rejected_by_decision_gate(self, base_graph):
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "4294967294",
            "reason": "Attempting to block OpenFlow LOCAL port"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Port s1-p4294967294 does not exist" in res["reason"]

    @pytest.mark.parametrize("invalid_port", [
        "4294967040",  # OFPP_MAX
        "65535",       # OFPP_ALL
        "0",
        "-1",
        "99",
        "LOCAL",
        "local",
        "eth1",
        "port1"
    ])
    def test_invalid_ports_rejected(self, base_graph, invalid_port):
        intent = {
            "action": "reroute",
            "target_switch": "1",
            "from_port": invalid_port,
            "reason": f"Attempting to reroute invalid port {invalid_port}"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert f"Port s1-p{invalid_port} does not exist" in res["reason"]

    def test_missing_port_field_rejected(self, base_graph):
        intent = {
            "action": "reroute",
            "target_switch": "1",
            "reason": "Missing from_port"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Missing target_switch or from_port" in res["reason"]

    def test_empty_port_string_rejected(self, base_graph):
        intent = {
            "action": "reroute",
            "target_switch": "1",
            "from_port": "",
            "reason": "Empty string port"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "Missing target_switch or from_port" in res["reason"]


# ==============================================================================
# 5. UNSAFE AI INTENTS & INJECTION RESISTANCE TESTS
# ==============================================================================

class TestUnsafeAIIntents:

    @pytest.mark.parametrize("injection_payload", [
        "1; rm -rf /",
        "1 && reboot",
        "1 | cat /etc/passwd",
        "1`reboot`",
        "1$(shutdown -h now)"
    ])
    def test_command_injection_in_port_safely_rejected(self, base_graph, injection_payload):
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": injection_payload,
            "reason": "Injection test"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "does not exist" in res["reason"]

    @pytest.mark.parametrize("injection_payload", [
        "1; drop database",
        "1' OR '1'='1"
    ])
    def test_injection_in_switch_safely_rejected(self, base_graph, injection_payload):
        intent = {
            "action": "block",
            "target_switch": injection_payload,
            "from_port": "1",
            "reason": "Injection test"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is False
        assert "does not exist" in res["reason"]


# ==============================================================================
# 6. CONNECTIVITY-BREAKING REMEDIATION TESTS
# ==============================================================================

class TestConnectivityBreakingRemediation:

    def test_blocking_access_port_in_star_topology_rejected(self, base_graph):
        """
        In a single-switch star topology (s1 connected to s1-p1, s1-p2, s1-p3),
        blocking any access port severs that endpoint without an alternative route.
        The verifier must reject this as unsafe.
        """
        for port in ["1", "2", "3"]:
            intent = {
                "action": "block",
                "target_switch": "1",
                "from_port": port,
                "reason": f"Adversarial request to block active port {port}"
            }
            res = apply_intent_to_graph(base_graph, intent)
            assert res["safe"] is False, f"Port {port} removal should be rejected due to loss of endpoint reachability"
            assert any("FAIL" in check for check in res.get("checks", []))

    def test_blocking_bridge_link_in_two_switch_topology_rejected(self):
        """
        Two switches connected by a single link (bridge).
        s1 (ports 1, 2) and s2 (ports 1, 2).
        Inter-switch link: s1-p2 <-> s2-p1.
        Removing this bridge link partitions the network.
        """
        multi_telemetry = {
            "switches": {
                "1": {
                    "ports": {
                        "1": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100},
                        "2": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100}
                    },
                    "flows": []
                },
                "2": {
                    "ports": {
                        "1": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100},
                        "2": {"rx_packets": 10, "tx_packets": 10, "rx_bytes": 100, "tx_bytes": 100}
                    },
                    "flows": []
                }
            }
        }
        g = build_topology(multi_telemetry)
        # Connect the two switches via their trunk ports
        g.add_edge("s1-p2", "s2-p1")

        # Baseline: normal check passes
        assert check_connectivity(g)[0] is True

        # Now simulate removing s1-p2 (bridge port)
        intent = {
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "Sever the inter-switch trunk link"
        }
        res = apply_intent_to_graph(g, intent)
        assert res["safe"] is False, "Severing bridge link must be rejected"

    def test_redundant_topology_port_removal_permitted_if_connected(self):
        """
        If a topology has true redundancy (e.g. 2 parallel links between s1 and s2),
        removing one redundant link leaves all access endpoints reachable.
        """
        g = nx.Graph()
        g.add_nodes_from([
            ("s1", {"type": "switch"}),
            ("s2", {"type": "switch"}),
            ("s1-p1", {"type": "port"}),  # Access port host 1
            ("s1-p2", {"type": "port"}),  # Trunk 1
            ("s1-p3", {"type": "port"}),  # Trunk 2
            ("s2-p1", {"type": "port"}),  # Trunk 1 peer
            ("s2-p2", {"type": "port"}),  # Trunk 2 peer
            ("s2-p3", {"type": "port"})   # Access port host 2
        ])
        g.add_edges_from([
            ("s1", "s1-p1"), ("s1", "s1-p2"), ("s1", "s1-p3"),
            ("s2", "s2-p1"), ("s2", "s2-p2"), ("s2", "s2-p3"),
            ("s1-p2", "s2-p1"),  # Trunk link 1
            ("s1-p3", "s2-p2")   # Trunk link 2 (redundant)
        ])

        # Access endpoints that must remain connected
        access_endpoints = ["s1-p1", "s2-p3"]

        # Simulate removing redundant link port s1-p2
        sim_res = sim_port_removal(g, "s1-p2", required_hosts=access_endpoints)
        assert sim_res["safe"] is True, "Removing a redundant link while preserving endpoint reachability should pass"

    def test_benign_no_action_always_approved(self, base_graph):
        """A healthy network requesting no_action must always be approved."""
        intent = {
            "action": "no_action",
            "reason": "All metrics are nominal"
        }
        res = apply_intent_to_graph(base_graph, intent)
        assert res["safe"] is True
        assert res.get("decision") == "APPROVED" or res.get("safe") is True
