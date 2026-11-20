"""Verification tests for safety verifier and decision gate on 4-switch / 4-host ring topology.

Uses fixture telemetry captured directly from the live Ring4 Mininet + Ryu lab
(explicitly labeled as a captured fixture).
"""
from __future__ import annotations

import json

import pytest

from netops_guardrail.controller.decision_gate import apply_intent_to_graph
from netops_guardrail.netops_paths import NETOPS_HOME
from netops_guardrail.verifier.safety_verifier import (
    build_topology,
    check_loop_freedom,
    check_reachability,
    check_topology_exists,
    get_access_endpoints,
    run_safety_checks,
)
from netops_guardrail.verifier.safety_verifier import (
    test_port_removal as verify_port_removal,
)

FIXTURE_PATH = NETOPS_HOME / "tests" / "fixtures" / "ring4_live_telemetry_fixture.json"


@pytest.fixture
def ring4_live_fixture():
    """Load live-captured ring4 telemetry fixture (labeled as a captured fixture)."""
    assert FIXTURE_PATH.exists(), f"Captured live fixture missing at {FIXTURE_PATH}"
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "_fixture_metadata" in data, "Fixture must be labeled with _fixture_metadata"
    assert "captured_live_lab" in data["_fixture_metadata"].get("source", "")
    return data


def test_fixture_provenance_and_labeling(ring4_live_fixture):
    """Verify fixture is explicitly labeled as captured from live ring4 lab."""
    meta = ring4_live_fixture["_fixture_metadata"]
    assert meta["topology"] == "ring4"
    assert meta["switches"] == 4
    assert meta["hosts"] == 4
    assert meta["stp_blocked_port"] == "s4-p4"
    assert meta["pingall_loss_pct"] == 0.0


def test_ring4_forwarding_graph_connected_and_loop_free(ring4_live_fixture):
    """Verify 4-switch topology is connected and loop-free under STP."""
    graph = build_topology(ring4_live_fixture)
    assert graph.graph.get("stp_telemetry_present") is True

    # 1. Topology exists
    exists_ok, exists_msg = check_topology_exists(graph)
    assert exists_ok is True, f"Topology check failed: {exists_msg}"

    # 2. Loop-free under STP forwarding tree
    loop_ok, loop_msg = check_loop_freedom(graph)
    assert loop_ok is True, f"Loop freedom check failed: {loop_msg}"

    # 3. Access endpoints are all mutually reachable in forwarding graph
    access = get_access_endpoints(graph)
    assert access == ["s1-p1", "s1-p2", "s4-p1", "s4-p2"]

    # 4. Overall safety checks with required access endpoints
    safety_res = run_safety_checks(graph, required_hosts=access, require_loop_free=True)
    assert safety_res["safe"] is True, f"Safety checks failed: {safety_res}"


def test_ring4_all_four_hosts_mutually_reachable(ring4_live_fixture):
    """Verify all four hosts (h1..h4 across s1 and s4 access ports) are mutually reachable."""
    graph = build_topology(ring4_live_fixture)

    access_endpoints = get_access_endpoints(graph)
    expected_access = ["s1-p1", "s1-p2", "s4-p1", "s4-p2"]
    assert access_endpoints == expected_access, f"Expected {expected_access}, got {access_endpoints}"

    reach_ok, reach_msg = check_reachability(graph, required_hosts=access_endpoints)
    assert reach_ok is True, f"Reachability failed: {reach_msg}"


def test_ring4_block_on_stp_blocked_link_accepted_by_decision_gate(ring4_live_fixture):
    """Verify that blocking the already STP-blocked standby link (s4-p4) is accepted as safe."""
    graph = build_topology(ring4_live_fixture)

    # 1. Decision gate evaluation for block on s4-p4 (STP blocked endpoint)
    intent_s4_p4 = {"action": "block", "target_switch": "4", "from_port": "4"}
    verdict_s4_p4 = apply_intent_to_graph(graph, intent_s4_p4)
    assert verdict_s4_p4["safe"] is True, f"Block on STP-blocked port s4-p4 should be safe: {verdict_s4_p4}"

    # 2. Decision gate evaluation for block on s3-p2 (other end of standby link)
    intent_s3_p2 = {"action": "block", "target_switch": "3", "from_port": "2"}
    verdict_s3_p2 = apply_intent_to_graph(graph, intent_s3_p2)
    assert verdict_s3_p2["safe"] is True, f"Block on standby port s3-p2 should be safe: {verdict_s3_p2}"

    # 3. Direct verifier verify_port_removal check
    port_removal_res = verify_port_removal(graph, "s4-p4")
    assert port_removal_res["safe"] is True


@pytest.mark.parametrize("active_port,target_switch,from_port", [
    ("s1-p3", "1", "3"),  # active trunk s1-p3 <-> s2-p1
    ("s2-p1", "2", "1"),  # active trunk s1-p3 <-> s2-p1
    ("s2-p2", "2", "2"),  # active trunk s2-p2 <-> s4-p3
    ("s4-p3", "4", "3"),  # active trunk s2-p2 <-> s4-p3
    ("s1-p4", "1", "4"),  # active trunk s1-p4 <-> s3-p1
    ("s3-p1", "3", "1"),  # active trunk s1-p4 <-> s3-p1
])
def test_ring4_block_on_active_link_partitioning_rejected_by_decision_gate(
    ring4_live_fixture, active_port, target_switch, from_port
):
    """Verify that blocking an active forwarding trunk partitions the network and is rejected."""
    graph = build_topology(ring4_live_fixture)

    intent = {"action": "block", "target_switch": target_switch, "from_port": from_port}
    verdict = apply_intent_to_graph(graph, intent)
    assert verdict["safe"] is False, (
        f"Block on active trunk {active_port} must be rejected as unsafe (partitioning), got: {verdict}"
    )

    port_removal_res = verify_port_removal(graph, active_port)
    assert port_removal_res["safe"] is False
