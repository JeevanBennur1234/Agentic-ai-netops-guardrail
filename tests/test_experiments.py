import os
import json
import pytest

from topologies import build_star_topology_data, build_redundant_topology_data
from experiment_suite import ExperimentSuite
from benchmark import PerformanceBenchmark


@pytest.fixture
def test_suite(tmp_path):
    work_dir = str(tmp_path / "exp_results")
    return ExperimentSuite(work_dir=work_dir)


def test_star_topology_generation():
    telemetry, graph = build_star_topology_data()
    assert "switches" in telemetry
    assert "1" in telemetry["switches"]
    assert "s1" in graph
    assert "s1-p1" in graph
    assert "s1-p2" in graph
    assert "s1-p3" in graph
    assert "s1-p4294967294" not in graph


def test_redundant_topology_generation():
    telemetry, graph, endpoints = build_redundant_topology_data()
    assert len(telemetry["switches"]) == 2
    assert "s1" in graph
    assert "s2" in graph
    # Check redundant trunk edges
    assert graph.has_edge("s1-p2", "s2-p1")
    assert graph.has_edge("s1-p3", "s2-p2")
    assert "s1-p1" in endpoints
    assert "s2-p3" in endpoints


def test_benchmark_stats_calculation():
    data = [10.0, 20.0, 30.0, 40.0, 50.0]
    stats = PerformanceBenchmark._calculate_stats(data)
    assert stats["count"] == 5
    assert stats["mean"] == 30.0
    assert stats["median"] == 30.0
    assert stats["min"] == 10.0
    assert stats["max"] == 50.0


def test_experiment_1_normal_operation(test_suite):
    res = test_suite.run_experiment_1_normal_operation()
    assert res["passed"] is True
    assert res["decision"] == "APPROVED"
    assert res["execution_success"] is True
    assert res["audit_chain_valid"] is True


def test_experiment_2_unsafe_remediation(test_suite):
    res = test_suite.run_experiment_2_unsafe_remediation()
    assert res["passed"] is True
    assert res["decision"] == "REJECTED"
    assert res["executor_blocked"] is True


def test_experiment_3_adversarial_intents(test_suite):
    res = test_suite.run_experiment_3_invalid_adversarial_intents()
    assert res["passed"] is True
    assert res["all_adversarial_rejected"] is True
    assert res["test_cases_count"] == 6


def test_experiment_5_audit_tamper_detection(test_suite):
    res = test_suite.run_experiment_5_audit_tamper_detection()
    assert res["passed"] is True
    assert res["all_attacks_detected"] is True
    assert res["attacks_evaluated"] == 6


def test_experiment_7_observability(test_suite):
    res = test_suite.run_experiment_7_observability()
    assert res["passed"] is True
    assert res["all_metrics_verified"] is True
