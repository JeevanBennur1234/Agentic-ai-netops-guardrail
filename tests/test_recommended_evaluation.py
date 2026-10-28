from experiments.evaluate_guardrail_cases import (
    benchmark_executor_transaction,
    evaluate_cases,
)


def test_labelled_safety_evaluation_counts_false_accepts_and_rejects():
    result = evaluate_cases()
    assert result["case_count"] == 12
    assert result["correct_count"] == 12
    assert result["false_accept_count"] == 0
    assert result["false_reject_count"] == 0
    assert result["false_accept_rate"] == 0.0
    assert result["false_reject_rate"] == 0.0


def test_simulated_executor_benchmark_runs_full_transaction_without_real_ovs():
    result = benchmark_executor_transaction(repetitions=3)
    assert result["success_count"] == 3
    assert result["failure_count"] == 0
    assert result["real_ovs_commands_executed"] is False
    assert result["live_connectivity_tested"] is False
    assert result["stats"]["count"] == 3
