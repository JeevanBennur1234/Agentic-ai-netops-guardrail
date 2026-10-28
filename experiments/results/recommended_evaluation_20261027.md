# Recommended Work Evaluation - 2026-10-27

## Labelled safety cases

- Cases: 12 (3 safe; 9 unsafe)
- Correct: 12 / 12
- False accepts: 0 / 9 (0.0%)
- False rejects: 0 / 3 (0.0%)

Manually labelled synthetic cases only; not a representative dataset or a measurement of LLM decision quality.

## Executor transaction benchmark

- Repetitions: 30
- Mean: 0.277 ms; median: 0.221 ms; p95: 0.38 ms
- Successful simulated transactions: 30 / 30
- Host OVS modified: no
- Live connectivity measured: no

Current RemediationExecutor logic with an in-memory command runner: preflight, paired adds, cookie verification, topology post-check, and a stub connectivity callback.

Software-path timing only; not real OVS latency or proof of live data-plane recovery.

## Fresh live integration evidence

- Two-switch topology/STP baseline: PASS; baseline pingall loss 0.0%.
- Paired trunk-remediation test: PASS; both rules verified, live connectivity remained at 0.0% loss, access-port block rejected, audit chain verified.
- Active-trunk safety decision: PASS; gate and executor both rejected an active-trunk block when the alternate was STP-blocked, with no flow-table changes and no connectivity loss.
- Active-route administrative-down experiment: FAILOVER_FAILED_ROLLBACK_PASS; post-failure ping loss reached 100.0%, then re-enabling the original trunk restored 0.0% loss in about 0.014 seconds.
- The admin-down experiments are not physical cable-unplug tests. Automatic physical-link failover remains unproven.

The JSON report embeds the full live-test reports. Rollback success is reported separately and is not counted as failover success.

## Reproduce

Run python3 experiments/evaluate_guardrail_cases.py from the project root. The synthetic evaluator does not modify host OVS.
