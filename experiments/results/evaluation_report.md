# Milestone 5: Experimental Evaluation and Benchmarking Report

**Evaluation Timestamp**: 2026-10-07T14:15:49.719900+00:00  
**Overall Status**: **PASS**

---

## 1. Executive Summary
This evaluation proves the actual safety, operational performance, and cryptographic properties of the **Agentic AI-NetOps Guardrail** system running against Mininet, Open vSwitch (OVS 2.17.12), and local Ollama (`qwen2.5-coder:1.5b`).

- **Unsafe Actions Prevented**: 100% of reachability-violating and adversarial intents were blocked before network modification.
- **Safe Remediation Verified**: Redundant trunk isolation executed safely and verified inside active OVS flow tables.
- **Cryptographic Tamper Detection**: 100% of tamper attempts (decision, intent, verifier result, execution result, hash chaining, and ECDSA signature) were caught.
- **Guardrail Runtime Overhead**: The entire formal guardrail safety verification and cryptographic audit layer executes in **31.927 ms**.

---

## 2. Experiment Results Matrix

| # | Experiment Name | Topology | Expected Outcome | Actual Outcome | Status |
|---|---|---|---|---|:---:|
| 1 | **Normal Operation** | Single-Switch Star (`s1`) | `no_action` approved, executed & signed | Approved, executed safely | **PASS** |
| 2 | **Unsafe Remediation** | Single-Switch Star (`s1`) | Access port block rejected; zero OVS changes | Rejected: reachability loss; executor blocked | **PASS** |
| 3 | **Adversarial Intents** | Star Topology (`s1`) | 6/6 invalid intents rejected before execution | 6/6 rejected (LOCAL port, nonexistent switch/port, injections) | **PASS** |
| 4 | **Safe Remediation** | Dual-Switch Redundant (`s1` <-> `s2`) | Redundant trunk blocked; OVS flow verified | Approved, executed & confirmed in active OVS table | **PASS** |
| 5 | **Tamper Detection** | Cryptographic Hash Chain | 6/6 tamper attacks caught by ECDSA / SHA3-256 | 6/6 detected (decision, intent, verifier, exec, hash, sig) | **PASS** |
| 6 | **Performance Benchmark** | Full Pipeline Testbed | Empirical latency measured across components | Mean guardrail latency: 31.927 ms | **PASS** |
| 7 | **Observability** | Prometheus Exporter | All decisions, executions & audit reflected | 100% metric families verified | **PASS** |

---

## 3. Performance Benchmark Latency Breakdown

| Pipeline Stage | Repetitions | Mean Latency (ms) | Median Latency (ms) | P95 Latency (ms) |
|---|:---:|:---:|:---:|:---:|
| **Schema Validation** | 100 | 1.799 ms | 1.551 ms | 2.731 ms |
| **Safety Verification** | 100 | 0.03 ms | 0.022 ms | 0.064 ms |
| **Decision Gate Logic** | 100 | 0.047 ms | 0.038 ms | 0.068 ms |
| **OVS Rule Execution** | 30 | 18.185 ms | 17.026 ms | 26.179 ms |
| **Post-Execution Verification** | 30 | 10.642 ms | 10.414 ms | 13.554 ms |
| **Cryptographic Audit (SHA3 + ECDSA)** | 50 | 1.224 ms | 1.119 ms | 2.129 ms |
| **Guardrail Subtotal (Deterministic)** | - | **31.927 ms** | - | - |
| **Ollama AI Agent (`qwen2.5-coder:1.5b`)** | 3 | 4648.231 ms | 807.65 ms | 12467.276 ms |
| **Total End-to-End Pipeline** | - | **4680.158 ms** | - | - |

---

## 4. Key Security & Operational Findings
1. **Zero Direct Network Access for LLM**: The AI model cannot touch OVS or Mininet directly; all changes must pass schema validation, graph reachability proofs, and decision gate authorization.
2. **Post-Execution Ground-Truth Verification**: The executor verifies that flow entries actually appear in `ovs-ofctl dump-flows`, preventing silent drop failures.
3. **Cryptographic Immutability**: Any tampering with audit trail decisions or execution records invalidates ECDSA signatures and SHA3-256 hash chaining.
