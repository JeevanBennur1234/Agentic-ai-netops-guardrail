import time
import json
import os
import sys
import statistics
import subprocess
import csv
from jsonschema import validate

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller", "executor", "observability", "experiments"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from safety_verifier import build_topology, run_safety_checks, test_port_removal
from decision_gate import apply_intent_to_graph
from remediation_executor import RemediationExecutor
from remediation_agent import INTENT_SCHEMA, propose_remediation
from audit_trail import AuditTrail
from topologies import build_star_topology_data


class PerformanceBenchmark:
    """
    Performance Benchmark Suite for Agentic AI-NetOps Guardrail.
    Measures empirical latencies (mean, median, p95, min, max) for every pipeline stage.
    """

    def __init__(self, work_dir=None):
        self.work_dir = work_dir or os.path.expanduser("~/netops_guardrail/experiments/results")
        os.makedirs(self.work_dir, exist_ok=True)

    @staticmethod
    def _calculate_stats(latencies_ms):
        if not latencies_ms:
            return {"count": 0, "mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
        sorted_l = sorted(latencies_ms)
        p95_idx = int(0.95 * len(sorted_l))
        p95_val = sorted_l[min(p95_idx, len(sorted_l) - 1)]
        return {
            "count": len(sorted_l),
            "mean": round(statistics.mean(sorted_l), 3),
            "median": round(statistics.median(sorted_l), 3),
            "p95": round(p95_val, 3),
            "min": round(min(sorted_l), 3),
            "max": round(max(sorted_l), 3)
        }

    def benchmark_schema_validation(self, reps=100):
        intent = {"action": "no_action", "reason": "Nominal telemetry"}
        times = []
        for _ in range(reps):
            t0 = time.perf_counter()
            validate(instance=intent, schema=INTENT_SCHEMA)
            times.append((time.perf_counter() - t0) * 1000)
        return self._calculate_stats(times)

    def benchmark_safety_verification(self, reps=100):
        _, graph = build_star_topology_data()
        times = []
        for _ in range(reps):
            t0 = time.perf_counter()
            run_safety_checks(graph)
            times.append((time.perf_counter() - t0) * 1000)
        return self._calculate_stats(times)

    def benchmark_decision_gate(self, reps=100):
        _, graph = build_star_topology_data()
        intent = {"action": "no_action", "reason": "Nominal check"}
        times = []
        for _ in range(reps):
            t0 = time.perf_counter()
            apply_intent_to_graph(graph, intent)
            times.append((time.perf_counter() - t0) * 1000)
        return self._calculate_stats(times)

    def benchmark_remediation_execution(self, reps=50):
        bridge_name = "s1"
        try:
            subprocess.run(["sudo", "ovs-vsctl", "add-br", bridge_name], check=False, capture_output=True)
        except Exception:
            pass

        telem_file = os.path.join(self.work_dir, "bench_telem.json")
        telem, _ = build_star_topology_data()
        with open(telem_file, "w") as f:
            json.dump(telem, f)

        executor = RemediationExecutor(telemetry_path=telem_file)
        intent = {"action": "block", "target_switch": "1", "from_port": "2", "reason": "Bench"}
        times = []

        for _ in range(reps):
            t0 = time.perf_counter()
            # Direct OVS command execution stage
            cmd = ["sudo", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", bridge_name, "priority=65500,in_port=2,actions=drop"]
            executor.cmd_runner(cmd)
            times.append((time.perf_counter() - t0) * 1000)

        try:
            subprocess.run(["sudo", "ovs-vsctl", "del-br", bridge_name], check=False, capture_output=True)
        except Exception:
            pass

        return self._calculate_stats(times)

    def benchmark_post_execution_verification(self, reps=50):
        bridge_name = "s1"
        try:
            subprocess.run(["sudo", "ovs-vsctl", "add-br", bridge_name], check=False, capture_output=True)
            subprocess.run(["sudo", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", bridge_name, "priority=65500,in_port=2,actions=drop"], check=False, capture_output=True)
        except Exception:
            pass

        telem_file = os.path.join(self.work_dir, "bench_telem.json")
        executor = RemediationExecutor(telemetry_path=telem_file)
        times = []

        for _ in range(reps):
            t0 = time.perf_counter()
            executor._verify_ovs_change(bridge_name, "in_port=2", "drop")
            executor._verify_topology_safety()
            times.append((time.perf_counter() - t0) * 1000)

        try:
            subprocess.run(["sudo", "ovs-vsctl", "del-br", bridge_name], check=False, capture_output=True)
        except Exception:
            pass

        return self._calculate_stats(times)

    def benchmark_cryptographic_audit(self, reps=100):
        log_file = os.path.join(self.work_dir, "bench_audit.json")
        key_file = os.path.join(self.work_dir, "bench_key.pem")
        trail = AuditTrail(log_path=log_file, key_path=key_file, auto_load=False)
        times = []

        for _ in range(reps):
            t0 = time.perf_counter()
            trail.record_decision(
                decision="APPROVED",
                intent={"action": "no_action"},
                verifier_result={"safe": True},
                execution_result={"success": True}
            )
            times.append((time.perf_counter() - t0) * 1000)

        return self._calculate_stats(times)

    def benchmark_agent_decision(self, reps=3):
        telem_file = os.path.expanduser("~/netops_guardrail/telemetry/data/latest.json")
        times = []
        for _ in range(reps):
            try:
                t0 = time.perf_counter()
                propose_remediation(telem_file)
                times.append((time.perf_counter() - t0) * 1000)
            except Exception:
                pass
        return self._calculate_stats(times)

    def run_all_benchmarks(self):
        """Run complete benchmark suite and return results."""
        results = {
            "schema_validation": self.benchmark_schema_validation(100),
            "safety_verification": self.benchmark_safety_verification(100),
            "decision_gate": self.benchmark_decision_gate(100),
            "ovs_execution": self.benchmark_remediation_execution(30),
            "post_execution_verification": self.benchmark_post_execution_verification(30),
            "cryptographic_audit": self.benchmark_cryptographic_audit(50),
            "agent_llm_decision": self.benchmark_agent_decision(3)
        }

        # Guardrail-only runtime (Deterministic pipeline without LLM inference)
        guardrail_runtime_mean = (
            results["schema_validation"]["mean"] +
            results["safety_verification"]["mean"] +
            results["decision_gate"]["mean"] +
            results["ovs_execution"]["mean"] +
            results["post_execution_verification"]["mean"] +
            results["cryptographic_audit"]["mean"]
        )
        results["guardrail_pipeline_latency"] = {
            "mean": round(guardrail_runtime_mean, 3),
            "description": "Total guardrail safety layer execution without LLM inference time"
        }

        # End-to-end total (including LLM)
        total_e2e_mean = guardrail_runtime_mean + results["agent_llm_decision"]["mean"]
        results["total_end_to_end_pipeline"] = {
            "mean": round(total_e2e_mean, 3),
            "description": "Full end-to-end pipeline: Telemetry -> Ollama LLM -> Schema -> Verifier -> Gate -> OVS -> Audit"
        }

        # Export CSV
        csv_file = os.path.join(self.work_dir, "performance_benchmark.csv")
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Component", "Count", "Mean (ms)", "Median (ms)", "P95 (ms)", "Min (ms)", "Max (ms)"])
            for comp, stats in results.items():
                if "count" in stats:
                    writer.writerow([
                        comp,
                        stats["count"],
                        stats["mean"],
                        stats["median"],
                        stats["p95"],
                        stats["min"],
                        stats["max"]
                    ])
                else:
                    writer.writerow([comp, "-", stats["mean"], "-", "-", "-", "-"])

        return results
