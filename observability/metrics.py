import json
import os
import sys

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for subdir in ["verifier", "audit", "agent", "controller", "executor"]:
    path = os.path.join(base_dir, subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from audit_trail import AuditTrail


DEFAULT_TELEMETRY_PATH = os.path.expanduser(
    "~/netops_guardrail/telemetry/data/latest.json"
)
DEFAULT_AUDIT_LOG_PATH = os.path.expanduser(
    "~/netops_guardrail/audit/audit_log.json"
)
LOCAL_PORT = "4294967294"
MAX_PHYSICAL_PORT = 4294967040


class NetOpsMetricsCollector:
    """
    Prometheus Metrics Collector for Agentic AI-NetOps Guardrail.
    
    Observes and exports:
    - Network telemetry (switches, physical ports, rx/tx packets, rx/tx bytes, flows)
    - Guardrail safety decisions (AI proposals, approvals, rejections, verifier failures)
    - Remediation execution outcomes (attempts, successes, failures, post-verification failures)
    - Cryptographic audit trail status (chain record count, cryptographic validity, verification failures)
    
    Guarantees:
    - Strictly READ-ONLY observability: cannot influence or modify network state or decisions.
    - Zero exposure of cryptographic private keys or sensitive credentials.
    """

    def __init__(self, telemetry_path=None, audit_log_path=None):
        self.telemetry_path = telemetry_path or DEFAULT_TELEMETRY_PATH
        self.audit_log_path = audit_log_path or DEFAULT_AUDIT_LOG_PATH

    def collect(self):
        # ==========================================================
        # 1. NETWORK TELEMETRY METRICS
        # ==========================================================
        sw_total = GaugeMetricFamily(
            "netops_switches_total",
            "Total number of active OpenFlow switches in the network."
        )
        active_ports = GaugeMetricFamily(
            "netops_active_physical_ports",
            "Number of active physical ports on switch (excluding OpenFlow LOCAL/reserved ports).",
            labels=["switch"]
        )
        rx_pkts = GaugeMetricFamily(
            "netops_port_rx_packets",
            "Received packet count on switch physical port.",
            labels=["switch", "port"]
        )
        tx_pkts = GaugeMetricFamily(
            "netops_port_tx_packets",
            "Transmitted packet count on switch physical port.",
            labels=["switch", "port"]
        )
        rx_bytes = GaugeMetricFamily(
            "netops_port_rx_bytes",
            "Received bytes on switch physical port.",
            labels=["switch", "port"]
        )
        tx_bytes = GaugeMetricFamily(
            "netops_port_tx_bytes",
            "Transmitted bytes on switch physical port.",
            labels=["switch", "port"]
        )
        active_flows = GaugeMetricFamily(
            "netops_active_flows_total",
            "Number of active flow table entries on switch.",
            labels=["switch"]
        )
        flow_pkts = GaugeMetricFamily(
            "netops_flow_packets",
            "Packet count matched by flow rule.",
            labels=["switch", "priority"]
        )
        flow_bytes = GaugeMetricFamily(
            "netops_flow_bytes",
            "Byte count matched by flow rule.",
            labels=["switch", "priority"]
        )

        telemetry = {}
        if os.path.exists(self.telemetry_path):
            try:
                with open(self.telemetry_path, "r") as f:
                    telemetry = json.load(f)
            except Exception:
                telemetry = {}

        switches = telemetry.get("switches", {})
        sw_total.add_metric([], float(len(switches)))

        for sw_id, sw_data in switches.items():
            ports = sw_data.get("ports", {})
            physical_count = 0
            for port_id, stats in ports.items():
                port_id_str = str(port_id).strip()
                # Exclude OpenFlow LOCAL and reserved ports
                if port_id_str == LOCAL_PORT:
                    continue
                if port_id_str.isdigit():
                    p_num = int(port_id_str)
                    if p_num <= 0 or p_num >= MAX_PHYSICAL_PORT:
                        continue

                physical_count += 1
                rx_pkts.add_metric([str(sw_id), port_id_str], float(stats.get("rx_packets", 0)))
                tx_pkts.add_metric([str(sw_id), port_id_str], float(stats.get("tx_packets", 0)))
                rx_bytes.add_metric([str(sw_id), port_id_str], float(stats.get("rx_bytes", 0)))
                tx_bytes.add_metric([str(sw_id), port_id_str], float(stats.get("tx_bytes", 0)))

            active_ports.add_metric([str(sw_id)], float(physical_count))

            flows = sw_data.get("flows", [])
            active_flows.add_metric([str(sw_id)], float(len(flows)))
            for flow in flows:
                prio = str(flow.get("priority", 0))
                flow_pkts.add_metric([str(sw_id), prio], float(flow.get("packet_count", 0)))
                flow_bytes.add_metric([str(sw_id), prio], float(flow.get("byte_count", 0)))

        yield sw_total
        yield active_ports
        yield rx_pkts
        yield tx_pkts
        yield rx_bytes
        yield tx_bytes
        yield active_flows
        yield flow_pkts
        yield flow_bytes

        # ==========================================================
        # 2. GUARDRAIL DECISION & AUDIT METRICS
        # ==========================================================
        ai_decisions_total = CounterMetricFamily(
            "netops_guardrail_ai_decisions_total",
            "Total AI remediation proposals evaluated by the safety guardrail."
        )
        decisions_total = CounterMetricFamily(
            "netops_guardrail_decisions_total",
            "Total guardrail decisions classified by verdict and action.",
            labels=["decision", "action"]
        )
        approved_total = CounterMetricFamily(
            "netops_guardrail_approved_total",
            "Total decisions APPROVED by the safety guardrail."
        )
        rejected_total = CounterMetricFamily(
            "netops_guardrail_rejected_total",
            "Total decisions REJECTED by the safety guardrail."
        )
        verifier_failures_total = CounterMetricFamily(
            "netops_guardrail_verifier_failures_total",
            "Total verifier safety check failures detected."
        )

        # ==========================================================
        # 3. REMEDIATION EXECUTION METRICS
        # ==========================================================
        rem_attempts = CounterMetricFamily(
            "netops_remediation_attempts_total",
            "Total remediation actions attempted by the executor.",
            labels=["action"]
        )
        rem_success = CounterMetricFamily(
            "netops_remediation_success_total",
            "Total remediation actions successfully executed and verified.",
            labels=["action"]
        )
        rem_failure = CounterMetricFamily(
            "netops_remediation_failure_total",
            "Total remediation actions failed during execution or validation.",
            labels=["action"]
        )
        post_verif_failures = CounterMetricFamily(
            "netops_remediation_post_verification_failures_total",
            "Total remediations that failed post-execution verification checks."
        )

        # ==========================================================
        # 4. CRYPTOGRAPHIC AUDIT METRICS
        # ==========================================================
        audit_records = GaugeMetricFamily(
            "netops_audit_records_total",
            "Total cryptographically signed records in the audit trail."
        )
        chain_valid = GaugeMetricFamily(
            "netops_audit_chain_valid",
            "Cryptographic hash chain validity (1 if intact and ECDSA signatures verified, 0 if tampered)."
        )
        audit_verif_failures = CounterMetricFamily(
            "netops_audit_verification_failures_total",
            "Total audit records failing cryptographic verification."
        )

        # Load and verify audit log
        chain = []
        if os.path.exists(self.audit_log_path):
            try:
                with open(self.audit_log_path, "r") as f:
                    chain = json.load(f)
            except Exception:
                chain = []

        audit_records.add_metric([], float(len(chain)))

        is_chain_valid = 1.0
        audit_fail_count = 0
        if chain:
            valid, msg = AuditTrail.verify_chain(chain)
            if not valid:
                is_chain_valid = 0.0
                audit_fail_count = 1

        chain_valid.add_metric([], is_chain_valid)
        audit_verif_failures.add_metric([], float(audit_fail_count))

        # Decision & Execution Aggregations
        ai_decisions_count = len(chain)
        ai_decisions_total.add_metric([], float(ai_decisions_count))

        appr_count = 0
        rej_count = 0
        verifier_fail_count = 0
        decision_action_counts = {}

        rem_att_counts = {}
        rem_succ_counts = {}
        rem_fail_counts = {}
        post_fail_count = 0

        for rec in chain:
            dec = rec.get("decision", "UNKNOWN")
            intent = rec.get("intent", {})
            act = intent.get("action", "unknown") if isinstance(intent, dict) else "unknown"

            if dec == "APPROVED":
                appr_count += 1
            elif dec == "REJECTED":
                rej_count += 1

            v_res = rec.get("verifier_result", {})
            if isinstance(v_res, dict) and not v_res.get("safe", False):
                verifier_fail_count += 1

            key = (dec, act)
            decision_action_counts[key] = decision_action_counts.get(key, 0) + 1

            exec_res = rec.get("execution_result")
            if exec_res:
                rem_att_counts[act] = rem_att_counts.get(act, 0) + 1
                if exec_res.get("success"):
                    rem_succ_counts[act] = rem_succ_counts.get(act, 0) + 1
                else:
                    rem_fail_counts[act] = rem_fail_counts.get(act, 0) + 1

                if not exec_res.get("change_verified") or not exec_res.get("safety_verified"):
                    post_fail_count += 1

        approved_total.add_metric([], float(appr_count))
        rejected_total.add_metric([], float(rej_count))
        verifier_failures_total.add_metric([], float(verifier_fail_count))

        for (dec, act), cnt in decision_action_counts.items():
            decisions_total.add_metric([dec, act], float(cnt))

        for act, cnt in rem_att_counts.items():
            rem_attempts.add_metric([act], float(cnt))
        for act, cnt in rem_succ_counts.items():
            rem_success.add_metric([act], float(cnt))
        for act, cnt in rem_fail_counts.items():
            rem_failure.add_metric([act], float(cnt))

        post_verif_failures.add_metric([], float(post_fail_count))

        yield ai_decisions_total
        yield decisions_total
        yield approved_total
        yield rejected_total
        yield verifier_failures_total
        yield rem_attempts
        yield rem_success
        yield rem_failure
        yield post_verif_failures
        yield audit_records
        yield chain_valid
        yield audit_verif_failures

    def get_summary_dict(self):
        """Return a structured dictionary of metrics for JSON inspection."""
        telemetry = {}
        if os.path.exists(self.telemetry_path):
            try:
                with open(self.telemetry_path, "r") as f:
                    telemetry = json.load(f)
            except Exception:
                telemetry = {}

        chain = []
        if os.path.exists(self.audit_log_path):
            try:
                with open(self.audit_log_path, "r") as f:
                    chain = json.load(f)
            except Exception:
                chain = []

        chain_valid, chain_msg = AuditTrail.verify_chain(chain) if chain else (True, "Empty chain")

        return {
            "network": {
                "switches_count": len(telemetry.get("switches", {})),
                "switches": list(telemetry.get("switches", {}).keys())
            },
            "guardrail": {
                "total_decisions": len(chain),
                "approved": sum(1 for r in chain if r.get("decision") == "APPROVED"),
                "rejected": sum(1 for r in chain if r.get("decision") == "REJECTED")
            },
            "audit": {
                "records_count": len(chain),
                "chain_valid": chain_valid,
                "chain_message": chain_msg
            }
        }
