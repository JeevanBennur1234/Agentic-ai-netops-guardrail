import json
import pytest

from metrics import NetOpsMetricsCollector
from server import create_metrics_app
from audit_trail import AuditTrail


@pytest.fixture
def mock_telemetry(tmp_path):
    data = {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {
                        "rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0
                    },
                    "1": {
                        "rx_packets": 15, "tx_packets": 25, "rx_bytes": 1500, "tx_bytes": 2500
                    },
                    "2": {
                        "rx_packets": 30, "tx_packets": 40, "rx_bytes": 3000, "tx_bytes": 4000
                    }
                },
                "flows": [
                    {
                        "priority": 0,
                        "packet_count": 55,
                        "byte_count": 5500
                    }
                ]
            }
        }
    }
    p = tmp_path / "latest.json"
    p.write_text(json.dumps(data))
    return str(p)


@pytest.fixture
def mock_audit_log(tmp_path):
    key_path = str(tmp_path / "test_key.pem")
    log_path = str(tmp_path / "test_audit_log.json")
    trail = AuditTrail(log_path=log_path, key_path=key_path)

    # Record 1: APPROVED no_action
    trail.record_decision(
        decision="APPROVED",
        intent={"action": "no_action", "reason": "nominal"},
        verifier_result={"safe": True},
        execution_result={"success": True, "action": "no_action", "change_verified": True, "safety_verified": True}
    )

    # Record 2: REJECTED block
    trail.record_decision(
        decision="REJECTED",
        intent={"action": "block", "target_switch": "1", "from_port": "99", "reason": "bad port"},
        verifier_result={"safe": False, "reason": "Port s1-p99 does not exist"}
    )

    return log_path


def get_samples_by_name(collector):
    """Helper to index all emitted samples by their exact sample name."""
    samples = {}
    for family in collector.collect():
        for s in family.samples:
            samples.setdefault(s.name, []).append(s)
    return samples


class TestObservabilityMetrics:

    def test_endpoint_health(self):
        app = create_metrics_app()
        client = app.test_client()
        res = client.get("/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["read_only"] is True

    def test_endpoint_metrics_format(self, mock_telemetry, mock_audit_log):
        app = create_metrics_app(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        client = app.test_client()
        res = client.get("/metrics")
        assert res.status_code == 200
        assert "text/plain" in res.content_type
        content = res.get_data(as_text=True)
        assert "# HELP netops_switches_total" in content
        assert "netops_switches_total 1.0" in content

    def test_network_telemetry_metrics(self, mock_telemetry, mock_audit_log):
        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        samples = get_samples_by_name(collector)

        # Switches & Ports
        assert samples["netops_switches_total"][0].value == 1.0
        assert samples["netops_active_physical_ports"][0].value == 2.0

        # Port counters
        rx_samples = {
            (s.labels["switch"], s.labels["port"]): s.value
            for s in samples["netops_port_rx_packets"]
        }
        assert rx_samples[("1", "1")] == 15.0
        assert rx_samples[("1", "2")] == 30.0

        # Flow counters
        flow_samples = {
            (s.labels["switch"], s.labels["priority"]): s.value
            for s in samples["netops_flow_packets"]
        }
        assert flow_samples[("1", "0")] == 55.0

    def test_local_port_excluded_from_metrics(self, mock_telemetry, mock_audit_log):
        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        samples = get_samples_by_name(collector)

        port_samples = samples["netops_port_rx_packets"]
        for s in port_samples:
            assert s.labels["port"] != "4294967294"

    def test_guardrail_decisions_metrics(self, mock_telemetry, mock_audit_log):
        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        samples = get_samples_by_name(collector)

        assert samples["netops_guardrail_ai_decisions_total"][0].value == 2.0
        assert samples["netops_guardrail_approved_total"][0].value == 1.0
        assert samples["netops_guardrail_rejected_total"][0].value == 1.0
        assert samples["netops_guardrail_verifier_failures_total"][0].value == 1.0

        dec_samples = {
            (s.labels["decision"], s.labels["action"]): s.value
            for s in samples["netops_guardrail_decisions_total"]
        }
        assert dec_samples[("APPROVED", "no_action")] == 1.0
        assert dec_samples[("REJECTED", "block")] == 1.0

    def test_remediation_execution_metrics(self, mock_telemetry, mock_audit_log):
        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        samples = get_samples_by_name(collector)

        assert samples["netops_remediation_attempts_total"][0].value == 1.0
        assert samples["netops_remediation_success_total"][0].value == 1.0
        assert samples["netops_remediation_post_verification_failures_total"][0].value == 0.0

    def test_audit_chain_valid_metric(self, mock_telemetry, mock_audit_log):
        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        samples = get_samples_by_name(collector)

        assert samples["netops_audit_records_total"][0].value == 2.0
        assert samples["netops_audit_chain_valid"][0].value == 1.0
        assert samples["netops_audit_verification_failures_total"][0].value == 0.0

    def test_audit_chain_tampered_metric(self, tmp_path, mock_telemetry):
        # Create a tampered audit log
        log_path = str(tmp_path / "tampered_log.json")
        key_path = str(tmp_path / "test_key.pem")
        trail = AuditTrail(log_path=log_path, key_path=key_path)
        trail.record_decision("APPROVED", {"action": "no_action"}, {"safe": True})
        trail.record_decision("APPROVED", {"action": "no_action"}, {"safe": True})

        # Tamper the file
        with open(log_path, "r") as f:
            chain = json.load(f)
        chain[1]["current_hash"] = "deadbeef" * 8
        with open(log_path, "w") as f:
            json.dump(chain, f)

        collector = NetOpsMetricsCollector(telemetry_path=mock_telemetry, audit_log_path=log_path)
        samples = get_samples_by_name(collector)

        assert samples["netops_audit_chain_valid"][0].value == 0.0
        assert samples["netops_audit_verification_failures_total"][0].value == 1.0

    def test_missing_telemetry_handled_gracefully(self, tmp_path):
        nonexistent = str(tmp_path / "nonexistent.json")
        collector = NetOpsMetricsCollector(telemetry_path=nonexistent, audit_log_path=nonexistent)
        samples = get_samples_by_name(collector)

        assert samples["netops_switches_total"][0].value == 0.0
        assert samples["netops_audit_records_total"][0].value == 0.0
        assert samples["netops_audit_chain_valid"][0].value == 1.0

    def test_metrics_json_summary_endpoint(self, mock_telemetry, mock_audit_log):
        app = create_metrics_app(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        client = app.test_client()
        res = client.get("/metrics/json")
        assert res.status_code == 200
        summary = res.get_json()

        assert summary["network"]["switches_count"] == 1
        assert summary["guardrail"]["total_decisions"] == 2
        assert summary["guardrail"]["approved"] == 1
        assert summary["guardrail"]["rejected"] == 1
        assert summary["audit"]["chain_valid"] is True

    def test_observability_read_only_invariant(self, mock_telemetry, mock_audit_log):
        # Scrape 10 times and verify underlying files remain completely byte-for-byte identical
        with open(mock_telemetry, "rb") as f:
            orig_telem = f.read()
        with open(mock_audit_log, "rb") as f:
            orig_audit = f.read()

        app = create_metrics_app(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        client = app.test_client()
        for _ in range(10):
            res = client.get("/metrics")
            assert res.status_code == 200

        with open(mock_telemetry, "rb") as f:
            assert f.read() == orig_telem
        with open(mock_audit_log, "rb") as f:
            assert f.read() == orig_audit

    def test_index_endpoint(self):
        app = create_metrics_app()
        client = app.test_client()
        res = client.get("/")
        assert res.status_code == 200
        data = res.get_json()
        assert "endpoints" in data
        assert "/metrics" in data["endpoints"]

    def test_grafana_dashboard_schema(self):
        import os
        dashboard_path = os.path.expanduser(
            "~/netops_guardrail/observability/grafana/netops_guardrail_dashboard.json"
        )
        assert os.path.exists(dashboard_path)
        with open(dashboard_path, "r") as f:
            dash = json.load(f)
        assert dash["title"] == "Agentic AI-NetOps Guardrail Overview"
        assert len(dash["panels"]) >= 10
        # Check required panels exist
        panel_titles = [p.get("title") for p in dash["panels"]]
        assert "Active OpenFlow Switches" in panel_titles
        assert "Cryptographic Audit Chain Integrity" in panel_titles
        assert "Port RX / TX Packet Rates" in panel_titles
        assert "Safety Gate Verdicts" in panel_titles
        assert "Total Signed Audit Records" in panel_titles
