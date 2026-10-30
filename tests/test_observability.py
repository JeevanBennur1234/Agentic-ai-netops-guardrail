import json

import pytest

from netops_guardrail.audit.audit_trail import AuditTrail
from netops_guardrail.observability.metrics import NetOpsMetricsCollector
from netops_guardrail.observability.server import create_metrics_app


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

    def test_dashboard_status_uses_latest_human_decision(self):
        app = create_metrics_app()
        client = app.test_client()
        res = client.get("/dashboard")
        assert res.status_code == 200
        html = res.get_data(as_text=True)

        # The topology badge follows the newest proposal lifecycle event,
        # not a global list of any pending proposal or an unrelated guardrail event.
        assert "const lifecycleRecords = chronological.filter(item =>" in html
        assert "Boolean(approvalInfoForTrace(item).proposal_id)" in html
        assert "const activePending = chronological.filter" not in html
        assert "Proposal ID: ' + approval.proposal_id" in html
        assert "HUMAN APPROVAL: APPROVED · NOT EXECUTED" in html

    def test_grafana_dashboard_schema(self):
        from netops_guardrail.netops_paths import NETOPS_HOME

        dashboard_path = (
            NETOPS_HOME / "observability" / "grafana"
            / "netops_guardrail_dashboard.json"
        )
        assert dashboard_path.exists()
        with dashboard_path.open("r", encoding="utf-8") as f:
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


    def test_chaos_endpoint_disabled_without_token(self, monkeypatch, mock_telemetry, mock_audit_log):
        monkeypatch.delenv("NETOPS_CHAOS_API_TOKEN", raising=False)
        app = create_metrics_app(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        client = app.test_client()
        res = client.post("/api/chaos/inject-loop?confirm=true")
        assert res.status_code == 503
        assert "disabled" in res.get_json()["error"].lower()

    def test_chaos_endpoint_rejects_missing_or_invalid_token(self, monkeypatch, mock_telemetry, mock_audit_log):
        monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "test-only-secret-token")
        app = create_metrics_app(telemetry_path=mock_telemetry, audit_log_path=mock_audit_log)
        client = app.test_client()
        assert client.post("/api/chaos/inject-loop?confirm=true").status_code == 401
        assert client.post(
            "/api/chaos/inject-loop?confirm=true",
            headers={"Authorization": "Bearer wrong-token"}
        ).status_code == 401


def test_human_approval_api_requires_authenticated_operator(
    mock_telemetry, mock_audit_log, tmp_path, monkeypatch
):
    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", '{"netops-admin":"test-only-strong-token"}')
    app = create_metrics_app(
        telemetry_path=mock_telemetry,
        audit_log_path=mock_audit_log,
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "human-approvals.json"),
    )
    client = app.test_client()

    assert client.get("/approvals").status_code == 200
    assert client.get("/api/approvals").status_code == 401
    assert client.get("/api/approvals", headers={"Authorization": "Bearer wrong"}).status_code == 401
    authorized = client.get(
        "/api/approvals",
        headers={"Authorization": "Bearer test-only-strong-token"},
    )
    assert authorized.status_code == 200
    assert authorized.get_json()["authenticated_approver"] == "netops-admin"


def test_human_approval_api_is_disabled_without_server_tokens(
    mock_telemetry, mock_audit_log, tmp_path, monkeypatch
):
    monkeypatch.delenv("NETOPS_APPROVER_TOKENS", raising=False)
    app = create_metrics_app(
        telemetry_path=mock_telemetry,
        audit_log_path=mock_audit_log,
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "human-approvals.json"),
    )
    response = app.test_client().get("/api/approvals")
    assert response.status_code == 503
    assert "disabled" in response.get_json()["error"].lower()


def test_human_verifier_approval_is_audited_and_execute_fails_closed_without_checker(
    mock_telemetry, mock_audit_log, tmp_path, monkeypatch
):
    from datetime import datetime, timezone

    from netops_guardrail.controller.human_verifier import HumanApprovalStore

    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", '{"netops-admin":"test-only-strong-token"}')
    monkeypatch.delenv("NETOPS_CONNECTIVITY_CHECKER", raising=False)

    telemetry_data = json.loads(open(mock_telemetry, encoding="utf-8").read())
    telemetry_data["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    with open(mock_telemetry, "w", encoding="utf-8") as handle:
        json.dump(telemetry_data, handle)

    approval_path = str(tmp_path / "human-approvals.json")
    app = create_metrics_app(
        telemetry_path=mock_telemetry,
        audit_log_path=mock_audit_log,
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=approval_path,
    )
    store = HumanApprovalStore(approval_path)
    proposal = store.create_proposal(
        intent={
            "action": "block",
            "target_switch": "1",
            "from_port": "2",
            "reason": "API approval lifecycle test",
        },
        verifier_result={"safe": True, "checks": ["test only"]},
        telemetry_path=mock_telemetry,
    )
    client = app.test_client()
    headers = {
        "Authorization": "Bearer test-only-strong-token",
        "Content-Type": "application/json",
    }

    decision = client.post(
        f"/api/approvals/{proposal['proposal_id']}/decision",
        headers=headers,
        json={
            "decision": "approve",
            "reason": "Reviewed test proposal",
            "proposal_fingerprint": proposal["proposal_fingerprint"],
        },
    )
    assert decision.status_code == 200
    assert decision.get_json()["proposal"]["status"] == "approved"

    execution = client.post(
        f"/api/approvals/{proposal['proposal_id']}/execute",
        headers=headers,
        json={},
    )
    assert execution.status_code == 503
    assert "connectivity check" in execution.get_json()["error"].lower()
    assert store.get_proposal(proposal["proposal_id"])["status"] == "approved"


def test_human_verifier_request_changes_is_audited(mock_telemetry, mock_audit_log, tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from netops_guardrail.controller.human_verifier import HumanApprovalStore

    monkeypatch.setenv("NETOPS_APPROVER_TOKENS", '{"netops-admin":"test-only-strong-token"}')
    telemetry_data = json.loads(open(mock_telemetry, encoding="utf-8").read())
    telemetry_data["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    with open(mock_telemetry, "w", encoding="utf-8") as handle:
        json.dump(telemetry_data, handle)

    approval_path = str(tmp_path / "human-approvals.json")
    app = create_metrics_app(
        telemetry_path=mock_telemetry,
        audit_log_path=mock_audit_log,
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=approval_path,
    )
    store = HumanApprovalStore(approval_path)
    proposal = store.create_proposal(
        intent={"action": "block", "target_switch": "1", "from_port": "2", "reason": "review test"},
        verifier_result={"safe": True, "checks": ["test only"]},
        telemetry_path=mock_telemetry,
    )
    client = app.test_client()
    approval_page = client.get("/approvals").get_data(as_text=True)
    assert "Request changes" in approval_page

    response = client.post(
        f"/api/approvals/{proposal['proposal_id']}/decision",
        headers={
            "Authorization": "Bearer test-only-strong-token",
            "Content-Type": "application/json",
        },
        json={
            "decision": "request_changes",
            "reason": "Add impact evidence before resubmission.",
            "proposal_fingerprint": proposal["proposal_fingerprint"],
        },
    )
    assert response.status_code == 200
    assert response.get_json()["proposal"]["status"] == "changes_requested"
    assert store.get_proposal(proposal["proposal_id"])["status"] == "changes_requested"

    # Terminal decisions must be visible in both Pipeline Trace and the
    # authenticated Human Verifier response.
    trace = client.get("/api/pipeline/trace?limit=10").get_json()
    assert trace[-1]["event_type"] == "human_approval_decision"
    assert trace[-1]["decision"] == "CHANGES_REQUESTED"
    assert trace[-1]["decision_reason"] == "Add impact evidence before resubmission."
    auth_headers = {"Authorization": "Bearer test-only-strong-token"}
    visible = client.get("/api/approvals", headers=auth_headers).get_json()["proposals"]
    assert any(p["proposal_id"] == proposal["proposal_id"] and p["status"] == "changes_requested" for p in visible)

    rejected = store.create_proposal(
        intent={"action": "block", "target_switch": "1", "from_port": "3", "reason": "reject regression test"},
        verifier_result={"safe": True, "checks": ["test only"]},
        telemetry_path=mock_telemetry,
    )
    rejected_reason = "Reject: I do not approve this network change."
    rejection = client.post(
        f"/api/approvals/{rejected['proposal_id']}/decision",
        headers={
            "Authorization": "Bearer test-only-strong-token",
            "Content-Type": "application/json",
        },
        json={
            "decision": "reject",
            "reason": rejected_reason,
            "proposal_fingerprint": rejected["proposal_fingerprint"],
        },
    )
    assert rejection.status_code == 200
    assert rejection.get_json()["proposal"]["status"] == "rejected"
    trace = client.get("/api/pipeline/trace?limit=10").get_json()
    assert trace[-1]["event_type"] == "human_approval_decision"
    assert trace[-1]["decision"] == "REJECTED"
    assert trace[-1]["decision_reason"] == rejected_reason
    visible = client.get("/api/approvals", headers=auth_headers).get_json()["proposals"]
    assert any(p["proposal_id"] == rejected["proposal_id"] and p["status"] == "rejected" for p in visible)


def test_fault_injection_runs_ai_gate_and_returns_human_proposal(monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace

    import netops_guardrail.observability.server as server_module

    telemetry_path = tmp_path / "latest.json"
    telemetry = {
        "updated_at_utc": "2026-10-28T06:30:00+00:00",
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"}},
        },
    }
    telemetry_path.write_text(json.dumps(telemetry), encoding="utf-8")
    audit_path = tmp_path / "audit.json"
    app = server_module.create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(audit_path),
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "test-fault-token")
    monkeypatch.setenv("NETOPS_CONNECTIVITY_CHECKER", "fake_checker:check")
    monkeypatch.setattr(
        server_module.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        server_module.importlib, "import_module",
        lambda name: SimpleNamespace(check=lambda: True) if name == "fake_checker"
        else __import__(name),
    )
    seen = {}

    def fake_decide(**kwargs):
        seen.update(kwargs)
        return {
            "decision": "PENDING_HUMAN_APPROVAL",
            "intent": {"action": "block", "target_switch": "1", "from_port": "3", "reason": "AI fault diagnosis"},
            "verification": {"safe": True, "checks": ["PASS: reachability preserved"]},
            "human_approval": {
                "proposal_id": "real-flow-test-proposal",
                "expires_at": "2026-10-28T06:35:00+00:00",
            },
        }

    monkeypatch.setattr(server_module, "decide", fake_decide)
    response = app.test_client().post(
        "/api/chaos/inject-loop?confirm=true",
        headers={"Authorization": "Bearer test-fault-token"},
        json={},
    )
    assert response.status_code == 200, response.get_json()
    payload = response.get_json()
    assert payload["proposal_id"] == "real-flow-test-proposal"
    assert payload["execution_started"] is False
    assert seen["execute_approved"] is False
    assert seen["incident_context"]["fault_type"] == "redundant_trunk_restored"
    assert seen["audit_logger"] is not None


def test_issue2_standby_forwarding_simulation_creates_review_only_proposal(
    monkeypatch, tmp_path
):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    import netops_guardrail.observability.server as server_module

    telemetry_path = tmp_path / "issue2-latest.json"
    telemetry = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"}},
        },
    }
    telemetry_path.write_text(json.dumps(telemetry), encoding="utf-8")
    app = server_module.create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(tmp_path / "audit.json"),
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "issue2-test-token")
    monkeypatch.setenv("NETOPS_CONNECTIVITY_CHECKER", "fake_checker:check")
    monkeypatch.setattr(
        server_module.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        server_module.importlib, "import_module",
        lambda name: SimpleNamespace(check=lambda: True) if name == "fake_checker"
        else __import__(name),
    )
    observed = {}

    def fake_decide(**kwargs):
        observed.update(kwargs)
        return {
            "decision": "PENDING_HUMAN_APPROVAL",
            "intent": {
                "action": "block", "target_switch": "1", "from_port": "3",
                "reason": "CONTROLLED DEMO SIGNAL: simulated issue for review.",
            },
            "verification": {"safe": True, "checks": ["PASS: primary path and host reachability preserved"]},
            "human_approval": {
                "proposal_id": "issue2-test-proposal",
                "expires_at": "2030-01-01T00:05:00+00:00",
            },
        }

    monkeypatch.setattr(server_module, "decide", fake_decide)
    response = app.test_client().post(
        "/api/chaos/standby-forwarding?confirm=true",
        headers={"Authorization": "Bearer issue2-test-token"},
        json={"allow_controlled_simulation": True},
    )
    assert response.status_code == 200, response.get_json()
    result = response.get_json()
    assert result["status"] == "issue2_proposal_created"
    assert result["detection_mode"] == "controlled_simulation"
    assert result["network_mutation_attempted"] is False
    assert result["execution_started"] is False
    assert result["observation"]["detected"] is False
    assert observed["execute_approved"] is False
    assert observed["incident_context"]["fault_type"] == "standby_forwarding_anomaly"
    assert observed["incident_context"]["simulation_mode"] is True


def test_issue2_detector_only_reports_no_live_anomaly_without_simulation(
    monkeypatch, tmp_path
):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    import netops_guardrail.observability.server as server_module

    telemetry_path = tmp_path / "issue2-healthy.json"
    telemetry = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": "FORWARD"}},
            "2": {"ports": {"1": {}, "2": {}, "3": {}},
                  "stp_port_states": {"1": "FORWARD", "2": "BLOCK", "3": "FORWARD"}},
        },
    }
    telemetry_path.write_text(json.dumps(telemetry), encoding="utf-8")
    app = server_module.create_metrics_app(
        telemetry_path=str(telemetry_path),
        audit_log_path=str(tmp_path / "audit.json"),
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "approvals.json"),
    )
    monkeypatch.setenv("NETOPS_CHAOS_API_TOKEN", "issue2-test-token")
    monkeypatch.setenv("NETOPS_CONNECTIVITY_CHECKER", "fake_checker:check")
    monkeypatch.setattr(
        server_module.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(
        server_module.importlib, "import_module",
        lambda name: SimpleNamespace(check=lambda: True) if name == "fake_checker"
        else __import__(name),
    )
    response = app.test_client().post(
        "/api/chaos/standby-forwarding?confirm=true",
        headers={"Authorization": "Bearer issue2-test-token"},
        json={},
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "no_live_anomaly"
    assert response.get_json()["network_mutation_attempted"] is False


def test_human_verifier_has_compact_issue_and_decision_sections(
    mock_telemetry, mock_audit_log, tmp_path
):
    app = create_metrics_app(
        telemetry_path=mock_telemetry,
        audit_log_path=mock_audit_log,
        trace_log_path=str(tmp_path / "trace.jsonl"),
        approval_path=str(tmp_path / "human-approvals.json"),
    )
    page = app.test_client().get("/approvals")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "Issue details" in html
    assert "Changes to address the issue" in html
    assert "Automated safety checks" in html
    assert "Your Decision" in html
    assert "Issue 2 — Unexpected standby forwarding" in html
    assert "CONTROLLED DEMO SIGNAL" in html
    assert "Proposed only — not applied to the network yet." in html
    assert "Technical details (fingerprints, timestamps and original reason)" in html
