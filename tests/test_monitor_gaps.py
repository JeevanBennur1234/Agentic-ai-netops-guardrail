import json
from datetime import datetime, timedelta, timezone

from netops_guardrail.controller.monitor import IncidentMonitor, detect_incidents


def test_evidence_identity_stable_across_fresh_telemetry_snapshots():
    now = datetime.now(timezone.utc)
    one = {
        "updated_at_utc": now.isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    two = {
        "updated_at_utc": (now + timedelta(seconds=5)).isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    assert detect_incidents(one)[0]["evidence_id"] == detect_incidents(two)[0]["evidence_id"]


def test_recovery_resolves_existing_incident(tmp_path):
    monitor = IncidentMonitor(tmp_path, debounce_reads=1, cooldown_seconds=0)
    broken = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    monitor.process_snapshot(broken)
    healthy = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "UP"}}}},
    }
    monitor.process_snapshot(healthy)
    records = json.loads((tmp_path / "incidents.json").read_text())
    assert records[0]["state"] == "RESOLVED"


def test_test_fixture_provenance_is_persisted_but_never_dispatched(tmp_path):
    calls = []
    monitor = IncidentMonitor(
        tmp_path,
        debounce_reads=1,
        cooldown_seconds=0,
        decision_pipeline=lambda **kwargs: calls.append(kwargs) or {},
    )
    data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": {"source": "test_fixture"},
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    emitted = monitor.process_snapshot(data)
    assert emitted[0]["source"] == "test_fixture"
    assert emitted[0]["execution_allowed"] is False
    assert calls == []


def test_dispatch_uses_existing_decision_gate_without_execution(tmp_path):
    calls = []

    def pipeline(**kwargs):
        calls.append(kwargs)
        return {
            "intent": {
                "action": "no_action",
                "reason": "Recovered path",
                "_agent_metadata": {
                    "model": "qwen2.5-coder:1.5b",
                    "model_invoked": True,
                    "status": "completed",
                },
            },
            "verification": {"safe": True},
            "decision": "APPROVED",
            "human_approval": None,
            "audit_record": {"index": 7, "current_hash": "abc"},
        }

    monitor = IncidentMonitor(
        tmp_path,
        debounce_reads=1,
        cooldown_seconds=0,
        decision_pipeline=pipeline,
    )
    data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    monitor.process_snapshot(data)
    assert len(calls) == 1
    assert calls[0]["execute_approved"] is False
    assert calls[0]["incident_context"]["source"] == "live_telemetry"
    records = json.loads((tmp_path / "incidents.json").read_text())
    assert records[0]["state"] == "AI_REVIEWED"
    assert records[0]["ai_invoked"] is True
    assert records[0]["ai_model"] == "qwen2.5-coder:1.5b"
    assert records[0]["stages"]["ai"] == "COMPLETED"
    assert records[0]["stages"]["executor"] == "NOT_STARTED"


def test_ai_dispatch_rate_limit_persists(tmp_path):
    calls = []
    monitor = IncidentMonitor(
        tmp_path,
        debounce_reads=1,
        cooldown_seconds=0,
        max_ai_calls_per_hour=0,
        decision_pipeline=lambda **kwargs: calls.append(kwargs) or {},
    )
    data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "switches": {"1": {"port_status": {"2": {"state": "DOWN"}}}},
    }
    monitor.process_snapshot(data)
    records = json.loads((tmp_path / "incidents.json").read_text())
    assert records[0]["ai_call_allowed"] is False
    assert calls == []


def test_topology_offline_incident_never_dispatches_to_ai(tmp_path):
    calls = []
    monitor = IncidentMonitor(
        tmp_path,
        debounce_reads=1,
        cooldown_seconds=0,
        decision_pipeline=lambda **kwargs: calls.append(kwargs) or {},
    )
    data = {
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "links": [],
        "switches": {
            switch_id: {
                "ports": {"1": {}, "2": {}, "3": {}},
                "flows": [],
                "stp_port_states": {"1": "DISABLE", "2": "DISABLE", "3": "DISABLE"},
                "port_status": {
                    "1": {"state": "MISSING"},
                    "2": {"state": "MISSING"},
                    "3": {"state": "MISSING"},
                },
            }
            for switch_id in ("1", "2")
        },
    }

    emitted = monitor.process_snapshot(data)

    assert [item["type"] for item in emitted] == ["topology_offline"]
    assert calls == []
    stored = json.loads((tmp_path / "incidents.json").read_text())
    assert stored[0]["ai_call_allowed"] is False
    assert stored[0]["remediation_allowed"] is False


def test_monitor_run_writes_ai_enabled_liveness_heartbeat(tmp_path):
    telemetry_path = tmp_path / "telemetry.json"
    telemetry_path.write_text(
        json.dumps(
            {
                "updated_at_utc": datetime.now(timezone.utc).isoformat(),
                "switches": {
                    "1": {"ports": {}, "flows": [], "port_status": {}, "stp_port_states": {}}
                },
                "links": [],
            }
        ),
        encoding="utf-8",
    )
    monitor = IncidentMonitor(
        tmp_path / "incidents",
        decision_pipeline=lambda **kwargs: {},
    )

    monitor.run(telemetry_path, interval_seconds=0.1, max_iterations=1)

    heartbeat = json.loads((tmp_path / "incidents" / "monitor_status.json").read_text())
    assert heartbeat["status"] == "running"
    assert heartbeat["ai_enabled"] is True
    assert heartbeat["interval_seconds"] == 0.1
    assert heartbeat["pid"] > 0
