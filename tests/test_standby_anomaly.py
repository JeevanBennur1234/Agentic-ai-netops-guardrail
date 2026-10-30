from datetime import datetime, timedelta, timezone

from netops_guardrail.controller.standby_anomaly import inspect_standby_forwarding


def sample_telemetry(standby_left="FORWARD", standby_right="BLOCK", age_seconds=0):
    updated = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return {
        "updated_at_utc": updated.isoformat(),
        "links": [
            {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
            {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
        ],
        "switches": {
            "1": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "stp_port_states": {"1": "FORWARD", "2": "FORWARD", "3": standby_left},
            },
            "2": {
                "ports": {"1": {}, "2": {}, "3": {}},
                "stp_port_states": {"1": "FORWARD", "2": standby_right, "3": "FORWARD"},
            },
        },
    }


def test_normal_standby_block_is_not_reported_as_anomaly():
    result = inspect_standby_forwarding(sample_telemetry())
    assert result["ready_for_investigation"] is True
    assert result["detected"] is False
    assert result["standby_both_forward"] is False


def test_both_standby_endpoints_forward_is_detected_from_live_snapshot():
    result = inspect_standby_forwarding(
        sample_telemetry(standby_left="FORWARD", standby_right="FORWARD")
    )
    assert result["ready_for_investigation"] is True
    assert result["detected"] is True
    assert result["standby_both_forward"] is True


def test_stale_telemetry_fails_closed():
    result = inspect_standby_forwarding(sample_telemetry(age_seconds=90))
    assert result["ready_for_investigation"] is False
    assert result["detected"] is False
    assert result["prerequisites"]["telemetry_fresh"] is False


def test_missing_standby_link_fails_closed():
    telemetry = sample_telemetry(standby_left="FORWARD", standby_right="FORWARD")
    telemetry["links"] = telemetry["links"][:1]
    result = inspect_standby_forwarding(telemetry)
    assert result["ready_for_investigation"] is False
    assert result["detected"] is False
    assert result["prerequisites"]["standby_trunk_discovered"] is False
