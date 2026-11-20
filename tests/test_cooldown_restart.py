from datetime import datetime, timedelta, timezone

from netops_guardrail.controller.monitor import IncidentMonitor


def test_cooldown_survives_monitor_restart_after_resolution(tmp_path):
    base = datetime.now(timezone.utc)
    broken = {
        "updated_at_utc": base.isoformat(),
        "switches": {"1": {"port_status": {"3": {"state": "DOWN"}}}},
    }
    healthy = {
        "updated_at_utc": (base + timedelta(seconds=1)).isoformat(),
        "switches": {"1": {"port_status": {"3": {"state": "UP"}}}},
    }
    first = IncidentMonitor(tmp_path, debounce_reads=1, cooldown_seconds=60)
    assert len(first.process_snapshot(broken, now=base)) == 1
    first.process_snapshot(healthy, now=base + timedelta(seconds=1))

    restarted = IncidentMonitor(tmp_path, debounce_reads=1, cooldown_seconds=60)
    assert restarted.process_snapshot(broken, now=base + timedelta(seconds=2)) == []
