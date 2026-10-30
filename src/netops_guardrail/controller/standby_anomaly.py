"""Detection for unexpected standby-trunk forwarding from live Ryu telemetry.

The detector is observation-only. It never changes a switch or fabricates a
telemetry state. Controlled demonstration alerts are handled separately by the
fault-injection API and are explicitly labeled as simulations.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

PRIMARY = (("s1-p2", "s2-p1"),)
STANDBY = (("s1-p3", "s2-p2"),)


def _parse_time(value: Any):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def inspect_standby_forwarding(telemetry: dict, max_age_seconds: int = 30, now=None) -> dict:
    """Return live evidence and whether both standby endpoints unexpectedly forward."""
    now = now or datetime.now(timezone.utc)
    timestamp = _parse_time(telemetry.get("updated_at_utc") or telemetry.get("timestamp"))
    age = (now.astimezone(timezone.utc) - timestamp).total_seconds() if timestamp else None
    telemetry_fresh = age is not None and -5 <= age <= max_age_seconds

    switches = telemetry.get("switches") if isinstance(telemetry.get("switches"), dict) else {}
    states = {
        str(switch_id): {
            str(port): str(state).upper()
            for port, state in (switch_data.get("stp_port_states") or {}).items()
        }
        for switch_id, switch_data in switches.items()
        if isinstance(switch_data, dict)
    }
    ports = {
        str(switch_id): {str(port) for port in (switch_data.get("ports") or {}).keys()}
        for switch_id, switch_data in switches.items()
        if isinstance(switch_data, dict)
    }

    discovered_links = set()
    for link in telemetry.get("links") or []:
        if not isinstance(link, dict):
            continue
        left = f"s{str(link.get('src_switch', '')).strip()}-p{str(link.get('src_port', '')).strip()}"
        right = f"s{str(link.get('dst_switch', '')).strip()}-p{str(link.get('dst_port', '')).strip()}"
        if left != "s-p" and right != "s-p":
            discovered_links.add(tuple(sorted((left, right))))

    primary_link_present = tuple(sorted(("s1-p2", "s2-p1"))) in discovered_links
    standby_link_present = tuple(sorted(("s1-p3", "s2-p2"))) in discovered_links
    required_ports_present = all(
        port in ports.get(switch_id, set())
        for switch_id, port in (("1", "1"), ("1", "2"), ("1", "3"),
                                ("2", "1"), ("2", "2"), ("2", "3"))
    )

    primary_forward = (
        states.get("1", {}).get("2") == "FORWARD"
        and states.get("2", {}).get("1") == "FORWARD"
    )
    host_access_forward = (
        states.get("1", {}).get("1") == "FORWARD"
        and states.get("2", {}).get("3") == "FORWARD"
    )
    standby_states = {
        "s1-p3": states.get("1", {}).get("3", "UNKNOWN"),
        "s2-p2": states.get("2", {}).get("2", "UNKNOWN"),
    }
    standby_both_forward = all(value == "FORWARD" for value in standby_states.values())

    prerequisites = {
        "telemetry_fresh": telemetry_fresh,
        "primary_trunk_discovered": primary_link_present,
        "standby_trunk_discovered": standby_link_present,
        "required_ports_present": required_ports_present,
        "primary_trunk_forwarding": primary_forward,
        "host_access_ports_forwarding": host_access_forward,
    }
    ready = all(prerequisites.values())
    detected = ready and standby_both_forward

    if detected:
        reason = (
            "Unexpected standby forwarding detected: both s1-p3 and s2-p2 are "
            "reported FORWARD while the primary trunk and host access ports are forwarding."
        )
    elif not ready:
        failed = [key for key, value in prerequisites.items() if not value]
        reason = "Cannot safely evaluate standby forwarding; failed checks: " + ", ".join(failed)
    else:
        reason = (
            "No live dual-forwarding anomaly detected. Standby states are "
            f"s1-p3={standby_states['s1-p3']} and s2-p2={standby_states['s2-p2']}."
        )

    return {
        "detected": detected,
        "ready_for_investigation": ready,
        "reason": reason,
        "telemetry_age_seconds": round(age, 3) if age is not None else None,
        "max_age_seconds": max_age_seconds,
        "prerequisites": prerequisites,
        "discovered_links": sorted([list(pair) for pair in discovered_links]),
        "primary_states": {
            "s1-p2": states.get("1", {}).get("2", "UNKNOWN"),
            "s2-p1": states.get("2", {}).get("1", "UNKNOWN"),
        },
        "standby_states": standby_states,
        "host_access_states": {
            "s1-p1": states.get("1", {}).get("1", "UNKNOWN"),
            "s2-p3": states.get("2", {}).get("3", "UNKNOWN"),
        },
        "standby_both_forward": standby_both_forward,
    }
