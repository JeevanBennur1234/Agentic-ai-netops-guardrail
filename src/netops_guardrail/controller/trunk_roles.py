"""Dynamic trunk role derivation and host discovery from live STP telemetry.

Classifies inter-switch links as primary or standby without hardcoding switch or port IDs.
Derives host endpoints connected to access ports based on MAC learning events.
"""

from __future__ import annotations

from typing import Any, Mapping


def derive_trunk_roles(telemetry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Derive primary and standby trunk roles dynamically from live STP telemetry.

    An inter-switch link is classified as:
    - 'standby': if at least one endpoint port is in STP state BLOCK.
    - 'primary': if both endpoint ports are in STP state FORWARD.
    - 'down': if an endpoint has port status DOWN, MISSING, or STP state DISABLE.
    - 'converging': if STP state is LISTEN, LEARN, or unknown.

    Works for arbitrary topologies (2-switch redundant, 3-switch triangle, 4-switch ring, etc.).
    """
    if not isinstance(telemetry, (dict, Mapping)):
        return {
            "primary_trunks": [],
            "standby_trunks": [],
            "blocked_ports": [],
            "links": [],
        }

    switches = telemetry.get("switches") or {}
    links = telemetry.get("links") or []

    primary_trunks: list[list[str]] = []
    standby_trunks: list[list[str]] = []
    blocked_ports: set[str] = set()
    link_details: list[dict[str, Any]] = []

    for link in links:
        if not isinstance(link, (dict, Mapping)):
            continue
        src_sw = str(link.get("src_switch", "")).strip()
        src_pt = str(link.get("src_port", "")).strip()
        dst_sw = str(link.get("dst_switch", "")).strip()
        dst_pt = str(link.get("dst_port", "")).strip()

        if not src_sw or not src_pt or not dst_sw or not dst_pt:
            continue

        src_node = f"s{src_sw}-p{src_pt}"
        dst_node = f"s{dst_sw}-p{dst_pt}"
        pair = sorted([src_node, dst_node])

        src_sw_data = switches.get(src_sw) if isinstance(switches.get(src_sw), dict) else {}
        dst_sw_data = switches.get(dst_sw) if isinstance(switches.get(dst_sw), dict) else {}

        src_stp = str((src_sw_data.get("stp_port_states") or {}).get(src_pt, "UNKNOWN")).upper()
        dst_stp = str((dst_sw_data.get("stp_port_states") or {}).get(dst_pt, "UNKNOWN")).upper()

        if src_stp == "BLOCK":
            blocked_ports.add(src_node)
        if dst_stp == "BLOCK":
            blocked_ports.add(dst_node)

        if src_stp == "BLOCK" or dst_stp == "BLOCK":
            role = "standby"
            if pair not in standby_trunks:
                standby_trunks.append(pair)
        elif src_stp == "FORWARD" and dst_stp == "FORWARD":
            role = "primary"
            if pair not in primary_trunks:
                primary_trunks.append(pair)
        elif "DISABLE" in (src_stp, dst_stp) or "DOWN" in (src_stp, dst_stp):
            role = "down"
        else:
            role = "converging"

        link_details.append({
            "src": src_node,
            "dst": dst_node,
            "role": role,
            "stp_states": {src_node: src_stp, dst_node: dst_stp},
        })

    return {
        "primary_trunks": sorted(primary_trunks),
        "standby_trunks": sorted(standby_trunks),
        "blocked_ports": sorted(blocked_ports),
        "links": link_details,
    }


def derive_discovered_hosts(telemetry: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Infer directly connected host endpoints from MAC learning on non-trunk physical ports."""
    if not isinstance(telemetry, (dict, Mapping)):
        return []

    switches = telemetry.get("switches") or {}
    trunk_ports: set[tuple[str, str]] = set()

    for link in (telemetry.get("links") or []) + (telemetry.get("link_events") or []):
        if not isinstance(link, (dict, Mapping)):
            continue
        event = str(link.get("event", "ADD")).upper()
        if event not in {"ADD", "DELETE"}:
            continue
        src_sw = str(link.get("src_switch", "")).strip()
        src_pt = str(link.get("src_port", "")).strip()
        dst_sw = str(link.get("dst_switch", "")).strip()
        dst_pt = str(link.get("dst_port", "")).strip()
        if src_sw and src_pt:
            trunk_ports.add((src_sw, src_pt))
        if dst_sw and dst_pt:
            trunk_ports.add((dst_sw, dst_pt))

    latest: dict[tuple[str, str, str], str] = {}
    for event in telemetry.get("mac_learning_events") or []:
        if not isinstance(event, (dict, Mapping)):
            continue
        switch_id = str(event.get("switch_id", "")).strip()
        port_id = str(event.get("port_id", "")).strip()
        mac = str(event.get("source_mac", "")).lower().strip()
        if not switch_id or not port_id or not mac or (switch_id, port_id) in trunk_ports:
            continue
        switch = switches.get(switch_id) or {}
        if port_id not in (switch.get("ports") or {}):
            continue
        try:
            if int(port_id) >= 4294967040:
                continue
        except ValueError:
            continue
        key = (switch_id, port_id, mac)
        timestamp = str(event.get("timestamp_utc", ""))
        if key not in latest or timestamp > latest[key]:
            latest[key] = timestamp

    return [
        {
            "id": f"host-{mac.replace(':', '')}",
            "label": f"Host {mac[-5:]}",
            "mac": mac,
            "switch_id": switch_id,
            "port_id": port_id,
            "last_seen_utc": timestamp,
        }
        for (switch_id, port_id, mac), timestamp in sorted(latest.items())
    ]
