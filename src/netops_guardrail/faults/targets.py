"""Resolve fault targets exclusively from a current controller telemetry snapshot."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from netops_guardrail.controller.trunk_roles import derive_trunk_roles

MARKER_COOKIE = 0x4E45544F5053


class TargetResolutionError(ValueError):
    """Raised when live telemetry cannot prove a safe fault target."""


def _fresh_live_snapshot(telemetry: Mapping[str, Any], max_age_seconds: float = 30.0) -> None:
    provenance = telemetry.get("provenance")
    source = provenance.get("source") if isinstance(provenance, Mapping) else None
    if source not in {"live_telemetry", "lab_injected_live"}:
        raise TargetResolutionError("Target resolution requires controller-produced live telemetry.")
    value = telemetry.get("updated_at_utc")
    if not isinstance(value, str):
        raise TargetResolutionError("Live telemetry timestamp is missing.")
    try:
        updated = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TargetResolutionError("Live telemetry timestamp is invalid.") from exc
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age < -5 or age > max_age_seconds:
        raise TargetResolutionError(f"Live telemetry is stale or from the future (age={age:.1f}s).")


def _endpoint(telemetry: Mapping[str, Any], switch_id: Any, port_id: Any) -> dict[str, str]:
    switch_id, port_id = str(switch_id), str(port_id)
    switch = (telemetry.get("switches") or {}).get(switch_id)
    if not isinstance(switch, Mapping):
        raise TargetResolutionError(f"Switch {switch_id} is absent from live telemetry.")
    ports = switch.get("ports") or {}
    if port_id not in ports:
        raise TargetResolutionError(f"Physical port {switch_id}/{port_id} is absent from live telemetry.")
    try:
        if int(port_id) >= 4294967040:
            raise TargetResolutionError("OpenFlow LOCAL/reserved ports cannot be fault targets.")
    except ValueError as exc:
        raise TargetResolutionError("Fault target port must be a physical numeric port.") from exc
    status = (switch.get("port_status") or {}).get(port_id) or {}
    state = str(status.get("state", "UNKNOWN")).upper()
    stp = str((switch.get("stp_port_states") or {}).get(port_id, "UNKNOWN")).upper()
    return {
        "switch_id": switch_id,
        "port_id": port_id,
        "bridge": f"s{switch_id}",
        "interface": f"s{switch_id}-eth{port_id}",
        "port_state": state,
        "stp_state": stp,
    }


def _role_pairs(telemetry: Mapping[str, Any], role: str) -> list[list[str]]:
    derived = derive_trunk_roles(telemetry)
    return list(derived.get(f"{role}_trunks") or [])


def resolve_fault_target(fault_id: str, telemetry: Mapping[str, Any]) -> dict[str, Any]:
    """Return a verified, telemetry-derived target; never guess a switch or port."""
    _fresh_live_snapshot(telemetry)
    switches = telemetry.get("switches") or {}
    if not isinstance(switches, Mapping) or not switches:
        raise TargetResolutionError("No live switches are available for target resolution.")

    if fault_id in {"trunk_down", "link_flapping"}:
        role = "primary" if fault_id == "trunk_down" else "standby"
        pairs = _role_pairs(telemetry, role)
        if not pairs:
            raise TargetResolutionError(f"No live {role} trunk is proven by STP telemetry.")
        for pair in sorted(pairs):
            endpoints = []
            for node in pair:
                try:
                    switch, port = node.split("-p", 1)
                    endpoint = _endpoint(telemetry, switch.removeprefix("s"), port)
                except (ValueError, TargetResolutionError):
                    endpoints = []
                    break
                if endpoint["port_state"] != "UP":
                    endpoints = []
                    break
                endpoints.append(endpoint)
            if len(endpoints) == 2:
                return {
                    "kind": "trunk", "role": role,
                    "endpoint": endpoints[0], "endpoints": endpoints,
                    "link": list(pair),
                }
        raise TargetResolutionError(f"No fully UP physical {role} trunk is proven by live telemetry.")

    if fault_id == "redundant_trunk_restored":
        standby_pairs = _role_pairs(telemetry, "standby")
        for pair in sorted(standby_pairs):
            endpoints = []
            for node in pair:
                try:
                    switch, port = node.split("-p", 1)
                    endpoints.append(_endpoint(telemetry, switch.removeprefix("s"), port))
                except (ValueError, TargetResolutionError):
                    endpoints = []
                    break
            if len(endpoints) == 2:
                return {"kind": "restorable_link", "role": "standby",
                        "endpoints": endpoints, "link": list(pair)}
        raise TargetResolutionError("No STP-blocked standby trunk with two telemetry-confirmed physical endpoints was found.")

    if fault_id in {"flow_drift", "flow_rule_drift"}:
        candidates = []
        for switch_id, switch in switches.items():
            if not isinstance(switch, Mapping) or not isinstance(switch.get("flows"), list):
                continue
            cookies = set()
            for flow in switch["flows"]:
                if isinstance(flow, Mapping):
                    try:
                        cookies.add(int(str(flow.get("cookie", "0")), 0))
                    except (TypeError, ValueError):
                        pass
            if MARKER_COOKIE not in cookies:
                candidates.append(str(switch_id))
        if not candidates:
            raise TargetResolutionError("No live switch with flow telemetry and a free marker cookie was found.")
        switch_id = sorted(candidates)[0]
        return {"kind": "flow_table", "switch_id": switch_id, "bridge": f"s{switch_id}", "cookie": MARKER_COOKIE}

    if fault_id == "mac_flooding":
        hosts = telemetry.get("hosts") or []
        for host in sorted(hosts, key=lambda item: (str(item.get("switch_id")), str(item.get("port_id")))):
            if not isinstance(host, Mapping):
                continue
            try:
                endpoint = _endpoint(telemetry, host.get("switch_id"), host.get("port_id"))
            except TargetResolutionError:
                continue
            if endpoint["port_state"] == "UP":
                return {"kind": "access_port", "endpoint": endpoint, "host_mac": host.get("mac")}
        raise TargetResolutionError("No live host/access-port attachment is available for MAC-flood targeting.")

    raise TargetResolutionError(f"Fault {fault_id!r} has no live target resolver.")


def build_lab_restore_commands(telemetry: Mapping[str, Any]) -> list[tuple[str, ...]]:
    """Build a tagged-flow-only baseline restore for all discovered physical ports."""
    _fresh_live_snapshot(telemetry)
    switches = telemetry.get("switches") or {}
    commands: list[tuple[str, ...]] = []
    for switch_id, switch in sorted(switches.items(), key=lambda item: str(item[0])):
        if not isinstance(switch, Mapping):
            continue
        ports = switch.get("ports") or {}
        if not isinstance(ports, Mapping):
            continue
        bridge = f"s{switch_id}"
        for port_id in sorted(ports, key=lambda value: str(value)):
            try:
                numeric_port = int(str(port_id))
            except (TypeError, ValueError):
                continue
            if numeric_port >= 4294967040:
                continue
            commands.append(("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13",
                             "mod-port", bridge, str(numeric_port), "up"))
            commands.append(("sudo", "-n", "ip", "link", "set", "dev",
                             f"{bridge}-eth{numeric_port}", "up"))
        commands.append(("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13",
                         "del-flows", bridge, f"cookie=0x{MARKER_COOKIE:x}/-1"))
    if not commands:
        raise TargetResolutionError("No physical switch ports were discovered for lab restore.")
    return commands
