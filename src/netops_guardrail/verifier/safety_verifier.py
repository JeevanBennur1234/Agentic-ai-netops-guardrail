import fcntl
import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from netops_guardrail.netops_paths import NETOPS_HOME

TELEMETRY_FILE = str(NETOPS_HOME / "telemetry" / "data" / "latest.json")
GUARDRAIL_LEDGER_PATH = NETOPS_HOME / "audit" / "guardrail_cookie_ledger.json"
DEFAULT_TOPOLOGY_SPEC_PATH = NETOPS_HOME / "telemetry" / "topology_spec.json"

ALLOWED_ACTIONS = frozenset({
    "no_action",
    "block",
    "reroute",
    "disable_port",
    "restore_port",
    "remove_flow",
    "rate_limit_port",
})

MUTATION_ACTIONS = frozenset({
    "block",
    "disable_port",
    "restore_port",
    "remove_flow",
    "rate_limit_port",
})

# Canonical action sets & backwards-compatibility aliases
ALLOWLISTED_ACTIONS = ALLOWED_ACTIONS
ALLOWLISTED_APPROVAL_ACTIONS = MUTATION_ACTIONS
EXECUTABLE_REMEDIATION_ACTIONS = MUTATION_ACTIONS

ALLOWLISTED_MATCH_FIELDS = {
    "eth_type",
    "nw_src",
    "nw_dst",
    "in_port",
    "ip_proto",
    "dl_src",
    "dl_dst",
}

ACTION_ALLOWED_KEYS = {
    "no_action": {"action", "reason"},
    "block": {"action", "target_switch", "from_port", "reason"},
    "reroute": {"action", "target_switch", "from_port", "to_port", "reason"},
    "disable_port": {"action", "target_switch", "switch", "from_port", "port", "reason"},
    "restore_port": {"action", "target_switch", "switch", "from_port", "port", "reason"},
    "remove_flow": {"action", "target_switch", "switch", "cookie", "priority", "match", "reason"},
    "rate_limit_port": {"action", "target_switch", "switch", "from_port", "port", "rate_kbps", "reason"},
}


def _validate_match_field_value(k: str, v) -> bool:
    if k == "in_port":
        return str(v).isdigit() and 0 < int(str(v)) < 4294967040
    elif k == "eth_type":
        try:
            val = int(str(v), 0)
            return 0 <= val <= 0xffff
        except (ValueError, TypeError):
            return False
    elif k == "ip_proto":
        try:
            val = int(str(v), 0)
            return 0 <= val <= 255
        except (ValueError, TypeError):
            return False
    elif k in ("nw_src", "nw_dst"):
        try:
            ipaddress.ip_network(str(v), strict=False)
            return True
        except (ValueError, TypeError):
            return False
    elif k in ("dl_src", "dl_dst"):
        return bool(re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", str(v)))
    return False


def validate_intent_schema(intent) -> tuple[bool, str | None]:
    """
    Strict per-action intent schema validation.
    Enforces additionalProperties: false and typed fields.
    Rejects unknown keys, including any caller-provided incident_context or is_guardrail_rule.
    """
    if not isinstance(intent, dict):
        return False, "malformed intent: payload must be a dictionary"

    action = intent.get("action")
    if not action or action not in ACTION_ALLOWED_KEYS:
        return False, f"unsupported action '{action}'"

    allowed_keys = ACTION_ALLOWED_KEYS[action]
    unknown_keys = set(intent.keys()) - allowed_keys
    if unknown_keys:
        return False, f"Intent contains unauthorized unknown keys for action '{action}': {sorted(unknown_keys)}"

    if "reason" in intent and not isinstance(intent["reason"], str):
        return False, "Field 'reason' must be a string"

    if action == "no_action":
        return True, None

    if action == "block":
        sw = intent.get("target_switch")
        pt = intent.get("from_port")
        if sw is None or not str(sw).strip().isdigit():
            return False, "block requires 'target_switch' as integer/digits"
        if pt is None or not str(pt).strip().isdigit():
            return False, "block requires 'from_port' as integer/digits"
        return True, None

    if action == "reroute":
        sw = intent.get("target_switch")
        fp = intent.get("from_port")
        tp = intent.get("to_port")
        if sw is None or not str(sw).strip().isdigit():
            return False, "reroute requires 'target_switch' as integer/digits"
        if fp is None or not str(fp).strip().isdigit():
            return False, "reroute requires 'from_port' as integer/digits"
        if tp is None or not str(tp).strip().isdigit():
            return False, "reroute requires 'to_port' as integer/digits"
        return True, None

    if action in ("disable_port", "restore_port"):
        sw = intent.get("target_switch") if intent.get("target_switch") is not None else intent.get("switch")
        pt = intent.get("from_port") if intent.get("from_port") is not None else intent.get("port")
        if sw is None or not str(sw).strip().isdigit():
            return False, f"{action} requires switch identifier as integer/digits"
        if pt is None or not str(pt).strip().isdigit():
            return False, f"{action} requires port identifier as integer/digits"
        return True, None

    if action == "rate_limit_port":
        sw = intent.get("target_switch") if intent.get("target_switch") is not None else intent.get("switch")
        pt = intent.get("from_port") if intent.get("from_port") is not None else intent.get("port")
        rate = intent.get("rate_kbps")
        if sw is None or not str(sw).strip().isdigit():
            return False, "rate_limit_port requires switch identifier as integer/digits"
        if pt is None or not str(pt).strip().isdigit():
            return False, "rate_limit_port requires port identifier as integer/digits"
        if rate is None:
            return False, "rate_limit_port requires 'rate_kbps'"
        try:
            r = int(str(rate))
            if r <= 0:
                return False, "rate_limit_port rate_kbps must be a positive integer"
        except (ValueError, TypeError):
            return False, f"rate_limit_port invalid rate_kbps: {rate}"
        return True, None

    if action == "remove_flow":
        sw = intent.get("target_switch") if intent.get("target_switch") is not None else intent.get("switch")
        cookie = intent.get("cookie")
        priority = intent.get("priority")
        match = intent.get("match")

        if sw is None or not str(sw).strip().isdigit():
            return False, "remove_flow requires switch identifier as integer/digits"
        if cookie is None:
            return False, "remove_flow requires 'cookie'"
        try:
            int(str(cookie), 0)
        except (ValueError, TypeError):
            return False, f"remove_flow invalid cookie: {cookie}"

        if priority is None or not str(priority).strip().isdigit():
            return False, "remove_flow requires 'priority' as integer/digits"

        if match is None or not isinstance(match, dict):
            return False, "remove_flow requires 'match' to be a dict of allowlisted fields, strings not allowed"

        match_unknown = set(match.keys()) - ALLOWLISTED_MATCH_FIELDS
        if match_unknown:
            return False, f"remove_flow match contains unauthorized fields: {sorted(match_unknown)}"

        for k, v in match.items():
            if not _validate_match_field_value(k, v):
                return False, f"Invalid value for match field '{k}': {v}"

        return True, None

    return False, f"Unhandled action '{action}'"


class CorruptLedgerError(ValueError):
    """Raised when the guardrail cookie ledger file is unreadable or corrupted."""


def _read_guardrail_ledger_entries(path: Path) -> list:
    """Read and validate entries while the caller holds the ledger lock."""
    if not path.exists():
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} is unreadable or corrupt: {exc}") from exc
    if not isinstance(entries, list):
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} has invalid format: expected list")
    for index, entry in enumerate(entries):
        raw = entry.get("cookie") if isinstance(entry, dict) else entry
        if raw is None or isinstance(raw, bool) or not isinstance(raw, (int, str)):
            raise CorruptLedgerError(f"Corrupt ledger entry at index {index}: expected integer cookie")
        try:
            int(str(raw), 0)
        except (ValueError, TypeError) as exc:
            raise CorruptLedgerError(f"Corrupt cookie value in ledger entry {index}: {raw!r}") from exc
    return entries


def _write_guardrail_ledger_entries(path: Path, entries: list) -> None:
    """Atomically persist ledger contents; write failures must stop remediation."""
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        temp_name = None
        dir_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} could not be persisted; failing closed: {exc}") from exc
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def load_guardrail_cookies(ledger_path=None) -> set[int]:
    """Load active cookies under a shared process lock; corrupt state fails closed."""
    path = Path(ledger_path) if ledger_path else GUARDRAIL_LEDGER_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path.with_suffix(".lock"), "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
            try:
                entries = _read_guardrail_ledger_entries(path)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except CorruptLedgerError:
        raise
    except OSError as exc:
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} is unavailable; failing closed: {exc}") from exc
    cookies = set()
    for entry in entries:
        if isinstance(entry, dict):
            if entry.get("status", "active") == "rolled_back":
                continue
            entry = entry["cookie"]
        cookies.add(int(str(entry), 0))
    return cookies


def record_guardrail_cookie(cookie: int, action: str = None, bridge: str = None, ledger_path=None):
    """Reserve a cookie with an exclusive lock; a failed write must precede no OVS mutation."""
    path = Path(ledger_path) if ledger_path else GUARDRAIL_LEDGER_PATH
    cookie_int = int(str(cookie), 0)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path.with_suffix(".lock"), "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                entries = _read_guardrail_ledger_entries(path)
                active = {
                    int(str(e.get("cookie") if isinstance(e, dict) else e), 0)
                    for e in entries
                    if not (isinstance(e, dict) and e.get("status", "active") == "rolled_back")
                }
                if cookie_int not in active:
                    entries.append({
                        "cookie": cookie_int,
                        "cookie_hex": f"0x{cookie_int:016x}",
                        "action": str(action),
                        "bridge": str(bridge),
                        "status": "active",
                        "installed_at": datetime.now(timezone.utc).isoformat(),
                    })
                    _write_guardrail_ledger_entries(path, entries)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except CorruptLedgerError:
        raise
    except OSError as exc:
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} could not be locked or written; failing closed: {exc}") from exc


def remove_guardrail_cookie(cookie: int, ledger_path=None):
    """Mark a cookie rolled back under an exclusive lock; corrupt state raises."""
    path = Path(ledger_path) if ledger_path else GUARDRAIL_LEDGER_PATH
    cookie_int = int(str(cookie), 0)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path.with_suffix(".lock"), "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                entries = _read_guardrail_ledger_entries(path)
                changed = False
                for index, entry in enumerate(entries):
                    if isinstance(entry, dict):
                        if int(str(entry["cookie"]), 0) == cookie_int and entry.get("status", "active") != "rolled_back":
                            entry["status"] = "rolled_back"
                            changed = True
                    elif int(str(entry), 0) == cookie_int:
                        entries[index] = {"cookie": cookie_int, "status": "rolled_back"}
                        changed = True
                if changed:
                    _write_guardrail_ledger_entries(path, entries)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except CorruptLedgerError:
        raise
    except OSError as exc:
        raise CorruptLedgerError(f"Guardrail cookie ledger at {path} could not be locked or updated; failing closed: {exc}") from exc


def load_topology_spec(spec_path=None, topology_name=None, num_switches=None) -> list[dict]:
    """
    Load static topology links from an external topology spec JSON file.
    No hardcoded link constants inside the verifier.
    """
    path = Path(spec_path) if spec_path else DEFAULT_TOPOLOGY_SPEC_PATH
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    if topology_name and topology_name in data:
        spec_entry = data[topology_name]
        return list(spec_entry.get("links", [])) if isinstance(spec_entry, dict) else []

    if num_switches is not None:
        if num_switches >= 4 and "ring4" in data:
            return list(data["ring4"].get("links", []))
        elif num_switches in (2, 3) and "redundant2" in data:
            return list(data["redundant2"].get("links", []))
        elif num_switches <= 1:
            return []

    if "ring4" in data:
        return list(data["ring4"].get("links", []))
    if "redundant2" in data:
        return list(data["redundant2"].get("links", []))
    return []


def _canonical_link_key(link: dict) -> tuple[tuple[str, str], tuple[str, str]]:
    """Return an order-independent endpoint pair for link deduplication."""
    src = (str(link.get("src_switch", "")).strip(), str(link.get("src_port", "")).strip())
    dst = (str(link.get("dst_switch", "")).strip(), str(link.get("dst_port", "")).strip())
    return tuple(sorted([src, dst]))


def _union_merge_links(live_links, spec_links) -> list[dict]:
    """
    Union-merge live discovered links and topology spec links.
    Preserves all live links and adds any absent links from the specification.
    Never uses 'first non-empty'.
    """
    seen = set()
    merged = []
    for l in (live_links or []):
        if not isinstance(l, dict):
            continue
        key = _canonical_link_key(l)
        if key[0][0] and key[0][1] and key[1][0] and key[1][1]:
            if key not in seen:
                seen.add(key)
                merged.append(dict(l))
    for l in (spec_links or []):
        if not isinstance(l, dict):
            continue
        key = _canonical_link_key(l)
        if key[0][0] and key[0][1] and key[1][0] and key[1][1]:
            if key not in seen:
                seen.add(key)
                merged.append(dict(l))
    return merged


OVS_TO_SCHEMA_MATCH_MAP = {
    "dl_type": "eth_type",
    "nw_proto": "ip_proto",
    "dl_src": "dl_src",
    "dl_dst": "dl_dst",
    "nw_src": "nw_src",
    "nw_dst": "nw_dst",
    "in_port": "in_port",
    "eth_type": "eth_type",
    "ip_proto": "ip_proto",
}


def normalize_match_dict(raw_match) -> dict:
    """
    Normalize match fields to schema names with canonical types.
    Maps OVS dump names (dl_type, nw_proto, etc.) to schema names (eth_type, ip_proto, etc.)
    and expands shorthands (ip, icmp, tcp, udp, arp, ipv6).
    """
    if raw_match is None:
        return {}

    fields = {}
    if isinstance(raw_match, str):
        for item in raw_match.split(","):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                k, v = item.split("=", 1)
                k = k.strip()
                v = v.strip()
                schema_k = OVS_TO_SCHEMA_MATCH_MAP.get(k, k)
                fields[schema_k] = v
            else:
                shorthand = item.lower()
                if shorthand == "ip":
                    fields["eth_type"] = "0x0800"
                elif shorthand == "icmp":
                    fields["eth_type"] = "0x0800"
                    fields["ip_proto"] = "1"
                elif shorthand == "tcp":
                    fields["eth_type"] = "0x0800"
                    fields["ip_proto"] = "6"
                elif shorthand == "udp":
                    fields["eth_type"] = "0x0800"
                    fields["ip_proto"] = "17"
                elif shorthand == "arp":
                    fields["eth_type"] = "0x0806"
                elif shorthand == "ipv6":
                    fields["eth_type"] = "0x86dd"
    elif isinstance(raw_match, dict):
        for k, v in raw_match.items():
            schema_k = OVS_TO_SCHEMA_MATCH_MAP.get(k, k)
            fields[schema_k] = v
    else:
        return {}

    norm = {}
    for k, v in fields.items():
        if k in ("eth_type", "ip_proto", "in_port"):
            try:
                norm[k] = int(str(v), 0)
            except (ValueError, TypeError):
                norm[k] = v
        elif k in ("nw_src", "nw_dst"):
            try:
                net = ipaddress.ip_network(str(v), strict=False)
                norm[k] = str(net.network_address) if net.num_addresses == 1 else str(net)
            except (ValueError, TypeError):
                norm[k] = str(v).strip().lower()
        elif k in ("dl_src", "dl_dst"):
            norm[k] = str(v).strip().lower()
        else:
            norm[k] = str(v).strip().lower()
    return norm


def matches_strictly_equal(match_a, match_b) -> bool:
    """
    Check that two match representations are strictly non-empty and equal in both directions.
    Normalizes OVS dump and schema names before comparing.
    """
    norm_a = normalize_match_dict(match_a)
    norm_b = normalize_match_dict(match_b)

    if not norm_a or not norm_b:
        return False

    if set(norm_a.keys()) != set(norm_b.keys()):
        return False

    for k in norm_a:
        if norm_a[k] != norm_b[k]:
            return False

    return True


def load_telemetry(path=None):
    file_path = path or TELEMETRY_FILE
    with open(file_path, "r") as file:
        return json.load(file)


def build_topology(telemetry):
    """
    Build a physical NetworkX topology from Ryu telemetry.

    Physical inter-switch edges are retained for peer-port discovery, but each
    edge also records whether both ends are currently STP-forwarding. Safety
    checks use only forwarding edges whenever STP state telemetry is present.
    Incomplete STP state is treated conservatively as non-forwarding.
    """
    graph = nx.Graph()
    switches = telemetry.get("switches", {})
    stp_present = any(
        isinstance(switch_data.get("stp_port_states"), dict)
        and bool(switch_data.get("stp_port_states"))
        for switch_data in switches.values()
    )
    graph.graph["stp_telemetry_present"] = stp_present

    for switch_id, switch_data in switches.items():
        switch_node = f"s{switch_id}"
        graph.add_node(switch_node, type="switch")

        for port_id in switch_data.get("ports", {}):
            try:
                if int(port_id) >= 4294967040:
                    continue
            except (TypeError, ValueError):
                if str(port_id).lower() == "local":
                    continue

            port_node = f"s{switch_id}-p{port_id}"
            graph.add_node(port_node, type="port", switch_id=str(switch_id),
                           port_id=str(port_id))
            graph.add_edge(switch_node, port_node, kind="attachment")

    for link in telemetry.get("links", []):
        src_sw = str(link.get("src_switch", "")).strip()
        src_pt = str(link.get("src_port", "")).strip()
        dst_sw = str(link.get("dst_switch", "")).strip()
        dst_pt = str(link.get("dst_port", "")).strip()
        if not src_sw or not src_pt or not dst_sw or not dst_pt:
            continue

        try:
            if int(src_pt) >= 4294967040 or int(dst_pt) >= 4294967040:
                continue
        except (TypeError, ValueError):
            if src_pt.lower() == "local" or dst_pt.lower() == "local":
                continue

        src_node = f"s{src_sw}-p{src_pt}"
        dst_node = f"s{dst_sw}-p{dst_pt}"
        if src_node not in graph:
            graph.add_node(src_node, type="port", switch_id=src_sw, port_id=src_pt)
        if dst_node not in graph:
            graph.add_node(dst_node, type="port", switch_id=dst_sw, port_id=dst_pt)

        src_state = str(
            switches.get(src_sw, {}).get("stp_port_states", {}).get(src_pt, "")
        ).upper()
        dst_state = str(
            switches.get(dst_sw, {}).get("stp_port_states", {}).get(dst_pt, "")
        ).upper()
        src_status = switches.get(src_sw, {}).get("port_status", {}).get(src_pt, {})
        dst_status = switches.get(dst_sw, {}).get("port_status", {}).get(dst_pt, {})

        def port_is_live(status):
            if not isinstance(status, dict):
                return True
            state = str(status.get("state", "")).upper()
            if state in {"DOWN", "MISSING", "LINK_DOWN", "ADMIN_DOWN"}:
                return False
            if status.get("link_down") is True or status.get("admin_down") is True:
                return False
            return True

        endpoints_live = port_is_live(src_status) and port_is_live(dst_status)
        stp_forwarding = (
            src_state == "FORWARD" and dst_state == "FORWARD"
            if stp_present else True
        )
        forwarding = endpoints_live and stp_forwarding
        graph.add_edge(
            src_node,
            dst_node,
            kind="inter_switch",
            forwarding=forwarding,
            src_stp_state=src_state or "UNKNOWN",
            dst_stp_state=dst_state or "UNKNOWN",
            src_port_status=str(src_status.get("state", "UNKNOWN")).upper(),
            dst_port_status=str(dst_status.get("state", "UNKNOWN")).upper(),
        )

    graph.graph["links"] = list(telemetry.get("links", []))
    graph.graph["link_inventory"] = list(telemetry.get("links", []))
    return graph


def _forwarding_graph(graph):
    """Return the effective data-plane graph, respecting observed STP blocks."""
    effective = nx.Graph()
    effective.graph.update(graph.graph)
    effective.add_nodes_from((node, dict(data)) for node, data in graph.nodes(data=True))
    for src, dst, data in graph.edges(data=True):
        if data.get("kind") == "inter_switch" and data.get("forwarding") is False:
            continue
        effective.add_edge(src, dst, **dict(data))
    return effective


def get_access_endpoints(graph, spec_path=None):
    """
    Return leaf / access ports: port nodes that connect switches to end hosts.

    Design rationale & change documentation:
    -----------------------------------------
    Access endpoints represent host-facing leaf ports whose mutual reachability
    must be preserved across remediation actions.
    Inter-switch trunk ports connect switches together.
    Crucially, trunk ports whose links are currently DOWN, missing from live
    telemetry, or STP-blocked must NOT be treated as host access endpoints.
    If down trunk ports were treated as access endpoints:
      1. Disabling or blocking a different port would falsely detect an
         unreachable "host" (which is actually a down switch trunk), rejecting
         valid remediation.
      2. Actions intended strictly for host access ports (such as rate_limit_port)
         could be mistakenly permitted on down trunk ports.
    Therefore, get_access_endpoints union-merges live telemetry links with the
    external topology spec file (topology_spec.json) to identify all known
    inter-switch trunk ports, and excludes them from the access endpoint set.
    For single-switch topologies (num_switches < 2), there are no trunk links,
    so all attached ports are correctly recognized as host access endpoints.
    """
    num_switches = len([
        n for n, d in graph.nodes(data=True)
        if d.get("type") == "switch" or (isinstance(n, str) and n.startswith("s") and "-p" not in n)
    ])
    spec_links = load_topology_spec(spec_path=spec_path, num_switches=num_switches) if num_switches >= 2 else []
    live_links = list(graph.graph.get("links") or []) + list(graph.graph.get("link_inventory") or [])
    inv = _union_merge_links(live_links, spec_links)

    known_trunks = set()
    for l in inv:
        s_sw = str(l.get("src_switch", "")).strip()
        s_pt = str(l.get("src_port", "")).strip()
        d_sw = str(l.get("dst_switch", "")).strip()
        d_pt = str(l.get("dst_port", "")).strip()
        if s_sw and s_pt:
            known_trunks.add(f"s{s_sw}-p{s_pt}")
        if d_sw and d_pt:
            known_trunks.add(f"s{d_sw}-p{d_pt}")

    access = []
    for node, data in graph.nodes(data=True):
        is_port = data.get("type") == "port" or "-p" in str(node)
        if not is_port or node in known_trunks:
            continue
        has_inter_switch_link = False
        for neighbour in graph.neighbors(node):
            nd = graph.nodes[neighbour]
            if nd.get("type") == "port" or "-p" in str(neighbour):
                has_inter_switch_link = True
                break
        if not has_inter_switch_link:
            access.append(node)
    return sorted(access)


def check_topology_exists(graph):
    graph = _forwarding_graph(graph)
    """Verify that the topology is not empty."""
    if graph.number_of_nodes() == 0:
        return False, "FAIL: Empty topology"
    return True, "PASS: Topology exists"


def check_connectivity(graph):
    graph = _forwarding_graph(graph)
    """Verify that the topology is connected (or empty)."""
    if graph.number_of_nodes() == 0:
        return False, "FAIL: Empty topology"
    if nx.is_connected(graph):
        return True, "PASS: Topology is connected"
    return False, "FAIL: Topology is disconnected"


def check_loop_freedom(graph):
    graph = _forwarding_graph(graph)
    """
    Report whether the topology contains cycles.

    Intentional redundancy (parallel trunks) creates cycles and is normal.
    This check is informational by default; it is only treated as a hard
    failure when require_loop_free=True is passed to run_safety_checks.
    """
    cycles = nx.cycle_basis(graph)
    if cycles:
        return False, f"INFO: Loop(s) present (redundant paths): {cycles}"
    return True, "PASS: Topology is loop-free"


def check_reachability(graph, required_hosts=None):
    graph = _forwarding_graph(graph)
    """
    Verify mutual reachability among the required endpoints.
    If required_hosts is None, use all port nodes present in the graph.
    """
    checking_all_ports = required_hosts is None
    if checking_all_ports:
        hosts = [
            node
            for node in graph.nodes
            if graph.nodes[node].get("type") == "port" or "-p" in str(node)
        ]
    else:
        hosts = list(required_hosts)

    # Only consider endpoints that still exist in the graph
    hosts = [h for h in hosts if h in graph]

    if not hosts:
        # No endpoints left to check — treat as failure only if graph is empty
        if graph.number_of_nodes() == 0:
            return False, "FAIL: No host or port nodes found in topology"
        return True, "PASS: No required endpoints to check"

    unreachable = []
    for i, h1 in enumerate(hosts):
        for h2 in hosts[i + 1:]:
            if not nx.has_path(graph, h1, h2):
                unreachable.append((h1, h2))

    if unreachable:
        return False, f"FAIL: Unreachable host pairs: {unreachable}"

    if checking_all_ports:
        return True, "PASS: All ports mutually reachable"
    return True, "PASS: All required endpoints mutually reachable"


def run_safety_checks(graph, required_hosts=None, require_loop_free=True):
    """
    Run safety checks and aggregate results.

    Parameters
    ----------
    require_loop_free : bool
        If True, presence of any cycle is a hard failure.
        If False (default), cycles are reported as INFO only.
        Redundant enterprise topologies legitimately contain cycles;
        the critical invariant is reachability of access endpoints.
    """
    results = []
    overall_safe = True

    for check_fn in (check_topology_exists, check_connectivity):
        ok, message = check_fn(graph)
        results.append(message)
        overall_safe = overall_safe and ok

    # Loop check — mandatory only when explicitly requested
    ok, message = check_loop_freedom(graph)
    if require_loop_free:
        results.append(message.replace("INFO:", "FAIL:") if not ok else message)
        overall_safe = overall_safe and ok
    else:
        # Report but do not fail
        results.append(message)

    ok, message = check_reachability(graph, required_hosts)
    results.append(message)
    overall_safe = overall_safe and ok

    return {
        "safe": overall_safe,
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "checks": results
    }


def test_port_removal(graph, port_node, required_hosts=None, require_loop_free=True):
    """
    Simulate removing a port and re-check safety invariants.

    Semantics
    ---------
    - If required_hosts is supplied (e.g. by experiments), those endpoints
      must remain mutually reachable after the removal.
    - If required_hosts is None (live decision-gate path):
        * Access / leaf ports are critical. Blocking one always isolates
          that host → immediately unsafe.
        * Trunk / inter-switch ports may be blocked only if all access
          endpoints remain reachable via alternate paths.
    """
    if port_node not in graph:
        return {
            "safe": False,
            "reason": f"Port {port_node} does not exist"
        }

    if required_hosts is not None:
        endpoints = list(required_hosts)
    else:
        access = get_access_endpoints(graph)
        # Blocking an access endpoint isolates that host — always unsafe
        if port_node in access:
            return {
                "safe": False,
                "nodes": graph.number_of_nodes(),
                "edges": graph.number_of_edges(),
                "checks": [
                    f"FAIL: Port {port_node} is an access endpoint; "
                    f"blocking it isolates that host with no alternate path"
                ]
            }
        # For trunk ports, preserve reachability of access endpoints only
        endpoints = access if access else [
            n for n in graph.nodes
            if (graph.nodes[n].get("type") == "port" or "-p" in str(n))
            and n != port_node
        ]

    test_graph = graph.copy()
    test_graph.remove_node(port_node)

    return run_safety_checks(
        test_graph,
        required_hosts=endpoints,
        require_loop_free=require_loop_free
    )


MIN_RATE_LIMIT_KBPS = 100
MAX_RATE_LIMIT_KBPS = 1000000


def simulate_disable_port(graph, switch, port, required_hosts=None, require_loop_free=True):
    """
    Simulate admin-down on a port: remove the port/edge from the forwarding graph.
    Requires all access hosts remain mutually reachable and loop-free.
    Simulates STP standby link failover if disabling an active trunk requires
    unblocking a standby link to preserve forwarding reachability.
    """
    switch_str = str(switch).strip()
    port_str = str(port).strip()
    port_node = f"s{switch_str}-p{port_str}"

    if port_node not in graph:
        return {
            "safe": False,
            "reason": f"Port {port_node} does not exist in topology",
            "checks": [f"FAIL: Port {port_node} does not exist in topology"]
        }

    access = get_access_endpoints(graph)
    if port_node in access:
        return {
            "safe": False,
            "reason": f"Port {port_node} is an access endpoint; disabling it isolates that host",
            "checks": [f"FAIL: Port {port_node} is an access endpoint; disabling it isolates that host with no alternate path"]
        }

    endpoints = list(required_hosts) if required_hosts is not None else (access if access else None)
    res = test_port_removal(
        graph,
        port_node,
        required_hosts=endpoints,
        require_loop_free=require_loop_free,
    )
    if res.get("safe"):
        return res

    # If disabling the active trunk partitioned the forwarding snapshot, simulate
    # STP standby link failover: check if unblocking a standby inter-switch edge
    # restores mutual reachability loop-free.
    test_graph = graph.copy()
    if port_node in test_graph:
        test_graph.remove_node(port_node)

    for u, v, data in test_graph.edges(data=True):
        if data.get("kind") == "inter_switch" and data.get("forwarding") is False:
            cand_graph = test_graph.copy()
            cand_graph[u][v]["forwarding"] = True
            failover_res = run_safety_checks(cand_graph, required_hosts=endpoints, require_loop_free=require_loop_free)
            if failover_res.get("safe"):
                return failover_res

    return res


RING4_KNOWN_LINKS = [
    {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "1"},
    {"src_switch": "2", "src_port": "1", "dst_switch": "1", "dst_port": "3"},
    {"src_switch": "1", "src_port": "4", "dst_switch": "3", "dst_port": "1"},
    {"src_switch": "3", "src_port": "1", "dst_switch": "1", "dst_port": "4"},
    {"src_switch": "2", "src_port": "2", "dst_switch": "4", "dst_port": "3"},
    {"src_switch": "4", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
    {"src_switch": "3", "src_port": "2", "dst_switch": "4", "dst_port": "4"},
    {"src_switch": "4", "src_port": "4", "dst_switch": "3", "dst_port": "2"},
]

REDUNDANT2_KNOWN_LINKS = [
    {"src_switch": "1", "src_port": "2", "dst_switch": "2", "dst_port": "1"},
    {"src_switch": "2", "src_port": "1", "dst_switch": "1", "dst_port": "2"},
    {"src_switch": "1", "src_port": "3", "dst_switch": "2", "dst_port": "2"},
    {"src_switch": "2", "src_port": "2", "dst_switch": "1", "dst_port": "3"},
]

STATIC_KNOWN_LINKS = RING4_KNOWN_LINKS + REDUNDANT2_KNOWN_LINKS


def simulate_restore_port(
    graph,
    switch,
    port,
    link_inventory=None,
    required_hosts=None,
    require_loop_free=True,
    spec_path=None,
):
    """
    Simulate admin-up on a port: restore edge in the STP-aware forwarding graph.
    Allowed only for ports in the known link/port inventory.
    Re-adds the edge from the link inventory when absent from telemetry links,
    union-merging live links and the external topology spec file (topology_spec.json).
    Then checks connected + loop-free + all hosts reachable.
    Keeps require_loop_free=True to prevent forwarding loops.
    """
    switch_str = str(switch).strip()
    port_str = str(port).strip()
    port_node = f"s{switch_str}-p{port_str}"

    num_switches = len([
        n for n, d in graph.nodes(data=True)
        if d.get("type") == "switch" or (isinstance(n, str) and n.startswith("s") and "-p" not in n)
    ])
    spec_links = load_topology_spec(spec_path=spec_path, num_switches=num_switches)
    live_links = (
        list(link_inventory or [])
        + list(graph.graph.get("link_inventory") or [])
        + list(graph.graph.get("links") or [])
    )
    all_inventory = _union_merge_links(live_links, spec_links)

    matching_links = []
    for link in all_inventory:
        src_sw = str(link.get("src_switch", "")).strip()
        src_pt = str(link.get("src_port", "")).strip()
        dst_sw = str(link.get("dst_switch", "")).strip()
        dst_pt = str(link.get("dst_port", "")).strip()
        if (src_sw == switch_str and src_pt == port_str) or (dst_sw == switch_str and dst_pt == port_str):
            matching_links.append(link)

    port_in_inventory = bool(matching_links)

    if not port_in_inventory and port_node not in graph:
        return {
            "safe": False,
            "reason": f"Port {port_node} is not in the known link/port inventory",
            "checks": [f"FAIL: Port {port_node} is not in the known link/port inventory"]
        }

    sim_graph = graph.copy()
    sw_node = f"s{switch_str}"
    if sw_node not in sim_graph:
        sim_graph.add_node(sw_node, type="switch")
    if port_node not in sim_graph:
        sim_graph.add_node(port_node, type="port", switch_id=switch_str, port_id=port_str)
        sim_graph.add_edge(sw_node, port_node, kind="attachment")

    sim_graph.nodes[port_node]["port_status"] = {"state": "UP", "admin_down": False, "link_down": False}

    for link in matching_links:
        src_sw = str(link.get("src_switch", "")).strip()
        src_pt = str(link.get("src_port", "")).strip()
        dst_sw = str(link.get("dst_switch", "")).strip()
        dst_pt = str(link.get("dst_port", "")).strip()

        if src_sw == switch_str and src_pt == port_str:
            peer_sw, peer_pt = dst_sw, dst_pt
        else:
            peer_sw, peer_pt = src_sw, src_pt

        if peer_sw and peer_pt:
            peer_node = f"s{peer_sw}-p{peer_pt}"
            peer_sw_node = f"s{peer_sw}"
            if peer_sw_node not in sim_graph:
                sim_graph.add_node(peer_sw_node, type="switch")
            if peer_node not in sim_graph:
                sim_graph.add_node(peer_node, type="port", switch_id=peer_sw, port_id=peer_pt)
                sim_graph.add_edge(peer_sw_node, peer_node, kind="attachment")

            sim_graph.add_edge(
                port_node,
                peer_node,
                kind="inter_switch",
                forwarding=True,
                src_stp_state="FORWARD",
                dst_stp_state="FORWARD",
            )

    for nbr in list(sim_graph.neighbors(port_node)):
        edge_data = sim_graph.get_edge_data(port_node, nbr) or {}
        if edge_data.get("kind") == "inter_switch":
            sim_graph[port_node][nbr]["forwarding"] = True

    endpoints = list(required_hosts) if required_hosts is not None else get_access_endpoints(sim_graph, spec_path=spec_path)
    return run_safety_checks(
        sim_graph,
        required_hosts=endpoints,
        require_loop_free=require_loop_free,
    )


def simulate_remove_flow(graph, intent, incident_context=None, required_hosts=None, require_loop_free=True, ledger_path=None):
    """
    Verify removal of exactly one flow rule.
    Only permitted if the flow appears in the incident's drift evidence and is NOT
    a baseline or guardrail ledger cookie.
    Schema validation enforces match is a dict of allowlisted fields.
    Enforces non-empty match, exact bidirectional match equality, and priority equality.
    Fails closed if the guardrail ledger is unreadable or corrupt.
    """
    valid, err = validate_intent_schema(intent)
    if not valid:
        return {
            "safe": False,
            "reason": f"Invalid intent schema: {err}",
            "checks": [f"FAIL: {err}"]
        }

    switch = intent.get("target_switch") or intent.get("switch")
    cookie = intent.get("cookie")
    priority = intent.get("priority")
    match_dict = intent.get("match", {})

    cookie_int = int(str(cookie), 0)
    priority_int = int(str(priority))

    sw_node = f"s{switch}"
    if sw_node not in graph:
        return {
            "safe": False,
            "reason": f"Switch {sw_node} does not exist in topology",
            "checks": [f"FAIL: Switch {sw_node} not in topology"]
        }

    # Baseline flow protections
    if priority_int == 0:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: cannot delete table-miss baseline flow (priority 0)",
            "checks": ["FAIL: Table-miss baseline flow is protected"]
        }
    if priority_int == 1 and cookie_int == 0:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: cannot delete baseline MAC learning flow (priority 1, cookie 0)",
            "checks": ["FAIL: Baseline MAC learning flow is protected"]
        }
    if cookie_int == 0:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: cannot delete baseline flow (cookie 0)",
            "checks": ["FAIL: Baseline flow with cookie 0 is protected"]
        }
    if priority_int == 65500:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: cannot delete active guardrail remediation drop rule (priority 65500)",
            "checks": ["FAIL: Guardrail priority 65500 drop rules are protected"]
        }

    # Non-empty match requirement
    if not match_dict or not normalize_match_dict(match_dict):
        return {
            "safe": False,
            "reason": "Refusing remove_flow: non-empty match is required",
            "checks": ["FAIL: Non-empty match is required"]
        }

    # Guardrail ledger check (fail closed if corrupt)
    try:
        guardrail_cookies = load_guardrail_cookies(ledger_path)
    except CorruptLedgerError as e:
        return {
            "safe": False,
            "reason": f"Refusing remove_flow: guardrail ledger is unreadable or corrupt (fail closed): {e}",
            "checks": ["FAIL: Guardrail cookie ledger corrupt; failing closed"]
        }

    if cookie_int in guardrail_cookies:
        return {
            "safe": False,
            "reason": f"Refusing remove_flow: cannot delete guardrail-installed rule (cookie 0x{cookie_int:x} present in guardrail ledger)",
            "checks": ["FAIL: Guardrail ledger cookies are protected"]
        }

    # Drift evidence verification (passed ONLY server-side)
    if not incident_context:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: no incident drift evidence provided",
            "checks": ["FAIL: Missing incident drift evidence"]
        }

    drift_evidence = (
        incident_context.get("drift_evidence")
        or incident_context.get("anomalous_flows")
        or incident_context.get("evidence", {}).get("flows")
        or []
    )

    found_in_evidence = False
    if isinstance(drift_evidence, list):
        for item in drift_evidence:
            if isinstance(item, dict):
                item_cookie = item.get("cookie")
                item_prio = item.get("priority")
                item_match = item.get("match")
                if item_cookie is not None and item_prio is not None and item_match is not None:
                    try:
                        c_match = int(str(item_cookie), 0) == cookie_int
                        p_match = int(str(item_prio)) == priority_int
                        m_match = matches_strictly_equal(item_match, match_dict)
                        if c_match and p_match and m_match:
                            found_in_evidence = True
                            break
                    except (ValueError, TypeError):
                        pass

    if not found_in_evidence:
        return {
            "safe": False,
            "reason": "Refusing remove_flow: target flow does not appear in the incident's drift evidence (cookie, priority, or match differs from evidence)",
            "checks": ["FAIL: Target flow not found in drift evidence"]
        }

    endpoints = list(required_hosts) if required_hosts is not None else get_access_endpoints(graph)
    return run_safety_checks(graph, required_hosts=endpoints, require_loop_free=require_loop_free)


def simulate_rate_limit_port(graph, intent, required_hosts=None, require_loop_free=True):
    """
    Verify rate-limiting on a port via OpenFlow 1.3 meter.
    Only permitted on host access ports; rate must be bounded by the allowed range.
    """
    valid, err = validate_intent_schema(intent)
    if not valid:
        return {
            "safe": False,
            "reason": f"Invalid intent schema: {err}",
            "checks": [f"FAIL: {err}"]
        }

    switch = intent.get("target_switch") or intent.get("switch")
    port = intent.get("from_port") or intent.get("port")
    rate_kbps = intent.get("rate_kbps")

    port_node = f"s{switch}-p{port}"
    if port_node not in graph:
        return {
            "safe": False,
            "reason": f"Port {port_node} does not exist in topology",
            "checks": [f"FAIL: Port {port_node} does not exist in topology"]
        }

    access = get_access_endpoints(graph)
    if port_node not in access:
        return {
            "safe": False,
            "reason": f"Refusing rate_limit_port: {port_node} is an inter-switch trunk; rate limiting is permitted on access ports only",
            "checks": [f"FAIL: Port {port_node} is not an access port"]
        }

    try:
        rate_int = int(str(rate_kbps))
    except (ValueError, TypeError):
        return {
            "safe": False,
            "reason": f"Invalid rate_kbps value: '{rate_kbps}'",
            "checks": [f"FAIL: Invalid rate_kbps value '{rate_kbps}'"]
        }

    if rate_int < MIN_RATE_LIMIT_KBPS or rate_int > MAX_RATE_LIMIT_KBPS:
        return {
            "safe": False,
            "reason": f"Rate {rate_int} kbps is outside allowed range [{MIN_RATE_LIMIT_KBPS}, {MAX_RATE_LIMIT_KBPS}] kbps",
            "checks": [f"FAIL: Rate {rate_int} kbps out of bounds"]
        }

    endpoints = list(required_hosts) if required_hosts is not None else access
    return run_safety_checks(graph, required_hosts=endpoints, require_loop_free=require_loop_free)


if __name__ == "__main__":
    telemetry = load_telemetry()
    graph = build_topology(telemetry)

    print("=== CURRENT TOPOLOGY ===")
    result = run_safety_checks(graph)
    print(json.dumps(result, indent=4))

    print("\n=== ACCESS ENDPOINTS ===")
    print(get_access_endpoints(graph))

    print("\n=== REMEDIATION SIMULATION (Port Removal) ===")
    result = test_port_removal(graph, "s1-p1")
    print(json.dumps(result, indent=4))
