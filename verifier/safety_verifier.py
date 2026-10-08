import json
import os
import networkx as nx

# Prefer project-local telemetry, fall back to the classic home path
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_LOCAL_TELEMETRY = os.path.join(_PROJECT_ROOT, "telemetry", "data", "latest.json")
_HOME_TELEMETRY = os.path.expanduser("~/netops_guardrail/telemetry/data/latest.json")
TELEMETRY_FILE = _LOCAL_TELEMETRY if os.path.exists(_LOCAL_TELEMETRY) else _HOME_TELEMETRY


def load_telemetry(path=None):
    file_path = path or TELEMETRY_FILE
    with open(file_path, "r") as file:
        return json.load(file)


def build_topology(telemetry):
    """
    Build an undirected NetworkX graph from telemetry.
    Switch nodes: s{id}
    Port nodes:   s{id}-p{port}
    Inter-switch links connect the corresponding port nodes.
    OpenFlow LOCAL / reserved ports are ignored.
    """
    graph = nx.Graph()

    for switch_id, switch_data in telemetry.get("switches", {}).items():
        switch_node = f"s{switch_id}"
        graph.add_node(switch_node, type="switch")

        for port_id in switch_data.get("ports", {}):
            # Ignore OpenFlow LOCAL and reserved ports
            try:
                if int(port_id) >= 4294967040:
                    continue
            except (TypeError, ValueError):
                if str(port_id).lower() == "local":
                    continue

            port_node = f"s{switch_id}-p{port_id}"
            graph.add_node(port_node, type="port")
            graph.add_edge(switch_node, port_node)

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
            graph.add_node(src_node, type="port")
        if dst_node not in graph:
            graph.add_node(dst_node, type="port")

        graph.add_edge(src_node, dst_node)

    return graph


def get_access_endpoints(graph):
    """
    Return leaf / access ports: port nodes that have NO edge to another port.

    Trunk / inter-switch ports have a neighbour that is also a port.
    Access ports are only connected to their parent switch.
    These are the endpoints whose reachability must be preserved.
    """
    access = []
    for node, data in graph.nodes(data=True):
        is_port = data.get("type") == "port" or "-p" in str(node)
        if not is_port:
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
    """Verify that the topology is not empty."""
    if graph.number_of_nodes() == 0:
        return False, "FAIL: Empty topology"
    return True, "PASS: Topology exists"


def check_connectivity(graph):
    """Verify that the topology is connected (or empty)."""
    if graph.number_of_nodes() == 0:
        return False, "FAIL: Empty topology"
    if nx.is_connected(graph):
        return True, "PASS: Topology is connected"
    return False, "FAIL: Topology is disconnected"


def check_loop_freedom(graph):
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


def run_safety_checks(graph, required_hosts=None, require_loop_free=False):
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


def test_port_removal(graph, port_node, required_hosts=None):
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
        require_loop_free=False
    )


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
