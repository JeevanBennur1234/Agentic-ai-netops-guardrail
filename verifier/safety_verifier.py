import json
import os
import networkx as nx

TELEMETRY_FILE = os.path.expanduser(
    "~/netops_guardrail/telemetry/data/latest.json"
)


def load_telemetry(path=None):
    file_path = path or TELEMETRY_FILE
    with open(file_path, "r") as file:
        return json.load(file)


def build_topology(telemetry):
    graph = nx.Graph()

    for switch_id, switch_data in telemetry["switches"].items():

        switch_node = f"s{switch_id}"

        graph.add_node(
            switch_node,
            type="switch"
        )

        for port_id in switch_data["ports"]:

            # Ignore OpenFlow LOCAL port
            if port_id == "4294967294":
                continue

            port_node = f"s{switch_id}-p{port_id}"

            graph.add_node(
                port_node,
                type="port"
            )

            graph.add_edge(
                switch_node,
                port_node
            )

    return graph


def check_topology_exists(graph):
    """Verify that the topology is not empty."""

    if graph.number_of_nodes() == 0:
        return False, "FAIL: Empty topology"

    return True, "PASS: Topology exists"


def check_connectivity(graph):
    """Verify that the topology is connected."""

    if nx.is_connected(graph):
        return True, "PASS: Topology is connected"

    return False, "FAIL: Topology is disconnected"


def check_loop_freedom(graph):
    """
    A switching topology should be loop-free.
    Cycles can cause broadcast storms and MAC flapping.
    """

    cycles = nx.cycle_basis(graph)

    if cycles:
        return False, f"FAIL: Loop(s) detected: {cycles}"

    return True, "PASS: Topology is loop-free"


def check_reachability(graph, required_hosts=None):
    """
    Verify that all required hosts (or physical ports) can reach each other.
    """

    hosts = required_hosts or [
        node
        for node in graph.nodes
        if str(node).startswith("h")
    ]

    if hosts:
        unreachable = []
        for i, h1 in enumerate(hosts):
            for h2 in hosts[i + 1:]:
                # If either host/endpoint was removed from topology or disconnected
                if h1 not in graph or h2 not in graph or not nx.has_path(graph, h1, h2):
                    unreachable.append((h1, h2))

        if unreachable:
            return False, f"FAIL: Unreachable host pairs: {unreachable}"

        return True, "PASS: All hosts mutually reachable"

    # Our current telemetry graph does not yet contain hosts.
    # Fallback: verify mutual reachability across all physical port endpoints.
    ports = [
        node
        for node in graph.nodes
        if graph.nodes[node].get("type") == "port" or "-p" in str(node)
    ]

    if ports:
        unreachable = []
        for i, p1 in enumerate(ports):
            for p2 in ports[i + 1:]:
                if not nx.has_path(graph, p1, p2):
                    unreachable.append((p1, p2))

        if unreachable:
            return False, f"FAIL: Unreachable port pairs: {unreachable}"

        return True, "PASS: All ports mutually reachable"

    return False, "FAIL: No host or port nodes found in topology"


def run_safety_checks(graph, required_hosts=None):
    """
    Run all safety checks and aggregate the results.
    """

    results = []
    overall_safe = True

    checks = [
        check_topology_exists,
        check_connectivity,
        check_loop_freedom
    ]

    for check_fn in checks:

        ok, message = check_fn(graph)

        results.append(message)

        overall_safe = overall_safe and ok

    # Run reachability separately so required_hosts can be supplied.
    ok, message = check_reachability(
        graph,
        required_hosts
    )

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
    Simulate removing a port without changing the real network.
    Preserves baseline endpoints so connectivity-breaking remediation is detected.
    """

    if port_node not in graph:

        return {
            "safe": False,
            "reason": f"Port {port_node} does not exist"
        }

    # Derive baseline endpoints from the original topology if not provided
    endpoints = required_hosts or [
        n for n in graph.nodes
        if str(n).startswith("h") or graph.nodes[n].get("type") == "port"
    ]

    test_graph = graph.copy()

    test_graph.remove_node(port_node)

    return run_safety_checks(
        test_graph,
        required_hosts=endpoints
    )


if __name__ == "__main__":

    telemetry = load_telemetry()

    graph = build_topology(telemetry)

    print("=== CURRENT TOPOLOGY ===")

    result = run_safety_checks(graph)

    print(json.dumps(result, indent=4))

    print("\n=== REMEDIATION SIMULATION (Port Removal) ===")

    result = test_port_removal(
        graph,
        "s1-p1"
    )

    print(json.dumps(result, indent=4))
