import networkx as nx


def build_star_topology_data():
    """
    Constructs telemetry JSON data and NetworkX graph for a single-switch star topology.
    Switch s1 with physical access ports 1, 2, 3 and OpenFlow LOCAL port 4294967294.
    """
    telemetry = {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {
                        "rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0
                    },
                    "1": {
                        "rx_packets": 100, "tx_packets": 100, "rx_bytes": 8000, "tx_bytes": 8000
                    },
                    "2": {
                        "rx_packets": 100, "tx_packets": 100, "rx_bytes": 8000, "tx_bytes": 8000
                    },
                    "3": {
                        "rx_packets": 100, "tx_packets": 100, "rx_bytes": 8000, "tx_bytes": 8000
                    }
                },
                "flows": [
                    {
                        "priority": 0,
                        "packet_count": 50,
                        "byte_count": 4000
                    }
                ]
            }
        }
    }

    graph = nx.Graph()
    graph.add_node("s1", type="switch")
    for p in ["1", "2", "3"]:
        port_node = f"s1-p{p}"
        graph.add_node(port_node, type="port")
        graph.add_edge("s1", port_node)

    return telemetry, graph


def build_redundant_topology_data():
    """
    Constructs telemetry JSON data and NetworkX graph for a dual-switch redundant topology.
    
    Structure:
    - Switch s1: Port 1 (Access h1), Port 2 (Trunk A), Port 3 (Trunk B)
    - Switch s2: Port 1 (Trunk A peer), Port 2 (Trunk B peer), Port 3 (Access h2)
    - Redundant links:
        s1-p2 <--> s2-p1 (Trunk Link A)
        s1-p3 <--> s2-p2 (Trunk Link B)
    
    Property:
    Blocking s1-p2 preserves reachability between s1-p1 (h1) and s2-p3 (h2) via Trunk Link B.
    """
    telemetry = {
        "switches": {
            "1": {
                "ports": {
                    "4294967294": {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0},
                    "1": {"rx_packets": 120, "tx_packets": 120, "rx_bytes": 9600, "tx_bytes": 9600},
                    "2": {"rx_packets": 60, "tx_packets": 60, "rx_bytes": 4800, "tx_bytes": 4800},
                    "3": {"rx_packets": 60, "tx_packets": 60, "rx_bytes": 4800, "tx_bytes": 4800}
                },
                "flows": [
                    {"priority": 0, "packet_count": 20, "byte_count": 1600}
                ]
            },
            "2": {
                "ports": {
                    "4294967294": {"rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0},
                    "1": {"rx_packets": 60, "tx_packets": 60, "rx_bytes": 4800, "tx_bytes": 4800},
                    "2": {"rx_packets": 60, "tx_packets": 60, "rx_bytes": 4800, "tx_bytes": 4800},
                    "3": {"rx_packets": 120, "tx_packets": 120, "rx_bytes": 9600, "tx_bytes": 9600}
                },
                "flows": [
                    {"priority": 0, "packet_count": 20, "byte_count": 1600}
                ]
            }
        }
    }

    graph = nx.Graph()
    graph.add_node("s1", type="switch")
    graph.add_node("s2", type="switch")

    # Add s1 ports
    for p in ["1", "2", "3"]:
        node = f"s1-p{p}"
        graph.add_node(node, type="port")
        graph.add_edge("s1", node)

    # Add s2 ports
    for p in ["1", "2", "3"]:
        node = f"s2-p{p}"
        graph.add_node(node, type="port")
        graph.add_edge("s2", node)

    # Add redundant inter-switch trunk links
    graph.add_edge("s1-p2", "s2-p1")
    graph.add_edge("s1-p3", "s2-p2")

    access_endpoints = ["s1-p1", "s2-p3"]

    return telemetry, graph, access_endpoints
